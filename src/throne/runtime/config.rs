//! Rust batch builder for native sing-box profiles and Xray/VLESS/full configs.
//! Unknown profile policies stay on the native Throne path instead of silently
//! dropping settings. The proxy protocols themselves remain in ThroneCore.
use super::wire::LoadConfig;
use crate::throne::models::Profile;
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OpenFlags};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    net::TcpListener,
    path::Path,
    time::Duration,
};

pub const BATCH_SIZE: usize = 100;
pub const CONCURRENCY: usize = 10;
#[derive(Debug)]
pub struct NativeRequired(pub &'static str);
impl std::fmt::Display for NativeRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for NativeRequired {}
fn native_when(condition: bool, reason: &'static str) -> Result<()> {
    if condition {
        return Err(NativeRequired(reason).into());
    }
    Ok(())
}
pub struct Source {
    pub profiles: Vec<(Profile, Value)>,
    pub native_profiles: HashSet<i64>,
    strategy: String,
    dns: Value,
    xray_dns_strategy: String,
    skip_cert: bool,
}
fn local_dns() -> Value {
    json!({"servers":[{"tag":"dns-direct","type":"local","domain_resolver":"dns-local"},{"tag":"dns-local","type":"local"}],"cache_capacity":65536,"final":"dns-direct"})
}

impl Source {
    #[cfg(test)]
    pub fn synthetic(profiles: Vec<(Profile, Value)>) -> Self {
        Self {
            profiles,
            native_profiles: HashSet::new(),
            strategy: String::new(),
            dns: local_dns(),
            xray_dns_strategy: "UseIP".into(),
            skip_cert: false,
        }
    }
    pub fn read(
        database: &Path,
        profiles: &[Profile],
        fingerprints: &HashMap<i64, String>,
    ) -> Result<Self> {
        let mut connection =
            Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        connection.busy_timeout(Duration::from_secs(2))?;
        let transaction = connection.transaction()?;
        let settings: HashMap<String, String> = transaction
            .prepare("SELECT key,value FROM settings")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<_, _>>()?;
        let setting = |key: &str| settings.get(key).map(String::as_str).unwrap_or("");
        for key in [
            "mux_default_on",
            "xray_mux_default_on",
            "fragment_default_on",
            "tls_spoof_default_on",
            "tls_tricks_default_on",
            "use_dns_object",
            "enable_ntp",
        ] {
            native_when(setting(key) == "true", "advanced global settings")?;
        }
        native_when(
            !matches!(setting("direct_dns"), "" | "localhost" | "local"),
            "custom direct DNS resolver",
        )?;
        native_when(
            !setting("utlsFingerprint").is_empty(),
            "global uTLS override",
        )?;
        native_when(
            !setting("core_box_underlying_dns").is_empty(),
            "custom underlying resolver",
        )?;
        let mut rows = Vec::with_capacity(profiles.len());
        let mut native_profiles = HashSet::new();
        for profile in profiles {
            let (name, kind, group, raw): (String, String, i64, String) = transaction.query_row(
                "SELECT name,type,gid,outbound_json FROM profiles WHERE id=?",
                [profile.id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?;
            let value: Value = serde_json::from_str(&raw)?;
            let hash = format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&(&name, &kind, group, &value))?)
            );
            ensure!(
                fingerprints.get(&profile.id) == Some(&hash),
                "Configurations changed; refresh the profile list"
            );
            let (front, landing): (i64, i64) = transaction.query_row(
                "SELECT front_proxy_id,landing_proxy_id FROM groups WHERE id=?",
                [group],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            ensure!(
                name == profile.name
                    && kind == profile.profile_type
                    && Some(group) == profile.group,
                "Profile identity changed"
            );
            if front >= 0 || landing >= 0 || validate(&kind, &value).is_err() {
                native_profiles.insert(profile.id);
            }
            rows.push((profile.clone(), value));
        }
        let mut strategy = setting("outbound_domain_strategy").to_owned();
        if setting("direct_dns_disable_ipv6") == "true" {
            strategy = "ipv4_only".into();
        }
        let xray_dns_strategy = match strategy.as_str() {
            "prefer_ipv4" => "UseIPv4v6",
            "prefer_ipv6" => "UseIPv6v4",
            "ipv6_only" => "ForceIPv6",
            "ipv4_only" if setting("outbound_domain_strategy") == "ipv4_only" => "ForceIPv4",
            "ipv4_only" => "UseIPv4",
            _ => "UseIP",
        }
        .to_owned();
        let mut dns = local_dns();
        dns["cache_capacity"] = json!(
            setting("dns_cache_capacity")
                .parse::<u32>()
                .unwrap_or(65536)
        );
        for (setting_key, field) in [
            ("dns_disable_cache", "disable_cache"),
            ("dns_disable_expire", "disable_expire"),
            ("dns_reverse_mapping", "reverse_mapping"),
        ] {
            if setting(setting_key) == "true" {
                dns[field] = json!(true);
            }
        }
        if !setting("dns_query_timeout").is_empty() {
            dns["timeout"] = json!(setting("dns_query_timeout"));
        }
        if setting("dns_optimistic") == "true"
            && setting("dns_disable_cache") != "true"
            && setting("dns_disable_expire") != "true"
        {
            dns["optimistic"] = if setting("dns_optimistic_timeout").is_empty() {
                json!(true)
            } else {
                json!({"enabled":true,"timeout":setting("dns_optimistic_timeout")})
            };
        }
        Ok(Self {
            profiles: rows,
            native_profiles,
            strategy,
            dns,
            xray_dns_strategy,
            skip_cert: setting("skip_cert") == "true",
        })
    }
    pub fn build(&self, profiles: &[(Profile, Value)]) -> Result<Plan> {
        let mut ports = Vec::new();
        let mut inbounds = Vec::new();
        let mut outbounds = Vec::new();
        let mut routes = Vec::new();
        let mut xray_inbounds = Vec::new();
        let mut xray_outbounds = Vec::new();
        let mut xray_routes = Vec::new();
        let mut full = Vec::new();
        let mut proxies = HashMap::new();
        for (profile, raw) in profiles {
            let proxy_port = reserve(&mut ports)?;
            let tag = format!("checker-{}", profile.id);
            let inbound = format!("{tag}-in");
            inbounds.push(
                json!({"type":"socks","tag":inbound,"listen":"127.0.0.1","listen_port":proxy_port}),
            );
            routes.push(json!({"inbound":[inbound],"action":"route","outbound":tag}));
            proxies.insert(profile.id, format!("127.0.0.1:{proxy_port}"));
            let mut outbound = if profile.profile_type == "xrayvless"
                || profile.profile_type == "custom"
            {
                let bridge = reserve(&mut ports)?;
                let auth = format!("{:032x}", rand::random::<u128>());
                let bridge_tag = if profile.profile_type == "custom" {
                    "throne-bridge".to_owned()
                } else {
                    format!("{tag}-bridge")
                };
                let mut bridge_in = json!({"tag":bridge_tag,"listen":"127.0.0.1","port":bridge,"protocol":"socks","settings":{"auth":"password","accounts":[{"user":auth,"pass":auth}],"udp":true}});
                if profile.profile_type == "custom" {
                    let mut config: Value = serde_json::from_str(
                        raw["config"].as_str().context("Missing Xray config")?,
                    )?;
                    bridge_in["sniffing"] = json!({"enabled":true,"destOverride":["http","tls","quic"],"routeOnly":false});
                    config["inbounds"] = json!([bridge_in]);
                    // Native batch builds replace user inbounds too. All routing/outbounds stay intact.
                    config["log"] = json!({"loglevel":"none","access":"none","error":"none"});
                    full.push(serde_json::to_string(&config)?);
                } else {
                    let mut xray = raw.clone();
                    xray["tag"] = json!(tag);
                    xray_inbounds.push(bridge_in);
                    xray_routes
                        .push(json!({"type":"field","inboundTag":[bridge_tag],"outboundTag":tag}));
                    xray_outbounds.push(xray);
                }
                json!({"type":"socks","server":"127.0.0.1","server_port":bridge,"version":"5","username":auth,"password":auth})
            } else {
                let mut outbound = raw.clone();
                let quic = outbound["transport"]["type"] == "quic";
                if let Some(tls) = outbound.get_mut("tls").and_then(Value::as_object_mut) {
                    if self.skip_cert {
                        tls.insert("insecure".into(), json!(true));
                    }
                    if quic {
                        tls.remove("utls");
                    }
                    if tls.get("enabled") != Some(&json!(true)) {
                        outbound.as_object_mut().unwrap().remove("tls");
                    }
                }
                outbound
            };
            outbound["tag"] = json!(tag);
            outbounds.push(outbound);
        }
        let config = json!({
            "log":{"disabled":true},
            "dns":self.dns,
            "inbounds":inbounds,"outbounds":outbounds,
            "route":{"auto_detect_interface":true,"default_domain_resolver":{"server":"dns-direct","strategy":self.strategy},"rules":routes}
        });
        let xray = if xray_outbounds.is_empty() {
            String::new()
        } else {
            serde_json::to_string(
                &json!({"log":{"loglevel":"none","access":"none","error":"none"},"inbounds":xray_inbounds,"outbounds":xray_outbounds,"routing":{"domainStrategy":"AsIs","rules":xray_routes}}),
            )?
        };
        Ok(Plan {
            load: LoadConfig {
                core_config: serde_json::to_string(&config)?,
                xray_config: xray,
                xray_full_configs: full,
                xray_dns_strategy: self.xray_dns_strategy.clone(),
            },
            proxies,
            ports,
        })
    }
}

fn validate(kind: &str, raw: &Value) -> Result<()> {
    let keys = raw.as_object().context("Profile is not a JSON object")?;
    let allowed: &[&str] = match kind {
        "vless" => &[
            "type",
            "server",
            "server_port",
            "tag",
            "uuid",
            "flow",
            "packet_encoding",
            "tls",
            "transport",
            "multiplex",
            "bind_interface",
            "connect_timeout",
            "inet4_bind_address",
            "inet6_bind_address",
            "tcp_fast_open",
            "tcp_multi_path",
            "udp_fragment",
            "domain_resolver",
            "network_strategy",
            "network_type",
            "fallback_network_type",
            "fallback_delay",
        ],
        "trojan" => &[
            "type",
            "server",
            "server_port",
            "tag",
            "password",
            "tls",
            "transport",
            "multiplex",
            "bind_interface",
            "connect_timeout",
            "inet4_bind_address",
            "inet6_bind_address",
            "tcp_fast_open",
            "tcp_multi_path",
            "udp_fragment",
            "domain_resolver",
            "network_strategy",
            "network_type",
            "fallback_network_type",
            "fallback_delay",
        ],
        "xrayvless" => &["protocol", "settings", "streamSettings", "mux", "tag"],
        "custom" => &["config", "name", "subtype", "type"],
        _ => anyhow::bail!("Native Throne required for profile type {kind}"),
    };
    ensure!(
        keys.keys().all(|key| allowed.contains(&key.as_str())),
        "Native Throne required for advanced profile fields"
    );
    if kind == "custom" {
        ensure!(
            raw["subtype"] == "xrayfullconfig",
            "Native Throne required for this custom profile"
        );
        let config: Value =
            serde_json::from_str(raw["config"].as_str().context("Missing custom config")?)?;
        ensure!(
            config.is_object() && config["outbounds"].is_array(),
            "Invalid Xray full config"
        );
    }
    if matches!(kind, "vless" | "trojan") {
        if let Some(transport) = raw.get("transport") {
            let transport = transport.as_object().context("Invalid transport")?;
            let kind = transport.get("type").and_then(Value::as_str).unwrap_or("");
            let fields: &[&str] = match kind {
                "http" => &[
                    "type",
                    "host",
                    "path",
                    "method",
                    "headers",
                    "idle_timeout",
                    "ping_timeout",
                ],
                "ws" => &[
                    "type",
                    "path",
                    "headers",
                    "max_early_data",
                    "early_data_header_name",
                ],
                "quic" => &["type"],
                "grpc" => &[
                    "type",
                    "service_name",
                    "idle_timeout",
                    "ping_timeout",
                    "permit_without_stream",
                ],
                "httpupgrade" => &["type", "host", "path", "headers"],
                _ => anyhow::bail!("Native Throne required for transport"),
            };
            ensure!(
                transport.keys().all(|key| fields.contains(&key.as_str())),
                "Native Throne required for transport conversion"
            );
            ensure!(
                !transport
                    .get("host")
                    .and_then(Value::as_str)
                    .is_some_and(|host| host.contains(',')),
                "Native Throne required for host-list conversion"
            );
        }
        if let Some(tls) = raw.get("tls") {
            let fields = tls.as_object().context("Invalid TLS object")?;
            // Stored GUI-only flags must be resolved by the original generator.
            ensure!(
                fields.keys().all(|key| [
                    "enabled",
                    "disable_sni",
                    "server_name",
                    "insecure",
                    "alpn",
                    "min_version",
                    "max_version",
                    "cipher_suites",
                    "curve_preferences",
                    "certificate",
                    "certificate_path",
                    "certificate_sha256",
                    "certificate_public_key_sha256",
                    "client_certificate",
                    "client_certificate_path",
                    "client_key",
                    "client_key_path",
                    "utls"
                ]
                .contains(&key.as_str())),
                "Native Throne required for advanced TLS settings"
            );
        }
    }
    Ok(())
}
fn reserve(ports: &mut Vec<TcpListener>) -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    ports.push(listener);
    Ok(port)
}
pub struct Plan {
    pub load: LoadConfig,
    pub proxies: HashMap<i64, String>,
    ports: Vec<TcpListener>,
}
impl Plan {
    pub fn release_ports(&mut self) {
        self.ports.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn each_profile_has_a_distinct_pinned_route_and_lossless_xray_payload() {
        let profiles = (0..12).map(|id| (Profile { id, profile_type:"xrayvless".into(), ..Default::default() }, json!({"protocol":"vless","settings":{"address":"127.0.0.1","port":9,"id":"00000000-0000-0000-0000-000000000001","encryption":"none"},"streamSettings":{"network":"raw","security":"none"}}))).collect();
        let source = Source::synthetic(profiles);
        let plan = source.build(&source.profiles).unwrap();
        let sing: Value = serde_json::from_str(&plan.load.core_config).unwrap();
        let xray: Value = serde_json::from_str(&plan.load.xray_config).unwrap();
        assert_eq!(
            plan.proxies
                .values()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            12
        );
        for (index, (_, raw)) in source.profiles.iter().enumerate() {
            let tag = format!("checker-{index}");
            assert_eq!(sing["route"]["rules"][index]["outbound"], tag);
            assert_eq!(xray["routing"]["rules"][index]["outboundTag"], tag);
            assert_eq!(xray["outbounds"][index]["settings"], raw["settings"]);
            assert_eq!(
                xray["outbounds"][index]["streamSettings"],
                raw["streamSettings"]
            );
            assert_eq!(
                sing["outbounds"][index]["server_port"],
                xray["inbounds"][index]["port"]
            );
            assert_eq!(
                sing["outbounds"][index]["password"],
                xray["inbounds"][index]["settings"]["accounts"][0]["pass"]
            );
        }
    }
    #[test]
    fn unknown_protocol_and_gui_only_options_require_the_native_generator() {
        assert!(validate("chain", &json!({})).is_err());
        assert!(validate("vless", &json!({"tls":{"spoof_enabled":true}})).is_err());
        assert!(validate("custom", &json!({"subtype":"fullconfig"})).is_err());
    }
    #[test]
    fn source_reads_committed_wal_and_rejects_changed_identity_without_relabeling_it() {
        let (_root, db) = crate::throne::db::tests::fixture();
        let writer = Connection::open(&db.db_path).unwrap();
        writer.execute_batch("PRAGMA journal_mode=WAL; ALTER TABLE groups ADD COLUMN front_proxy_id INTEGER DEFAULT -1; ALTER TABLE groups ADD COLUMN landing_proxy_id INTEGER DEFAULT -1; CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);").unwrap();
        let profiles = vec![db.read_profiles().unwrap().remove(0)];
        let hashes = db.fingerprints().unwrap();
        assert_eq!(
            Source::read(&db.db_path, &profiles, &hashes)
                .unwrap()
                .profiles
                .len(),
            1
        );
        let mixed = Source::read(&db.db_path, &db.read_profiles().unwrap(), &hashes).unwrap();
        assert_eq!(mixed.profiles.len(), 3);
        assert_eq!(mixed.native_profiles, HashSet::from([2]));
        writer.execute("UPDATE profiles SET outbound_json=json_set(outbound_json,'$.uuid','changed') WHERE id=1",[]).unwrap();
        let error = Source::read(&db.db_path, &profiles, &hashes).err().unwrap();
        assert!(
            !error.is::<NativeRequired>(),
            "A changed identity must stop; it must not fall back and save against the old fingerprint"
        );
        let fresh = db.fingerprints().unwrap();
        assert!(Source::read(&db.db_path, &profiles, &fresh).is_ok());
        writer
            .execute("INSERT INTO settings VALUES('mux_default_on','true')", [])
            .unwrap();
        assert!(
            Source::read(&db.db_path, &profiles, &fresh)
                .err()
                .unwrap()
                .is::<NativeRequired>()
        );
        assert_eq!(db.fingerprints().unwrap(), fresh);
    }
    #[test]
    #[ignore = "Read-only installed DB compatibility audit; no processes or network requests; requires THRONE_TEST_DB"]
    fn installed_profiles_build_without_touching_the_database() {
        let path =
            std::path::PathBuf::from(std::env::var_os("THRONE_TEST_DB").expect("THRONE_TEST_DB"));
        let db = crate::throne::db::ThroneDb::new(path.clone());
        let profiles = db.read_profiles().unwrap();
        let hashes = db.fingerprints().unwrap();
        let source = Source::read(&path, &profiles, &hashes).unwrap();
        let supported: Vec<_> = source
            .profiles
            .iter()
            .filter(|(profile, _)| !source.native_profiles.contains(&profile.id))
            .cloned()
            .collect();
        for batch in supported.chunks(BATCH_SIZE) {
            source.build(batch).unwrap().load.encode().unwrap();
        }
        assert_eq!(db.fingerprints().unwrap(), hashes);
        println!(
            "Rust builder supports {} installed profiles; {} use native generation; original definitions unchanged; no network",
            supported.len(),
            source.native_profiles.len()
        );
    }
}
