use crate::checker::verdicts::{AiVerdict, NodeCheckResult};
use crate::throne::{
    controller::Controller,
    models::{Group, Profile},
};
use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone)]
pub struct ThroneDb {
    pub db_path: PathBuf,
}
pub struct DatabaseSnapshot {
    pub profiles: Vec<Profile>,
    pub groups: Vec<Group>,
    pub fingerprints: HashMap<i64, String>,
    pub connection: (Controller, String, bool),
}
pub struct SyncSummary {
    pub ok: usize,
    pub blocked: usize,
    pub skipped: usize,
    pub backup: PathBuf,
}
const BLOCKED_GROUP: &str = "[AI-BLOCKED] Google AI";

pub(crate) fn tune_connection(connection: &Connection) -> rusqlite::Result<()> {
    // These limits belong to the connection, leaving Throne's on-disk settings
    // and journaling mode untouched, including when reading a live WAL.
    connection
        .execute_batch("PRAGMA cache_size=-500; PRAGMA mmap_size=0; PRAGMA temp_store=MEMORY;")
}
impl ThroneDb {
    pub fn new(path: PathBuf) -> Self {
        Self { db_path: path }
    }
    fn open(&self, write: bool) -> Result<Connection> {
        if !self.db_path.is_file() {
            bail!("Файл базы Throne не найден");
        }
        let conn = Connection::open_with_flags(
            &self.db_path,
            if write {
                OpenFlags::SQLITE_OPEN_READ_WRITE
            } else {
                OpenFlags::SQLITE_OPEN_READ_ONLY
            },
        )?;
        tune_connection(&conn)?;
        conn.busy_timeout(Duration::from_secs(2))?;
        for (table, required) in [
            (
                "profiles",
                vec![
                    "id",
                    "name",
                    "type",
                    "gid",
                    "latency",
                    "latency_at",
                    "outbound_json",
                ],
            ),
            (
                "groups",
                vec!["id", "name", "archive", "url", "profiles_json"],
            ),
            ("groups_order", vec!["group_id", "display_order"]),
        ] {
            let mut q = conn.prepare(&format!("PRAGMA table_info(\"{table}\")"))?;
            let columns = q
                .query_map([], |r| r.get::<_, String>(1))?
                .collect::<Result<Vec<_>, _>>()?;
            if required.iter().any(|c| !columns.iter().any(|s| s == c)) {
                bail!("Неподдерживаемая схема Throne: {table}; требуется SQLite Throne 1.3.2+");
            }
        }
        Ok(conn)
    }
    #[cfg(test)]
    pub fn read_profiles(&self) -> Result<Vec<Profile>> {
        let c = self.open(false)?;
        Ok(Self::profiles_on(&c, false)?.0)
    }
    fn profiles_on(c: &Connection, hash: bool) -> Result<(Vec<Profile>, HashMap<i64, String>)> {
        use sha2::{Digest, Sha256};
        let mut q = c.prepare("SELECT p.id,p.name,p.type,p.gid,p.latency,p.latency_at,p.outbound_json,g.archive FROM profiles p JOIN groups g ON g.id=p.gid ORDER BY p.id")?;
        let mut rows = q.query([])?;
        let count: usize = c.query_row("SELECT count(*) FROM profiles", [], |row| row.get(0))?;
        let mut profiles = Vec::with_capacity(count);
        let mut fingerprints = HashMap::with_capacity(if hash { count } else { 0 });
        let mut canonical = Vec::new();
        while let Some(row) = rows.next()? {
            let id = row.get(0)?;
            let name: String = row.get(1)?;
            let kind: String = row.get(2)?;
            let group: i64 = row.get(3)?;
            let value: serde_json::Value = serde_json::from_str(row.get_ref(6)?.as_str()?)?;
            if hash {
                canonical.clear();
                serde_json::to_writer(&mut canonical, &(&name, &kind, group, &value))?;
                fingerprints.insert(id, format!("{:x}", Sha256::digest(&canonical)));
            }
            profiles.push(Profile {
                id,
                name,
                profile_type: kind,
                address: address(&value),
                group: Some(group),
                latency_ms: Some(row.get(4)?),
                latency_at: Some(row.get(5)?),
                disabled: Some(row.get(7)?),
                ..Default::default()
            });
        }
        Ok((profiles, fingerprints))
    }
    pub fn snapshot(&self) -> Result<DatabaseSnapshot> {
        let mut c = self.open(false)?;
        // A sequential startup read needs little SQLite page cache. JSON is
        // parsed one row at a time and never retained alongside the UI rows.
        c.pragma_update(None, "cache_size", -128)?;
        let tx = c.transaction()?;
        let (profiles, fingerprints) = Self::profiles_on(&tx, true)?;
        let mut counts = HashMap::<i64, u64>::new();
        for profile in &profiles {
            if let Some(group) = profile.group {
                *counts.entry(group).or_default() += 1;
            }
        }
        let mut groups = Self::group_rows_on(&tx)?;
        for group in &mut groups {
            group.profile_count = Some(counts.get(&group.id).copied().unwrap_or(0));
        }
        let snapshot = DatabaseSnapshot {
            profiles,
            fingerprints,
            groups,
            connection: Self::connection_on(&tx)?,
        };
        tx.commit()?;
        Ok(snapshot)
    }
    #[cfg(test)]
    pub fn read_groups(&self) -> Result<Vec<Group>> {
        let c = self.open(false)?;
        Self::groups_on(&c)
    }
    fn group_rows_on(c: &Connection) -> Result<Vec<Group>> {
        let mut q = c.prepare("SELECT g.id,g.name,g.archive,g.url FROM groups g LEFT JOIN groups_order o ON o.group_id=g.id ORDER BY o.display_order,g.id")?;
        Ok(q.query_map([], |r| {
            Ok(Group {
                id: r.get(0)?,
                name: r.get(1)?,
                archived: Some(r.get(2)?),
                subscription: Some(
                    r.get::<_, Option<String>>(3)?
                        .is_some_and(|url| !url.is_empty()),
                ),
                profile_count: None,
                updated_at: None,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?)
    }
    #[cfg(test)]
    fn groups_on(c: &Connection) -> Result<Vec<Group>> {
        let mut q = c.prepare("SELECT g.id,g.name,g.archive,g.url,COALESCE(n.total,0) FROM groups g LEFT JOIN groups_order o ON o.group_id=g.id LEFT JOIN (SELECT gid,count(*) AS total FROM profiles GROUP BY gid) n ON n.gid=g.id ORDER BY o.display_order,g.id")?;
        let rows = q.query_map([], |r| {
            Ok(Group {
                id: r.get(0)?,
                name: r.get(1)?,
                archived: Some(r.get(2)?),
                subscription: Some(
                    r.get::<_, Option<String>>(3)?
                        .is_some_and(|url| !url.is_empty()),
                ),
                profile_count: Some(r.get(4)?),
                updated_at: None,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
    #[cfg(test)]
    pub fn fingerprints(&self) -> Result<HashMap<i64, String>> {
        use sha2::{Digest, Sha256};
        let conn = self.open(false)?;
        let mut query = conn.prepare("SELECT id,name,type,gid,outbound_json FROM profiles")?;

        query
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?
            .map(|row| {
                let (id, name, kind, group, json) = row?;
                let value: serde_json::Value = serde_json::from_str(&json)?;
                let canonical = serde_json::to_vec(&(name, kind, group, value))?;
                Ok((id, format!("{:x}", Sha256::digest(canonical))))
            })
            .collect()
    }
    pub fn native_config(&self, id: i64) -> Result<String> {
        let c = self.open(false)?;
        let raw: String =
            c.query_row("SELECT outbound_json FROM profiles WHERE id=?", [id], |r| {
                r.get(0)
            })?;
        native_config_json(&raw)
    }
    pub fn connection(&self) -> Result<(Controller, String, bool)> {
        let c = self.open(false)?;
        Self::connection_on(&c)
    }
    fn connection_on(c: &Connection) -> Result<(Controller, String, bool)> {
        let setting = |name: &str, fallback: &str| -> String {
            c.query_row("SELECT value FROM settings WHERE key=?", [name], |r| {
                r.get::<_, String>(0)
            })
            .unwrap_or_else(|_| fallback.into())
        };
        let port: u16 = setting("remote_api_port", "9095").parse()?;
        let socks: u16 = setting("inbound_socks_port", "2080").parse()?;
        Ok((
            Controller::Wire {
                addr: format!("127.0.0.1:{port}"),
                key: setting("remote_api_key", ""),
            },
            format!("127.0.0.1:{socks}"),
            setting("remote_api_enable", "false") == "true",
        ))
    }
    #[cfg(test)]
    pub fn group_for_url(&self, url: &str) -> Result<i64> {
        let c = self.open(false)?;
        c.query_row("SELECT id FROM groups WHERE url=?", [url.trim()], |r| {
            r.get(0)
        })
        .context(
            "Подписка ещё не импортирована в Throne. Импортируйте её в клиенте и обновите список",
        )
    }
    pub fn sync_sandbox_results(
        &self,
        results: &[NodeCheckResult],
        data_root: &Path,
        guard: impl Fn() -> Result<()>,
    ) -> Result<SyncSummary> {
        if !self
            .db_path
            .canonicalize()?
            .starts_with(data_root.canonicalize()?)
        {
            bail!("Запись разрешена только в sandbox_data");
        }
        self.sync_guarded(results, guard)
    }
    fn sync_guarded(
        &self,
        results: &[NodeCheckResult],
        guard: impl Fn() -> Result<()>,
    ) -> Result<SyncSummary> {
        guard()?;
        let mut c = self.open(true)?;
        let parent = self
            .db_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let file = tempfile::Builder::new()
            .prefix("throne-ai-backup-")
            .suffix(".sqlite")
            .tempfile_in(parent)?;
        let (_, backup) = file.keep()?;
        c.backup(rusqlite::DatabaseName::Main, &backup, None)?;
        guard()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let mut groups: HashMap<i64, Vec<i64>> = HashMap::new();
        {
            let mut q = tx.prepare("SELECT id,profiles_json FROM groups")?;
            for row in q.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))? {
                let (id, json) = row?;
                groups.insert(id, serde_json::from_str(&json)?);
            }
        }
        let mut summary = SyncSummary {
            ok: 0,
            blocked: 0,
            skipped: 0,
            backup,
        };
        let mut blocked_gid = None;
        for res in results {
            // Authentication, ambiguous and transient network errors never disable a node.
            if !matches!(res.verdict, AiVerdict::Unlocked | AiVerdict::Geoblock) {
                summary.skipped += 1;
                continue;
            }
            let (name, typ, gid, outbound): (String, String, i64, String) = tx
                .query_row(
                    "SELECT name,type,gid,outbound_json FROM profiles WHERE id=?",
                    [res.profile_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .context("Профиль удалён после проверки; изменения отменены")?;
            let mut outbound: serde_json::Value = serde_json::from_str(&outbound)?;
            if clean_name(&name) != clean_name(&res.profile_name)
                || typ != res.protocol
                || address(&outbound) != res.server_address
            {
                bail!(
                    "Профиль {} изменён после проверки; изменения отменены",
                    res.profile_id
                );
            }
            let ok = res.verdict.is_working();
            let name = format!(
                "{} {}",
                if ok { "[AI-OK]" } else { "[AI-BLOCKED]" },
                clean_name(&name)
            );
            outbound
                .as_object_mut()
                .context("Некорректный outbound_json")?
                .insert("tag".into(), name.clone().into());
            let new_gid = if !ok {
                if blocked_gid.is_none() {
                    // Use a fresh archive owned by this operation, never repurpose a user's group.
                    let id:i64=tx.query_row("SELECT MAX(COALESCE((SELECT MAX(id) FROM groups),0),group_last_id)+1 FROM entity_ids",[],|r|r.get(0))?;
                    tx.execute("INSERT INTO groups(id,name,archive,skip_auto_update,profiles_json) VALUES(?,?,1,1,'[]')",params![id,BLOCKED_GROUP])?;
                    tx.execute("INSERT INTO groups_order(group_id,display_order) VALUES(?,(SELECT COALESCE(MAX(display_order),-1)+1 FROM groups_order))",[id])?;
                    tx.execute("UPDATE entity_ids SET group_last_id=?", [id])?;
                    groups.insert(id, vec![]);
                    blocked_gid = Some(id);
                }
                let dest = blocked_gid.unwrap();
                groups
                    .get_mut(&gid)
                    .context("Исходная группа не найдена")?
                    .retain(|id| *id != res.profile_id);
                groups.get_mut(&dest).unwrap().push(res.profile_id);
                dest
            } else {
                gid
            };
            let latency = if ok {
                res.latency_ms
                    .context("Нет измеренной задержки подтверждённой ноды")?
                    .max(1)
                    .min(i64::MAX as u64) as i64
            } else {
                -1
            };
            tx.execute("UPDATE profiles SET name=?,outbound_json=?,latency=?,latency_at=?,gid=?,updated_at=? WHERE id=?",
                params![name,serde_json::to_string(&outbound)?,latency,now,new_gid,now,res.profile_id])?;
            if ok {
                summary.ok += 1;
            } else {
                summary.blocked += 1;
            }
        }
        for (gid, ids) in groups {
            tx.execute(
                "UPDATE groups SET profiles_json=? WHERE id=?",
                params![serde_json::to_string(&ids)?, gid],
            )?;
        }
        tx.commit()?;
        Ok(summary)
    }
}
fn address(outbound: &serde_json::Value) -> String {
    if outbound["protocol"].is_string() {
        let server = outbound
            .pointer("/settings/vnext/0")
            .or_else(|| outbound.pointer("/settings/servers/0"));
        if let Some(server) = server
            && let (Some(host), Some(port)) = (server["address"].as_str(), server["port"].as_u64())
        {
            return format!("{host}:{port}");
        }
    }
    match (
        outbound["server"].as_str(),
        outbound["server_port"].as_u64(),
    ) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        _ => String::new(),
    }
}
fn native_config_json(raw: &str) -> Result<String> {
    configuration_json(serde_json::from_str(raw)?)
}

pub(super) fn configuration_json(mut config: serde_json::Value) -> Result<String> {
    if config["type"] == "custom" {
        config = serde_json::from_str(
            config["config"]
                .as_str()
                .context("В custom-профиле нет JSON конфига")?,
        )?;
    }
    if !config.is_object() {
        bail!("Конфиг ноды должен быть JSON-объектом");
    }
    // Preserve the native Xray / sing-box structure, credentials and transport
    // exactly as stored; custom full configurations are already complete.
    // Match Qt's indented JSON export, including empty objects and Unicode.
    let mut bytes = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut serializer = serde_json::Serializer::with_formatter(&mut bytes, formatter);
    serde::Serialize::serialize(&config, &mut serializer)?;
    bytes.push(b'\n');
    Ok(String::from_utf8(bytes)?)
}
fn clean_name(name: &str) -> &str {
    let mut name = name.trim();
    loop {
        if let Some(n) = name
            .strip_prefix("[AI-OK]")
            .or_else(|| name.strip_prefix("[AI-BLOCKED]"))
        {
            name = n.trim();
        } else {
            return name;
        }
    }
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    #[test]
    fn startup_snapshot_matches_saved_fingerprints_and_sees_new_wal_rows() {
        let (_dir, db) = fixture();
        let writer = Connection::open(&db.db_path).unwrap();
        writer
            .execute_batch(
                "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;
            CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
            INSERT INTO settings VALUES('remote_api_port','19095'),('inbound_socks_port','12080');",
            )
            .unwrap();
        let snapshot = db.snapshot().unwrap();
        assert_eq!(
            serde_json::to_value(snapshot.profiles).unwrap(),
            serde_json::to_value(db.read_profiles().unwrap()).unwrap()
        );
        assert_eq!(
            serde_json::to_value(snapshot.groups).unwrap(),
            serde_json::to_value(db.read_groups().unwrap()).unwrap()
        );
        assert_eq!(snapshot.fingerprints, db.fingerprints().unwrap());
        assert_eq!(snapshot.connection.1, "127.0.0.1:12080");
        writer.execute_batch("INSERT INTO profiles VALUES(4,'New','vless',5,0,0,'{\"server\":\"new.test\",\"server_port\":443}',0)").unwrap();
        let snapshot = db.snapshot().unwrap();
        assert_eq!(snapshot.profiles.len(), 4);
        assert_eq!(snapshot.groups[0].profile_count, Some(4));
        assert_eq!(snapshot.fingerprints, db.fingerprints().unwrap());
    }

    #[test]
    #[ignore = "Read-only startup benchmark; optional CHECKER_BENCH_DB, CHECKER_BENCH_MODE=split/snapshot"]
    fn startup_database_benchmark() {
        let (_dir, fixture) = fixture();
        let db = if let Some(path) = std::env::var_os("CHECKER_BENCH_DB") {
            ThroneDb::new(path.into())
        } else {
            let mut c = Connection::open(&fixture.db_path).unwrap();
            let tx = c.transaction().unwrap();
            let full = serde_json::json!({"type":"custom","subtype":"xrayfullconfig","config":include_str!("../../tests/fixtures/custom-xray-full.json")}).to_string();
            for id in 4..=3000 {
                tx.execute(
                    "INSERT INTO profiles VALUES(?,'Fixture','custom',5,0,0,?,0)",
                    params![id, full],
                )
                .unwrap();
            }
            tx.commit().unwrap();
            fixture
        };
        let mode = std::env::var("CHECKER_BENCH_MODE").unwrap_or_else(|_| "snapshot".into());
        let mut times = Vec::new();
        let mut count = 0;
        for _ in 0..25 {
            let start = std::time::Instant::now();
            if mode == "split" {
                let data = (
                    db.read_profiles().unwrap(),
                    db.read_groups().unwrap(),
                    db.connection().unwrap(),
                    db.fingerprints().unwrap(),
                );
                count = data.0.len();
                std::hint::black_box(data);
            } else {
                let data = db.snapshot().unwrap();
                count = data.profiles.len();
                std::hint::black_box(data);
            }
            times.push(start.elapsed().as_secs_f64() * 1000.0);
        }
        times.sort_by(f64::total_cmp);
        println!(
            "Database startup mode={mode}, profiles={count}, median_ms={:.2}, max_ms={:.2}",
            times[12], times[24]
        );
    }
    pub(crate) fn fixture() -> (tempfile::TempDir, ThroneDb) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Throne.db");
        let c = Connection::open(&path).unwrap();
        c.execute_batch(r#"
            CREATE TABLE groups(id INTEGER PRIMARY KEY,name TEXT,archive INTEGER DEFAULT 0,skip_auto_update INTEGER DEFAULT 0,url TEXT,profiles_json TEXT);
            CREATE TABLE groups_order(group_id INTEGER PRIMARY KEY,display_order INTEGER);
            CREATE TABLE entity_ids(group_last_id INTEGER);
            INSERT INTO entity_ids VALUES(5);
            INSERT INTO groups VALUES(5,'Subscription',0,0,'https://example.test/sub','[1,2,3]');
            INSERT INTO groups_order VALUES(5,0);
            CREATE TABLE profiles(id INTEGER PRIMARY KEY,name TEXT,type TEXT,gid INTEGER,latency INTEGER,latency_at INTEGER,outbound_json TEXT,updated_at INTEGER);
            INSERT INTO profiles VALUES(1,'Good','vless',5,0,0,'{"tag":"Good","server":"a.test","server_port":443,"uuid":"secret"}',0);
            INSERT INTO profiles VALUES(2,'Blocked','tuic',5,0,0,'{"tag":"Blocked","server":"b.test","server_port":443}',0);
            INSERT INTO profiles VALUES(3,'Login','vless',5,0,0,'{"tag":"Login","server":"c.test","server_port":443}',0);
        "#).unwrap();
        (dir, ThroneDb::new(path))
    }
    fn result(p: &Profile, v: AiVerdict) -> NodeCheckResult {
        NodeCheckResult {
            profile_id: p.id,
            profile_name: p.name.clone(),
            protocol: p.profile_type.clone(),
            server_address: p.address.clone(),
            verdict: v,
            details: String::new(),
            latency_ms: Some(123),
            final_url: None,
            checked_at: None,
            timings: None,
        }
    }
    #[test]
    fn native_copy_preserves_xray_transport_and_unwraps_custom_configs() {
        let raw = r#"{"protocol":"vless","tag":"fixture","settings":{"vnext":[{"address":"x.test","port":443,"users":[{"id":"fixture-uuid","encryption":"none"}]}]},"streamSettings":{"network":"xhttp","security":"reality","realitySettings":{"publicKey":"fixture-key","shortId":"abcd"},"xhttpSettings":{"path":"/test","extra":{"scMaxBufferedPosts":40}}}}"#;
        let original: serde_json::Value = serde_json::from_str(raw).unwrap();
        let copied: serde_json::Value =
            serde_json::from_str(&native_config_json(raw).unwrap()).unwrap();
        assert_eq!(copied, original);
        assert_eq!(address(&copied), "x.test:443");
        let custom = serde_json::json!({"type":"custom","subtype":"xrayoutbound","config":raw});
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                &native_config_json(&custom.to_string()).unwrap()
            )
            .unwrap(),
            original
        );
        let full = serde_json::json!({"outbounds":[original],"routing":{"rules":[]},"inbounds":[]});
        let custom = serde_json::json!({"type":"custom","subtype":"xrayfullconfig","config":full.to_string()});
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                &native_config_json(&custom.to_string()).unwrap()
            )
            .unwrap(),
            full
        );
        assert!(!native_config_json(raw).unwrap().contains("throne://"));
        let (_dir, db) = fixture();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&db.native_config(1).unwrap()).unwrap()["uuid"],
            "secret"
        );
    }
    #[test]
    fn copy_full_custom_preserves_every_field_from_a_throne_share_link() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let full: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/custom-xray-full.json"))
                .unwrap();
        let custom = serde_json::json!({"type":"custom","subtype":"xrayfullconfig","name":"fixture","config":full.to_string()});
        let link = format!(
            "throne://add/{}",
            URL_SAFE_NO_PAD.encode(custom.to_string())
        );
        let decoded = URL_SAFE_NO_PAD
            .decode(link.strip_prefix("throne://add/").unwrap())
            .unwrap();
        let (_dir, db) = fixture();
        db.open(true)
            .unwrap()
            .execute(
                "UPDATE profiles SET type='custom',outbound_json=? WHERE id=1",
                [String::from_utf8(decoded).unwrap()],
            )
            .unwrap();
        let copied = db.native_config(1).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&copied).unwrap(),
            full
        );
        assert!(copied.starts_with("{\n    \"dns\": {\n        \"queryStrategy\""));
        assert!(copied.contains("🇦🇪 ОАЭ"));
        assert!(!copied.contains("throne://"));
        assert!(!copied.contains("xrayfullconfig"));
        for subtype in ["outbound", "fullconfig", "xrayoutbound", "xrayfullconfig"] {
            let wrapper =
                serde_json::json!({"type":"custom","subtype":subtype,"config":full.to_string()});
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&configuration_json(wrapper).unwrap())
                    .unwrap(),
                full
            );
        }
        for invalid in [
            serde_json::json!({"type":"custom"}),
            serde_json::json!({"type":"custom","config":"[]"}),
            serde_json::json!({"type":"custom","config":"broken"}),
            serde_json::json!(null),
        ] {
            assert!(configuration_json(invalid).is_err());
        }
    }
    #[test]
    fn direct_reads_include_new_groups_and_live_wal_profiles() {
        let (_dir, db) = fixture();
        let source = Connection::open(&db.db_path).unwrap();
        source.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;
            CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
            INSERT INTO settings VALUES('remote_api_port','9095'),('inbound_socks_port','2080'),('remote_api_enable','false');").unwrap();
        assert_eq!(db.read_groups().unwrap().len(), 1);
        source.execute_batch("INSERT INTO groups VALUES(7,'New group',0,0,'','[4]');
            INSERT INTO groups_order VALUES(7,1);
            INSERT INTO profiles VALUES(4,'New node','vless',7,0,0,'{\"server\":\"new.test\",\"server_port\":443}',0);").unwrap();
        let groups = db.read_groups().unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[1].profile_count, Some(1));
        assert_eq!(db.read_profiles().unwrap()[3].group, Some(7));
        let (_, proxy, enabled) = db.connection().unwrap();
        assert_eq!(proxy, "127.0.0.1:2080");
        assert!(!enabled);
        assert!(source.execute("DELETE FROM profiles", []).is_ok());
        assert!(db.read_profiles().unwrap().is_empty());
    }
    #[test]
    fn actual_schema_backup_archive_and_auth_skip() {
        let (_d, db) = fixture();
        let p = db.read_profiles().unwrap();
        assert_eq!(db.group_for_url("https://example.test/sub").unwrap(), 5);
        let s = db
            .sync_guarded(
                &[
                    result(&p[0], AiVerdict::Unlocked),
                    result(&p[1], AiVerdict::Geoblock),
                    result(&p[2], AiVerdict::SessionExpired),
                    result(&p[2], AiVerdict::GoogleChallenge),
                ],
                || Ok(()),
            )
            .unwrap();
        assert_eq!((s.ok, s.blocked, s.skipped), (1, 1, 2));
        assert!(s.backup.exists());
        let p = db.read_profiles().unwrap();
        assert_eq!(p[0].latency_ms, Some(123));
        assert_eq!(p[1].disabled, Some(true));
        assert_eq!(p[2].name, "Login");
        let c = db.open(false).unwrap();
        let out: String = c
            .query_row("SELECT outbound_json FROM profiles WHERE id=1", [], |r| {
                r.get(0)
            })
            .unwrap();
        let out: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(out["uuid"], "secret");
        assert_eq!(out["tag"], "[AI-OK] Good");
        let backup = ThroneDb::new(s.backup);
        assert_eq!(backup.read_profiles().unwrap()[0].name, "Good");
    }
    #[test]
    fn changed_identity_rolls_back_entire_batch() {
        let (_d, db) = fixture();
        let p = db.read_profiles().unwrap();
        let mut bad = result(&p[1], AiVerdict::Geoblock);
        bad.server_address = "different:443".into();
        assert!(
            db.sync_guarded(&[result(&p[0], AiVerdict::Unlocked), bad], || Ok(()))
                .is_err()
        );
        assert_eq!(db.read_profiles().unwrap()[0].name, "Good");
    }
    #[test]
    fn saved_result_fingerprint_checks_credentials_and_ignores_cached_latency() {
        let (_dir, db) = fixture();
        let before = db.fingerprints().unwrap();
        let conn = db.open(true).unwrap();
        conn.execute("UPDATE profiles SET latency=777 WHERE id=1", [])
            .unwrap();
        assert_eq!(db.fingerprints().unwrap(), before);
        let raw: String = conn
            .query_row("SELECT outbound_json FROM profiles WHERE id=1", [], |row| {
                row.get(0)
            })
            .unwrap();
        let mut json: serde_json::Value = serde_json::from_str(&raw).unwrap();
        json["uuid"] = serde_json::json!("updated fixture credentials");
        conn.execute(
            "UPDATE profiles SET outbound_json=? WHERE id=1",
            [json.to_string()],
        )
        .unwrap();
        let after = db.fingerprints().unwrap();
        assert_ne!(before[&1], after[&1]);
        assert_eq!(before[&2], after[&2]);
    }
}
