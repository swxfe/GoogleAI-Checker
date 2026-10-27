use super::{
    engine::{EngineEvent, ScanConfig, TestEngine, cancelled},
    probe::Probe,
    verdicts::{AiVerdict, CheckTimings, NodeCheckResult},
};
use crate::{
    events::EventSender,
    throne::{
        models::Profile,
        runtime::{
            Runtime,
            config::{BATCH_SIZE, CONCURRENCY, NativeRequired, Source},
        },
    },
};
use anyhow::Result;
use futures_util::{StreamExt, stream};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Returns false only before any profile was tested, allowing native generation
/// for unsupported policies. Once results start, failures stop the scan.
pub(super) async fn run(
    config: &ScanConfig,
    stop: &Arc<AtomicBool>,
    tx: &EventSender<EngineEvent>,
) -> Result<bool> {
    let Some(runtime_config) = &config.native_runtime else {
        return Ok(false);
    };
    let started = Instant::now();
    let mut source = match Source::read(
        &runtime_config.database,
        &config.profiles,
        &runtime_config.fingerprints,
    ) {
        Ok(source) => source,
        Err(error) if error.is::<NativeRequired>() => return Ok(false),
        Err(error) => return Err(error),
    };
    let compatible: Vec<_> = source
        .profiles
        .iter()
        .filter(|(profile, _)| !source.native_profiles.contains(&profile.id))
        .cloned()
        .collect();
    let (_, families) = group_profiles(&compatible)?;
    source.profiles.retain(|(profile, _)| {
        source.native_profiles.contains(&profile.id) || families.contains_key(&profile.id)
    });
    let probe = Probe::open(config).inspect_err(|_| {
        if config.require_login {
            let _ = tx.send(EngineEvent::LoginExpired);
        }
    })?;
    let mut emitted = false;
    let mut setup_ms = 0;
    let mut offset = 0;
    while offset < source.profiles.len() {
        if stopped(config, stop) {
            break;
        }
        let use_native = source
            .native_profiles
            .contains(&source.profiles[offset].0.id);
        let end = (offset + 1..source.profiles.len().min(offset + BATCH_SIZE))
            .find(|index| {
                source
                    .native_profiles
                    .contains(&source.profiles[*index].0.id)
                    != use_native
            })
            .unwrap_or(source.profiles.len().min(offset + BATCH_SIZE));
        let batch = &source.profiles[offset..end];
        offset = end;
        if use_native {
            if native_batch(config, batch, stop, tx).await {
                let _ = tx.send(EngineEvent::Finished { cancelled: true });
                return Ok(true);
            }
            emitted = true;
            continue;
        }
        let batch_started = Instant::now();
        let plan = source.build(batch)?;
        let launch = Runtime::start(runtime_config.clone(), plan);
        let mut runtime = match tokio::select! {
            result = launch => Some(result),
            _ = cancelled(stop) => None,
        } {
            None => break,
            Some(Ok(runtime)) => runtime,
            // A refused native-core configuration must never become a dead-node verdict.
            Some(Err(_)) => {
                let expanded: Vec<_> = batch
                    .iter()
                    .flat_map(|(profile, raw)| {
                        families[&profile.id]
                            .iter()
                            .map(move |alias| (alias.clone(), raw.clone()))
                    })
                    .collect();
                if native_batch(config, &expanded, stop, tx).await {
                    let _ = tx.send(EngineEvent::Finished { cancelled: true });
                    return Ok(true);
                }
                emitted = true;
                continue;
            }
        };
        setup_ms += ms(batch_started);
        if !emitted {
            let _ = tx.send(EngineEvent::BrowserSelected {
                path: config.browser_path.clone(),
            });
            setup_ms = ms(started);
        }
        let budget = config
            .node_timeout
            .clamp(Duration::from_secs(2), Duration::from_secs(12));
        let budget = if config.profiles.len() == 1 {
            budget
        } else {
            budget.min(Duration::from_secs(4))
        };
        let work: Vec<_> = batch
            .iter()
            .map(|(profile, _)| (profile.clone(), runtime.proxies[&profile.id].clone()))
            .collect();
        let jobs = stream::iter(work.into_iter().map(|(profile, proxy): (Profile, String)| {
            let probe = probe.fork();
            let family = families[&profile.id].clone();
            let tx = tx.clone();
            async move {
                for alias in family.iter().skip(1) {
                    let _ = tx.send(EngineEvent::NodeTesting {
                        profile_id: alias.id,
                    });
                }
                check_node(profile, probe, proxy, budget, tx).await
            }
        }))
        .buffer_unordered(CONCURRENCY);
        let mut jobs = Box::pin(jobs);
        loop {
            let next = tokio::select! {
                result = jobs.next() => result,
                _ = cancelled(stop) => None,
            };
            let Some(result) = next else {
                break;
            };
            runtime.ensure_running()?;
            if stopped(config, stop) {
                break;
            }
            let mut result = result?;
            if result.verdict == AiVerdict::SessionExpired {
                let _ = tx.send(EngineEvent::LoginExpired);
                anyhow::bail!("Google session expired. Queue paused; sign in again");
            }
            if let Some(timing) = &mut result.timings {
                timing.setup_ms = setup_ms;
                timing.total_ms = timing.total_ms.saturating_add(setup_ms);
            }
            setup_ms = 0;
            let rate_limited = result.verdict == AiVerdict::RateLimited;
            for profile in &families[&result.profile_id] {
                let mut shared = result.clone();
                shared.profile_id = profile.id;
                shared.profile_name = profile.name.clone();
                shared.protocol = profile.profile_type.clone();
                shared.server_address = profile.address.clone();
                let _ = tx.send(EngineEvent::NodeFinished { result: shared });
            }
            emitted = true;
            if rate_limited {
                anyhow::bail!("Google rate-limited requests. The queue is paused; retry later");
            }
        }
        // In-flight futures are dropped before the owned host/core tree.
        drop(jobs);
        drop(runtime);
    }
    let _ = tx.send(EngineEvent::Finished {
        cancelled: stopped(config, stop),
    });
    Ok(true)
}
type ProfileBatch = Vec<(Profile, serde_json::Value)>;
type Families = HashMap<i64, Vec<Profile>>;
fn group_profiles(profiles: &[(Profile, serde_json::Value)]) -> Result<(ProfileBatch, Families)> {
    let mut unique = Vec::new();
    let mut families: Families = HashMap::new();
    let mut keys = HashMap::new();
    for (profile, raw) in profiles {
        let mut config = raw.clone();
        if let Some(object) = config.as_object_mut() {
            object.remove("tag");
            object.remove("name");
        }
        let key = serde_json::to_vec(&(&profile.profile_type, config))?;
        let representative = *keys.entry(key).or_insert_with(|| {
            unique.push((profile.clone(), raw.clone()));
            profile.id
        });
        families
            .entry(representative)
            .or_default()
            .push(profile.clone());
    }
    Ok((unique, families))
}
async fn native_batch(
    config: &ScanConfig,
    profiles: &[(Profile, serde_json::Value)],
    stop: &Arc<AtomicBool>,
    tx: &EventSender<EngineEvent>,
) -> bool {
    let mut native = config.clone();
    native.native_runtime = None;
    native.profiles = profiles
        .iter()
        .map(|(profile, _)| profile.clone())
        .collect();
    if config.profiles.len() > 1 {
        native.node_timeout = native.node_timeout.min(Duration::from_secs(4));
    }
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
    let run = TestEngine::run_serial(native, stop.clone(), sender.into());
    let forward = async {
        let mut cancelled = true;
        while let Some(event) = receiver.recv().await {
            match event {
                EngineEvent::Finished { cancelled: result } => cancelled = result,
                event => {
                    let _ = tx.send(event);
                }
            }
        }
        cancelled
    };
    let (_, cancelled) = tokio::join!(run, forward);
    cancelled
}
fn stopped(config: &ScanConfig, stop: &AtomicBool) -> bool {
    stop.load(Ordering::Relaxed)
        || config
            .shutdown_flag
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Relaxed))
}
async fn check_node(
    profile: Profile,
    mut probe: Probe,
    proxy: String,
    budget: Duration,
    tx: EventSender<EngineEvent>,
) -> Result<NodeCheckResult> {
    #[cfg(test)]
    probe.identify(profile.id);
    let _ = tx.send(EngineEvent::NodeTesting {
        profile_id: profile.id,
    });
    let started = Instant::now();
    // Each future has a private route and account jar. No global active profile
    // can change the exit beneath an in-flight HTTP request.
    let (verdict, details, latency_ms, final_url) = match tokio::time::timeout(
        budget + Duration::from_millis(100),
        probe.check_with_timeout(&proxy, budget),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => (
            AiVerdict::Timeout,
            "Лимит времени проверки исчерпан".into(),
            None,
            None,
        ),
    };
    anyhow::ensure!(verdict != AiVerdict::CheckError, "{details}");
    Ok(NodeCheckResult {
        profile_id: profile.id,
        profile_name: profile.name,
        protocol: profile.profile_type,
        server_address: profile.address,
        verdict,
        details,
        latency_ms,
        final_url,
        checked_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs()),
        timings: Some(CheckTimings {
            setup_ms: 0,
            throne_ms: 0,
            google_ms: Some(ms(started)),
            cleanup_ms: 0,
            total_ms: ms(started),
            reused_browser: false,
        }),
    })
}
fn ms(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, atomic::AtomicUsize};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[test]
    fn duplicate_connection_settings_share_one_observation_but_keep_their_names() {
        let profile = Profile {
            id: 1031,
            name: "France #2".into(),
            profile_type: "xrayvless".into(),
            ..Default::default()
        };
        let raw = serde_json::json!({"tag":"France #2","protocol":"vless","settings":{"address":"server.test","port":443,"id":"uuid-one"}});
        let alias = Profile {
            id: 1037,
            name: "France #8".into(),
            ..profile.clone()
        };
        let mut alias_raw = raw.clone();
        alias_raw["tag"] = serde_json::json!("France #8");
        let other = Profile {
            id: 1040,
            ..profile.clone()
        };
        let mut other_raw = raw.clone();
        other_raw["settings"]["id"] = serde_json::json!("different-uuid");
        let (unique, families) =
            group_profiles(&[(profile, raw), (alias, alias_raw), (other, other_raw)]).unwrap();
        assert_eq!(unique.len(), 2);
        assert_eq!(
            families[&1031].iter().map(|p| p.id).collect::<Vec<_>>(),
            [1031, 1037]
        );
        assert_eq!(families[&1031][1].name, "France #8");
        assert_eq!(families[&1040].len(), 1);
    }
    #[tokio::test]
    async fn native_fallback_does_not_finish_the_outer_queue_and_restores_its_profile() {
        let fixture = crate::throne::controller::tests::fixture().await;
        let profiles: Vec<_> = [5, 6]
            .into_iter()
            .map(|id| {
                (
                    Profile {
                        id,
                        ..Default::default()
                    },
                    serde_json::json!({}),
                )
            })
            .collect();
        let config = ScanConfig {
            native_runtime: None,
            profiles: profiles
                .iter()
                .map(|(profile, _)| profile.clone())
                .collect(),
            mode: super::super::engine::EngineMode::Throne(fixture.controller.clone()),
            browser_path: "unused-browser".into(),
            proxy: "127.0.0.1:1".into(),
            node_timeout: Duration::from_secs(4),
            browser_root: None,
            shutdown_flag: None,
            require_login: false,
        };
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        assert!(
            !native_batch(
                &config,
                &profiles,
                &Arc::new(AtomicBool::new(false)),
                &sender.into()
            )
            .await
        );
        let mut ids = Vec::new();
        while let Ok(event) = receiver.try_recv() {
            match event {
                EngineEvent::NodeFinished { result } => ids.push(result.profile_id),
                EngineEvent::Started { .. } | EngineEvent::Finished { .. } => {
                    panic!("A fallback batch reset or finished the outer queue")
                }
                EngineEvent::Error { message } => panic!("{message}"),
                _ => {}
            }
        }
        assert_eq!(ids, [5, 6]);
        assert_eq!(*fixture.selected.lock().unwrap(), Some(9));
    }
    #[tokio::test]
    async fn parallel_model_checks_overlap_and_keep_cookies_and_results_isolated() {
        use tokio_rustls::rustls::{ServerConfig, pki_types::PrivatePkcs8KeyDer};
        let certificate = rcgen::generate_simple_self_signed(vec![
            "alkalimakersuite-pa.clients6.google.com".into(),
        ])
        .unwrap();
        let server = ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.cert.der().clone()],
            PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der()).into(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let mut proxies = Vec::new();
        let mut servers = Vec::new();
        for route in 0..2 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            proxies.push(listener.local_addr().unwrap().to_string());
            let acceptor = acceptor.clone();
            let active = active.clone();
            let peak = peak.clone();
            let requests = requests.clone();
            servers.push(tokio::spawn(async move {
                let mut clients = tokio::task::JoinSet::new();
                loop {
                    let (mut socket,_) = listener.accept().await.unwrap();
                    let acceptor = acceptor.clone(); let active = active.clone(); let peak = peak.clone(); let requests = requests.clone();
                    clients.spawn(async move {
                        let mut hello = [0;2]; socket.read_exact(&mut hello).await.unwrap();
                        let mut methods = vec![0;hello[1] as usize]; socket.read_exact(&mut methods).await.unwrap();
                        socket.write_all(&[5,0]).await.unwrap();
                        let mut header = [0;5]; socket.read_exact(&mut header).await.unwrap();
                        assert_eq!(&header[..4],&[5,1,0,3]);
                        let mut target = vec![0;header[4] as usize+2]; socket.read_exact(&mut target).await.unwrap();
                        socket.write_all(&[5,0,0,1,127,0,0,1,0,1]).await.unwrap();
                        let mut tls = acceptor.accept(socket).await.unwrap();
                        let mut request = Vec::new(); let mut buffer = [0;4096];
                        loop {
                            let count = tls.read(&mut buffer).await.unwrap(); assert_ne!(count,0);
                            request.extend_from_slice(&buffer[..count]); assert!(request.len()<65536);
                            if let Some(end) = request.windows(4).position(|w|w==b"\r\n\r\n") {
                                let text = String::from_utf8_lossy(&request[..end]);
                                let length = text.lines().filter_map(|l|l.split_once(':')).find(|(k,_)|k.eq_ignore_ascii_case("content-length")).map(|(_,v)|v.trim().parse::<usize>().unwrap()).unwrap_or(0);
                                if request.len()>=end+4+length {break;}
                            }
                        }
                        requests.lock().unwrap().push(String::from_utf8(request).unwrap());
                        let count = active.fetch_add(1,Ordering::SeqCst)+1; peak.fetch_max(count,Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        let (status,body) = if route==0 { (200,r#"{"models":[{"name":"test-model"}]}"#) } else { (403,r#"{"error":{"message":"User location is not supported"}}"#) };
                        let response = format!("HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nSet-Cookie: route-marker={route}; Secure; Path=/\r\nConnection: close\r\n\r\n{body}",body.len());
                        tls.write_all(response.as_bytes()).await.unwrap();
                        active.fetch_sub(1,Ordering::SeqCst);
                    });
                }
            }));
        }
        let probe = Probe::local(certificate.cert.der().to_vec());
        let (tx, mut events) = tokio::sync::mpsc::unbounded_channel();
        let tx = EventSender::from(tx);
        let work = (0..20)
            .map(|id| {
                check_node(
                    Profile {
                        id,
                        ..Default::default()
                    },
                    probe.fork(),
                    proxies[id as usize % 2].clone(),
                    Duration::from_secs(3),
                    tx.clone(),
                )
            })
            .collect::<Vec<_>>();
        let started = Instant::now();
        let results: Vec<_> = stream::iter(work)
            .buffer_unordered(CONCURRENCY)
            .collect()
            .await;
        for result in results {
            let result = result.unwrap();
            assert_eq!(
                result.verdict,
                if result.profile_id % 2 == 0 {
                    AiVerdict::Unlocked
                } else {
                    AiVerdict::Geoblock
                }
            );
        }
        assert!(peak.load(Ordering::SeqCst) > 1);
        assert!(peak.load(Ordering::SeqCst) <= CONCURRENCY);
        assert_eq!(
            requests.lock().unwrap().len(),
            30,
            "Ten explicit region refusals receive one confirmation each"
        );
        let recorded = requests.lock().unwrap();
        assert_eq!(
            recorded
                .iter()
                .filter(|r| !r.contains("route-marker="))
                .count(),
            20,
            "Each node starts from saved cookies"
        );
        assert_eq!(
            recorded
                .iter()
                .filter(|r| r.contains("route-marker=1"))
                .count(),
            10,
            "Only the same node's confirmation can reuse response cookies"
        );
        assert!(
            !recorded.iter().any(|r| r.contains("route-marker=0")),
            "Successful nodes cannot contaminate another node's cookies"
        );
        drop(recorded);
        let mut testing = Vec::new();
        while let Ok(EngineEvent::NodeTesting { profile_id }) = events.try_recv() {
            testing.push(profile_id);
        }
        assert_eq!(
            testing,
            (0..20).collect::<Vec<_>>(),
            "Queued nodes start in source order"
        );
        for server in servers {
            server.abort();
        }
        println!(
            "20 synthetic HTTPS model checks with 100ms response delay: {:?}, peak {}",
            started.elapsed(),
            peak.load(Ordering::SeqCst)
        );
    }
}
