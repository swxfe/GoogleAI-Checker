use crate::{
    checker::verdicts::{AiVerdict, CheckTimings, NodeCheckResult},
    events::EventSender,
    throne::{
        controller::{Controller, ProfileStartFailed},
        models::Profile,
    },
};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::time::timeout;
pub const DEFAULT_NODE_TIMEOUT: Duration = Duration::from_secs(8);
#[derive(Clone)]
pub enum EngineMode {
    Throne(Controller),
    #[cfg(test)]
    ManualProxy,
}
#[derive(Debug)]
pub enum EngineEvent {
    BrowserSelected { path: PathBuf },
    Started { total: usize },
    NodeTesting { profile_id: i64 },
    NodeActivated { profile_id: i64 },
    ConnectionRestored { profile_id: Option<i64> },
    NodeFinished { result: NodeCheckResult },
    Finished { cancelled: bool },
    Error { message: String },
    LoginExpired,
}
#[derive(Clone)]
pub struct ScanConfig {
    pub native_runtime: Option<crate::throne::runtime::RuntimeConfig>,
    pub profiles: Vec<Profile>,
    pub mode: EngineMode,
    pub browser_path: PathBuf,
    pub proxy: String,

    pub node_timeout: Duration,
    pub browser_root: Option<PathBuf>,
    pub shutdown_flag: Option<Arc<AtomicBool>>,
    pub require_login: bool,
}
pub struct TestEngine;
pub async fn cancelled(flag: &AtomicBool) {
    while !flag.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
}
impl TestEngine {
    pub async fn run_scan(
        config: ScanConfig,
        stop: Arc<AtomicBool>,
        tx: impl Into<EventSender<EngineEvent>> + Send + 'static,
    ) {
        let tx = tx.into();
        let _ = tx.send(EngineEvent::Started {
            total: config.profiles.len(),
        });
        match super::parallel::run(&config, &stop, &tx).await {
            Ok(true) => return,
            Ok(false) => {}
            Err(error) => {
                Self::error(&tx, &format!("{error:#}"));
                return;
            }
        }
        Self::run_serial(config, stop, tx).await;
    }
    pub(super) async fn run_serial(
        config: ScanConfig,
        stop: Arc<AtomicBool>,
        tx: EventSender<EngineEvent>,
    ) {
        let setup_started = std::time::Instant::now();
        let controller = match &config.mode {
            EngineMode::Throne(c) => Some(c.session()),
            #[cfg(test)]
            EngineMode::ManualProxy => None,
        };
        let original = if let Some(c) = &controller {
            match timeout(Duration::from_secs(5), c.status()).await {
                Ok(Ok(s)) if s.state == "idle" || s.state == "running" => Some(s),
                _ => {
                    Self::error(&tx, "Throne is busy or unavailable; scan not started");
                    return;
                }
            }
        } else {
            None
        };
        if let Some(s) = &original
            && let Some(i) = &s.inbound
        {
            let port = config
                .proxy
                .parse::<std::net::SocketAddr>()
                .ok()
                .map(|a| a.port());
            if i.enabled == Some(false) || (i.port.is_some() && i.port != port) {
                Self::error(
                    &tx,
                    "SOCKS5 port does not match Throne's inbound, or the inbound is off",
                );
                return;
            }
        }
        let mut browser = match tokio::select! {
            r=std::future::ready(super::probe::Probe::open(&config))=>Some(r),
            _=cancelled(&stop)=>None,
        } {
            Some(Ok(b)) => b,
            Some(Err(e)) => {
                if config.require_login {
                    let _ = tx.send(EngineEvent::LoginExpired);
                }
                Self::error(&tx, &format!("{e:#}"));
                return;
            }
            None => {
                let _ = tx.send(EngineEvent::Finished { cancelled: true });
                return;
            }
        };
        let mut failed = false;
        let _ = tx.send(EngineEvent::BrowserSelected {
            path: config.browser_path.clone(),
        });
        let single = config.profiles.len() == 1;
        let mut setup_ms = elapsed_ms(setup_started);
        for p in config.profiles {
            if failed || stop.load(Ordering::Relaxed) {
                break;
            }
            let _ = tx.send(EngineEvent::NodeTesting { profile_id: p.id });
            let node_started = std::time::Instant::now();
            let mut throne_ms = 0;
            let mut throne_started = None;
            let mut google_ms = None;
            let mut google_started = None;
            let mut activated = controller.is_none();
            let mut start_failed = false;
            let limit = config
                .node_timeout
                .clamp(Duration::from_secs(2), Duration::from_secs(12));
            let budget = if single {
                limit
            } else {
                limit.min(Duration::from_secs(4))
            };
            let check = async {
                if let Some(c) = &controller {
                    throne_started = Some(std::time::Instant::now());
                    let activation = c.activate(p.id).await;
                    throne_ms += elapsed_ms(throne_started.take().expect("activation timer"));
                    if let Err(error) = activation {
                        start_failed = error.is::<ProfileStartFailed>();
                        if start_failed {
                            let _ = tx.send(EngineEvent::ConnectionRestored { profile_id: None });
                        }
                        return Err(error);
                    }
                    let _ = tx.send(EngineEvent::NodeActivated { profile_id: p.id });
                }
                activated = true;
                google_started = Some(std::time::Instant::now());
                let observed = browser
                    .check_with_timeout(
                        &config.proxy,
                        budget.saturating_sub(Duration::from_secs(1)),
                    )
                    .await;
                google_ms = google_started.map(elapsed_ms);
                let observation = observed?;
                if let Some(c) = &controller {
                    throne_started = Some(std::time::Instant::now());
                    let status = c.status().await;
                    throne_ms += elapsed_ms(throne_started.take().expect("verification timer"));
                    let status = status?;
                    if status.state != "running"
                        || status.profile.as_ref().map(|p| p.id) != Some(p.id)
                    {
                        activated = false;
                        anyhow::bail!("The active Throne node changed during the scan");
                    }
                }
                Ok::<_, anyhow::Error>(observation)
            };
            let check_budget = budget.saturating_sub(Duration::from_millis(400));
            let result = tokio::select! {
                r=timeout(check_budget,check)=>Some(r),
                _=cancelled(&stop)=>None,
            };
            if google_ms.is_none() {
                google_ms = google_started.map(elapsed_ms);
            }
            if let Some(started) = throne_started {
                throne_ms += elapsed_ms(started);
            }
            let Some(result) = result else {
                break;
            };
            let (verdict, details, latency_ms, final_url) = match result {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => (
                    if start_failed {
                        AiVerdict::StartFailed
                    } else {
                        AiVerdict::CheckError
                    },
                    format!("{e:#}"),
                    None,
                    None,
                ),
                Err(_) => (
                    AiVerdict::Timeout,
                    "Switching and scan time limit reached".into(),
                    None,
                    None,
                ),
            };
            if verdict == AiVerdict::SessionExpired {
                failed = true;
                let _ = tx.send(EngineEvent::LoginExpired);
                let _ = tx.send(EngineEvent::Error {
                    message: "Google session expired. Queue paused; sign in again".into(),
                });
                break;
            }
            if verdict == AiVerdict::CheckError {
                failed = true;
                let _ = tx.send(EngineEvent::Error { message: details });
                break;
            }
            if !activated && !start_failed && controller.is_some() {
                failed = true;
                let _ = tx.send(EngineEvent::Error {
                    message: "Throne switch was not confirmed; scan stopped to restore the original connection".into(),
                });
                break;
            }
            let _ = tx.send(EngineEvent::NodeFinished {
                result: NodeCheckResult {
                    profile_id: p.id,
                    profile_name: p.name,
                    protocol: p.profile_type,
                    server_address: p.address,
                    verdict,
                    details,
                    latency_ms,
                    final_url,
                    checked_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .ok()
                        .map(|d| d.as_secs()),
                    timings: Some(CheckTimings {
                        setup_ms,
                        throne_ms,
                        google_ms,
                        cleanup_ms: 0,
                        total_ms: setup_ms.saturating_add(elapsed_ms(node_started)),
                        reused_browser: false,
                    }),
                },
            });
            setup_ms = 0;
            if verdict == AiVerdict::RateLimited {
                let _ = tx.send(EngineEvent::Error {
                    message: "Google rate-limited requests. The queue is paused; retry later"
                        .into(),
                });
                failed = true;
                break;
            }
            if failed {
                break;
            }
        }
        drop(browser);
        if let (Some(c), Some(s)) = (controller, original)
            && !config
                .shutdown_flag
                .as_ref()
                .is_some_and(|flag| flag.load(Ordering::SeqCst))
        {
            match timeout(Duration::from_secs(20), c.restore(&s)).await {
                Ok(Ok(())) => {
                    let _ = tx.send(EngineEvent::ConnectionRestored {
                        profile_id: s.profile.as_ref().map(|p| p.id),
                    });
                }
                _ => {
                    failed = true;
                    let _ = tx.send(EngineEvent::Error {
                        message: "Could not restore the original Throne connection".into(),
                    });
                }
            }
        }
        let _ = tx.send(EngineEvent::Finished {
            cancelled: failed || stop.load(Ordering::Relaxed),
        });
    }
    fn error(tx: &EventSender<EngineEvent>, message: &str) {
        let _ = tx.send(EngineEvent::Error {
            message: message.into(),
        });
        let _ = tx.send(EngineEvent::Finished { cancelled: true });
    }
}
fn elapsed_ms(started: std::time::Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn wreq_scan_never_launches_a_browser_and_restores_the_original_profile() {
        let fixture = crate::throne::controller::tests::fixture().await;
        let root = tempfile::tempdir().unwrap();
        let browser = root.path().join("not-an-executable");
        std::fs::write(&browser, b"This fixture cannot launch a browser").unwrap();
        crate::browser::session::fixture_session()
            .save(root.path(), &browser)
            .unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        TestEngine::run_scan(
            ScanConfig {
                native_runtime: None,
                profiles: vec![Profile {
                    id: 5,
                    name: "wreq only".into(),
                    ..Default::default()
                }],
                mode: EngineMode::Throne(fixture.controller.clone()),
                browser_path: browser,
                proxy: "127.0.0.1:1".into(),
                node_timeout: DEFAULT_NODE_TIMEOUT,
                browser_root: Some(root.path().to_owned()),

                shutdown_flag: None,
                require_login: true,
            },
            Arc::new(AtomicBool::new(false)),
            tx,
        )
        .await;
        let mut final_results = 0;
        while let Ok(event) = rx.try_recv() {
            match event {
                EngineEvent::NodeFinished { result } => {
                    assert_eq!(result.verdict, AiVerdict::ConnectionError);
                    final_results += 1;
                }
                EngineEvent::Error { message } => panic!("{message}"),
                EngineEvent::Finished { cancelled } => assert!(!cancelled),
                _ => {}
            }
        }
        assert_eq!(final_results, 1);
        assert_eq!(*fixture.connections.lock().unwrap(), vec![5, 9]);
        assert_eq!(*fixture.selected.lock().unwrap(), Some(9));
        assert_eq!(
            fixture.handshakes.load(Ordering::Relaxed),
            1,
            "One authenticated local API stream must cover the scan and restoration"
        );
    }
    #[tokio::test]
    async fn direct_single_check_activates_once_and_batches_never_start_latency_jobs() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap().to_string();
        let refusals = tokio::spawn(async move {
            let mut clients = tokio::task::JoinSet::new();
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                clients.spawn(async move {
                    let mut hello = [0; 2];
                    socket.read_exact(&mut hello).await.unwrap();
                    let mut methods = vec![0; hello[1] as usize];
                    socket.read_exact(&mut methods).await.unwrap();
                    socket.write_all(&[5, 0]).await.unwrap();
                    let mut request = [0; 5];
                    socket.read_exact(&mut request).await.unwrap();
                    assert_eq!(&request[..4], &[5, 1, 0, 3]);
                    let mut destination = vec![0; request[4] as usize + 2];
                    socket.read_exact(&mut destination).await.unwrap();
                    socket
                        .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                        .await
                        .unwrap();
                });
                while clients.try_join_next().is_some() {}
            }
        });
        let fixture = crate::throne::controller::tests::fixture().await;
        let (_dir, db) = crate::throne::db::tests::fixture();
        let before = db.fingerprints().unwrap();
        let mut profiles = db.read_profiles().unwrap();
        profiles.push(Profile {
            id: 4,
            name: "Fourth fixture".into(),
            ..profiles[0].clone()
        });
        let browser = PathBuf::from("unused-browser-fixture");
        for selected in [vec![profiles[0].clone()], profiles] {
            fixture.connections.lock().unwrap().clear();
            let ids: Vec<_> = selected.iter().map(|p| p.id).collect();
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            timeout(
                Duration::from_secs(12),
                TestEngine::run_scan(
                    ScanConfig {
                        native_runtime: None,
                        profiles: selected,
                        mode: EngineMode::Throne(fixture.controller.clone()),
                        browser_path: browser.clone(),
                        proxy: proxy.clone(),
                        node_timeout: DEFAULT_NODE_TIMEOUT,
                        browser_root: None,

                        shutdown_flag: None,
                        require_login: false,
                    },
                    Arc::new(AtomicBool::new(false)),
                    tx,
                ),
            )
            .await
            .unwrap();
            let mut final_ids = Vec::new();
            let mut active = None;
            let mut started_ids = Vec::new();
            while let Ok(event) = rx.try_recv() {
                match event {
                    EngineEvent::NodeTesting { profile_id } => {
                        assert!(
                            active.replace(profile_id).is_none(),
                            "Finish the current node before testing the next"
                        );
                        started_ids.push(profile_id);
                    }
                    EngineEvent::NodeFinished { result } => {
                        assert_eq!(active.take(), Some(result.profile_id));
                        assert_eq!(result.verdict, AiVerdict::ConnectionError);
                        final_ids.push(result.profile_id);
                    }
                    EngineEvent::Error { message } => panic!("{message}"),
                    EngineEvent::Finished { cancelled } => assert!(!cancelled),
                    _ => {}
                }
            }
            assert!(active.is_none());
            assert_eq!(started_ids, ids);
            assert_eq!(final_ids, ids);
            for id in &ids {
                assert_eq!(
                    fixture
                        .connections
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|p| **p == *id)
                        .count(),
                    1
                );
            }
            assert!(fixture.test_calls.lock().unwrap().is_empty());
            assert_eq!(*fixture.selected.lock().unwrap(), Some(9));
        }
        assert_eq!(db.fingerprints().unwrap(), before);
        refusals.abort();
    }
    #[tokio::test]
    #[ignore = "Explicit opt-in live scan through installed Throne using saved checker login"]
    async fn live_installed_scan() {
        let root =
            PathBuf::from(std::env::var("CHECKER_LIVE_ROOT").expect("Set CHECKER_LIVE_ROOT"));
        let ids: std::collections::HashSet<i64> = std::env::var("CHECKER_LIVE_IDS")
            .expect("Set CHECKER_LIVE_IDS")
            .split(',')
            .map(|id| id.parse().unwrap())
            .collect();
        let report_path =
            PathBuf::from(std::env::var("CHECKER_LIVE_REPORT").expect("Set CHECKER_LIVE_REPORT"));
        let db = crate::throne::db::ThroneDb::new(root.join("bin/config/throne.db"));
        let before = db.fingerprints().unwrap();
        let (controller, proxy, _) = db.connection().unwrap();
        let original = controller.status().await.unwrap();
        assert_eq!(original.state, "idle", "Live scan requires idle checker");
        let profiles: Vec<_> = db
            .read_profiles()
            .unwrap()
            .into_iter()
            .filter(|p| ids.contains(&p.id))
            .collect();
        assert_eq!(profiles.len(), ids.len());
        let browser_root = root.join("sandbox_data/browser_profiles");
        let login: serde_json::Value =
            serde_json::from_slice(&std::fs::read(browser_root.join("google-login.json")).unwrap())
                .unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let scan = tokio::spawn(TestEngine::run_scan(
            ScanConfig {
                native_runtime: None,
                profiles,
                mode: EngineMode::Throne(controller.clone()),
                browser_path: PathBuf::from(login["browser"].as_str().unwrap()),
                proxy,
                node_timeout: DEFAULT_NODE_TIMEOUT,
                browser_root: Some(browser_root),

                shutdown_flag: None,
                require_login: true,
            },
            Arc::new(AtomicBool::new(false)),
            tx,
        ));
        let mut results = Vec::new();
        let mut errors = Vec::new();
        let started = std::time::Instant::now();
        let mut first_available_ms = None;
        while let Some(event) = rx.recv().await {
            match event {
                EngineEvent::NodeFinished { result } => {
                    println!("LIVE ENGINE {} {:?}", result.profile_id, result.verdict);
                    if result.verdict.is_working() && first_available_ms.is_none() {
                        first_available_ms = Some(started.elapsed().as_millis() as u64);
                    }
                    results.push(result);
                    std::fs::write(
                        &report_path,
                        serde_json::to_vec_pretty(
                            &serde_json::json!({"results":results,"errors":errors,"elapsed_ms":started.elapsed().as_millis() as u64,"first_available_ms":first_available_ms}),
                        )
                        .unwrap(),
                    )
                    .unwrap();
                }
                EngineEvent::Error { message } => {
                    println!("LIVE ERROR {message}");
                    errors.push(message);
                }
                _ => {}
            }
        }
        scan.await.unwrap();
        assert_eq!(controller.status().await.unwrap().state, "idle");
        assert_eq!(
            db.fingerprints().unwrap(),
            before,
            "Live scan changed profile definitions"
        );
        assert!(
            errors.is_empty(),
            "Live scan encountered checker errors: {errors:?}"
        );
        assert_eq!(results.len(), ids.len());
        assert!(!results.iter().any(|r| r.verdict == AiVerdict::CheckError));
    }
    async fn fixture_scan(ids: &[i64]) -> Vec<EngineEvent> {
        let fixture = crate::throne::controller::tests::fixture().await;
        let browser = PathBuf::from("unused-browser-fixture");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        timeout(
            Duration::from_secs(15),
            TestEngine::run_scan(
                ScanConfig {
                    native_runtime: None,
                    profiles: ids
                        .iter()
                        .map(|id| Profile {
                            id: *id,
                            name: format!("Fixture {id}"),
                            ..Default::default()
                        })
                        .collect(),
                    mode: EngineMode::Throne(fixture.controller.clone()),
                    browser_path: browser,
                    proxy: "127.0.0.1:1".into(),

                    node_timeout: Duration::from_secs(7),
                    browser_root: None,

                    shutdown_flag: None,
                    require_login: false,
                },
                Arc::new(AtomicBool::new(false)),
                tx,
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            *fixture.selected.lock().unwrap(),
            Some(9),
            "Original connection must be restored"
        );
        let mut events = Vec::new();
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }
        events
    }

    #[tokio::test]
    async fn invalid_profiles_are_skipped_and_queue_finishes() {
        let events = fixture_scan(&[13, 14]).await;
        let results: Vec<_> = events
            .iter()
            .filter_map(|e| {
                if let EngineEvent::NodeFinished { result } = e {
                    Some((result.profile_id, result.verdict))
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(
            results,
            vec![(13, AiVerdict::StartFailed), (14, AiVerdict::StartFailed)]
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, EngineEvent::Finished { cancelled: false }))
        );
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, EngineEvent::Error { .. }))
        );
    }

    #[tokio::test]
    async fn ambiguous_switch_stops_queue_after_skipped_invalid_profile() {
        let events = fixture_scan(&[13, 15, 14]).await;
        assert!(
            events
                .iter()
                .any(|e| matches!(e, EngineEvent::Finished { cancelled: true }))
        );
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, EngineEvent::NodeTesting { profile_id: 14 }))
        );
        assert!(events.iter().any(|e| matches!(e, EngineEvent::NodeFinished { result } if result.profile_id == 13 && result.verdict == AiVerdict::StartFailed)));
        assert!(
            !events.iter().any(
                |e| matches!(e, EngineEvent::NodeFinished { result } if result.profile_id == 15)
            )
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, EngineEvent::Error { .. }))
        );
    }

    #[tokio::test]
    async fn missing_login_stops_queue_before_any_node_is_tested() {
        let browser = PathBuf::from("unused-browser-fixture");
        let root = tempfile::tempdir().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let scan = tokio::spawn(TestEngine::run_scan(
            ScanConfig {
                native_runtime: None,
                profiles: vec![
                    Profile {
                        id: 1,
                        name: "First".into(),
                        ..Default::default()
                    },
                    Profile {
                        id: 2,
                        name: "Second".into(),
                        ..Default::default()
                    },
                ],
                mode: EngineMode::ManualProxy,
                browser_path: browser,
                proxy: "127.0.0.1:1".into(),

                node_timeout: Duration::from_secs(7),
                browser_root: Some(root.path().to_owned()),

                shutdown_flag: None,
                require_login: true,
            },
            Arc::new(AtomicBool::new(false)),
            tx,
        ));
        let mut expired = false;
        let mut finished = false;
        timeout(Duration::from_secs(12), async {
            while let Some(event) = rx.recv().await {
                match event {
                    EngineEvent::LoginExpired => expired = true,
                    EngineEvent::Finished { cancelled } => {
                        assert!(cancelled);
                        finished = true;
                        break;
                    }
                    EngineEvent::NodeTesting { .. } | EngineEvent::NodeFinished { .. } => {
                        panic!("Queue must not test nodes without a Google session")
                    }
                    _ => {}
                }
            }
        })
        .await
        .unwrap();
        assert!(expired && finished);
        scan.await.unwrap();
    }
    #[tokio::test]
    async fn cancellation_interrupts_hung_socks_and_finishes_cleanly() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let mut sockets = Vec::new();
            loop {
                sockets.push(listener.accept().await.unwrap().0);
            }
        });
        let browser = PathBuf::from("unused-browser-fixture");
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let scan = tokio::spawn(TestEngine::run_scan(
            ScanConfig {
                native_runtime: None,
                profiles: vec![Profile {
                    id: -1,
                    name: "Local fixture".into(),
                    profile_type: "socks5".into(),
                    ..Default::default()
                }],
                mode: EngineMode::ManualProxy,
                browser_path: browser,
                proxy,

                node_timeout: Duration::from_secs(7),
                browser_root: None,

                shutdown_flag: None,
                require_login: false,
            },
            stop.clone(),
            tx,
        ));
        timeout(Duration::from_secs(10), async {
            loop {
                if matches!(rx.recv().await, Some(EngineEvent::NodeTesting { .. })) {
                    break;
                }
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        let start = std::time::Instant::now();
        stop.store(true, Ordering::Relaxed);
        let mut finished = false;
        timeout(Duration::from_secs(3), async {
            while let Some(event) = rx.recv().await {
                if let EngineEvent::Finished { cancelled } = event {
                    assert!(cancelled);
                    finished = true;
                    break;
                }
                assert!(
                    !matches!(event, EngineEvent::NodeFinished { .. }),
                    "A cancelled check must not emit a final node verdict"
                );
            }
        })
        .await
        .unwrap();
        assert!(finished);
        assert!(start.elapsed() < Duration::from_secs(3));
        scan.await.unwrap();
        server.abort();
    }
}
