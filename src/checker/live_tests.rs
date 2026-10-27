//! Explicit opt-in diagnostics. Reports never contain session material or raw configs.
use super::engine::{DEFAULT_NODE_TIMEOUT, EngineEvent, EngineMode, ScanConfig, TestEngine};
use crate::throne::{
    db::ThroneDb,
    runtime::{RuntimeConfig, config::Source},
};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Real account/network diagnostics; explicitly set CHECKER_LIVE_ROOT, CHECKER_LIVE_GROUP, CHECKER_LIVE_REPORT and CHECKER_TEST_HOST"]
async fn authorized_group_diagnostics() {
    let root = PathBuf::from(std::env::var_os("CHECKER_LIVE_ROOT").expect("CHECKER_LIVE_ROOT"));
    let group = std::env::var("CHECKER_LIVE_GROUP").expect("CHECKER_LIVE_GROUP");
    let report =
        PathBuf::from(std::env::var_os("CHECKER_LIVE_REPORT").expect("CHECKER_LIVE_REPORT"));
    let repeats = std::env::var("CHECKER_LIVE_REPEATS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(3)
        .clamp(1, 5);
    let database = ThroneDb::new(root.join("bin/config/throne.db"));
    let fingerprints = database.fingerprints().unwrap();
    let group = database
        .read_groups()
        .unwrap()
        .into_iter()
        .find(|g| g.name.eq_ignore_ascii_case(&group))
        .expect("Unknown group");
    let mut profiles = database
        .read_profiles()
        .unwrap()
        .into_iter()
        .filter(|p| p.group == Some(group.id))
        .collect::<Vec<_>>();
    if let Ok(ids) = std::env::var("CHECKER_LIVE_IDS") {
        let ids = ids
            .split(',')
            .map(|s| s.parse::<i64>().unwrap())
            .collect::<std::collections::HashSet<_>>();
        profiles.retain(|p| ids.contains(&p.id));
    }
    assert!(!profiles.is_empty());
    let source = Source::read(&database.db_path, &profiles, &fingerprints).unwrap();
    let native_required = source.native_profiles;
    profiles.retain(|p| !native_required.contains(&p.id));
    assert!(
        !profiles.is_empty(),
        "No isolated batch-compatible profiles in this group"
    );
    if !native_required.is_empty() {
        println!(
            "Native-only profiles omitted from isolated live diagnostics: {}",
            native_required.len()
        );
    }
    let (controller, proxy, _) = database.connection().unwrap();
    if let Ok(status) = controller.status().await {
        assert_eq!(
            status.state, "idle",
            "Leave the checker idle during diagnostics"
        );
    }
    let browser_root = root.join("sandbox_data/browser_profiles");
    let browser =
        crate::browser::login::saved_browser(&browser_root).expect("Saved browser marker missing");
    let state = root.join("sandbox_data/checker-state.json");
    let before_state = std::fs::read(&state).unwrap();
    let mut runs = Vec::new();
    for pass in 0..repeats {
        let config = ScanConfig {
            native_runtime: Some(RuntimeConfig {
                database: database.db_path.clone(),
                throne_executable: root.join("bin/Throne.exe"),
                data_root: root.join("sandbox_data"),
                fingerprints: fingerprints.clone(),
            }),
            profiles: profiles.clone(),
            mode: EngineMode::Throne(controller.clone()),
            browser_path: browser.clone(),
            proxy: proxy.clone(),
            node_timeout: DEFAULT_NODE_TIMEOUT,
            browser_root: Some(browser_root.clone()),
            shutdown_flag: None,
            require_login: true,
        };
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(TestEngine::run_scan(
            config,
            Arc::new(AtomicBool::new(false)),
            sender,
        ));
        let started = Instant::now();
        let mut results = Vec::new();
        let mut errors = Vec::new();
        let mut cancelled = true;
        tokio::time::timeout(Duration::from_secs(180), async {
            while let Some(event) = receiver.recv().await {
                match event {
                    EngineEvent::NodeFinished { result } => results.push(result),
                    EngineEvent::Error { message } => errors.push(message),
                    EngineEvent::Finished { cancelled: value } => cancelled = value,
                    _ => {}
                }
            }
        })
        .await
        .unwrap();
        task.await.unwrap();
        let mut counts = BTreeMap::new();
        for result in &results {
            *counts
                .entry(format!("{:?}", result.verdict))
                .or_insert(0usize) += 1;
        }
        println!(
            "GROUP {} pass {}: {:?}, {} ms, errors {}, cancelled {}",
            group.id,
            pass + 1,
            counts,
            started.elapsed().as_millis(),
            errors.len(),
            cancelled
        );
        // Native error payloads may embed runtime JSON: reports retain fixed summaries only.
        for result in &mut results {
            if result.details.contains("decode config at") {
                result.details = "Native configuration rejected".into();
            }
        }
        runs.push(serde_json::json!({"pass":pass+1,"elapsed_ms":started.elapsed().as_millis(),"counts":counts,"cancelled":cancelled,"errors":errors.iter().map(|_|"Checker/session failure").collect::<Vec<_>>(),"results":results}));
        std::fs::write(
            &report,
            serde_json::to_vec_pretty(
                &serde_json::json!({"group_id":group.id,"profiles":profiles.len(),"native_required_ids":native_required,"runs":runs}),
            )
            .unwrap(),
        )
        .unwrap();
        if cancelled {
            break;
        }
    }
    assert_eq!(database.fingerprints().unwrap(), fingerprints);
    assert_eq!(
        std::fs::read(&state).unwrap(),
        before_state,
        "Diagnostics must not overwrite saved user results"
    );
}
