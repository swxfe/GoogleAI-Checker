use crate::checker::verdicts::{AiVerdict, NodeCheckResult};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex},
};

#[derive(Clone, Serialize, Deserialize)]
pub struct Entry {
    pub fingerprint: String,
    pub result: NodeCheckResult,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub version: u32,
    pub source: String,
    pub entries: Vec<Entry>,
    pub queue: HashSet<i64>,
}
impl Snapshot {
    pub fn restore(
        &self,
        source: &str,
        fingerprints: &HashMap<i64, String>,
    ) -> (HashMap<i64, NodeCheckResult>, HashSet<i64>) {
        if self.version != 1 || self.source != source {
            return (HashMap::new(), HashSet::new());
        }
        let results: HashMap<_, _> = self
            .entries
            .iter()
            .filter_map(|entry| {
                let mut result = entry.result.clone();
                if fingerprints.get(&result.profile_id) != Some(&entry.fingerprint) {
                    return None;
                }
                if result.verdict == AiVerdict::Testing {
                    result.verdict = AiVerdict::Pending;
                }
                if result.verdict == AiVerdict::Inconclusive
                    && result.details
                        == "AI Studio: page responded; model access remains unconfirmed"
                {
                    result.verdict = AiVerdict::AiUnavailable;
                }
                if !result.verdict.is_working() {
                    result.latency_ms = None;
                }
                if result.verdict == AiVerdict::Geoblock
                    && result.details == "ListModels: Google rejected this exit IP (HTTP 403)"
                {
                    result.verdict = AiVerdict::Inconclusive;
                    result.details =
                        "HTTP 403 needs AI Studio confirmation; recheck this configuration".into();
                }
                if result.verdict == AiVerdict::ConnectionError
                    && (result
                        .details
                        .contains("Cannot find context with specified id")
                        || result.details.contains("Execution context was destroyed")
                        || result.details == "Request timed out.")
                {
                    result.verdict = AiVerdict::CheckError;
                }
                Some((result.profile_id, result))
            })
            .collect();
        let queue = self
            .queue
            .iter()
            .filter(|id| results.contains_key(id))
            .copied()
            .collect();
        (results, queue)
    }
}
struct Pending {
    snapshot: Option<Arc<Snapshot>>,
    closing: bool,
    error: Option<String>,
}
pub struct StateStore {
    path: PathBuf,
    shared: Arc<(Mutex<Pending>, Condvar)>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl StateStore {
    pub fn new(data: &Path) -> Result<Self> {
        let path = data.join("checker-state.json");
        let shared = Arc::new((
            Mutex::new(Pending {
                snapshot: None,
                closing: false,
                error: None,
            }),
            Condvar::new(),
        ));
        let worker_shared = shared.clone();
        let worker_path = path.clone();
        let worker = std::thread::Builder::new()
            .name("checker-state".into())
            .spawn(move || {
                loop {
                    let (lock, wake) = &*worker_shared;
                    let mut pending = lock.lock().unwrap_or_else(|e| e.into_inner());
                    while pending.snapshot.is_none() && !pending.closing {
                        pending = wake.wait(pending).unwrap_or_else(|e| e.into_inner());
                    }
                    let Some(snapshot) = pending.snapshot.take() else {
                        break;
                    };
                    drop(pending);
                    if let Err(error) = write_snapshot(&worker_path, &snapshot) {
                        lock.lock().unwrap_or_else(|e| e.into_inner()).error =
                            Some(format!("{error:#}"));
                    }
                }
            })?;
        Ok(Self {
            path,
            shared,
            worker: Some(worker),
        })
    }
    pub fn read(&self) -> Result<Option<Snapshot>> {
        if !self.path.exists() {
            return Ok(None);
        }
        anyhow::ensure!(
            std::fs::metadata(&self.path)?.len() <= 16 * 1024 * 1024,
            "Saved results exceed 16 MiB"
        );
        let bytes = std::fs::read(&self.path)?;
        match serde_json::from_slice(&bytes) {
            Ok(snapshot) => Ok(Some(snapshot)),
            Err(error) => {
                let stamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_nanos();
                std::fs::copy(
                    &self.path,
                    self.path
                        .with_file_name(format!("checker-state-corrupt-{stamp}.json")),
                )?;
                Err(error).context("Saved results are damaged; the original file was backed up")
            }
        }
    }
    pub fn queue(&self, snapshot: impl Into<Arc<Snapshot>>) {
        let (lock, wake) = &*self.shared;
        lock.lock().unwrap_or_else(|e| e.into_inner()).snapshot = Some(snapshot.into());
        wake.notify_one();
    }
    pub fn take_error(&self) -> Option<String> {
        self.shared
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .error
            .take()
    }
}
impl Drop for StateStore {
    fn drop(&mut self) {
        self.shared
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .closing = true;
        self.shared.1.notify_one();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn write_snapshot(path: &Path, snapshot: &Snapshot) -> Result<()> {
    let mut file = tempfile::NamedTempFile::new_in(path.parent().context("No results directory")?)?;
    serde_json::to_writer(&mut file, snapshot)?;
    file.flush()?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|e| e.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restored_browser_context_failure_is_not_a_network_failure() {
        let mut result =
            NodeCheckResult::new_pending(1, "node".into(), "vless".into(), String::new());
        result.verdict = AiVerdict::ConnectionError;
        result.details = "Error -32000: Cannot find context with specified id".into();
        let snapshot = Snapshot {
            version: 1,
            source: "same".into(),
            entries: vec![Entry {
                fingerprint: "same".into(),
                result,
            }],
            queue: HashSet::new(),
        };
        let (restored, _) = snapshot.restore("same", &HashMap::from([(1, "same".into())]));
        assert_eq!(restored[&1].verdict, AiVerdict::CheckError);
    }
    #[test]
    fn latest_results_are_flushed_and_replace_the_previous_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::new(dir.path()).unwrap();
        for count in 0..100 {
            let result = NodeCheckResult::new_pending(
                1,
                count.to_string(),
                "vless".into(),
                "fixture:9".into(),
            );
            store.queue(Snapshot {
                version: 1,
                source: "fixture".into(),
                entries: vec![Entry {
                    fingerprint: "same config".into(),
                    result,
                }],
                queue: HashSet::from([1]),
            });
        }
        drop(store);
        let store = StateStore::new(dir.path()).unwrap();
        assert_eq!(
            store.read().unwrap().unwrap().entries[0]
                .result
                .profile_name,
            "99"
        );
    }
    #[test]
    fn durable_restore_rejects_changed_configs_and_resumes_only_pending() {
        let dir = tempfile::tempdir().unwrap();
        let mut completed =
            NodeCheckResult::new_pending(1, "node".into(), "vless".into(), "example:443".into());
        completed.verdict = AiVerdict::Unlocked;
        let mut active = completed.clone();
        active.profile_id = 2;
        active.verdict = AiVerdict::Testing;
        let snapshot = Snapshot {
            version: 1,
            source: "source-a".into(),
            entries: vec![
                Entry {
                    fingerprint: "a".into(),
                    result: completed,
                },
                Entry {
                    fingerprint: "b".into(),
                    result: active,
                },
            ],
            queue: HashSet::from([1, 2]),
        };
        let store = StateStore::new(dir.path()).unwrap();
        store.queue(snapshot.clone());
        drop(store);
        let store = StateStore::new(dir.path()).unwrap();
        let saved = store.read().unwrap().unwrap();
        let fingerprints = HashMap::from([(1, "a".into()), (2, "b".into())]);
        let (results, queue) = saved.restore("source-a", &fingerprints);
        assert_eq!(results[&1].verdict, AiVerdict::Unlocked);
        assert_eq!(results[&2].verdict, AiVerdict::Pending);
        assert_eq!(queue, HashSet::from([1, 2]));
        assert!(saved.restore("source-b", &fingerprints).0.is_empty());
        assert!(
            saved
                .restore("source-a", &HashMap::from([(1, "changed".into())]))
                .0
                .is_empty()
        );
        let malformed = dir.path().join("checker-state.json");
        std::fs::write(&malformed, b"{broken").unwrap();
        assert!(store.read().is_err());
        assert!(std::fs::read_dir(dir.path()).unwrap().count() >= 2);
    }
    #[test]
    fn legacy_generic_403_is_unconfirmed_but_explicit_region_evidence_is_kept() {
        let mut old =
            NodeCheckResult::new_pending(1, "one".into(), "vless".into(), "fixture".into());
        old.verdict = AiVerdict::Geoblock;
        old.details = "ListModels: Google rejected this exit IP (HTTP 403)".into();
        let mut confirmed = old.clone();
        confirmed.profile_id = 2;
        confirmed.details = "Region restriction / available-regions".into();
        let snapshot = Snapshot {
            version: 1,
            source: "fixture".into(),
            entries: vec![
                Entry {
                    fingerprint: "one".into(),
                    result: old,
                },
                Entry {
                    fingerprint: "two".into(),
                    result: confirmed,
                },
            ],
            queue: HashSet::new(),
        };
        let (restored, _) = snapshot.restore(
            "fixture",
            &HashMap::from([(1, "one".into()), (2, "two".into())]),
        );
        assert_eq!(restored[&1].verdict, AiVerdict::Inconclusive);
        assert_eq!(restored[&2].verdict, AiVerdict::Geoblock);
    }
    #[test]
    fn restored_html_shell_responses_are_ai_unavailable_without_false_latency() {
        let mut result =
            NodeCheckResult::new_pending(1, "fixture".into(), "custom".into(), "".into());
        result.verdict = AiVerdict::Inconclusive;
        result.details = "AI Studio: page responded; model access remains unconfirmed".into();
        result.latency_ms = Some(641);
        let snapshot = Snapshot {
            version: 1,
            source: "fixture".into(),
            entries: vec![Entry {
                fingerprint: "same".into(),
                result,
            }],
            queue: HashSet::new(),
        };
        let (results, _) = snapshot.restore("fixture", &HashMap::from([(1, "same".into())]));
        assert_eq!(results[&1].verdict, AiVerdict::AiUnavailable);
        assert_eq!(results[&1].latency_ms, None);
        assert_eq!(results[&1].verdict.summary_label(), Some("AI unavailable"));
    }
}
