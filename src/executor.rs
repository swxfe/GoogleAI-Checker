use std::{future::Future, thread::JoinHandle, time::Duration};
use tokio::{runtime::Handle, sync::oneshot, task};

/// One sleeping I/O thread drives all scan and login futures. Blocking database
/// and filesystem jobs use Tokio's bounded, lazily created blocking pool.
pub struct BackgroundRuntime {
    handle: Handle,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl BackgroundRuntime {
    pub fn new() -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(4)
            .thread_keep_alive(Duration::from_secs(2))
            .build()?;
        let handle = runtime.handle().clone();
        let (stop, stopped) = oneshot::channel();
        let thread = std::thread::Builder::new()
            .name("checker-io".into())
            .spawn(move || {
                runtime.block_on(async {
                    let _ = stopped.await;
                });
                runtime.shutdown_timeout(Duration::from_secs(2));
            })?;
        Ok(Self {
            handle,
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    pub fn spawn<F>(&self, future: F) -> task::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.handle.spawn(future)
    }

    pub fn spawn_blocking<F, R>(&self, job: F) -> task::JoinHandle<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        self.handle.spawn_blocking(job)
    }
}

impl Drop for BackgroundRuntime {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };

    #[test]
    fn ten_io_tasks_overlap_on_one_background_thread_and_stop_on_drop() {
        let runtime = BackgroundRuntime::new().unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(10));
        let (tx, rx) = mpsc::channel();
        for _ in 0..10 {
            let (barrier, tx) = (barrier.clone(), tx.clone());
            runtime.spawn(async move {
                barrier.wait().await;
                tokio::time::sleep(Duration::from_millis(10)).await;
                tx.send(std::thread::current().id()).unwrap();
            });
        }
        let ids: Vec<_> = (0..10)
            .map(|_| rx.recv_timeout(Duration::from_secs(2)).unwrap())
            .collect();
        assert!(ids.iter().all(|id| *id == ids[0]));
        assert_ne!(ids[0], std::thread::current().id());
        let blocked = tx.clone();
        runtime.spawn_blocking(move || blocked.send(std::thread::current().id()).unwrap());
        assert_ne!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), ids[0]);
        struct Cancelled(Arc<AtomicBool>);
        impl Drop for Cancelled {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        let guard = Cancelled(cancelled.clone());
        runtime.spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        drop(runtime);
        assert!(cancelled.load(Ordering::SeqCst));
    }
}
