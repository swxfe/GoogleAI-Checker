use super::{
    client::{ConnectionRejected, ThroneClient},
    models::{Group, Profile, Status},
};
use anyhow::{Result, bail};
use std::time::Duration;
use tokio::sync::{Mutex, MutexGuard};

/// The requested start has completed unsuccessfully and no profile is running.
#[derive(Debug)]
pub struct ProfileStartFailed(pub String);
impl std::fmt::Display for ProfileStartFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ProfileStartFailed {}

fn confirmed_idle(status: &Status) -> bool {
    status.state == "idle" && status.profile.is_none()
}

#[derive(Clone)]
pub enum Controller {
    Wire { addr: String, key: String },
}
pub struct ControllerSession {
    controller: Controller,
    client: Mutex<Option<ThroneClient>>,
}

impl Controller {
    async fn wire(&self) -> Result<ThroneClient> {
        match self {
            Self::Wire { addr, key } => {
                ThroneClient::connect(addr, key, Duration::from_secs(3)).await
            }
        }
    }
    pub async fn status(&self) -> Result<Status> {
        self.wire().await?.get_status().await
    }
    pub async fn groups(&self) -> Result<Vec<Group>> {
        self.wire().await?.get_groups().await
    }
    pub async fn profiles(&self, group: Option<i64>) -> Result<Vec<Profile>> {
        self.wire().await?.get_profiles(group).await
    }
    pub async fn import(&self, input: &str) -> Result<usize> {
        self.wire().await?.import(input).await
    }
    pub fn session(&self) -> ControllerSession {
        ControllerSession {
            controller: self.clone(),
            client: Mutex::new(None),
        }
    }
    #[cfg(test)]
    pub async fn activate(&self, id: i64) -> Result<()> {
        self.session().activate(id).await
    }
    #[cfg(test)]
    pub async fn restore(&self, original: &Status) -> Result<()> {
        self.session().restore(original).await
    }
}
impl ControllerSession {
    async fn wire(&self) -> Result<MutexGuard<'_, Option<ThroneClient>>> {
        let mut slot = self.client.lock().await;
        if !slot.as_ref().is_some_and(ThroneClient::reusable) {
            *slot = None;
            *slot = Some(self.controller.wire().await?);
        }
        Ok(slot)
    }
    pub async fn status(&self) -> Result<Status> {
        let mut slot = self.wire().await?;
        let result = slot.as_mut().expect("connected API").get_status().await;
        if result.is_err() && !slot.as_ref().is_some_and(ThroneClient::reusable) {
            // A read can be repeated after server idle-close or interrupted IO.
            // Connection mutations below are never automatically replayed.
            *slot = None;
            *slot = Some(self.controller.wire().await?);
            return slot.as_mut().expect("reconnected API").get_status().await;
        }
        result
    }
    async fn connect_profile(&self, id: i64) -> Result<Status> {
        self.wire()
            .await?
            .as_mut()
            .expect("connected API")
            .connect_profile(id, 1)
            .await
    }
    async fn disconnect(&self) -> Result<Status> {
        self.wire()
            .await?
            .as_mut()
            .expect("connected API")
            .disconnect()
            .await
    }
    pub async fn activate(&self, id: i64) -> Result<()> {
        let started = self.connect_profile(id).await;
        if let Err(error) = &started {
            // Only a completed server rejection can be skipped. A lost response or
            // timeout may still leave a PUT in flight, even if GET currently says idle.
            if error
                .downcast_ref::<ConnectionRejected>()
                .is_some_and(|e| matches!(e.status, 400 | 404 | 422 | 500) && e.code != "busy")
            {
                let status = self.status().await?;
                if confirmed_idle(&status) {
                    return Err(
                        ProfileStartFailed(format!("Профиль {id} не запущен: {error}")).into(),
                    );
                }
            }
            return Err(started.unwrap_err());
        }
        if let Ok(status) = started
            && status.state == "running"
            && status.profile.as_ref().map(|p| p.id) == Some(id)
        {
            return Ok(());
        }
        loop {
            let s = self.status().await?;
            if s.state == "running" && s.profile.as_ref().map(|p| p.id) == Some(id) {
                return Ok(());
            }
            if confirmed_idle(&s) {
                return Err(ProfileStartFailed(format!("Throne не запустил профиль {id}; проверьте конфигурацию и поддержку транспорта ядром")).into());
            }
            if s.state == "idle" {
                bail!("Throne вернул противоречивый статус профиля {id}");
            }
            if s.state == "running" {
                bail!("Активирован другой профиль; проверка остановлена");
            }
            tokio::time::sleep(Duration::from_millis(70)).await;
        }
    }
    pub async fn restore(&self, original: &Status) -> Result<()> {
        // A cancelled PUT can still finish in Throne. Wait for it before restoring.
        loop {
            let s = self.status().await?;
            if s.state != "connecting" && s.state != "stopping" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if let Some(p) = &original.profile {
            self.activate(p.id).await
        } else {
            self.disconnect().await?;
            loop {
                if self.status().await?.state == "idle" {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::throne::client::{derive_keys, open_frame, seal_frame};
    use serde_json::json;
    use std::sync::{Arc, Mutex};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    pub(crate) struct Fixture {
        pub controller: Controller,
        pub selected: Arc<Mutex<Option<i64>>>,
        pub(crate) connections: Arc<Mutex<Vec<i64>>>,
        pub(crate) test_calls: Arc<Mutex<Vec<String>>>,
        pub(crate) handshakes: Arc<std::sync::atomic::AtomicUsize>,
        pause_status: Arc<std::sync::atomic::AtomicBool>,
        close_status: Arc<std::sync::atomic::AtomicBool>,
        status_received: Arc<tokio::sync::Notify>,
        server: tokio::task::JoinHandle<()>,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    pub(crate) async fn fixture() -> Fixture {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let key_text = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
        let key = crate::throne::client::parse_key(key_text).unwrap();
        let selected = Arc::new(Mutex::new(Some(9_i64)));
        let selected_server = selected.clone();
        let connections = Arc::new(Mutex::new(Vec::<i64>::new()));
        let server_connections = connections.clone();
        let test_calls = Arc::new(Mutex::new(Vec::new()));
        let server_test_calls = test_calls.clone();
        let handshakes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accepted = handshakes.clone();
        let pause_status = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let close_status = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let status_received = Arc::new(tokio::sync::Notify::new());
        let server_pause = pause_status.clone();
        let server_close = close_status.clone();
        let server_received = status_received.clone();
        let server = tokio::spawn(async move {
            let mut clients = tokio::task::JoinSet::new();
            loop {
                let (mut stream, _) = tokio::select! {
                    stream=listener.accept()=>stream.unwrap(),
                    completed=clients.join_next(),if !clients.is_empty()=>{ completed.unwrap().unwrap(); continue; }
                };
                accepted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let selected_server = selected_server.clone();
                let server_connections = server_connections.clone();
                let server_test_calls = server_test_calls.clone();
                let pause_status = server_pause.clone();
                let close_status = server_close.clone();
                let status_received = server_received.clone();
                clients.spawn(async move {
                stream.set_nodelay(true).unwrap();
                let s = [37u8; 16];
                stream.write_all(&s).await.unwrap();
                let mut hello = [0u8; 17];
                stream.read_exact(&mut hello).await.unwrap();
                assert_eq!(hello[0], 1);
                let c: [u8; 16] = hello[1..].try_into().unwrap();
                let (c2s, s2c) = derive_keys(&key, &s, &c).unwrap();
                for counter in 0..u64::MAX {
                let mut aad = [0u8; 4];
                if stream.read_exact(&mut aad).await.is_err() { return; }
                let mut sealed = vec![0; u32::from_be_bytes(aad) as usize];
                stream.read_exact(&mut sealed).await.unwrap();
                let plain = open_frame(
                    &c2s,
                    counter,
                    &[aad.as_slice(), sealed.as_slice()].concat(),
                    1024 * 1024,
                )
                .unwrap();
                let req: serde_json::Value = serde_json::from_slice(&plain).unwrap();
                        let is_status = req["method"] == "GET" && req["path"] == "/v1/status";
                        if is_status && pause_status.swap(false, std::sync::atomic::Ordering::SeqCst) {
                            status_received.notify_one();
                            std::future::pending::<()>().await;
                        }
                if req["path"].as_str().unwrap().starts_with("/v1/tests") {
                    server_test_calls
                        .lock()
                        .unwrap()
                        .push(req["path"].to_string());
                    panic!("The direct AI checker must not start native latency tests");
                }
                let mut response_status = 200;
                let mut state = "running";
                if req["method"] == "PUT" {
                    let id = req["body"]["profile"].as_i64().unwrap();
                    *selected_server.lock().unwrap() = match id {
                        13 | 14 | 16 | 17 => None,
                        15 => Some(99),
                        _ => Some(id),
                    };
                    server_connections.lock().unwrap().push(id);
                    // Simulate a lost PUT response: idle GET is not proof of rejection.
                    if id == 16 {
                        return;
                    }
                    response_status = match id {
                        13 => 500,
                        17 => 409,
                        _ => 202,
                    };
                    state = "connecting";
                } else if req["method"] == "DELETE" {
                    *selected_server.lock().unwrap() = None;
                    response_status = 202;
                    state = "stopping";
                }
                let id = *selected_server.lock().unwrap();
                if id.is_none() && response_status == 200 {
                    state = "idle";
                }
                let profile =
                    id.map(|id| json!({"id":id,"name":format!("Profile {id}"),"type":"vless"}));
                let body = json!({"state":state,"profile":profile});
                let response = if response_status >= 400 {
                    let code = if response_status == 409 {
                        "busy"
                    } else {
                        "start_failed"
                    };
                    serde_json::to_vec(&json!({"status":response_status,"error":{"code":code,"message":"fixture: unsupported transport"}})).unwrap()
                } else {
                    serde_json::to_vec(&json!({"status":response_status,"body":body})).unwrap()
                };
                stream
                    .write_all(&seal_frame(&s2c, counter, &response, 64 * 1024 * 1024).unwrap())
                    .await
                    .unwrap();
                        if is_status && close_status.swap(false, std::sync::atomic::Ordering::SeqCst) { return; }
                }
                });
            }
        });
        let controller = Controller::Wire {
            addr,
            key: key_text.into(),
        };
        Fixture {
            controller,
            selected,
            connections,
            test_calls,
            handshakes,
            pause_status,
            close_status,
            status_received,
            server,
        }
    }

    #[tokio::test]
    async fn encrypted_controller_waits_for_202_and_restores_original() {
        let f = fixture().await;
        let controller = &f.controller;
        let original = controller.status().await.unwrap();
        assert_eq!(original.profile.as_ref().unwrap().id, 9);
        controller.activate(5).await.unwrap();
        assert_eq!(*f.selected.lock().unwrap(), Some(5));
        controller.restore(&original).await.unwrap();
        assert_eq!(*f.selected.lock().unwrap(), Some(9));
        assert_eq!(*f.connections.lock().unwrap(), vec![5, 9]);
        let idle: Status = serde_json::from_value(json!({"state":"idle","profile":null})).unwrap();
        controller.restore(&idle).await.unwrap();
        assert_eq!(*f.selected.lock().unwrap(), None);
    }
    #[tokio::test]
    async fn persistent_session_discards_cancelled_frames_and_reconnects_read_only() {
        use std::sync::atomic::Ordering;
        let fixture = fixture().await;
        let session = fixture.controller.session();
        assert_eq!(session.status().await.unwrap().profile.unwrap().id, 9);
        fixture.pause_status.store(true, Ordering::SeqCst);
        {
            let request = session.status();
            tokio::pin!(request);
            tokio::select! {
                result=&mut request=>panic!("Paused query unexpectedly completed: {result:?}"),
                _=fixture.status_received.notified()=>{},
                _=tokio::time::sleep(Duration::from_secs(1))=>panic!("No query reached the fixture"),
            }
        }
        assert!(!session.client.lock().await.as_ref().unwrap().reusable());
        assert_eq!(session.status().await.unwrap().profile.unwrap().id, 9);
        assert_eq!(fixture.handshakes.load(Ordering::Relaxed), 2);
        fixture.close_status.store(true, Ordering::SeqCst);
        session.status().await.unwrap();
        session.status().await.unwrap();
        assert_eq!(fixture.handshakes.load(Ordering::Relaxed), 3);
        assert!(fixture.connections.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn persistent_session_does_not_replay_a_mutation_after_losing_its_response() {
        let fixture = fixture().await;
        let session = fixture.controller.session();
        session.status().await.unwrap();
        assert!(session.activate(16).await.is_err());
        assert_eq!(session.status().await.unwrap().state, "idle");
        assert_eq!(*fixture.connections.lock().unwrap(), vec![16]);
    }

    #[tokio::test]
    async fn only_confirmed_start_failures_are_recoverable() {
        let f = fixture().await;
        for id in [13, 14] {
            let error = f.controller.activate(id).await.unwrap_err();
            assert!(error.is::<ProfileStartFailed>(), "{error:#}");
            assert!(confirmed_idle(&f.controller.status().await.unwrap()));
        }
        for id in [15, 16, 17] {
            let error = f.controller.activate(id).await.unwrap_err();
            assert!(
                !error.is::<ProfileStartFailed>(),
                "Unsafe to continue for {id}: {error:#}"
            );
        }
        // A bad profile must not prevent starting the next valid profile.
        f.controller.activate(5).await.unwrap();
        assert_eq!(*f.selected.lock().unwrap(), Some(5));
    }
}
