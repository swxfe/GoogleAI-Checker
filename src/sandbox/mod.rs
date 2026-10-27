pub mod process;
#[cfg(windows)]
mod window;
use crate::{
    checker::verdicts::NodeCheckResult,
    throne::{client::parse_key, controller::Controller, db::ThroneDb},
};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use fs2::FileExt;
use process::ManagedProcess;
use rand::RngCore;
use rusqlite::{Connection, params};
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

pub const API_ADDR: &str = "127.0.0.1:19095";
pub const PROXY_ADDR: &str = "127.0.0.1:12080";
#[derive(Clone)]
pub struct SandboxPaths {
    pub root: PathBuf,
    pub bin: PathBuf,
    pub data: PathBuf,
    pub database: PathBuf,
    pub browser: PathBuf,
}
impl SandboxPaths {
    pub fn beside_executable() -> Result<Self> {
        Self::at(
            std::env::current_exe()?
                .parent()
                .context("Нет каталога программы")?,
        )
    }
    pub fn at(root: &Path) -> Result<Self> {
        let root = dunce::canonicalize(root)?;
        let bin = root.join("bin");
        let data = root.join("sandbox_data");
        for path in [
            &bin,
            &data,
            &data.join("config"),
            &data.join("logs"),
            &data.join("imports"),
            &data.join("browser_profiles"),
            &data.join("tmp"),
        ] {
            fs::create_dir_all(path).with_context(|| {
                format!(
                    "Не удалось создать каталог {} рядом с программой",
                    path.display()
                )
            })?;
            if !path.canonicalize()?.starts_with(root.canonicalize()?) {
                bail!(
                    "Каталоги песочницы должны находиться рядом с программой; внешние ссылки не допускаются"
                );
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&data, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            database: data.join("config/throne.db"),
            browser: data.join("browser_profiles"),
            root,
            bin,
            data,
        })
    }
    pub fn verify_layout(&self) -> Result<()> {
        let root = self.root.canonicalize()?;
        if !self.bin.canonicalize()?.starts_with(&root)
            || !self.data.canonicalize()?.starts_with(&root)
        {
            bail!("bin и sandbox_data не могут указывать за каталог программы");
        }
        Ok(())
    }
    fn verify_database(&self) -> Result<()> {
        self.verify_layout()?;
        if self.database.exists()
            && !self
                .database
                .canonicalize()?
                .starts_with(&self.data.canonicalize()?)
        {
            bail!("База песочницы указывает за sandbox_data");
        }
        Ok(())
    }
}
struct State {
    child: Option<ManagedProcess>,
    key: Option<String>,
    exit: Option<String>,
    #[cfg(windows)]
    gui_launch: Option<(PathBuf, PathBuf)>,
}
pub struct Sandbox {
    pub paths: SandboxPaths,
    state: Mutex<State>,
    pub closed: Arc<AtomicBool>,
    _lease: File,
}
impl Sandbox {
    pub fn new(paths: SandboxPaths) -> Result<Self> {
        let lease = File::options()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(paths.data.join("checker.lock"))?;
        lease
            .try_lock_exclusive()
            .context("Эта переносная песочница уже открыта другим чекером")?;
        Ok(Self {
            paths,
            state: Mutex::new(State {
                child: None,
                key: None,
                exit: None,
                #[cfg(windows)]
                gui_launch: None,
            }),
            closed: Arc::new(AtomicBool::new(false)),
            _lease: lease,
        })
    }
    pub fn executable(&self) -> Option<PathBuf> {
        self.paths.verify_layout().ok()?;
        find_executable(&self.paths.bin)
    }
    pub fn direct_database(&self) -> Option<PathBuf> {
        if let Ok(path) = fs::read_to_string(self.paths.data.join("throne-source.txt")) {
            let path = PathBuf::from(path.trim());
            if path.is_file() {
                return Some(path);
            }
        }
        let path = self.executable()?.parent()?.join("config/throne.db");
        path.is_file().then_some(path)
    }
    pub fn is_running(&self) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let polled = state.child.as_mut().map(|p| p.exit_status());
        let running = match polled {
            Some(Ok(None)) => true,
            Some(Ok(Some(status))) => {
                state.exit = Some(status.to_string());
                false
            }
            Some(Err(e)) => {
                state.exit = Some(e.to_string());
                false
            }
            None => false,
        };
        if !running {
            state.child.take();
        }
        running
    }
    #[cfg(test)]
    pub fn pid(&self) -> Option<u32> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .child
            .as_ref()
            .map(|p| p.id())
    }
    pub fn controller(&self) -> Result<Controller> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if self.closed.load(Ordering::SeqCst) || state.child.is_none() {
            bail!("Песочница Throne не запущена");
        }
        Ok(Controller::Wire {
            addr: API_ADDR.into(),
            key: state.key.clone().context("Нет локального ключа API")?,
        })
    }
    fn spawn(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if self.closed.load(Ordering::SeqCst) {
            bail!("Песочница закрывается");
        }
        if state.child.is_some() {
            bail!("Дочерний Throne уже запущен");
        }
        let exe = self.executable().context(
            rust_i18n::t!("Throne is missing from ./bin/. Extract the complete release bundle.")
                .to_string(),
        )?;
        self.paths.verify_database()?;
        let direct = self.direct_database();
        let appdata = if let Some(db) = &direct {
            let config = db.parent().context("Нет каталога базы")?;
            if config.file_name().is_none_or(|name| name != "config") {
                bail!("Для автоматического запуска выберите Throne config/throne.db");
            }
            let root = config.parent().context("Нет каталога Throne")?;
            let adjacent = root.join(if cfg!(windows) {
                "Throne.exe"
            } else {
                "Throne"
            });
            if adjacent.is_file() && process::executable_is_running(&adjacent)? {
                bail!("Throne с этой базой уже запущен. Закройте его перед запуском чекера");
            }
            root.to_path_buf()
        } else {
            self.paths.data.clone()
        };
        if process::executable_is_running(&exe)? {
            bail!(
                "Этот Throne уже запущен вне чекера. Закройте его окно и нажмите «Обновить группы и конфиги» — чекер настроит и запустит его в фоне"
            );
        }
        for addr in [API_ADDR, PROXY_ADDR] {
            std::net::TcpListener::bind(addr).with_context(||format!("Выделенный порт {addr} уже занят; чужой процесс не будет подключён или остановлен"))?;
        }
        let key = if let Some(database) = direct {
            let backup_dir = self.paths.data.join("backups");
            fs::create_dir_all(&backup_dir)?;
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos();
            let source =
                Connection::open_with_flags(&database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            source.backup(
                rusqlite::DatabaseName::Main,
                backup_dir.join(format!("throne-before-autostart-{stamp}.sqlite")),
                None,
            )?;
            drop(source);
            prepare_database_settings(&database)?
        } else {
            prepare_settings(&self.paths)?
        };
        let mut command = Command::new(&exe);
        command
            .current_dir(exe.parent().context("Нет каталога Throne")?)
            .arg("-appdata")
            .arg(&appdata)
            .arg("-tray")
            .env("TMPDIR", self.paths.data.join("tmp"))
            .env("TEMP", self.paths.data.join("tmp"))
            .env("TMP", self.paths.data.join("tmp"));
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("THRONE_") {
                command.env_remove(name);
            }
        }
        // Keep one GUI process hidden in the tray; opening its window must not
        // restart the active proxy or open the profile database in another owner.
        let process = ManagedProcess::spawn(command, &self.paths.data.join("logs/child.log"))?;
        if self.closed.load(Ordering::SeqCst) {
            drop(process);
            bail!("Запуск отменён");
        }
        state.key = Some(key);
        state.exit = None;
        state.child = Some(process);
        #[cfg(windows)]
        {
            state.gui_launch = Some((exe, appdata));
        }
        Ok(())
    }
    #[cfg(windows)]
    pub fn window_visible(&self) -> Result<bool> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let child = state.child.as_ref().context("Throne не запущен чекером")?;
        window::visible(child.root_pid())
    }
    #[cfg(windows)]
    pub fn set_window_visible(&self, visible: bool) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if self.closed.load(Ordering::SeqCst) {
            bail!("Чекер закрывается");
        }
        let child = state.child.as_mut().context("Throne не запущен чекером")?;
        if child.exit_status()?.is_some() {
            bail!("Throne завершился; нажмите «Обновить»");
        }
        let pid = child.root_pid();
        if visible {
            let (exe, data) = state.gui_launch.as_ref().context("Нет параметров Throne")?;
            // A second invocation hands off to the existing GUI before opening
            // its database. This also creates Qt's native window on first open.
            let mut command = Command::new(exe);
            command
                .current_dir(exe.parent().context("Нет каталога Throne")?)
                .arg("-appdata")
                .arg(data)
                .arg("-tray");
            for (name, _) in std::env::vars_os() {
                if name.to_string_lossy().starts_with("THRONE_") {
                    command.env_remove(name);
                }
            }
            let mut activation =
                ManagedProcess::spawn(command, &self.paths.data.join("logs/window.log"))?;
            let deadline = std::time::Instant::now() + Duration::from_secs(4);
            loop {
                if let Some(status) = activation.exit_status()? {
                    if !status.success() {
                        bail!("Throne не открыл окно: {status}");
                    }
                    break;
                }
                if self.closed.load(Ordering::SeqCst) || std::time::Instant::now() >= deadline {
                    bail!("Throne не ответил на открытие окна");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        // IPC hands off before Qt handles its queued Raise message and creates
        // the native main window. Wait on the worker, never on the checker UI.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            match window::set_visible(pid, visible) {
                Ok(()) => return Ok(()),
                Err(_)
                    if visible
                        && std::time::Instant::now() < deadline
                        && !self.closed.load(Ordering::SeqCst) =>
                {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => return Err(error),
            }
        }
    }
    pub async fn start(self: &Arc<Self>) -> Result<Controller> {
        if !self.is_running() {
            let manager = self.clone();
            tokio::task::spawn_blocking(move || manager.spawn()).await??;
        }
        let manager = self.clone();
        let ready = async {
            loop {
                if !manager.is_running() {
                    let log = fs::read_to_string(manager.paths.data.join("logs/child.log"))
                        .unwrap_or_default();
                    let tail = log
                        .chars()
                        .rev()
                        .take(2000)
                        .collect::<String>()
                        .chars()
                        .rev()
                        .collect::<String>();
                    let reason = manager
                        .state
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .exit
                        .clone()
                        .unwrap_or_default();
                    bail!("Дочерний Throne завершился при запуске ({reason}). child.log: {tail}");
                }
                let controller = manager.controller()?;
                if let Ok(Ok(status)) =
                    tokio::time::timeout(Duration::from_secs(2), controller.status()).await
                {
                    let inbound = status
                        .inbound
                        .context("Эта сборка не сообщает mixed inbound")?;
                    if inbound.enabled != Some(true)
                        || inbound.port != Some(12080)
                        || status.tun == Some(true)
                        || status.system_proxy == Some(true)
                    {
                        bail!(
                            "Throne не подтвердил изолированные порты или выключенные Tun / системный прокси"
                        );
                    }
                    return Ok(controller);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };
        let result = tokio::select! {
            r=tokio::time::timeout(Duration::from_secs(20),ready)=>r.unwrap_or_else(|_|Err(anyhow::anyhow!("Throne не открыл API 19095; проверьте logs/child.log"))),
            _=wait_cancelled(&self.closed)=>Err(anyhow::anyhow!("Запуск отменён при закрытии окна")),
        };
        if result.is_err() {
            self.stop();
        }
        result
    }
    pub fn stop(&self) {
        let child = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .child
            .take();
        drop(child);
    }
    pub fn shutdown(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.stop();
    }
    pub async fn import(self: &Arc<Self>, input: &str) -> Result<usize> {
        tokio::select! {r=self.import_inner(input)=>r,_=wait_cancelled(&self.closed)=>bail!("Импорт отменён при закрытии окна")}
    }
    async fn import_inner(self: &Arc<Self>, input: &str) -> Result<usize> {
        // Headless Throne accepts imports through the encrypted local management API.
        // No restart or temporary plaintext subscription file is needed.
        let controller = self.start().await?;
        controller.import(input).await
    }
    pub fn apply(&self, results: &[NodeCheckResult]) -> Result<crate::throne::db::SyncSummary> {
        self.stop();
        self.paths.verify_database()?;
        ThroneDb::new(self.paths.database.clone()).sync_sandbox_results(
            results,
            &self.paths.data,
            || {
                if self.is_running() {
                    bail!("Дочерний Throne ещё работает");
                }
                Ok(())
            },
        )
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        self.shutdown();
    }
}
pub async fn wait_cancelled(closed: &AtomicBool) {
    while !closed.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
}

pub fn find_executable(root: &Path) -> Option<PathBuf> {
    fn walk(root: &Path, depth: usize) -> Option<PathBuf> {
        if depth > 8 {
            return None;
        }
        let mut entries = fs::read_dir(root)
            .ok()?
            .filter_map(|e| e.ok())
            .collect::<Vec<_>>();
        entries.sort_by_key(|e| e.path());
        for entry in &entries {
            let typ = entry.file_type().ok()?;
            if typ.is_file()
                && entry
                    .file_name()
                    .to_string_lossy()
                    .eq_ignore_ascii_case(if cfg!(windows) {
                        "Throne.exe"
                    } else {
                        "Throne"
                    })
            {
                return Some(entry.path());
            }
        }
        for entry in entries {
            if entry.file_type().ok()?.is_dir()
                && let Some(path) = walk(&entry.path(), depth + 1)
            {
                return Some(path);
            }
        }
        None
    }
    let path = walk(root, 0)?;
    if path
        .canonicalize()
        .ok()?
        .starts_with(root.canonicalize().ok()?)
    {
        Some(path)
    } else {
        None
    }
}
fn prepare_settings(paths: &SandboxPaths) -> Result<String> {
    paths.verify_database()?;
    prepare_database_settings(&paths.database)
}
fn prepare_database_settings(database: &Path) -> Result<String> {
    let mut conn = Connection::open(database)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL)",
    )?;
    let existing: Option<String> = conn
        .query_row(
            "SELECT value FROM settings WHERE key='remote_api_key'",
            [],
            |r| r.get(0),
        )
        .ok();
    let key = existing
        .filter(|k| parse_key(k).is_ok())
        .unwrap_or_else(|| {
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            URL_SAFE_NO_PAD.encode(bytes)
        });
    let values = [
        ("remote_api_enable", "true"),
        ("remote_api_lan", "false"),
        ("remote_api_admin_lan", "false"),
        ("remote_api_port", "19095"),
        ("remote_api_key", key.as_str()),
        ("remote_api_allow", "127.0.0.1/32"),
        ("inbound_address", "127.0.0.1"),
        ("inbound_socks_port", "12080"),
        ("disable_mixed_inbound", "false"),
        ("random_inbound_port", "false"),
        ("inbound_auth", "false"),
        ("system_proxy_enabled", "false"),
        ("tun_mode_enabled", "false"),
        ("remember_enable", "false"),
        ("remember_id", "-1"),
        ("kill_switch", "false"),
        ("windows_set_admin", "false"),
        ("disable_run_admin", "true"),
        ("auto_run", "false"),
        ("url_scheme_auto_register", "false"),
        ("file_assoc_auto_register", "false"),
        ("start_minimal", "true"),
        ("disable_tray", "false"),
        ("hk_startstop", ""),
        ("hk_tun", ""),
        ("hk_toggle", ""),
        ("hk_spmenu", ""),
        ("hk_route", ""),
        ("core_box_clash_api", "-19090"),
        ("core_box_api_port", "-19091"),
        ("core_dns_in_port", "12053"),
        ("enable_ntp", "false"),
        ("language", "1"),
        ("allow_beta_update", "false"),
    ];
    let tx = conn.transaction()?;
    for (name, value) in values {
        tx.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",params![name,value])?;
    }
    tx.commit()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(database, fs::Permissions::from_mode(0o600))?;
    }
    Ok(key)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paths_key_and_settings_are_local_and_repeatable() {
        let d = tempfile::tempdir().unwrap();
        let paths = SandboxPaths::at(d.path()).unwrap();
        let manager = Sandbox::new(paths.clone()).unwrap();
        assert!(Sandbox::new(paths.clone()).is_err());
        let key = prepare_settings(&paths).unwrap();
        assert!(parse_key(&key).is_ok());
        assert_eq!(prepare_settings(&paths).unwrap(), key);
        let conn = Connection::open(&paths.database).unwrap();
        let port: String = conn
            .query_row(
                "SELECT value FROM settings WHERE key='remote_api_port'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(port, "19095");
        let proxy: String = conn
            .query_row(
                "SELECT value FROM settings WHERE key='system_proxy_enabled'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(proxy, "false");
        assert!(
            paths
                .database
                .starts_with(dunce::canonicalize(d.path()).unwrap())
        );
        drop(manager);
        assert!(Sandbox::new(paths).is_ok());
    }
    #[test]
    fn occupied_port_is_never_adopted_or_killed() {
        let d = tempfile::tempdir().unwrap();
        let paths = SandboxPaths::at(d.path()).unwrap();
        fs::write(
            paths.bin.join(if cfg!(windows) {
                "Throne.exe"
            } else {
                "Throne"
            }),
            b"not executable; must never run",
        )
        .unwrap();
        let manager = Sandbox::new(paths).unwrap();
        let listener = std::net::TcpListener::bind(API_ADDR).ok();
        let err = manager
            .spawn()
            .expect_err("Busy port must fail before process creation");
        assert!(format!("{err:#}").contains("порт"));
        assert!(manager.pid().is_none());
        if let Some(listener) = listener {
            assert_eq!(listener.local_addr().unwrap().port(), 19095);
        }
    }
    #[cfg(unix)]
    #[test]
    fn outside_data_symlink_is_rejected_before_writing() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("sandbox_data")).unwrap();
        assert!(SandboxPaths::at(root.path()).is_err());
        assert!(fs::read_dir(outside.path()).unwrap().next().is_none());
    }
    #[tokio::test]
    #[ignore = "Runs a prebuilt portable Throne bundle in an isolated fixture"]
    async fn real_bundle_start_import_activate_and_cleanup() {
        let d = tempfile::tempdir().unwrap();
        let paths = SandboxPaths::at(d.path()).unwrap();
        let fixture = std::env::var("GOOGLEAI_CHECKER_TEST_BIN")
            .expect("Set GOOGLEAI_CHECKER_TEST_BIN to an extracted bundle's bin directory");
        fn copy_tree(source: &Path, destination: &Path) {
            fs::create_dir_all(destination).unwrap();
            for entry in fs::read_dir(source).unwrap() {
                let entry = entry.unwrap();
                let dest = destination.join(entry.file_name());
                if entry.file_type().unwrap().is_dir() {
                    copy_tree(&entry.path(), &dest);
                } else {
                    fs::copy(entry.path(), dest).unwrap();
                }
            }
        }
        copy_tree(Path::new(&fixture), &paths.bin);
        let manager = Arc::new(Sandbox::new(paths.clone()).unwrap());
        let started = manager.start().await;
        if started.is_err() {
            eprintln!("Failed startup fixture: {}", d.path().display());
            let _ = d.keep();
        }
        let controller = started.unwrap();
        let s = controller.status().await.unwrap();
        assert!(
            s.version
                .as_deref()
                .is_some_and(|v| v.contains(crate::THRONE_VERSION.trim())),
            "Unexpected core: {:?}",
            s.version
        );
        let original_pid = manager.pid().unwrap();
        assert_eq!(s.inbound.unwrap().port, Some(12080));
        assert_eq!(s.system_proxy, Some(false));
        assert_eq!(s.tun, Some(false));
        let input=(0..200).map(|i|format!("vless://11111111-1111-4111-8111-{i:012x}@127.0.0.1:9?encryption=none#Sandbox%20fixture%20{i}")).collect::<Vec<_>>().join("\n");
        let (text, last) = input.rsplit_once('\n').unwrap();
        let n = manager.import(text).await.unwrap();
        assert_eq!(n, 199);
        // Exercise Throne's URL importer too, without accessing any real subscription.
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/fixture", server.local_addr().unwrap());
        let last = last.to_owned();
        let download = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut stream, _) = server.accept().await.unwrap();
            let mut request = [0; 4096];
            let n = stream.read(&mut request).await.unwrap();
            assert!(request[..n].starts_with(b"GET /fixture "));
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                last.len(),
                last
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        assert_eq!(manager.import(&url).await.unwrap(), 1);
        download.await.unwrap();
        assert_eq!(
            manager.pid(),
            Some(original_pid),
            "API import must not restart Throne"
        );
        let controller = manager.controller().unwrap();
        let profiles = controller.profiles(None).await.unwrap();
        assert_eq!(profiles.len(), 200);
        #[cfg(windows)]
        {
            use windows_sys::Win32::{
                Foundation::{HWND, LPARAM},
                UI::WindowsAndMessaging::{EnumWindows, GetWindowThreadProcessId, IsWindowVisible},
            };
            struct Windows {
                pid: u32,
                visible: usize,
            }
            unsafe extern "system" fn check(hwnd: HWND, param: LPARAM) -> i32 {
                let data = unsafe { &mut *(param as *mut Windows) };
                let mut owner = 0;
                unsafe {
                    GetWindowThreadProcessId(hwnd, &mut owner);
                }
                if owner == data.pid && unsafe { IsWindowVisible(hwnd) } != 0 {
                    data.visible += 1;
                }
                1
            }
            let mut data = Windows {
                pid: manager.pid().unwrap(),
                visible: 0,
            };
            unsafe {
                EnumWindows(Some(check), &mut data as *mut _ as LPARAM);
            }
            assert_eq!(
                data.visible, 0,
                "The managed Throne must stay in the background"
            );
        }
        tokio::time::timeout(Duration::from_secs(10), controller.activate(profiles[0].id))
            .await
            .unwrap()
            .unwrap();
        let status = controller.status().await.unwrap();
        assert_eq!(status.inbound.unwrap().port, Some(12080));
        assert!(std::net::TcpStream::connect(PROXY_ADDR).is_ok());
        #[cfg(windows)]
        for _ in 0..2 {
            let m = manager.clone();
            tokio::task::spawn_blocking(move || m.set_window_visible(true))
                .await
                .unwrap()
                .unwrap();
            tokio::time::timeout(Duration::from_secs(3), async {
                while !manager.window_visible().unwrap() {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                }
            })
            .await
            .unwrap();
            assert_eq!(manager.pid(), Some(original_pid));
            assert_eq!(
                controller.status().await.unwrap().profile.unwrap().id,
                profiles[0].id
            );
            manager.set_window_visible(false).unwrap();
            tokio::time::timeout(Duration::from_secs(3), async {
                while manager.window_visible().unwrap() {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                }
            })
            .await
            .unwrap();
            assert_eq!(manager.pid(), Some(original_pid));
            assert!(std::net::TcpStream::connect(PROXY_ADDR).is_ok());
            assert_eq!(
                controller.status().await.unwrap().profile.unwrap().id,
                profiles[0].id
            );
        }
        #[cfg(windows)]
        {
            let m = manager.clone();
            tokio::task::spawn_blocking(move || m.set_window_visible(true))
                .await
                .unwrap()
                .unwrap();
            tokio::time::timeout(Duration::from_secs(3), async {
                while !manager.window_visible().unwrap() {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                }
            })
            .await
            .unwrap();
            window::close_for_test(original_pid).unwrap();
            tokio::time::timeout(Duration::from_secs(3), async {
                while manager.window_visible().unwrap() {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                }
            })
            .await
            .unwrap();
            assert!(
                manager.is_running(),
                "The title-bar close button must hide to tray"
            );
            assert_eq!(
                controller.status().await.unwrap().profile.unwrap().id,
                profiles[0].id
            );
        }
        let result = NodeCheckResult {
            profile_id: profiles[0].id,
            profile_name: profiles[0].name.clone(),
            protocol: profiles[0].profile_type.clone(),
            server_address: profiles[0].address.clone(),
            verdict: crate::checker::verdicts::AiVerdict::Geoblock,
            details: "Isolated test fixture".into(),
            latency_ms: None,
            final_url: None,
            checked_at: None,
            timings: None,
        };
        let applied = manager.apply(&[result]).unwrap();
        assert_eq!(applied.blocked, 1);
        assert!(applied.backup.is_file());
        let controller = manager.start().await.unwrap();
        let after = controller.profiles(None).await.unwrap();
        let blocked = after.iter().find(|p| p.id == profiles[0].id).unwrap();
        assert!(blocked.name.starts_with("[AI-BLOCKED]"));
        assert!(
            controller
                .groups()
                .await
                .unwrap()
                .iter()
                .any(|g| Some(g.id) == blocked.group && g.archived == Some(true))
        );
        let next = after.iter().find(|p| p.group != blocked.group).unwrap();
        tokio::time::timeout(Duration::from_secs(10), controller.activate(next.id))
            .await
            .unwrap()
            .unwrap();
        assert!(std::net::TcpStream::connect(PROXY_ADDR).is_ok());
        drop(manager);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(std::net::TcpListener::bind(API_ADDR).is_ok());
        assert!(std::net::TcpListener::bind(PROXY_ADDR).is_ok());
        // The direct mode starts against the original config directory, with
        // all existing IDs and groups intact and no second profile database.
        let external = tempfile::tempdir().unwrap();
        let direct_dir = external.path().join("config");
        fs::create_dir_all(&direct_dir).unwrap();
        let direct_db = direct_dir.join("throne.db");
        Connection::open(&paths.database)
            .unwrap()
            .backup(rusqlite::DatabaseName::Main, &direct_db, None)
            .unwrap();
        // An external desktop installation can have an older binary. Always
        // run our provisioned beta.3 binary against the selected data directory.
        fs::write(
            external.path().join(if cfg!(windows) {
                "Throne.exe"
            } else {
                "Throne"
            }),
            b"old desktop binary: must never be started",
        )
        .unwrap();
        fs::write(
            paths.data.join("throne-source.txt"),
            direct_db.to_str().unwrap(),
        )
        .unwrap();
        let original_ids = ThroneDb::new(direct_db.clone())
            .read_profiles()
            .unwrap()
            .iter()
            .map(|p| p.id)
            .collect::<Vec<_>>();
        let manager = Arc::new(Sandbox::new(paths.clone()).unwrap());
        assert_eq!(manager.direct_database().unwrap(), direct_db);
        let controller = manager.start().await.unwrap();
        let mut loaded_ids = controller
            .profiles(None)
            .await
            .unwrap()
            .iter()
            .map(|p| p.id)
            .collect::<Vec<_>>();
        loaded_ids.sort_unstable();
        assert_eq!(loaded_ids, original_ids);
        assert_eq!(
            controller.status().await.unwrap().inbound.unwrap().port,
            Some(12080)
        );
        assert_eq!(fs::read_dir(paths.data.join("backups")).unwrap().count(), 1);
        assert!(process::executable_is_running(&manager.executable().unwrap()).unwrap());
        drop(manager);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(std::net::TcpListener::bind(API_ADDR).is_ok());
        assert!(std::net::TcpListener::bind(PROXY_ADDR).is_ok());
    }
}
