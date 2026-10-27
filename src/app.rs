use crate::{
    browser::{
        detector::{BrowserDetector, DetectedBrowser},
        login::{self, LoginCommand, LoginConfig, LoginEvent},
    },
    checker::{
        engine::{DEFAULT_NODE_TIMEOUT, EngineEvent, EngineMode, ScanConfig, TestEngine},
        verdicts::{AiVerdict, NodeCheckResult, latency_color, protocol_badge_colors},
    },
    events::EventSender,
    i18n::{self, Language, tr},
    sandbox::{PROXY_ADDR, Sandbox, SandboxPaths},
    state::{Entry, Snapshot, StateStore},
    throne::{
        controller::Controller,
        db::ThroneDb,
        models::{Group, Profile, Status},
    },
};
use egui::{Color32, RichText};
use egui_extras::{Column, TableBuilder};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    runtime::Runtime,
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
};

enum UiEvent {
    Data {
        profiles: Vec<Profile>,
        groups: Vec<Group>,
        fingerprints: HashMap<i64, String>,
        source: String,
        status: Box<Status>,
        controller: Controller,
        proxy: String,
        direct: bool,
        notice: String,
    },
    Error(String),
    Login(LoginEvent),
    Copied(Result<String, String>),
    Exported(Result<PathBuf, String>),
    #[cfg(windows)]
    ThroneWindow(Result<(), String>),
}
struct Row {
    profile: Profile,
    result: NodeCheckResult,
    search_text: String,
}
impl Row {
    fn new(profile: Profile) -> Self {
        let search_text = format!(
            "{} {} {}",
            profile.name, profile.address, profile.profile_type
        )
        .to_lowercase();
        let result = NodeCheckResult::new_pending(
            profile.id,
            profile.name.clone(),
            profile.profile_type.clone(),
            profile.address.clone(),
        );
        Self {
            profile,
            result,
            search_text,
        }
    }
    fn unfinished(&self, ids: &HashSet<i64>) -> bool {
        ids.contains(&self.profile.id)
            && self.eligible()
            && self.result.verdict == AiVerdict::Pending
    }
    fn eligible(&self) -> bool {
        self.profile.disabled != Some(true)
            && !matches!(
                self.profile.profile_type.as_str(),
                "autoselector" | "direct" | "chain"
            )
    }
}
pub struct CheckerApp {
    flags: crate::flags::Flags,
    runtime: Runtime,
    sandbox: Option<Arc<Sandbox>>,
    rx: UnboundedReceiver<UiEvent>,
    tx: EventSender<UiEvent>,
    scan_rx: UnboundedReceiver<EngineEvent>,
    scan_tx: EventSender<EngineEvent>,
    rows: Vec<Row>,
    state_store: Option<StateStore>,
    state_cache: Option<Arc<Snapshot>>,
    fingerprints: HashMap<i64, String>,
    source: String,
    groups: Vec<Group>,
    group: Option<i64>,
    controller: Option<Controller>,
    proxy: String,
    direct: bool,
    browser: String,
    login_ready: bool,
    login_open: bool,
    detected_browsers: Vec<DetectedBrowser>,
    login_commands: Option<UnboundedSender<LoginCommand>>,

    timeout: f32,
    search: String,
    search_normalized: String,
    copying: bool,
    exporting: bool,
    #[cfg(windows)]
    window_busy: bool,
    scan_started: Option<std::time::Instant>,
    scan_ids: HashSet<i64>,
    saved_queue: Option<HashSet<i64>>,
    language: Language,

    stopping: bool,
    only_ok: bool,
    subscription: String,
    busy: bool,
    scanning: bool,
    closing: bool,
    running: bool,
    stop: Arc<AtomicBool>,
    total: usize,
    done: usize,
    message: String,
    errors: Vec<String>,
    release: String,
    smoke_deadline: Option<std::time::Instant>,
    #[cfg(feature = "qa-screenshot")]
    qa_frame: usize,
}
impl CheckerApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        let sandbox = SandboxPaths::beside_executable()
            .and_then(Sandbox::new)
            .map(Arc::new);
        let mut message = match &sandbox {
            Ok(_) => "Select a Throne database or import a subscription to get started".into(),
            Err(e) => {
                rust_i18n::t!("Local data unavailable: %{e}", e = format!("{:#}", e)).to_string()
            }
        };
        let sandbox = sandbox.ok();
        if let Some(manager) = &sandbox {
            login::migrate_legacy_marker(&manager.paths.browser);
        }
        let mut language = sandbox
            .as_ref()
            .map(|s| Language::load(&s.paths.data))
            .unwrap_or_default();
        if cfg!(feature = "qa-screenshot")
            && let Ok(code) = std::env::var("GOOGLEAI_CHECKER_QA_LANGUAGE")
        {
            language = Language::ALL
                .into_iter()
                .find(|l| l.code() == code)
                .unwrap_or_default();
        }
        rust_i18n::set_locale(language.code());
        i18n::install_fonts(&cc.egui_ctx);
        let release = crate::THRONE_VERSION.trim().to_owned();
        let state_store = match sandbox
            .as_ref()
            .map(|s| StateStore::new(&s.paths.data))
            .transpose()
        {
            Ok(store) => store,
            Err(error) => {
                message = error.to_string();
                None
            }
        };
        let state_cache = match state_store.as_ref().map(StateStore::read).transpose() {
            Ok(snapshot) => snapshot.flatten().map(Arc::new),
            Err(error) => {
                message = error.to_string();
                None
            }
        };
        let (tx, rx) = mpsc::unbounded_channel();
        let tx = EventSender::with_ui(tx, cc.egui_ctx.clone());
        let detected_browsers = BrowserDetector::detect_all();
        let selected_browser = sandbox
            .as_ref()
            .and_then(|s| {
                std::fs::read_to_string(s.paths.browser.join("selected-browser.txt")).ok()
            })
            .map(|s| PathBuf::from(s.trim()))
            .filter(|p| p.is_file());
        let selected_browser = selected_browser
            .or_else(|| {
                sandbox
                    .as_ref()
                    .and_then(|s| login::saved_browser(&s.paths.browser))
            })
            .or_else(BrowserDetector::find_best);
        let login_ready = selected_browser.as_ref().is_some_and(|browser| {
            sandbox
                .as_ref()
                .is_some_and(|s| login::has_saved_session(&s.paths.browser, browser))
        });
        let (scan_tx, scan_rx) = mpsc::unbounded_channel();
        let scan_tx = EventSender::with_ui(scan_tx, cc.egui_ctx.clone());
        let smoke = std::env::args().any(|a| a == "--smoke-test");
        let qa = cfg!(feature = "qa-screenshot")
            && std::env::var_os("GOOGLEAI_CHECKER_SCREENSHOT_TO").is_some();
        let mut app = Self {
            runtime: tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("Tokio runtime"),
            sandbox,
            rx,
            tx,
            scan_rx,
            scan_tx,
            rows: vec![],
            flags: crate::flags::Flags::new(&cc.egui_ctx),
            state_store,
            state_cache,
            fingerprints: HashMap::new(),
            source: String::new(),
            groups: vec![],
            group: None,
            controller: None,
            proxy: PROXY_ADDR.into(),
            direct: false,
            login_ready,
            login_open: false,
            detected_browsers,
            login_commands: None,
            browser: selected_browser
                .map(|p| p.display().to_string())
                .unwrap_or_default(),

            timeout: DEFAULT_NODE_TIMEOUT.as_secs_f32(),
            search: String::new(),
            search_normalized: String::new(),
            copying: false,
            exporting: false,
            #[cfg(windows)]
            window_busy: false,
            scan_started: None,
            scan_ids: HashSet::new(),
            saved_queue: None,
            language,

            stopping: false,
            only_ok: false,
            subscription: String::new(),
            busy: false,
            scanning: false,
            closing: false,
            running: false,
            stop: Arc::new(AtomicBool::new(false)),
            total: 0,
            done: 0,
            message,
            errors: vec![],
            release,
            smoke_deadline: smoke.then(|| std::time::Instant::now() + Duration::from_secs(3)),
            #[cfg(feature = "qa-screenshot")]
            qa_frame: 0,
        };
        if !smoke
            && !qa
            && app
                .sandbox
                .as_ref()
                .is_some_and(|s| s.direct_database().is_some() || s.executable().is_some())
        {
            app.load();
        }
        #[cfg(feature = "qa-screenshot")]
        if qa {
            cc.egui_ctx
                .style_mut(|style| style.interaction.tooltip_delay = 60.0);
            app.prepare_qa();
        }
        app
    }
    #[cfg(feature = "qa-screenshot")]
    fn prepare_qa(&mut self) {
        let mut profiles = crate::subscription::parser::SubscriptionParser::get_sample_profiles();
        for (index, (profile, name)) in profiles
            .iter_mut()
            .zip([
                "🇪🇪 Estonia #1",
                "🇺🇸 Los Angeles #2",
                "🇩🇪 Frankfurt #3",
                "🇯🇵 Tokyo #4",
                "🇷🇺 Moscow #5",
                "🇨🇳 Shanghai #6",
                "🇳🇱 Amsterdam #7",
                "🇸🇬 Singapore #8",
            ])
            .enumerate()
        {
            profile.name = name.into();
            profile.address = format!("192.0.2.{}:443", index + 1);
        }
        self.set_profiles(profiles, vec![]);
        for ((row, status), latency) in self
            .rows
            .iter_mut()
            .zip([
                AiVerdict::Unlocked,
                AiVerdict::Unlocked,
                AiVerdict::Unlocked,
                AiVerdict::ConnectionError,
                AiVerdict::Geoblock,
                AiVerdict::Geoblock,
                AiVerdict::Unlocked,
                AiVerdict::Unlocked,
            ])
            .zip([53, 137, 68, 0, 0, 0, 82, 164])
        {
            row.result.verdict = status;
            row.result.latency_ms = status.is_working().then_some(latency);
        }
        self.message = "Preview data; personal Throne is not used".into();
    }
    fn manager(&mut self) -> Option<Arc<Sandbox>> {
        if self.sandbox.is_none() {
            self.message = "Cannot create the local data directory".into();
        }
        self.sandbox.clone()
    }
    async fn read_data(manager: Arc<Sandbox>, mut notice: String) -> anyhow::Result<UiEvent> {
        if let Some(path) = manager.direct_database() {
            let db = ThroneDb::new(path.clone());
            let reader = db.clone();
            let source = dunce::canonicalize(&path)?.to_string_lossy().into_owned();
            let (profiles, groups, (existing, _, enabled), fingerprints) =
                tokio::task::spawn_blocking(move || {
                    Ok::<_, anyhow::Error>((
                        reader.read_profiles()?,
                        reader.read_groups()?,
                        reader.connection()?,
                        reader.fingerprints()?,
                    ))
                })
                .await??;
            let already_ready = if enabled {
                existing.status().await.ok()
            } else {
                None
            };
            let (controller, status) = if let Some(status) = already_ready {
                (existing, status)
            } else {
                let controller = manager.start().await?;
                let status = controller.status().await?;
                (controller, status)
            };
            let (_, proxy, _) = tokio::task::spawn_blocking(move || db.connection()).await??;
            notice = rust_i18n::t!("Loaded: %{a0} nodes", a0 = profiles.len()).to_string();
            return Ok(UiEvent::Data {
                profiles,
                groups,
                fingerprints,
                source,
                status: Box::new(status),
                controller,
                proxy,
                direct: true,
                notice,
            });
        }
        let controller = manager.start().await?;
        let status = controller.status().await?;
        let (groups, profiles) = tokio::try_join!(controller.groups(), controller.profiles(None))?;
        let database = manager.paths.database.clone();
        let source = dunce::canonicalize(&database)?
            .to_string_lossy()
            .into_owned();
        let fingerprints =
            tokio::task::spawn_blocking(move || ThroneDb::new(database).fingerprints()).await??;
        Ok(UiEvent::Data {
            profiles,
            groups,
            fingerprints,
            source,
            status: Box::new(status),
            controller,
            proxy: PROXY_ADDR.into(),
            direct: false,
            notice,
        })
    }
    fn load(&mut self) {
        let Some(manager) = self.manager() else {
            return;
        };
        let tx = self.tx.clone();
        self.busy = true;
        self.message = "Loading…".into();
        self.runtime.spawn(async move {
            let r = Self::read_data(manager, String::new()).await;
            let _ = tx.send(r.unwrap_or_else(|e| {
                UiEvent::Error(rust_i18n::t!("Throne: %{e}", e = format!("{:#}", e)).to_string())
            }));
        });
    }
    fn import(&mut self) {
        if self.subscription.trim().is_empty() {
            self.message = "Paste a subscription URL or node configurations".into();
            return;
        }
        let Some(manager) = self.manager() else {
            return;
        };
        let input = self.subscription.clone();
        let tx = self.tx.clone();
        self.busy = true;
        self.message = "Importing subscription…".into();
        self.controller = None;
        self.runtime.spawn(async move {
            let result = async {
                let count = manager.import(&input).await?;
                Self::read_data(
                    manager,
                    rust_i18n::t!("Imported %{count} nodes", count = count).to_string(),
                )
                .await
            }
            .await;
            let _ = tx.send(result.unwrap_or_else(|e| {
                UiEvent::Error(rust_i18n::t!("Import: %{e}", e = format!("{:#}", e)).to_string())
            }));
        });
    }
    fn set_profiles(&mut self, profiles: Vec<Profile>, groups: Vec<Group>) {
        let archived: HashSet<_> = groups
            .iter()
            .filter(|g| g.archived == Some(true))
            .map(|g| g.id)
            .collect();
        self.rows = profiles
            .into_iter()
            .map(|mut p| {
                p.disabled = Some(
                    p.disabled == Some(true) || p.group.is_some_and(|g| archived.contains(&g)),
                );
                Row::new(p)
            })
            .collect();
        self.groups = groups;
        self.group = None;
        self.total = 0;
        self.done = 0;
        self.scan_ids.clear();
        self.saved_queue = None;
        self.scan_started = None;
        if let Some(saved) = &self.state_cache {
            let (results, queue) = saved.restore(&self.source, &self.fingerprints);
            for row in &mut self.rows {
                if let Some(result) = results.get(&row.profile.id)
                    && row.eligible()
                {
                    row.result = result.clone();
                }
            }
            self.scan_ids = queue;
        }
        self.persist_state();
    }
    fn persist_state(&mut self) {
        if self.source.is_empty() {
            return;
        }
        let mut queue = self.scan_ids.clone();
        if let Some(saved) = &self.saved_queue {
            queue.extend(saved);
        }
        let entries = self
            .rows
            .iter()
            .filter_map(|row| {
                self.fingerprints
                    .get(&row.profile.id)
                    .map(|fingerprint| Entry {
                        fingerprint: fingerprint.clone(),
                        result: row.result.clone(),
                    })
            })
            .collect();
        let snapshot = Arc::new(Snapshot {
            version: 1,
            source: self.source.clone(),
            entries,
            queue,
        });
        if let Some(store) = &self.state_store {
            store.queue(snapshot.clone());
        }
        self.state_cache = Some(snapshot);
    }
    fn visible(&self, r: &Row) -> bool {
        self.group.is_none_or(|g| r.profile.group == Some(g))
            && (!self.only_ok || r.result.verdict.is_working())
            && (self.search_normalized.is_empty()
                || r.search_text.contains(&self.search_normalized))
    }
    fn can_resume(&self) -> bool {
        self.rows.iter().any(|r| r.unfinished(&self.scan_ids))
    }

    fn start(&mut self, resume: bool) {
        self.start_selection(resume, None);
    }
    fn start_selection(&mut self, resume: bool, single: Option<i64>) {
        if self.busy || (resume && !self.can_resume()) {
            return;
        }
        if !self.login_ready {
            self.message = "Sign in to Google before starting a scan".into();
            return;
        }
        let Some(manager) = self.manager() else {
            return;
        };
        if !self.direct && !manager.is_running() {
            self.load();
            self.message = "Starting Throne. Start the scan after profiles load".into();
            return;
        }
        let Some(controller) = self.controller.clone() else {
            self.message = "Load profiles first".into();
            return;
        };
        if !PathBuf::from(self.browser.trim()).is_file() {
            self.message = "Select an installed Chromium-based browser".into();
            return;
        }
        let profiles = select_profiles(&self.rows, &self.scan_ids, resume, single, |row| {
            self.visible(row)
        });
        if profiles.is_empty() {
            self.message = "No eligible nodes to check".into();
            return;
        }
        let selected: HashSet<_> = profiles.iter().map(|p| p.id).collect();
        for r in &mut self.rows {
            if selected.contains(&r.profile.id) {
                r.result = NodeCheckResult::new_pending(
                    r.profile.id,
                    r.profile.name.clone(),
                    r.profile.profile_type.clone(),
                    r.profile.address.clone(),
                );
            }
        }
        self.stop = Arc::new(AtomicBool::new(false));
        self.scanning = true;
        self.busy = true;
        if single.is_some() {
            self.saved_queue = Some(self.scan_ids.clone());
        } else {
            self.saved_queue = None;
        }
        self.scan_ids = selected;
        self.scan_started = Some(std::time::Instant::now());
        self.stopping = false;
        self.total = profiles.len();
        self.done = 0;
        self.errors.clear();
        self.message = "Scanning…".into();
        self.persist_state();
        self.runtime.spawn(TestEngine::run_scan(
            ScanConfig {
                native_runtime: manager.executable().map(|throne_executable| {
                    crate::throne::runtime::RuntimeConfig {
                        database: PathBuf::from(&self.source),
                        throne_executable,
                        data_root: manager.paths.data.clone(),
                        fingerprints: self.fingerprints.clone(),
                    }
                }),
                profiles,
                mode: EngineMode::Throne(controller),
                browser_path: PathBuf::from(self.browser.trim()),
                proxy: self.proxy.clone(),

                node_timeout: Duration::from_secs_f32(self.timeout),
                browser_root: Some(manager.paths.browser.clone()),
                shutdown_flag: if manager.is_running() {
                    Some(manager.closed.clone())
                } else {
                    None
                },
                require_login: true,
            },
            self.stop.clone(),
            self.scan_tx.clone(),
        ));
    }
    fn login(&mut self) {
        let Some(manager) = self.manager() else {
            return;
        };
        if !PathBuf::from(self.browser.trim()).is_file() {
            self.message = "Select an installed browser".into();
            return;
        }
        self.stop = Arc::new(AtomicBool::new(false));
        self.busy = true;
        self.login_open = true;
        self.stopping = false;
        self.login_ready = false;
        self.errors.clear();
        self.message = "Opening browser…".into();
        login::forget_marker(&manager.paths.browser, std::path::Path::new(&self.browser));
        let (commands, receiver) = mpsc::unbounded_channel();
        self.login_commands = Some(commands);
        let (events, mut event_receiver) = mpsc::unbounded_channel();
        let tx = self.tx.clone();
        self.runtime.spawn(async move {
            while let Some(event) = event_receiver.recv().await {
                let _ = tx.send(UiEvent::Login(event));
            }
        });
        self.runtime.spawn(login::run(
            LoginConfig {
                browser: PathBuf::from(self.browser.trim()),
                root: manager.paths.browser.clone(),

                proxy: self.proxy.clone(),
            },
            self.stop.clone(),
            receiver,
            events,
        ));
    }
    fn select_browser(&mut self, path: PathBuf) {
        self.browser = dunce::canonicalize(&path)
            .unwrap_or(path)
            .display()
            .to_string();
        if let Some(manager) = &self.sandbox {
            self.login_ready = login::has_saved_session(
                &manager.paths.browser,
                std::path::Path::new(&self.browser),
            );
            if let Err(error) = std::fs::write(
                manager.paths.browser.join("selected-browser.txt"),
                &self.browser,
            ) {
                self.message =
                    rust_i18n::t!("Could not save browser choice: %{error}", error = error)
                        .to_string();
                return;
            }
        }
        if !self
            .detected_browsers
            .iter()
            .any(|b| BrowserDetector::same_path(&b.path, std::path::Path::new(&self.browser)))
        {
            self.detected_browsers.push(DetectedBrowser {
                name: BrowserDetector::product_name(std::path::Path::new(&self.browser))
                    .unwrap_or_else(|| "Selected browser".into()),
                path: PathBuf::from(&self.browser),
                is_default_candidate: false,
            });
        }
        self.message = if self.login_ready {
            "Browser selected; saved sign-in is available".into()
        } else {
            "Browser selected. Sign in for this browser".into()
        };
    }
    fn copy_config(&mut self, id: i64) {
        if self.copying {
            return;
        }
        let Some(manager) = self.manager() else {
            return;
        };
        let database = manager
            .direct_database()
            .unwrap_or_else(|| manager.paths.database.clone());
        self.copying = true;
        self.message = "Reading configuration…".into();
        let tx = self.tx.clone();
        self.runtime.spawn_blocking(move || {
            let result = ThroneDb::new(database)
                .native_config(id)
                .map_err(|e| rust_i18n::t!("Copy: %{e}", e = format!("{:#}", e)).to_string());
            let _ = tx.send(UiEvent::Copied(result));
        });
    }

    fn apply(&mut self) {
        let Some(manager) = self.manager() else {
            return;
        };
        let results: Vec<_> = self.rows.iter().map(|r| r.result.clone()).collect();
        let tx = self.tx.clone();
        self.busy = true;
        self.message = "Stopping Throne, backing up and applying results…".into();
        self.controller = None;
        self.runtime.spawn(async move {
            let m = manager.clone();
            let result = async {
                let s = tokio::task::spawn_blocking(move || m.apply(&results)).await??;
                let notice = rust_i18n::t!(
                    "Applied: %{a0} available, %{a1} archived, %{a2} skipped. Backup: %{a3}",
                    a0 = s.ok,
                    a1 = s.blocked,
                    a2 = s.skipped,
                    a3 = s.backup.display()
                )
                .to_string();
                Self::read_data(manager, notice).await
            }
            .await;
            let _ = tx.send(result.unwrap_or_else(|e| {
                UiEvent::Error(rust_i18n::t!("Apply: %{e}", e = format!("{:#}", e)).to_string())
            }));
        });
    }
    fn stop_core(&mut self) {
        if let Some(s) = &self.sandbox {
            s.stop();
        }
        self.running = false;
        self.controller = None;
        self.message = "Managed Throne stopped. Your personal VPN was not changed".into();
    }
    #[cfg(windows)]
    fn toggle_throne_window(&mut self, visible: bool) {
        let Some(manager) = self.sandbox.clone() else {
            return;
        };
        self.window_busy = true;
        let tx = self.tx.clone();
        self.runtime.spawn(async move {
            let result = tokio::task::spawn_blocking(move || manager.set_window_visible(visible))
                .await
                .map_err(|e| e.to_string())
                .and_then(|result| result.map_err(|e| format!("{e:#}")));
            let _ = tx.send(UiEvent::ThroneWindow(result));
        });
    }
    fn export(&mut self) {
        let mut dialog = rfd::FileDialog::new()
            .set_file_name("google-ai-results.json")
            .add_filter("JSON", &["json"]);
        if let Some(s) = &self.sandbox {
            dialog = dialog.set_directory(&s.paths.data);
        }
        if let Some(path) = dialog.save_file() {
            let results: Vec<_> = self
                .rows
                .iter()
                .filter(|r| r.result.verdict.is_final())
                .map(|r| r.result.clone())
                .collect();
            let proxy = self.proxy.clone();
            let mode = if self.direct {
                "source_database"
            } else {
                "standalone_sandbox"
            };
            self.exporting = true;
            self.message = "Saving results…".into();
            let tx = self.tx.clone();
            self.runtime.spawn_blocking(move || {
                let result = (|| -> anyhow::Result<PathBuf> {
                    let data = serde_json::json!({"schema_version":3,"service":"Google AI Studio","mode":mode,"proxy":proxy,"exported_at":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),"results":results});
                    let mut file = tempfile::NamedTempFile::new_in(path.parent().ok_or_else(|| anyhow::anyhow!("No export directory selected"))?)?;
                    serde_json::to_writer_pretty(&mut file, &data)?;
                    file.as_file().sync_all()?;
                    file.persist(&path)?;
                    Ok(path)
                })().map_err(|e| rust_i18n::t!("Export: %{e}", e = format!("{:#}", e)).to_string());
                let _ = tx.send(UiEvent::Exported(result));
            });
        }
    }

    fn events(&mut self, ctx: &egui::Context) {
        if let Some(error) = self.state_store.as_ref().and_then(StateStore::take_error) {
            self.message =
                rust_i18n::t!("Could not save results: %{error}", error = error).to_string();
        }
        while let Ok(e) = self.rx.try_recv() {
            match e {
                #[cfg(windows)]
                UiEvent::ThroneWindow(result) => {
                    self.window_busy = false;
                    if let Err(error) = result {
                        self.message = error;
                    }
                    ctx.request_repaint();
                }
                UiEvent::Copied(result) => {
                    self.copying = false;
                    match result {
                        Ok(config) => {
                            ctx.copy_text(config);
                            self.message = "Original JSON copied".into();
                        }
                        Err(error) => self.message = error,
                    }
                }
                UiEvent::Exported(result) => {
                    self.exporting = false;
                    self.message = match result {
                        Ok(path) => rust_i18n::t!("Saved: %{a0}", a0 = path.display()).to_string(),
                        Err(error) => error,
                    };
                }
                UiEvent::Login(event) => match event {
                    LoginEvent::Opened { browser } => {
                        self.browser = browser.display().to_string();
                        self.message = "Sign in using the browser, then click Done".into();
                    }
                    LoginEvent::Notice(message) => self.message = message,
                    LoginEvent::Finished { ready, message } => {
                        self.stopping = false;
                        self.login_ready = ready;
                        self.login_open = false;
                        self.login_commands = None;
                        self.busy = false;
                        self.message = message;
                    }
                },
                UiEvent::Error(message) => {
                    self.busy = false;
                    self.message = message;
                    self.running = self.sandbox.as_ref().is_some_and(|s| s.is_running());
                    if !self.running {
                        self.controller = None;
                    }
                }
                UiEvent::Data {
                    profiles,
                    groups,
                    fingerprints,
                    source,
                    status,
                    controller,
                    proxy,
                    direct,
                    notice,
                } => {
                    self.busy = false;
                    self.running = !direct || status.state != "offline";
                    self.direct = direct;
                    self.proxy = proxy;
                    self.controller = Some(controller);
                    self.release = status.version.clone().unwrap_or_default();
                    self.fingerprints = fingerprints;
                    self.source = source;
                    self.set_profiles(profiles, groups);
                    let restored = self
                        .rows
                        .iter()
                        .filter(|row| row.result.verdict.is_final())
                        .count();
                    self.message = if notice.is_empty() {
                        rust_i18n::t!(
                            "Throne %{a0}: %{a1} profiles; %{a2}",
                            a0 = self.release,
                            a1 = self.rows.len(),
                            a2 = status.state
                        )
                        .to_string()
                    } else {
                        notice
                    };
                    if restored > 0 {
                        self.message.push_str(" · ");
                        self.message.push_str(&rust_i18n::t!(
                            "Restored results: %{count}",
                            count = restored
                        ));
                    }
                }
            }
        }
        let mut save_results = false;
        while let Ok(e) = self.scan_rx.try_recv() {
            match e {
                EngineEvent::LoginExpired => {
                    self.login_ready = false;
                    if let Some(manager) = &self.sandbox {
                        login::forget_marker(
                            &manager.paths.browser,
                            std::path::Path::new(&self.browser),
                        );
                    }
                }
                EngineEvent::Started { total } => {
                    self.total = total;
                }
                EngineEvent::BrowserSelected { path } => {
                    self.browser = path.display().to_string();
                }
                EngineEvent::NodeTesting { profile_id } => {
                    if let Some(r) = self.rows.iter_mut().find(|r| r.profile.id == profile_id) {
                        r.result.verdict = AiVerdict::Testing;
                    }
                }
                EngineEvent::NodeActivated { profile_id } => {
                    for r in &mut self.rows {
                        r.profile.running = Some(r.profile.id == profile_id);
                    }
                }
                EngineEvent::ConnectionRestored { profile_id } => {
                    for r in &mut self.rows {
                        r.profile.running = Some(Some(r.profile.id) == profile_id);
                    }
                }
                EngineEvent::NodeFinished { result } => {
                    if let Some(r) = self
                        .rows
                        .iter_mut()
                        .find(|r| r.profile.id == result.profile_id)
                    {
                        r.result = result;
                    }
                    self.done += 1;
                    save_results = true;
                }
                EngineEvent::Error { message } => {
                    self.errors.push(message);
                }
                EngineEvent::Finished { cancelled } => {
                    self.busy = false;
                    self.scanning = false;
                    self.stopping = false;
                    if let Some(queue) = self.saved_queue.take() {
                        self.scan_ids = queue;
                    }
                    for r in &mut self.rows {
                        if r.result.verdict == AiVerdict::Testing {
                            r.result.verdict = AiVerdict::Pending;
                        }
                    }
                    self.message = if cancelled {
                        rust_i18n::t!("Scan stopped: %{a0}/%{a1}", a0 = self.done, a1 = self.total)
                            .to_string()
                    } else {
                        rust_i18n::t!("Scan finished: %{a0} nodes", a0 = self.done).to_string()
                    };
                    save_results = true;
                }
            }
        }
        if save_results {
            self.persist_state();
        }
        if !self.direct
            && !self.busy
            && self.running
            && !self.sandbox.as_ref().is_some_and(|s| s.is_running())
        {
            self.running = false;
            self.controller = None;
            self.message = "Throne exited. Refresh to start it again".into();
        }
    }
}
impl eframe::App for CheckerApp {
    fn clear_color(&self, visuals: &egui::Visuals) -> [f32; 4] {
        // Cleared frames match the opaque panel background, including resize
        // and restore frames before the UI has filled the whole surface.
        egui::Rgba::from(visuals.panel_fill).to_array()
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        #[cfg(feature = "qa-screenshot")]
        if let Ok(path) = std::env::var("GOOGLEAI_CHECKER_SCREENSHOT_TO") {
            self.qa_frame += 1;
            ctx.request_repaint();
            if self.qa_frame == 60 {
                ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot);
            }
            for event in ctx.input(|i| i.events.clone()) {
                if let egui::Event::Screenshot { image, .. } = event {
                    let rgba: Vec<u8> = image.pixels.iter().flat_map(|p| p.to_array()).collect();
                    image::save_buffer(
                        path.clone(),
                        &rgba,
                        image.width() as u32,
                        image.height() as u32,
                        image::ColorType::Rgba8,
                    )
                    .expect("GUI screenshot");
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }
        if self
            .smoke_deadline
            .is_some_and(|d| std::time::Instant::now() >= d)
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        self.events(ctx);
        if ctx.input(|i| i.viewport().close_requested()) {
            self.persist_state();
            self.stop.store(true, Ordering::SeqCst);
            if let Some(s) = &self.sandbox {
                s.shutdown();
            }
            self.running = false;
            self.closing = true;
            if self.busy {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.message =
                    rust_i18n::t!("Throne stopped. Closing browser and background tasks…")
                        .to_string();
            }
        }
        if self.closing && !self.busy {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        ctx.request_repaint_after(Duration::from_millis(
            if self.busy || self.copying || self.exporting {
                250
            } else {
                1000
            },
        ));
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.add_space(10.0);
            ui.heading("Google AI Checker");
            ui.add_space(6.0);
            if !self
                .sandbox
                .as_ref()
                .is_some_and(|s| s.executable().is_some())
            {
                ui.label(tr(
                    "Throne is missing from ./bin/. Extract the complete release bundle.",
                ));
            }
        });
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.add_space(5.0);
            ui.label(tr(&self.message).chars().take(140).collect::<String>())
                .on_hover_text(tr(&self.message));
            egui::ScrollArea::vertical()
                .max_height(90.0)
                .show(ui, |ui| {
                    for e in &self.errors {
                        ui.colored_label(
                            Color32::from_rgb(248, 113, 113),
                            tr(e).chars().take(140).collect::<String>(),
                        )
                        .on_hover_text(tr(e));
                    }
                });
            ui.add_space(5.0);
        });
        egui::SidePanel::left("settings")
            .resizable(true)
            .default_width(225.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.small(tr("Language"));
                    let previous_language = self.language;
                    egui::ComboBox::from_id_salt("language")
                        .selected_text(self.language.name())
                        .width(ui.available_width())
                        .show_ui(ui, |ui| {
                            for language in Language::ALL {
                                ui.selectable_value(&mut self.language, language, language.name());
                            }
                        });
                    if previous_language != self.language {
                        rust_i18n::set_locale(self.language.code());
                        i18n::install_fonts(ctx);
                        if let Some(manager) = &self.sandbox
                            && let Err(error) = self.language.save(&manager.paths.data) {
                                self.message = error.to_string();
                            }
                    }
                    ui.separator();
                    ui.heading(tr("Database"));
                    ui.colored_label(
                        if self.running {
                            Color32::LIGHT_GREEN
                        } else {
                            Color32::GRAY
                        },
                        if self.running {
                            tr("Connected")
                        } else {
                            tr("Disconnected")
                        },
                    );
                    #[cfg(windows)]
                    {
                        let managed = self.sandbox.as_ref().is_some_and(|s| s.is_running());
                        let visible = self.sandbox.as_ref()
                            .and_then(|s| s.window_visible().ok()).unwrap_or(false);
                        if ui.add_enabled(managed && !self.window_busy && !self.closing,
                            egui::Button::new(if visible { tr("Hide Throne window") } else { tr("Open Throne") }))
                            .on_hover_text(tr("Show or hide the window without stopping the scan"))
                            .clicked()
                        {
                            self.toggle_throne_window(!visible);
                        }
                    }
                    ui.add_enabled_ui(!self.busy && self.sandbox.is_some(), |ui| {
                        ui.horizontal(|ui| {
                            if ui.button(tr("Refresh")).on_hover_text(tr("Reload profiles; unchanged configurations keep their results")).clicked() {
                                self.load();
                            }
                            if ui.button(tr("Browse…")).clicked()
                                && let Some(path) = rfd::FileDialog::new()
                                    .add_filter(tr("Throne database"), &["db"])
                                    .pick_file()
                                    && let Some(manager) = &self.sandbox {
                                        manager.stop();
                                        match std::fs::write(
                                            manager.paths.data.join("throne-source.txt"),
                                            path.to_string_lossy().as_bytes(),
                                        ) {
                                            Ok(()) => self.load(),
                                            Err(e) => self.message = e.to_string(),
                                        }
                                    }
                        });
                        if let Some(path) = self.sandbox.as_ref().and_then(|s| s.direct_database())
                        {
                            ui.small(path.file_name().unwrap_or_default().to_string_lossy())
                                .on_hover_text(path.display().to_string());
                        }
                        ui.separator();
                        ui.heading(tr("Browser"));
                        let mut chosen_browser = None;
                        egui::ComboBox::from_id_salt("detected-browser")
                            .width(ui.available_width())
                            .selected_text(
                                self.detected_browsers
                                    .iter()
                                    .find(|b| {
                                        BrowserDetector::same_path(
                                            &b.path,
                                            std::path::Path::new(&self.browser),
                                        )
                                    })
                                    .map(|b| b.name.clone())
                                    .unwrap_or_else(|| {
                                        BrowserDetector::product_name(std::path::Path::new(
                                            &self.browser,
                                        ))
                                        .unwrap_or_else(|| tr("Select a browser"))
                                    }),
                            )
                            .show_ui(ui, |ui| {
                                for browser in &self.detected_browsers {
                                    if ui
                                        .selectable_label(
                                            BrowserDetector::same_path(
                                                &browser.path,
                                                std::path::Path::new(&self.browser),
                                            ),
                                            &browser.name,
                                        )
                                        .on_hover_text(browser.path.display().to_string())
                                        .clicked()
                                    {
                                        chosen_browser = Some(browser.path.clone());
                                    }
                                }
                            });
                        ui.horizontal(|ui| {
                            if ui
                                .small_button("↻")
                                .on_hover_text(tr("Refresh browsers"))
                                .clicked()
                            {
                                self.detected_browsers = BrowserDetector::detect_all();
                            }
                            if ui
                                .small_button("…")
                                .on_hover_text(tr("Browse for browser"))
                                .clicked()
                                && let Some(path) = rfd::FileDialog::new().pick_file() {
                                    chosen_browser = Some(path);
                                }
                        });
                        if let Some(path) = chosen_browser {
                            self.select_browser(path);
                        }
                        ui.separator();
                        ui.heading("Google");
                        ui.colored_label(
                            if self.login_ready {
                                Color32::LIGHT_GREEN
                            } else {
                                Color32::YELLOW
                            },
                            if self.login_ready {
                                tr("Signed in")
                            } else {
                                tr("Not signed in")
                            },
                        );
                        ui.separator();
                        ui.heading(tr("Scan"));
                        ui.add(egui::Slider::new(&mut self.timeout, 3.0..=12.0).text(tr("Timeout, s"))).on_hover_text(tr("In list order: finish each node before the next. Single check: selected limit; batch: up to 4 s per node."));
                        ui.add_space(10.0);
                        egui::CollapsingHeader::new(tr("Advanced")).show(ui, |ui| {
                            if ui
                                .add_enabled(
                                    self.running
                                        && self.sandbox.as_ref().is_some_and(|s| s.is_running()),
                                    egui::Button::new(tr("Stop Throne")),
                                )
                                .clicked()
                            {
                                self.stop_core();
                            }
                            if !self.direct {
                                ui.add(
                                    egui::TextEdit::multiline(&mut self.subscription)
                                        .desired_rows(3)
                                        .hint_text(tr("Subscription URL or configs")),
                                );
                                if ui.button(tr("Import")).clicked() {
                                    self.import();
                                }
                                let applicable = self.rows.iter().any(|r| {
                                    matches!(
                                        r.result.verdict,
                                        AiVerdict::Unlocked | AiVerdict::Geoblock
                                    )
                                });
                                if ui
                                    .add_enabled(
                                        applicable,
                                        egui::Button::new(tr("Apply results")),
                                    )
                                    .clicked()
                                {
                                    self.apply();
                                }
                            }
                        });
                    });
                });
            });
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_enabled_ui(!self.busy, |ui| {
                ui.horizontal_wrapped(|ui| {
                    egui::ComboBox::from_id_salt("group")
                        .selected_text(
                            self.group
                                .and_then(|id| {
                                    self.groups
                                        .iter()
                                        .find(|g| g.id == id)
                                        .map(|g| g.name.clone())
                                })
                                .unwrap_or(tr("All groups")),
                        )
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.group, None, tr("All groups"));
                            for g in &self.groups {
                                if g.archived != Some(true) {
                                    ui.selectable_value(
                                        &mut self.group,
                                        Some(g.id),
                                        format!("{} ({})", g.name, g.profile_count.unwrap_or(0)),
                                    );
                                }
                            }
                        });
                    if ui
                        .add(
                            egui::TextEdit::singleline(&mut self.search)
                                .hint_text(tr("Search nodes / protocols"))
                                .desired_width(190.0),
                        )
                        .changed()
                    {
                        self.search_normalized = self.search.trim().to_lowercase();
                    }
                    if !self.search.is_empty() && ui.small_button(tr("Clear")).clicked()
                    {
                        self.search.clear();
                        self.search_normalized.clear();
                    }
                    ui.checkbox(&mut self.only_ok, tr("Available only"));
                });
            });
            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(
                        !self.busy && PathBuf::from(self.browser.trim()).is_file(),
                        egui::Button::new(if self.login_ready {
                            tr("Sign in again")
                        } else {
                            tr("Sign in")
                        }),
                    )
                    .clicked()
                {
                    self.login();
                }
                if self.login_open && ui.button(tr("Done")).clicked()
                    && let Some(commands) = &self.login_commands {
                        let _ = commands.send(LoginCommand::Finish);
                        self.message = rust_i18n::t!("Checking and saving sign-in…").to_string();
                    }
                if ui
                    .add_enabled(
                        !self.busy
                            && self.login_ready
                            && self.controller.is_some()
                            && !self.rows.is_empty(),
                        egui::Button::new(tr("Start")).fill(Color32::from_rgb(37, 99, 235)),
                    )
                    .clicked()
                {
                    self.start(false);
                }
                if ui
                    .add_enabled(
                        !self.busy
                            && self.login_ready
                            && self.controller.is_some()
                            && self.can_resume(),
                        egui::Button::new(tr("Continue")),
                    )
                    .on_hover_text(tr("Check the remaining nodes in the paused queue"))
                    .clicked()
                {
                    self.start(true);
                }
                if ui
                    .add_enabled(
                        (self.scanning || self.login_open) && !self.stopping,
                        egui::Button::new(if self.stopping {
                            tr("Stopping…")
                        } else {
                            tr("■ Stop")
                        })
                        .fill(Color32::from_rgb(185, 28, 28)),
                    )
                    .clicked()
                {
                    self.stop.store(true, Ordering::SeqCst);
                    self.stopping = true;
                    self.message = rust_i18n::t!("Stopping the scan…").to_string();
                }
                if ui
                    .add_enabled(
                        !self.busy
                            && !self.exporting
                            && self.rows.iter().any(|r| r.result.verdict.is_final()),
                        egui::Button::new(if self.exporting {
                            tr("Saving…")
                        } else {
                            tr("Export")
                        }),
                    )
                    .clicked()
                {
                    self.export();
                }
            });
            if self.total > 0 {
                ui.add(
                    egui::ProgressBar::new(self.done as f32 / self.total as f32)
                        .text(format!("{} / {}", self.done, self.total)),
                );
            }
            if self.scanning
                && let Some(started) = self.scan_started {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(i18n::display(
                            rust_i18n::t!("Elapsed: %{a0} s", a0 = started.elapsed().as_secs())
                                .as_ref(),
                        ));
                        if self.done > 0 && !self.stopping {
                            let remaining = started.elapsed().as_secs_f64() / self.done as f64
                                * self.total.saturating_sub(self.done) as f64;
                            ui.label(i18n::display(
                                rust_i18n::t!(
                                    "About %{a0} s remaining",
                                    a0 = format!("{:.0}", remaining)
                                )
                                .as_ref(),
                            ));
                        }
                    });
                }
            let visible: Vec<_> = self.rows.iter().filter(|r| self.visible(r)).collect();
            let mut copy_id = None;
            let mut retry_id = None;
            ui.add_space(8.0);
            ui.label(i18n::display(
                rust_i18n::t!(
                    "Nodes: %{a0}   Available: %{a1}   AI unavailable: %{a2}",
                    a0 = visible.len(),
                    a1 = visible
                        .iter()
                        .filter(|r| r.result.verdict.is_working())
                        .count(),
                    a2 = visible
                        .iter()
                        .filter(|r| r.result.verdict.summary_label() == Some("AI unavailable"))
                        .count()
                )
                .as_ref(),
            ));
            if visible.is_empty() {
                ui.add_space(24.0);
                ui.label(if self.rows.is_empty() {
                    tr("Select a Throne database or import a subscription to load nodes")
                } else {
                    tr("No matching nodes. Change the group or search filters")
                });
            }
            TableBuilder::new(ui)
                .id_salt("profiles-full-width-v2")
                .auto_shrink([false, false])
                .striped(true)
                .resizable(true)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::initial(270.0).at_least(150.0).clip(true))
                .column(Column::initial(92.0))
                .column(Column::initial(80.0))
                .column(Column::initial(145.0))
                .column(Column::initial(80.0))
                .column(Column::remainder().at_least(125.0))
                .header(30.0, |mut h| {
                    for name in [
                        tr("Name"),
                        tr("Protocol"),
                        "Throne".to_string(),
                        tr("AI Studio access"),
                        tr("Latency"),
                        tr("Actions"),
                    ] {
                        h.col(|ui| {
                            ui.strong(name);
                        });
                    }
                })
                .body(|body| {
                    body.rows(34.0, visible.len(), |mut row| {
                        let r = visible[row.index()];
                        row.col(|ui| {
                            self.flags.label(ui,&r.profile.name)
                                .on_hover_text(&r.profile.address)
                                .context_menu(|ui| {
                                    if ui.button(tr("Copy the original configuration JSON")).clicked()
                                    {
                                        copy_id = Some(r.profile.id);
                                        ui.close_menu();
                                    }
                                });
                        });
                        row.col(|ui| {
                            badge(
                                ui,
                                if r.profile.profile_type == "xrayvless" {
                                    "VLESS · Xray"
                                } else {
                                    &r.profile.profile_type
                                },
                                protocol_badge_colors(&r.profile.profile_type),
                            );
                        });
                        row.col(|ui| {
                            ui.label(if r.profile.disabled == Some(true) {
                                tr("Archived")
                            } else if r.profile.running == Some(true) {
                                tr("Active")
                            } else {
                                tr("Saved")
                            })
                            .on_hover_text(tr(
                                "The profile is saved in Throne. AI Studio access is shown separately.",
                            ));
                        });
                        row.col(|ui| {
                            verdict_cell(ui, &r.result);
                        });
                        row.col(|ui| {
                            let latency = r.result.verdict.is_working().then_some(r.result.latency_ms).flatten();
                            ui.colored_label(
                                latency_color(latency),
                                latency
                                    .map(|v| {
                                        i18n::display(rust_i18n::t!("%{v} ms", v = v).as_ref())
                                    })
                                    .unwrap_or("—".into()),
                            ).on_hover_text(tr("AI Studio HTTPS response time through this node, including SOCKS and TLS; not ICMP ping"));
                        });
                        row.col(|ui| {
                            ui.horizontal(|ui| {
                                let copy = egui::Button::new(tr("Copy"))
                                    .min_size(egui::vec2(76.0, 26.0))
                                    .rounding(6.0)
                                    .fill(Color32::from_rgb(40, 58, 82))
                                    .stroke(egui::Stroke::new(
                                        1.0_f32,
                                        Color32::from_rgb(70, 94, 126),
                                    ));
                                if ui
                                    .add_enabled(!self.copying, copy)
                                    .on_hover_text(tr("Copy the original configuration JSON"))
                                    .clicked()
                                {
                                    copy_id = Some(r.profile.id);
                                }
                                if ui
                                    .add_enabled(
                                        !self.busy
                                            && self.login_ready
                                            && self.controller.is_some()
                                            && r.eligible(),
                                        egui::Button::new("↻")
                                            .min_size(egui::vec2(30.0, 26.0))
                                            .rounding(6.0),
                                    )
                                    .on_hover_text(tr("Recheck this node only"))
                                    .clicked()
                                {
                                    retry_id = Some(r.profile.id);
                                }
                            });
                        });
                    });
                });
            if let Some(id) = copy_id {
                self.copy_config(id);
            }
            if let Some(id) = retry_id {
                self.start_selection(false, Some(id));
            }
        });
    }
}
impl Drop for CheckerApp {
    fn drop(&mut self) {
        self.persist_state();
        self.stop.store(true, Ordering::SeqCst);
        if let Some(s) = &self.sandbox {
            s.shutdown();
        }
    }
}
fn select_profiles(
    rows: &[Row],
    queue: &HashSet<i64>,
    resume: bool,
    single: Option<i64>,
    visible: impl Fn(&Row) -> bool,
) -> Vec<Profile> {
    rows.iter()
        .filter(|row| {
            row.eligible()
                && match single {
                    Some(id) => row.profile.id == id,
                    None if resume => row.unfinished(queue),
                    None => visible(row),
                }
        })
        .map(|row| row.profile.clone())
        .collect()
}
fn last_checked(checked_at: Option<u64>) -> String {
    let Some(at) = checked_at else {
        return tr("Not checked yet");
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let elapsed = now.saturating_sub(at);
    let (key, count) = if elapsed < 60 {
        ("Checked %{count} s ago", elapsed)
    } else if elapsed < 3600 {
        ("Checked %{count} min ago", elapsed / 60)
    } else if elapsed < 86400 {
        ("Checked %{count} h ago", elapsed / 3600)
    } else {
        ("Checked %{count} days ago", elapsed / 86400)
    };
    i18n::display(&rust_i18n::t!(key, count = count))
}
fn badge(ui: &mut egui::Ui, text: &str, colors: (Color32, Color32)) -> egui::Response {
    egui::Frame::none()
        .fill(colors.0)
        .rounding(4.0)
        .inner_margin(egui::Margin::symmetric(6.0, 3.0))
        .show(ui, |ui| {
            ui.label(RichText::new(text).color(colors.1));
        })
        .response
}

fn verdict_cell(ui: &mut egui::Ui, result: &NodeCheckResult) -> egui::Response {
    if result.verdict == AiVerdict::Pending {
        return ui.label("");
    }
    if result.verdict == AiVerdict::Testing {
        return activity_spinner(ui);
    }
    let response = if let Some(label) = result.verdict.summary_label() {
        badge(ui, &tr(label), result.verdict.badge_colors())
    } else {
        ui.weak("—")
    };
    let reason = tr(result.verdict.badge_label());
    let timing = result.timings.as_ref().map(|t| i18n::display(&rust_i18n::t!(
        "Setup %{setup} ms · Throne %{throne} ms · Google %{google} ms · Cleanup %{cleanup} ms",
        setup=t.setup_ms,throne=t.throne_ms,
        google=t.google_ms.map(|ms|ms.to_string()).unwrap_or_else(||"—".into()),cleanup=t.cleanup_ms,
    ))).unwrap_or_default();
    response.on_hover_text(format!(
        "Google AI Studio\n{}\n{}\n{}\n{}\n{}",
        reason,
        last_checked(result.checked_at),
        tr(&result.details),
        result.final_url.as_deref().unwrap_or(""),
        timing
    ))
}
fn activity_spinner(ui: &mut egui::Ui) -> egui::Response {
    const FRAME_INTERVAL: Duration = Duration::from_millis(80);
    let (rect, response) = ui.allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::hover());
    response.widget_info(|| egui::WidgetInfo::new(egui::WidgetType::ProgressIndicator));
    if ui.is_rect_visible(rect) {
        ui.ctx().request_repaint_after(FRAME_INTERVAL);
        let phase = ui.input(|i| i.time) as f32 * std::f32::consts::TAU;
        let points = (0..20)
            .map(|step| {
                let angle = phase + step as f32 / 19.0 * std::f32::consts::TAU * 0.7;
                rect.center() + egui::vec2(angle.cos(), angle.sin()) * 6.0
            })
            .collect();
        ui.painter().add(egui::Shape::line(
            points,
            egui::Stroke::new(2.0_f32, ui.visuals().strong_text_color()),
        ));
    }
    response
}

#[cfg(test)]
mod ui_logic_tests {
    use super::*;

    fn row(id: i64, verdict: AiVerdict) -> Row {
        let mut row = Row::new(Profile {
            id,
            name: "Москва 🇷🇺".into(),
            address: "EXAMPLE.com".into(),
            profile_type: "vless".into(),
            ..Default::default()
        });
        row.result.verdict = verdict;
        row
    }

    #[test]
    fn resume_keeps_original_queue_and_skips_completed_results() {
        let ids = HashSet::from([1, 2, 3]);
        let rows = [
            row(1, AiVerdict::Unlocked),
            row(2, AiVerdict::Pending),
            row(3, AiVerdict::Timeout),
            row(4, AiVerdict::Pending),
        ];
        let remaining: Vec<_> = rows
            .iter()
            .filter(|r| r.unfinished(&ids))
            .map(|r| r.profile.id)
            .collect();
        assert_eq!(remaining, vec![2]);
    }
    #[test]
    fn single_node_recheck_ignores_filters_and_preserves_other_results() {
        let mut rows = vec![
            row(1, AiVerdict::Unlocked),
            row(2, AiVerdict::Timeout),
            row(3, AiVerdict::Pending),
            row(4, AiVerdict::Pending),
        ];
        rows[3].profile.disabled = Some(true);
        let queue = HashSet::from([1, 3, 4]);
        let selected = select_profiles(&rows, &queue, false, Some(2), |_| false);
        assert_eq!(selected.iter().map(|p| p.id).collect::<Vec<_>>(), vec![2]);
        let selected_ids: HashSet<_> = selected.iter().map(|p| p.id).collect();
        for row in &mut rows {
            if selected_ids.contains(&row.profile.id) {
                row.result = NodeCheckResult::new_pending(
                    row.profile.id,
                    row.profile.name.clone(),
                    row.profile.profile_type.clone(),
                    row.profile.address.clone(),
                );
            }
        }
        assert_eq!(rows[0].result.verdict, AiVerdict::Unlocked);
        assert_eq!(rows[1].result.verdict, AiVerdict::Pending);
        assert_eq!(
            select_profiles(&rows, &queue, true, None, |_| false)
                .iter()
                .map(|p| p.id)
                .collect::<Vec<_>>(),
            vec![3]
        );
        assert!(select_profiles(&rows, &queue, false, Some(4), |_| true).is_empty());
    }

    #[test]
    fn resume_excludes_archived_and_non_node_profiles() {
        let ids = HashSet::from([1]);
        let mut r = row(1, AiVerdict::Pending);
        r.profile.disabled = Some(true);
        assert!(!r.unfinished(&ids));
        r.profile.disabled = Some(false);
        for protocol in ["autoselector", "direct", "chain"] {
            r.profile.profile_type = protocol.into();
            assert!(!r.unfinished(&ids));
        }
    }

    #[test]
    fn indexed_search_handles_unicode_address_and_protocol() {
        let r = row(1, AiVerdict::Pending);
        for query in ["МОСКВА", "Example.COM", "VLESS", "🇷🇺"] {
            assert!(r.search_text.contains(&query.to_lowercase()));
        }
        assert!(!r.search_text.contains("unknown"));
    }
}
