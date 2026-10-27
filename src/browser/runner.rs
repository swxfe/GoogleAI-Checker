use super::cdp::{Cdp, Page};
use crate::checker::verdicts::{AI_STUDIO_URL, AiVerdict};
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio::time::timeout;

pub type Observation = (AiVerdict, String, Option<u64>, Option<String>);
fn regional_rejection(text: &str) -> bool {
    text.contains("user location is not supported")
        || text.contains("region not supported")
        || text.contains("available-regions")
        || text.contains("not available in your country")
        || text.contains("isn't supported in your country")
        || text.contains("недоступен в вашей стране")
}
pub(super) fn rpc_observation(reply: &super::rpc::Reply) -> Observation {
    let text = reply.body.to_ascii_lowercase();
    let (verdict, detail) = if reply.status == 429 {
        (
            AiVerdict::RateLimited,
            "Google temporarily rate-limited requests",
        )
    } else if text.contains("our systems have detected unusual traffic")
        || text.contains("/sorry/index")
    {
        (
            AiVerdict::GoogleChallenge,
            "Google requested traffic verification / CAPTCHA",
        )
    } else if reply.status == 403 && regional_rejection(&text) {
        (
            AiVerdict::Geoblock,
            "ListModels: Google regional rejection (HTTP 403)",
        )
    } else if reply.status == 200 && super::rpc::model_list(&reply.body) {
        (
            AiVerdict::Unlocked,
            "ListModels returned a successful JSON response",
        )
    } else if reply.error.as_deref() == Some("timeout") {
        (AiVerdict::Timeout, "The AI Studio request timed out")
    } else if let Some(error) = reply.network_error.as_ref().filter(|error| {
        !matches!(
            error.as_str(),
            "net::ERR_FAILED"
                | "net::ERR_ABORTED"
                | "net::ERR_BLOCKED_BY_CLIENT"
                | "net::ERR_BLOCKED_BY_RESPONSE"
        )
    }) {
        return (
            AiVerdict::ConnectionError,
            error.clone(),
            None,
            Some(AI_STUDIO_URL.into()),
        );
    } else if reply.status >= 500 {
        (
            AiVerdict::Inconclusive,
            "AI Studio is temporarily unavailable; the node is not marked faulty",
        )
    } else {
        (
            AiVerdict::Inconclusive,
            "The AI Studio request did not confirm access",
        )
    };
    (
        verdict,
        detail.into(),
        (reply.status > 0).then_some(reply.elapsed_ms),
        Some(AI_STUDIO_URL.into()),
    )
}
fn transient_context_error(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("cannot find context with specified id")
        || message.contains("execution context was destroyed")
        || message.contains("cannot find default execution context")
}
pub fn account_profile(root: &Path, path: &Path) -> Result<PathBuf> {
    use sha2::{Digest, Sha256};
    let hash = format!(
        "{:x}",
        Sha256::digest(dunce::canonicalize(path)?.to_string_lossy().as_bytes())
    );
    Ok(root.join("google_account").join(&hash[..12]))
}
const OBSERVER: &str = r#"(() => {
 const s = window.__aiCheck = {rpcOk:false, denied:false, authLost:false, rpcMs:null, rpcSeen:false, rpcStatus:null, rpcRejected:false};
 const inspect = (url, status, body, ms) => {
   if (!/listmodels/i.test(url)) return;
   s.rpcSeen=true; s.rpcStatus=status;
   if (status===401) {s.authLost=true; return;}
   if (/user location is not supported|region not supported|available-regions|not available in your country|isn't supported in your country/i.test(body)) s.denied=true;
   if (status===403 || /permission.denied/i.test(body)) s.rpcRejected=true;
   try {
     const json=JSON.parse(body.replace(/^\)\]\}'\s*/, ''));
     // AI Studio also uses protobuf's positional JSON encoding for model lists.
     const named=Array.isArray(json?.models) && json.models.some(m=>typeof m?.name==='string' && m.name.length>0);
     const positional=Array.isArray(json?.[0]) && json[0].some(m=>Array.isArray(m) && typeof m[0]==='string' && m[0].length>0);
     if (status>=200 && status<300 && !s.denied && !json?.error && (named || positional)) {
       s.rpcOk=true; s.rpcMs=Math.round(ms);
     }
   } catch (_) {}
 };
 const fetch0=window.fetch;
 window.fetch=async function(...args) {
   try {
     const raw=typeof args[0]==='string'?args[0]:args[0]?.url || String(args[0] || '');
     if (/listmodels/i.test(raw)) {
       const request=new Request(args[0] instanceof Request?args[0].clone():args[0],args[1]);
       const captured={url:request.url,method:request.method,headers:Object.fromEntries(request.headers),body:''};
       request.clone().text().then(body=>{captured.body=body;window.__aiRequest=captured}).catch(()=>{});
     }
   } catch (_) {}
   const start=performance.now(), r=await fetch0.apply(this,args);
   const u=typeof args[0]==='string'?args[0]:args[0]?.url || String(args[0] || '');
   if (/listmodels/i.test(u)) r.clone().text().then(b=>inspect(u,r.status,b,performance.now()-start)).catch(()=>{});
   return r;
 };
 const open0=XMLHttpRequest.prototype.open, send0=XMLHttpRequest.prototype.send;
 const header0=XMLHttpRequest.prototype.setRequestHeader;
 XMLHttpRequest.prototype.open=function(method,url,...rest) {this.__aiUrl=String(url);this.__aiMethod=method;this.__aiHeaders={};return open0.call(this,method,url,...rest)};
 XMLHttpRequest.prototype.setRequestHeader=function(name,value) {this.__aiHeaders[name]=this.__aiHeaders[name]?this.__aiHeaders[name]+', '+value:String(value);return header0.call(this,name,value)};
 XMLHttpRequest.prototype.send=function(...args) {
   if (/listmodels/i.test(this.__aiUrl) && (args[0]==null || typeof args[0]==='string')) window.__aiRequest={url:new URL(this.__aiUrl,location.href).href,method:this.__aiMethod,headers:this.__aiHeaders,body:args[0]||''};
   const start=performance.now();
   this.addEventListener('load',()=>{try {inspect(this.__aiUrl,this.status,typeof this.response==='string'?this.response:JSON.stringify(this.response),performance.now()-start)}catch(_){}});
   return send0.apply(this,args);
 };
})()"#;

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub url: String,
    pub text: String,
    pub rpc_ok: bool,
    pub denied: bool,
    #[serde(default)]
    pub auth_lost: bool,
    #[serde(default)]
    pub rpc_seen: bool,
    #[serde(default)]
    pub net_error: String,
    #[serde(default)]
    pub(super) request: Option<super::rpc::ModelRequest>,
}

pub fn classify(e: &Evidence) -> AiVerdict {
    let parsed = url::Url::parse(&e.url).ok();
    let host = parsed.as_ref().and_then(|u| u.host_str()).unwrap_or("");
    let path = parsed.as_ref().map(|u| u.path()).unwrap_or("");
    let text = e.text.to_lowercase();
    if google_domain(host)
        && (path == "/sorry"
            || path.starts_with("/sorry/")
            || text.contains("our systems have detected unusual traffic")
            || text.contains("your computer or network may be sending automated queries")
            || text.contains("наши системы обнаружили подозрительный трафик")
            || text.contains("наши системы обнаружили необычный трафик")
            || text.contains("вашей сети поступают автоматические запросы"))
    {
        AiVerdict::GoogleChallenge
    } else if host == "accounts.google.com" || e.auth_lost {
        AiVerdict::SessionExpired
    } else if e.denied
        || (matches!(host, "ai.google.dev" | "aistudio.google.com")
            && path.contains("available-regions"))
        || regional_rejection(&text)
    {
        AiVerdict::Geoblock
    } else if !e.net_error.is_empty()
        || e.url.starts_with("chrome-error:")
        || text.contains("err_proxy_connection_failed")
        || text.contains("err_tunnel_connection_failed")
        || text.contains("err_cert_")
    {
        AiVerdict::ConnectionError
    } else if host == "aistudio.google.com" && e.rpc_ok {
        AiVerdict::Unlocked
    } else {
        AiVerdict::Inconclusive
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Cookie {
    name: String,
    value: String,
    domain: String,
    path: String,
    secure: bool,
    expires: f64,
    session: bool,
    #[serde(default)]
    partition_key: Option<serde_json::Value>,
    #[serde(default)]
    partition_key_opaque: bool,
}
fn is_auth_cookie(name: &str) -> bool {
    matches!(name, "SID" | "__Secure-1PSID" | "__Secure-3PSID")
}
fn google_domain(domain: &str) -> bool {
    let domain = domain.trim_start_matches('.');
    domain == "google.com" || domain.ends_with(".google.com")
}
fn has_google_login(cookies: &[Cookie]) -> bool {
    cookies.iter().any(|c| {
        google_domain(&c.domain)
            && is_auth_cookie(&c.name)
            && !c.value.is_empty()
            && (c.session || c.expires > super::session::now() as f64)
    })
}
pub struct BrowserRunner {
    browser: Cdp,
    process: std::sync::Mutex<crate::sandbox::process::ManagedProcess>,
    _profile_lock: std::fs::File,
    model_request: Option<super::rpc::ModelRequest>,
    account_cookies: Vec<Cookie>,
}
impl BrowserRunner {
    pub async fn launch_authenticated(path: &Path, _proxy: &str, root: &Path) -> Result<Self> {
        timeout(Duration::from_secs(7), Self::launch_one(path, root))
            .await
            .context("Selected browser launch timed out")?
            .with_context(|| {
                rust_i18n::t!(
                    "Could not launch the selected browser %{a0}",
                    a0 = path.display()
                )
                .to_string()
            })
    }
    async fn launch_one(path: &Path, root: &Path) -> Result<Self> {
        let profile = account_profile(root, path)?;
        std::fs::create_dir_all(&profile)?;
        anyhow::ensure!(
            profile.canonicalize()?.starts_with(root.canonicalize()?),
            "Google profile must stay inside the checker directory"
        );
        use fs2::FileExt;
        let lease = std::fs::File::options()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(profile.join("checker-profile.lock"))?;
        lease
            .try_lock_exclusive()
            .context("The browser profile is in use; close the sign-in window")?;
        let port_file = profile.join("DevToolsActivePort");
        if let Ok(old) = std::fs::read_to_string(&port_file) {
            if let Some(port) = old.lines().next().and_then(|s| s.parse::<u16>().ok())
                && matches!(
                    timeout(
                        Duration::from_millis(150),
                        tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
                    )
                    .await,
                    Ok(Ok(_))
                )
            {
                anyhow::bail!("The browser profile is open. Close its window before signing in");
            }
            std::fs::remove_file(&port_file)?;
        }
        let mut command = std::process::Command::new(path);
        command
            .arg(format!("--user-data-dir={}", profile.display()))
            .args([
                "--remote-debugging-port=0",
                "--remote-debugging-address=127.0.0.1",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-sync",
                "--disable-extensions",
                "--disable-background-networking",
                "--disable-quic",
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            ]);
        command.arg("--headless=new");
        command.arg("about:blank");
        {
            let temporary = root.parent().unwrap_or(root).join("tmp");
            std::fs::create_dir_all(&temporary)?;
            for variable in ["TEMP", "TMP", "TMPDIR"] {
                command.env(variable, &temporary);
            }
        }
        let process = std::sync::Mutex::new(crate::sandbox::process::ManagedProcess::spawn(
            command,
            &profile.join("launcher.log"),
        )?);

        let browser = timeout(Duration::from_secs(7), async {
            loop {
                if let Ok(port) = std::fs::read_to_string(&port_file) {
                    let mut lines = port.lines();
                    if let (Some(port), Some(endpoint)) = (
                        lines.next().and_then(|p| p.parse::<u16>().ok()),
                        lines.next(),
                    ) && port > 0
                        && endpoint.starts_with("/devtools/browser/")
                        && endpoint
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '/' || c == '-')
                    {
                        return super::cdp::Cdp::connect(&format!(
                            "ws://127.0.0.1:{port}{endpoint}"
                        ))
                        .await;
                    }
                }
                if !process
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .tree_running()
                {
                    anyhow::bail!("The selected browser exited before connecting");
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .context("The selected browser did not connect within 7 seconds")??;
        let mut runner = Self {
            browser,
            process,
            _profile_lock: lease,
            model_request: None,
            account_cookies: Vec::new(),
        };
        runner.account_cookies = runner.cookies().await?;
        Ok(runner)
    }
    async fn cookies(&self) -> Result<Vec<Cookie>> {
        let mut result = self
            .browser
            .call(None, "Storage.getCookies", json!({}))
            .await?;
        Ok(serde_json::from_value(result["cookies"].take())?)
    }
    pub async fn has_login(&self) -> Result<bool> {
        Ok(has_google_login(&self.cookies().await?))
    }
    pub fn session_available(&self) -> bool {
        has_google_login(&self.account_cookies)
    }
    pub(super) async fn export_http_session(&self) -> Result<super::session::HttpSession> {
        let request = self.model_request.clone().filter(super::rpc::ModelRequest::validate)
            .context("AI Studio did not provide a model request. Open AI Studio on a working connection and sign in again")?;
        let version = self
            .browser
            .call(None, "Browser.getVersion", json!({}))
            .await?;
        let agent = version["userAgent"]
            .as_str()
            .context("Browser user agent missing")?
            .to_owned();
        // Read cookies after capture, including cookies refreshed by Google's frontend.
        let cookies = self
            .cookies()
            .await?
            .into_iter()
            .filter(|c| {
                google_domain(&c.domain) && c.partition_key.is_none() && !c.partition_key_opaque
            })
            .map(|c| super::session::SessionCookie {
                name: c.name,
                value: c.value,
                domain: c.domain,
                path: c.path,
                secure: c.secure,
                expires: (!c.session && c.expires > 0.0).then_some(c.expires),
            })
            .collect();
        super::session::HttpSession::new(request, cookies, agent)
    }
    pub async fn warm_up(&mut self, budget: Duration) {
        if !self.session_available() {
            return;
        }
        // The default browser context uses the normal system route during sign-in.
        let deadline = Instant::now() + budget;
        let page = match timeout(budget, self.browser.new_page()).await {
            Ok(Ok(page)) => page,
            _ => return,
        };
        let _ = timeout(
            deadline.saturating_duration_since(Instant::now()),
            self.learn_on_page(&page, AI_STUDIO_URL, deadline),
        )
        .await;
        let _ = timeout(Duration::from_millis(200), page.close()).await;
    }
    async fn learn_on_page(&mut self, page: &Page, url: &str, deadline: Instant) -> Result<()> {
        page.call(
            "Page.addScriptToEvaluateOnNewDocument",
            json!({"source":OBSERVER}),
        )
        .await?;
        let navigation = page.call("Page.navigate", json!({"url":url})).await?;
        anyhow::ensure!(
            navigation.get("errorText").is_none(),
            "Browser navigation failed"
        );
        while Instant::now() < deadline {
            let response = page.evaluate(r#"(() => {
                const s=window.__aiCheck || {};
                return {...s,url:location.href,text:(document.body?.innerText||'').slice(0,100000),request:window.__aiRequest||null};
            })()"#).await;
            match response {
                Ok(value) => {
                    let evidence: Evidence = serde_json::from_value(value)?;
                    if let Some(request) =
                        evidence.request.filter(super::rpc::ModelRequest::validate)
                    {
                        self.model_request = Some(request);
                    }
                    if self.model_request.is_some() && evidence.rpc_seen {
                        break;
                    }
                }
                Err(error) if transient_context_error(&error.to_string()) => {}
                Err(error) => return Err(error),
            }
            tokio::time::sleep(Duration::from_millis(75)).await;
        }
        Ok(())
    }
    pub async fn shutdown(self) {
        let _ = timeout(
            Duration::from_millis(500),
            self.browser.call(None, "Browser.close", json!({})),
        )
        .await;
        let deadline = Instant::now() + Duration::from_secs(2);
        while self
            .process
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .tree_running()
            && Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        // ManagedProcess owns only this browser's job/process group; Drop kills its descendants.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn account_cookies_require_google_domain_and_valid_expiry() {
        let cookie = |domain: &str, expires: f64| Cookie {
            name: "SID".into(),
            value: "synthetic".into(),
            domain: domain.into(),
            path: "/".into(),
            secure: true,
            expires,
            session: false,
            partition_key: None,
            partition_key_opaque: false,
        };
        assert!(has_google_login(&[cookie(".google.com", 4102444800.0)]));
        assert!(!has_google_login(&[cookie(
            ".google.com.evil.test",
            4102444800.0
        )]));
        assert!(!has_google_login(&[cookie(".google.com", 1.0)]));
    }

    #[tokio::test]
    #[ignore = "Owned headless browser; intercepts all frontend/RPC requests with synthetic local replies"]
    async fn cdp_captures_session_from_intercepted_frontend_and_releases_profile() {
        use base64::Engine as _;
        let path = crate::browser::detector::BrowserDetector::find_best().unwrap();
        let root = tempfile::tempdir().unwrap();
        let mut runner = BrowserRunner::launch_authenticated(&path, "127.0.0.1:1", root.path())
            .await
            .unwrap();
        assert!(!runner.has_login().await.unwrap());
        runner.browser.call(None, "Storage.setCookies", json!({"cookies":[{"name":"SID","value":"synthetic-login-export","domain":".google.com","path":"/","secure":true,"expires":4102444800.0}]})).await.unwrap();
        assert!(runner.has_login().await.unwrap());
        let page = runner.browser.new_page().await.unwrap();
        let mut events = runner.browser.events();
        page.call("Fetch.enable", json!({"patterns":[{"urlPattern":"*"}]}))
            .await
            .unwrap();
        let intercepted = page.clone();
        let intercept = tokio::spawn(async move {
            while let Ok(event) = events.recv().await {
                if event["sessionId"] != intercepted.session
                    || event["method"] != "Fetch.requestPaused"
                {
                    continue;
                }
                let url = event["params"]["request"]["url"]
                    .as_str()
                    .unwrap_or_default();
                let (body, kind) = if url == AI_STUDIO_URL {
                    (
                        "<!doctype html><script>fetch('https://alkalimakersuite-pa.clients6.google.com/$rpc/service/ListModels',{method:'POST',body:'[]'})</script>",
                        "text/html",
                    )
                } else if url.ends_with("/ListModels") {
                    (
                        r#"{"models":[{"name":"offline-fixture-model"}]}"#,
                        "application/json",
                    )
                } else {
                    ("", "text/plain")
                };
                if intercepted.call("Fetch.fulfillRequest", json!({"requestId":event["params"]["requestId"],"responseCode":200,
                    "responseHeaders":[{"name":"Content-Type","value":kind},{"name":"Access-Control-Allow-Origin","value":"*"}],
                    "body":base64::engine::general_purpose::STANDARD.encode(body)})).await.is_err() { break; }
            }
        });
        runner
            .learn_on_page(
                &page,
                AI_STUDIO_URL,
                Instant::now() + Duration::from_secs(4),
            )
            .await
            .unwrap();
        let session = runner.export_http_session().await.unwrap();
        assert!(session.request.validate());
        assert_eq!(session.request.body, "[]");
        session.save(root.path(), &path).unwrap();
        assert!(super::super::transport::HttpProbe::load(root.path(), &path).is_ok());
        page.close().await.unwrap();
        intercept.abort();
        let profile = account_profile(root.path(), &path).unwrap();
        let port: u16 = std::fs::read_to_string(profile.join("DevToolsActivePort"))
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        runner.shutdown().await;
        assert!(
            tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
                .await
                .is_ok()
        );
        let next = BrowserRunner::launch_authenticated(&path, "127.0.0.1:1", root.path())
            .await
            .unwrap();
        // Continuity uses the saved checker session, independently of Chromium's
        // persistence policy for synthetic cookies created through CDP.
        assert!(super::super::transport::HttpProbe::load(root.path(), &path).is_ok());
        drop(next);
    }
    #[test]
    fn model_rpc_statuses_distinguish_account_control_rate_limits_and_networks() {
        let mut reply = super::super::rpc::Reply {
            status: 403,
            body: "[null,[7,\"Permission denied\"]]".into(),
            elapsed_ms: 50,
            error: None,
            network_error: None,
        };
        assert_eq!(rpc_observation(&reply).0, AiVerdict::Inconclusive);
        reply.body = "User location is not supported".into();
        assert_eq!(rpc_observation(&reply).0, AiVerdict::Geoblock);
        reply.body.clear();
        reply.status = 429;
        assert_eq!(rpc_observation(&reply).0, AiVerdict::RateLimited);
        reply.status = 503;
        assert_eq!(rpc_observation(&reply).0, AiVerdict::Inconclusive);
        reply.status = 0;
        reply.error = Some("fetch_failed".into());
        reply.network_error = Some("net::ERR_CONNECTION_CLOSED".into());
        assert_eq!(rpc_observation(&reply).0, AiVerdict::ConnectionError);
        reply.error = Some("timeout".into());
        assert_eq!(rpc_observation(&reply).0, AiVerdict::Timeout);
    }
    #[test]
    fn ambiguous_browser_failures_and_permission_denials_do_not_prove_dead_servers_or_regions() {
        let mut reply = super::super::rpc::Reply {
            status: 0,
            body: String::new(),
            elapsed_ms: 10,
            error: Some("fetch_failed".into()),
            network_error: Some("net::ERR_FAILED".into()),
        };
        assert_eq!(rpc_observation(&reply).0, AiVerdict::Inconclusive);
        reply.network_error = Some("net::ERR_CONNECTION_REFUSED".into());
        assert_eq!(rpc_observation(&reply).0, AiVerdict::ConnectionError);
        reply.network_error = None;
        reply.error = None;
        reply.status = 403;
        reply.body = "Permission denied".into();
        assert_eq!(rpc_observation(&reply).0, AiVerdict::Inconclusive);
        reply.body = "User location is not supported".into();
        assert_eq!(rpc_observation(&reply).0, AiVerdict::Geoblock);
        reply.status = 503;
        reply.body.clear();
        assert_eq!(rpc_observation(&reply).0, AiVerdict::Inconclusive);
    }
    #[test]
    fn evidence_prevents_false_success() {
        let mut e = Evidence {
            url: "https://aistudio.google.com/app".into(),
            ..Default::default()
        };
        assert_eq!(classify(&e), AiVerdict::Inconclusive);
        e.rpc_ok = true;
        assert_eq!(classify(&e), AiVerdict::Unlocked);
        e.denied = true;
        assert_eq!(classify(&e), AiVerdict::Geoblock);
        e.denied = false;
        e.url = "https://accounts.google.com/v3/signin".into();
        assert_eq!(classify(&e), AiVerdict::SessionExpired);
        e.url = "https://evil.test/?next=https://aistudio.google.com/app".into();
        assert_eq!(classify(&e), AiVerdict::Inconclusive);
    }
    #[test]
    fn generic_permission_failure_is_not_a_region_block() {
        let mut e = Evidence {
            url: AI_STUDIO_URL.into(),
            text: "Failed to list models: permission denied".into(),
            ..Default::default()
        };
        assert_eq!(classify(&e), AiVerdict::Inconclusive);
        e.url = "https://aistudio.google.com/docs/available-regions".into();
        assert_eq!(classify(&e), AiVerdict::Geoblock);
        e.url = "https://example.test/docs/available-regions".into();
        assert_eq!(classify(&e), AiVerdict::Inconclusive);
        assert!(transient_context_error(
            "Error -32000: Cannot find context with specified id"
        ));
        assert!(!transient_context_error("net::ERR_CONNECTION_CLOSED"));
    }
    #[test]
    fn google_challenge_is_distinct_from_access_region_and_session() {
        for url in [
            "https://www.google.com/sorry/index?continue=https://aistudio.google.com/app",
            "https://google.com/sorry/",
            "https://www.google.com/sorry",
        ] {
            let e = Evidence {
                url: url.into(),
                rpc_ok: true,

                denied: true,
                ..Default::default()
            };
            assert_eq!(classify(&e), AiVerdict::GoogleChallenge);
        }
        let e = Evidence {
            url: "https://aistudio.google.com/app".into(),
            text: "Our systems have detected unusual traffic from your computer network".into(),

            ..Default::default()
        };
        assert_eq!(classify(&e), AiVerdict::GoogleChallenge);
        let e = Evidence {
            url: "https://evil.test/sorry/index?continue=https://aistudio.google.com/app".into(),
            ..e
        };
        assert_eq!(classify(&e), AiVerdict::Inconclusive);
        assert!(!AiVerdict::GoogleChallenge.is_working());
    }
    #[tokio::test]
    async fn explicit_missing_browser_never_falls_back_to_another() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing-browser.exe");
        let result =
            BrowserRunner::launch_authenticated(&missing, "127.0.0.1:1", root.path()).await;
        let Err(error) = result else {
            panic!("An invalid explicit browser selection must never start another browser")
        };
        assert!(format!("{error:#}").contains(&missing.display().to_string()));
        assert!(!root.path().join("google_account").exists());
    }
}
