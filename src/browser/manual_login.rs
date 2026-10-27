use crate::sandbox::process::ManagedProcess;
use anyhow::{Context, Result};
use fs2::FileExt;
use std::{fs::File, path::Path, process::Command, time::Duration};

/// Google authentication is performed by the human in an ordinary browser.
/// No DevTools connection, automation flags, injected scripts or DOM reads.
pub struct ManualLogin {
    process: ManagedProcess,
    _lease: File,
}
fn command(browser: &Path, profile: &Path, proxy: Option<&str>, url: &str) -> Command {
    let mut command = Command::new(browser);
    command
        .arg(format!("--user-data-dir={}", profile.display()))
        .args([
            "--no-first-run",
            "--no-default-browser-check",
            "--new-window",
        ])
        .arg("--window-size=1100,850")
        .arg(url);
    if let Some(proxy) = proxy {
        command.arg(format!("--proxy-server=socks5://{proxy}"));
    }
    command
}
impl ManualLogin {
    pub fn launch(browser: &Path, root: &Path, proxy: Option<&str>, url: &str) -> Result<Self> {
        let profile = super::runner::account_profile(root, browser)?;
        std::fs::create_dir_all(&profile)?;
        anyhow::ensure!(
            profile.canonicalize()?.starts_with(root.canonicalize()?),
            "Профиль должен находиться в каталоге чекера"
        );
        let lease = File::options()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(profile.join("checker-profile.lock"))?;
        lease
            .try_lock_exclusive()
            .context("Закройте предыдущее окно браузера перед входом")?;
        // A stale port file must not give the manual window an automation UI.
        let port_file = profile.join("DevToolsActivePort");
        if port_file.is_file() {
            std::fs::remove_file(port_file)?;
        }
        let process = ManagedProcess::spawn(
            command(browser, &profile, proxy, url),
            &profile.join("manual-login.log"),
        )?;
        Ok(Self {
            process,
            _lease: lease,
        })
    }
    pub async fn close(self) {
        self.process.request_close();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while self.process.tree_running() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // Drop owns the entire tree, including Edge's delegated main process.
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manual_authentication_has_no_automation_interface() {
        let command = command(
            Path::new("browser.exe"),
            Path::new("profile"),
            None,
            "https://aistudio.google.com/app",
        );
        let args = command
            .get_args()
            .map(|a| a.to_string_lossy())
            .collect::<Vec<_>>();
        assert!(args.iter().any(|a| a == "https://aistudio.google.com/app"));
        assert!(!args.iter().any(|a| a.contains("remote-debugging")
            || a.contains("headless")
            || a.contains("enable-automation")
            || a.contains("disable-web-security")));
        assert!(
            !args
                .iter()
                .any(|a| a.contains("proxy-server") || a.contains("disable-quic")),
            "Manual sign-in must use the browser's normal network route"
        );
    }
    #[tokio::test]
    #[ignore = "Installed ordinary browser, temporary profile and local HTTP page; no Throne or Google account"]
    async fn normal_route_loads_page_without_checker_proxy_or_core() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://{}/login-route-fixture",
            listener.local_addr().unwrap()
        );
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0; 1024];
                while request.len() < 4096 && !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = stream.read(&mut buffer).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..n]);
                }
                // Chromium may open and close a speculative TCP connection first.
                if request.is_empty() {
                    continue;
                }
                assert!(String::from_utf8_lossy(&request).starts_with("GET /login-route-fixture "));
                let body = "<!doctype html><title>Checker sign-in network test</title>OK";
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).as_bytes()).await.unwrap();
                break;
            }
        });
        let browser = super::super::detector::BrowserDetector::find_best().unwrap();
        let root = tempfile::tempdir().unwrap();
        let manual = ManualLogin::launch(&browser, root.path(), None, &url).unwrap();
        let received = tokio::time::timeout(Duration::from_secs(8), server).await;
        let profile = super::super::runner::account_profile(root.path(), &browser).unwrap();
        assert!(!profile.join("DevToolsActivePort").exists());
        manual.close().await;
        received.unwrap().unwrap();
    }
    #[tokio::test]
    #[ignore = "Opens a blank ordinary browser window; uses no Google account"]
    async fn normal_window_does_not_open_devtools_and_releases_profile() {
        let browser = super::super::detector::BrowserDetector::find_best().unwrap();
        let root = tempfile::tempdir().unwrap();
        let manual =
            ManualLogin::launch(&browser, root.path(), Some("127.0.0.1:1"), "about:blank").unwrap();
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert!(manual.process.tree_running());
        let profile = super::super::runner::account_profile(root.path(), &browser).unwrap();
        assert!(!profile.join("DevToolsActivePort").exists());
        manual.close().await;
        let probe = super::super::runner::BrowserRunner::launch_authenticated(
            &browser,
            "127.0.0.1:1",
            root.path(),
        )
        .await
        .unwrap();
        assert!(!probe.session_available());
        probe.shutdown().await;
    }
}
