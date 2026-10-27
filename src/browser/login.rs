use super::runner::BrowserRunner;
use crate::checker::engine::cancelled;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

pub enum LoginCommand {
    Finish,
}
pub enum LoginEvent {
    Opened { browser: PathBuf },
    Notice(String),
    Finished { ready: bool, message: String },
}
pub struct LoginConfig {
    pub browser: PathBuf,
    pub root: PathBuf,
    pub proxy: String,
}
#[derive(Serialize, Deserialize)]
struct SavedLogin {
    browser: PathBuf,
}
pub fn saved_browser(root: &Path) -> Option<PathBuf> {
    let saved: SavedLogin =
        serde_json::from_slice(&std::fs::read(root.join("google-login.json")).ok()?).ok()?;
    saved.browser.is_file().then_some(saved.browser)
}
pub fn migrate_legacy_marker(root: &Path) {
    if let Ok(bytes) = std::fs::read(root.join("google-login.json"))
        && let Ok(saved) = serde_json::from_slice::<SavedLogin>(&bytes)
        && let Ok(profile) = super::runner::account_profile(root, &saved.browser)
        && profile.is_dir()
        && !profile.join("checker-login.json").exists()
    {
        let _ = std::fs::write(profile.join("checker-login.json"), bytes);
    }
}
pub fn has_saved_session(root: &Path, browser: &Path) -> bool {
    if super::session::HttpSession::load(root, browser).is_err() {
        return false;
    }
    if let Ok(profile) = super::runner::account_profile(root, browser)
        && let Ok(bytes) = std::fs::read(profile.join("checker-login.json"))
        && let Ok(saved) = serde_json::from_slice::<SavedLogin>(&bytes)
    {
        return super::detector::BrowserDetector::same_path(&saved.browser, browser);
    }
    saved_browser(root)
        .is_some_and(|saved| super::detector::BrowserDetector::same_path(&saved, browser))
}
pub fn forget_marker(root: &Path, browser: &Path) {
    if let Ok(profile) = super::runner::account_profile(root, browser) {
        let _ = std::fs::remove_file(profile.join("checker-login.json"));
        let _ = std::fs::remove_file(profile.join("checker-http-session.bin"));
    }
    if saved_browser(root)
        .is_some_and(|saved| super::detector::BrowserDetector::same_path(&saved, browser))
    {
        let _ = std::fs::remove_file(root.join("google-login.json"));
    }
}
pub async fn run(
    config: LoginConfig,
    stop: Arc<AtomicBool>,
    mut commands: UnboundedReceiver<LoginCommand>,
    events: UnboundedSender<LoginEvent>,
) {
    let mut browser: Option<super::manual_login::ManualLogin> = None;
    let work = async {
        browser = Some(super::manual_login::ManualLogin::launch(
            &config.browser,
            &config.root,
            None,
            crate::checker::verdicts::AI_STUDIO_URL,
        )?);
        let _ = events.send(LoginEvent::Opened {
            browser: config.browser.clone(),
        });
        loop {
            let command = commands.recv().await;
            if command.is_none() {
                bail!("Sign-in cancelled");
            }
            let _ = events.send(LoginEvent::Notice(
                "Closing browser and verifying saved sign-in…".into(),
            ));
            if let Some(manual) = browser.take() {
                manual.close().await;
            }
            let mut probe =
                BrowserRunner::launch_authenticated(&config.browser, &config.proxy, &config.root)
                    .await?;
            let logged_in = probe.has_login().await?;
            if logged_in {
                let _ = events.send(LoginEvent::Notice(
                    "Preparing AI Studio HTTP session…".into(),
                ));
                tokio::select! {
                    _=probe.warm_up(std::time::Duration::from_secs(10))=>{},
                    _=cancelled(&stop)=>bail!("Sign-in stopped"),
                }
                let session = probe.export_http_session().await?;
                session.save(&config.root, &config.browser)?;
            }
            probe.shutdown().await;
            if logged_in {
                let saved = SavedLogin {
                    browser: config.browser.clone(),
                };
                let mut file = tempfile::NamedTempFile::new_in(&config.root)?;
                use std::io::Write;
                file.write_all(&serde_json::to_vec(&saved)?)?;
                file.persist(config.root.join("google-login.json"))
                    .map_err(|e| e.error)?;
                let profile = super::runner::account_profile(&config.root, &saved.browser)?;
                std::fs::write(
                    profile.join("checker-login.json"),
                    serde_json::to_vec(&saved)?,
                )?;
                break;
            }
            browser = Some(super::manual_login::ManualLogin::launch(
                &config.browser,
                &config.root,
                None,
                crate::checker::verdicts::AI_STUDIO_URL,
            )?);
            let _ = events.send(LoginEvent::Notice(
                "Sign-in was not saved. Complete sign-in in the browser, then click Done".into(),
            ));
        }
        Ok::<_, anyhow::Error>(())
    };
    let result: Result<()> = tokio::select! {
        result=work=>result,
        _=cancelled(&stop)=>Err(anyhow::anyhow!("Sign-in stopped")),
    };
    if let Some(browser) = browser {
        browser.close().await;
    }
    let ready = result.is_ok();
    if !ready {
        forget_marker(&config.root, &config.browser);
    }
    let message = match result {
        Ok(()) => "Sign-in saved. You can now check nodes with this Google account".into(),
        Err(error) => {
            rust_i18n::t!("Sign-in: %{error}", error = format!("{:#}", error)).to_string()
        }
    };
    let _ = events.send(LoginEvent::Finished { ready, message });
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn switching_browsers_keeps_independent_login_markers() {
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("first-browser");
        let second = root.path().join("second-browser");
        std::fs::write(&first, b"fixture").unwrap();
        std::fs::write(&second, b"fixture").unwrap();
        let first_profile = super::super::runner::account_profile(root.path(), &first).unwrap();
        let second_profile = super::super::runner::account_profile(root.path(), &second).unwrap();
        std::fs::create_dir_all(&first_profile).unwrap();
        std::fs::create_dir_all(&second_profile).unwrap();
        let old = SavedLogin {
            browser: first.clone(),
        };
        std::fs::write(
            root.path().join("google-login.json"),
            serde_json::to_vec(&old).unwrap(),
        )
        .unwrap();
        migrate_legacy_marker(root.path());
        super::super::session::fixture_session()
            .save(root.path(), &first)
            .unwrap();
        super::super::session::fixture_session()
            .save(root.path(), &second)
            .unwrap();
        let other = SavedLogin {
            browser: second.clone(),
        };
        std::fs::write(
            second_profile.join("checker-login.json"),
            serde_json::to_vec(&other).unwrap(),
        )
        .unwrap();
        std::fs::write(
            root.path().join("google-login.json"),
            serde_json::to_vec(&other).unwrap(),
        )
        .unwrap();
        assert!(has_saved_session(root.path(), &first));
        assert!(has_saved_session(root.path(), &second));
        forget_marker(root.path(), &second);
        assert!(has_saved_session(root.path(), &first));
        assert!(!has_saved_session(root.path(), &second));
    }
}
