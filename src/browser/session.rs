use super::rpc::ModelRequest;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::{
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub(super) const ORIGIN: &str = "https://aistudio.google.com";
const MAX_SESSION_FILE: u64 = 1024 * 1024;
const MAX_SESSION_AGE: u64 = 24 * 3600;
const STATIC_AUTH_AGE: u64 = 600;

// No Debug implementation: these values authorize the user's isolated checker account.
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct SessionCookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub expires: Option<f64>,
}
impl SessionCookie {
    pub fn valid(&self, now: u64) -> bool {
        let host = self.domain.trim_start_matches('.');
        (host == "google.com" || host.ends_with(".google.com"))
            && !self.name.is_empty()
            && self.name.len() < 256
            && self.value.len() < 16384
            && !self.name.contains(['\r', '\n', ';', '=', ' '])
            && !self.value.contains(['\r', '\n', ';'])
            && self.path.starts_with('/')
            && !self.path.contains(['\r', '\n', ';'])
            && self
                .expires
                .is_none_or(|at| at.is_finite() && at > now as f64)
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct AuthBinding {
    scheme: String,
    cookie_name: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct HttpSession {
    version: u32,
    captured_at: u64,
    pub(super) request: ModelRequest,
    pub(super) cookies: Vec<SessionCookie>,
    pub(super) user_agent: String,
    bindings: Vec<AuthBinding>,
}
pub(super) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn signature(timestamp: &str, cookie: &str) -> String {
    format!(
        "{:x}",
        Sha1::digest(format!("{timestamp} {cookie} {ORIGIN}"))
    )
}
impl HttpSession {
    pub(super) fn new(
        request: ModelRequest,
        cookies: Vec<SessionCookie>,
        user_agent: String,
    ) -> Result<Self> {
        let mut session = Self {
            version: 1,
            captured_at: now(),
            request,
            cookies,
            user_agent,
            bindings: Vec::new(),
        };
        // Regenerate only schemes whose captured signature is proven by these cookies.
        // Unknown/suffixed authorization formats retain their original short lifetime.
        if let Some(auth) = session
            .request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v)
        {
            let parts: Vec<_> = auth.split_whitespace().collect();
            if !parts.is_empty() && parts.len() % 2 == 0 {
                for pair in parts.as_chunks::<2>().0 {
                    let candidates: &[&str] = match pair[0] {
                        "SAPISIDHASH" => &["SAPISID", "__Secure-3PAPISID"],
                        "SAPISID1PHASH" => &["__Secure-1PAPISID"],
                        "SAPISID3PHASH" => &["__Secure-3PAPISID"],
                        _ => &[],
                    };
                    let Some((timestamp, hash)) = pair[1].split_once('_') else {
                        break;
                    };
                    let matched = session.cookies.iter().find(|c| {
                        candidates.contains(&c.name.as_str())
                            && c.domain == ".google.com"
                            && c.valid(now())
                            && timestamp.parse::<u64>().is_ok()
                            && signature(timestamp, &c.value) == hash
                    });
                    if let Some(cookie) = matched {
                        session.bindings.push(AuthBinding {
                            scheme: pair[0].into(),
                            cookie_name: cookie.name.clone(),
                        });
                    }
                }
                if session.bindings.len() != parts.len() / 2 {
                    session.bindings.clear();
                }
            }
        }
        session.validate()?;
        Ok(session)
    }
    pub(super) fn validate(&self) -> Result<()> {
        let current = now();
        ensure!(
            self.version == 1 && self.request.validate(),
            "Invalid AI Studio session format"
        );
        ensure!(
            self.captured_at <= current.saturating_add(60)
                && current.saturating_sub(self.captured_at) < MAX_SESSION_AGE,
            "Google session expired; sign in again"
        );
        ensure!(
            !self.cookies.is_empty() && self.cookies.len() <= 512,
            "Invalid Google session cookies"
        );
        ensure!(
            self.cookies.iter().any(|c| c.valid(current)
                && !c.value.is_empty()
                && matches!(c.name.as_str(), "SID" | "__Secure-1PSID" | "__Secure-3PSID")),
            "Google session expired; sign in again"
        );
        ensure!(
            !self.user_agent.is_empty()
                && self.user_agent.len() < 2048
                && !self.user_agent.contains(['\r', '\n']),
            "Invalid session user agent"
        );
        ensure!(
            self.bindings.len() <= 3
                && self.bindings.iter().all(|b| matches!(
                    b.scheme.as_str(),
                    "SAPISIDHASH" | "SAPISID1PHASH" | "SAPISID3PHASH"
                ) && matches!(
                    b.cookie_name.as_str(),
                    "SAPISID" | "__Secure-1PAPISID" | "__Secure-3PAPISID"
                )),
            "Invalid session authorization binding"
        );
        if self.bindings.is_empty() {
            ensure!(
                current.saturating_sub(self.captured_at) < STATIC_AUTH_AGE,
                "Google session expired; sign in again"
            );
        }
        Ok(())
    }
    pub(super) fn authorization(&self, jar: &wreq::cookie::Jar) -> Result<Option<String>> {
        self.validate()?;
        if self.bindings.is_empty() {
            return Ok(None);
        }
        let timestamp = now().to_string();
        let mut tokens = Vec::new();
        for binding in &self.bindings {
            let cookie = jar
                .matches(ORIGIN)
                .find(|c| c.name() == binding.cookie_name && c.domain() == Some("google.com"))
                .context("Google session expired; sign in again")?;
            tokens.push(format!(
                "{} {}_{}",
                binding.scheme,
                timestamp,
                signature(&timestamp, cookie.value())
            ));
        }
        Ok(Some(tokens.join(" ")))
    }
    pub(crate) fn load(root: &Path, browser: &Path) -> Result<Self> {
        let path = super::runner::account_profile(root, browser)?.join("checker-http-session.bin");
        ensure!(
            std::fs::metadata(&path)?.len() <= MAX_SESSION_FILE,
            "Session file too large"
        );
        let bytes = unprotect(&std::fs::read(path)?)?;
        let session: Self =
            serde_json::from_slice(&bytes).context("Invalid saved AI Studio session")?;
        session.validate()?;
        Ok(session)
    }
    pub(crate) fn save(&self, root: &Path, browser: &Path) -> Result<()> {
        self.validate()?;
        let directory = super::runner::account_profile(root, browser)?;
        std::fs::create_dir_all(&directory)?;
        let bytes = protect(&serde_json::to_vec(self)?)?;
        ensure!(
            bytes.len() as u64 <= MAX_SESSION_FILE,
            "Session file too large"
        );
        let mut file = tempfile::NamedTempFile::new_in(&directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(&bytes)?;
        file.as_file().sync_all()?;
        file.persist(directory.join("checker-http-session.bin"))
            .map_err(|e| e.error)?;
        Ok(())
    }
}

#[cfg(windows)]
fn crypt(data: &[u8], encrypt: bool) -> Result<Vec<u8>> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
        },
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len().try_into()?,
        pbData: data.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // DPAPI binds the local session to the current Windows user; no prompt is allowed.
    unsafe {
        let ok = if encrypt {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error())
                .context("Windows could not protect/open the checker session");
        }
        let bytes = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        LocalFree(output.pbData.cast());
        Ok(bytes)
    }
}
#[cfg(windows)]
fn protect(data: &[u8]) -> Result<Vec<u8>> {
    crypt(data, true)
}
#[cfg(windows)]
fn unprotect(data: &[u8]) -> Result<Vec<u8>> {
    crypt(data, false)
}
#[cfg(not(windows))]
fn protect(data: &[u8]) -> Result<Vec<u8>> {
    Ok(data.to_vec())
}
#[cfg(not(windows))]
fn unprotect(data: &[u8]) -> Result<Vec<u8>> {
    Ok(data.to_vec())
}

#[cfg(test)]
pub(crate) fn fixture_session() -> HttpSession {
    HttpSession::new(
        ModelRequest {
            url: "https://alkalimakersuite-pa.clients6.google.com/$rpc/test/ListModels".into(),
            method: "POST".into(),
            headers: Default::default(),
            body: "[]".into(),
        },
        vec![SessionCookie {
            name: "SID".into(),
            value: "synthetic-test-cookie".into(),
            domain: ".google.com".into(),
            path: "/".into(),
            secure: true,
            expires: None,
        }],
        "Local fixture".into(),
    )
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn session_roundtrip_rejects_corruption_and_expired_material() {
        let root = tempfile::tempdir().unwrap();
        let browser = root.path().join("fixture-browser");
        std::fs::write(&browser, b"not an executable").unwrap();
        let mut session = fixture_session();
        session.save(root.path(), &browser).unwrap();
        assert!(HttpSession::load(root.path(), &browser).is_ok());
        let file = super::super::runner::account_profile(root.path(), &browser)
            .unwrap()
            .join("checker-http-session.bin");
        #[cfg(windows)]
        assert!(
            !String::from_utf8_lossy(&std::fs::read(&file).unwrap())
                .contains("synthetic-test-cookie")
        );
        std::fs::write(file, b"corrupt").unwrap();
        assert!(HttpSession::load(root.path(), &browser).is_err());
        session.captured_at = now() - STATIC_AUTH_AGE - 1;
        assert!(session.validate().is_err());
        session = fixture_session();
        session.cookies[0].expires = Some((now() - 1) as f64);
        assert!(session.validate().is_err());
    }
    #[test]
    fn only_verified_cookie_signatures_can_be_renewed() {
        let mut session = fixture_session();
        session.cookies.push(SessionCookie {
            name: "SAPISID".into(),
            value: "synthetic-signing-cookie".into(),
            ..session.cookies[0].clone()
        });
        let timestamp = now().to_string();
        session.request.headers.insert(
            "authorization".into(),
            format!(
                "SAPISIDHASH {timestamp}_{}",
                signature(&timestamp, "synthetic-signing-cookie")
            ),
        );
        let session =
            HttpSession::new(session.request, session.cookies, session.user_agent).unwrap();
        assert_eq!(session.bindings.len(), 1);
        let jar = wreq::cookie::Jar::default();
        jar.add(
            "SAPISID=synthetic-signing-cookie; Domain=google.com; Path=/; Secure",
            ORIGIN,
        );
        assert!(
            session
                .authorization(&jar)
                .unwrap()
                .unwrap()
                .starts_with("SAPISIDHASH ")
        );
        let mut stale = session.clone();
        stale.captured_at = now() - 3600;
        assert!(stale.validate().is_ok());
        stale
            .request
            .headers
            .insert("authorization".into(), "SAPISIDHASH 1_unverified_u".into());
        let unknown = HttpSession::new(stale.request, stale.cookies, stale.user_agent).unwrap();
        assert!(unknown.bindings.is_empty());
    }
}
