use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// Session-bearing request data lives only in memory and intentionally has no Debug implementation.
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct ModelRequest {
    pub url: String,
    pub method: String,
    pub headers: BTreeMap<String, String>,
    pub body: String,
}
impl ModelRequest {
    pub fn validate(&self) -> bool {
        let Ok(url) = url::Url::parse(&self.url) else {
            return false;
        };
        url.scheme() == "https"
            && url.port_or_known_default() == Some(443)
            && matches!(
                url.host_str(),
                Some(
                    "alkalimakersuite-pa.clients6.google.com"
                        | "alkalimakersuite-pa.googleapis.com"
                )
            )
            && url.path().ends_with("/ListModels")
            && url.username().is_empty()
            && url.password().is_none()
            && self.method == "POST"
            && self.body.len() <= 256 * 1024
            && self.headers.len() <= 64
            && self
                .headers
                .iter()
                .all(|(k, v)| k.len() < 256 && v.len() < 16384 && !v.contains(['\r', '\n']))
    }
}
#[derive(Deserialize)]
pub(super) struct Reply {
    pub status: u16,
    pub body: String,
    pub elapsed_ms: u64,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub network_error: Option<String>,
}

pub(super) fn model_list(body: &str) -> bool {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(
        body.trim_start().trim_start_matches(")]}'").trim_start(),
    ) else {
        return false;
    };
    if json.get("error").is_some() {
        return false;
    }
    json.get("models")
        .and_then(|v| v.as_array())
        .is_some_and(|models| {
            models.iter().any(|m| {
                m.get("name")
                    .and_then(|n| n.as_str())
                    .is_some_and(|s| !s.is_empty())
            })
        })
        || json
            .get(0)
            .and_then(|v| v.as_array())
            .is_some_and(|models| {
                models.iter().any(|m| {
                    m.as_array().is_some_and(|m| {
                        m.first()
                            .and_then(|n| n.as_str())
                            .is_some_and(|s| !s.is_empty())
                    })
                })
            })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_nonempty_recognized_model_lists_confirm_access() {
        for body in [
            r#"{"models":[{"name":"models/test"}]}"#,
            r#"[[["models/test",null]]]"#,
            ")]}'\n{\"models\":[{\"name\":\"test\"}]}",
        ] {
            assert!(model_list(body));
        }
        for body in [
            "null",
            "[]",
            "{}",
            r#"{"models":[]}"#,
            r#"[null,[7,"permission denied"]]"#,
            r#"[["error"]]"#,
            r#"{"error":{},"models":[{"name":"test"}]}"#,
        ] {
            assert!(!model_list(body));
        }
    }
    #[test]
    fn captured_credentials_can_only_be_sent_to_the_expected_google_rpc() {
        let mut request = ModelRequest {
            url: "https://alkalimakersuite-pa.clients6.google.com/$rpc/service/ListModels".into(),
            method: "POST".into(),
            headers: BTreeMap::new(),
            body: "[]".into(),
        };
        assert!(request.validate());
        for url in [
            "https://evil.test/ListModels",
            "https://alkalimakersuite-pa.clients6.google.com.evil.test/ListModels",
            "http://alkalimakersuite-pa.clients6.google.com/ListModels",
            "https://alkalimakersuite-pa.clients6.google.com:8443/ListModels",
            "https://user@alkalimakersuite-pa.clients6.google.com/ListModels",
            "https://alkalimakersuite-pa.clients6.google.com/GenerateContent",
        ] {
            request.url = url.into();
            assert!(!request.validate());
        }
    }
}
