use super::{
    runner::{Evidence, Observation, classify, rpc_observation},
    session::{HttpSession, ORIGIN},
};
use crate::checker::verdicts::{AI_STUDIO_URL, AiVerdict};
use anyhow::{Context, Result, ensure};
use futures_util::StreamExt;
use std::{
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use wreq::{Client, Proxy, cookie::Jar, header, redirect::Policy};

const MAX_BODY: usize = 2 * 1024 * 1024;
// A second connector starts only after a negative reply or a slow first request.
const HEDGE_DELAY: Duration = Duration::from_millis(600);
const ROUTE_CHECK_URLS: [&str; 2] = [
    "https://www.gstatic.com/generate_204",
    "https://www.cloudflare.com/cdn-cgi/trace",
];
pub(crate) struct HttpProbe {
    session: HttpSession,
    jar: Arc<Jar>,
    #[cfg(test)]
    trusted_root: Option<Vec<u8>>,
    #[cfg(test)]
    node_id: Option<i64>,
}
impl HttpProbe {
    pub fn fork(&self) -> Self {
        Self {
            session: self.session.clone(),
            jar: Self::cookie_jar(&self.session),
            #[cfg(test)]
            trusted_root: self.trusted_root.clone(),
            #[cfg(test)]
            node_id: self.node_id,
        }
    }
    #[cfg(test)]
    pub(crate) fn synthetic_session() -> Result<Self> {
        Self::new(super::session::fixture_session())
    }
    #[cfg(test)]
    pub(crate) fn synthetic_with_root(cert: Vec<u8>) -> Result<Self> {
        let mut probe = Self::synthetic_session()?;
        probe.trusted_root = Some(cert);
        Ok(probe)
    }

    pub fn load(root: &Path, browser: &Path) -> Result<Self> {
        Self::new(HttpSession::load(root, browser)?)
    }
    fn new(session: HttpSession) -> Result<Self> {
        session.validate()?;
        Ok(Self {
            jar: Self::cookie_jar(&session),
            session,
            #[cfg(test)]
            trusted_root: None,
            #[cfg(test)]
            node_id: None,
        })
    }
    #[cfg(test)]
    pub(crate) fn identify(&mut self, id: i64) {
        self.node_id = Some(id);
    }
    fn cookie_jar(session: &HttpSession) -> Arc<Jar> {
        let jar = Arc::new(Jar::default());
        let current = super::session::now();
        for c in session.cookies.iter().filter(|c| c.valid(current)) {
            let host = c.domain.trim_start_matches('.');
            let mut value = format!("{}={}; Path={}", c.name, c.value, c.path);
            if c.domain.starts_with('.') {
                value.push_str(&format!("; Domain={host}"));
            }
            if c.secure {
                value.push_str("; Secure");
            }
            if let Some(expires) = c.expires {
                value.push_str(&format!(
                    "; Max-Age={}",
                    (expires as u64).saturating_sub(current)
                ));
            }
            jar.add(value.as_str(), format!("https://{host}{}", c.path).as_str());
        }
        jar
    }
    fn client(&self, proxy: &str, budget: Duration) -> Result<Client> {
        // A new connector/TLS session cache for every active node prevents cross-node reuse.
        let builder = Client::builder()
            .emulation(wreq_util::Emulation::Chrome145)
            .no_proxy()
            .proxy(Proxy::all(format!("socks5h://{proxy}"))?.no_proxy(None))
            .cookie_provider(self.jar.clone())
            .redirect(Policy::none())
            .timeout(budget)
            .connect_timeout(budget)
            .pool_max_idle_per_host(0);
        #[cfg(test)]
        let builder = if let Some(cert) = &self.trusted_root {
            builder.tls_cert_store(
                wreq::tls::trust::CertStore::builder()
                    .add_der_cert(cert)
                    .build()?,
            )
        } else {
            builder
        };
        Ok(builder.build()?)
    }
    pub async fn check(&mut self, proxy: &str, budget: Duration) -> Result<Observation> {
        self.jar = Self::cookie_jar(&self.session);
        let started = Instant::now();
        let mut models = futures_util::stream::FuturesUnordered::new();
        models.push(self.check_google(proxy, budget));
        let hedge = tokio::time::sleep(HEDGE_DELAY.min(budget / 3));
        let control_start = tokio::time::sleep(HEDGE_DELAY.min(budget / 3));
        tokio::pin!(hedge, control_start);
        let mut routes = futures_util::stream::FuturesUnordered::new();
        let mut backup_started = false;
        let mut controls_started = false;
        let mut reachable = None;
        let mut observed: Option<Observation> = None;
        loop {
            tokio::select! {
                result = models.next(), if !models.is_empty() => {
                    let next = result.expect("nonempty model requests")?;
                    if next.0 == AiVerdict::Unlocked {
                        return Ok(observed.as_ref().map_or(next.clone(), |first| confirmation_result(first,next)));
                    }
                    if matches!(next.0,AiVerdict::SessionExpired | AiVerdict::RateLimited | AiVerdict::GoogleChallenge | AiVerdict::CheckError) {
                        let mut next=next;next.2=None;return Ok(next);
                    }
                    observed=Some(match observed.take() {
                        None=>next,
                        Some(first)=>{
                            // A timeout cannot erase an actual HTTP/region response.
                            if matches!(next.0,AiVerdict::Timeout | AiVerdict::ConnectionError)
                                && !matches!(first.0,AiVerdict::Timeout | AiVerdict::ConnectionError) {first}
                            else if first.0==AiVerdict::Geoblock && next.0==AiVerdict::AiUnavailable {confirmation_result(&next,first)}
                            else {confirmation_result(&first,next)}
                        }
                    });
                    if !backup_started {
                        let remaining=budget.saturating_sub(started.elapsed());
                        backup_started=true;
                        if !remaining.is_zero() {models.push(self.check_google(proxy,remaining));}
                    }
                }
                _ = &mut hedge, if !backup_started => {
                    backup_started=true;
                    let remaining=budget.saturating_sub(started.elapsed());
                    if !remaining.is_zero() {models.push(self.check_google(proxy,remaining));}
                }
                _ = &mut control_start, if !controls_started => {
                    controls_started=true;
                    routes.push(self.route_reachable(proxy,budget.saturating_sub(started.elapsed())));
                }
                result=routes.next(), if !routes.is_empty() => {reachable=Some(result.expect("nonempty route checks")?);}
            }
            if models.is_empty() && backup_started {
                break;
            }
        }
        let mut observed = observed.context("Model checks produced no observation")?;
        if matches!(observed.0, AiVerdict::Timeout | AiVerdict::ConnectionError) {
            if reachable.is_none() {
                let remaining = budget.saturating_sub(started.elapsed());
                if !controls_started && !remaining.is_zero() {
                    routes.push(self.route_reachable(proxy, remaining));
                }
                if !routes.is_empty() {
                    reachable = tokio::time::timeout(remaining, routes.next())
                        .await
                        .ok()
                        .flatten()
                        .transpose()?;
                }
            }
            if reachable == Some(true) {
                observed = route_without_google();
            }
        }
        observed.2 = None;
        Ok(observed)
    }
    async fn route_reachable(&self, proxy: &str, remaining: Duration) -> Result<bool> {
        if remaining.is_zero() {
            return Ok(false);
        }
        let budget = remaining;
        let client = self.client(proxy, budget)?;
        // These hosts are outside Google account-cookie scope. RPC headers are
        // attached to individual model requests, never to this client.
        let probes = futures_util::stream::FuturesUnordered::new();
        for url in ROUTE_CHECK_URLS {
            let request = client.get(url).header(header::CACHE_CONTROL, "no-cache");
            // TLS is verified: even an origin's 403/429/5xx proves that this
            // route carried HTTPS. A control site's policy is not a dead proxy.
            probes.push(async move { request.send().await.is_ok() });
        }
        let work = async {
            let mut probes = probes;
            while let Some(reachable) = probes.next().await {
                if reachable {
                    return true;
                }
            }
            false
        };
        Ok(tokio::time::timeout(budget, work).await.unwrap_or(false))
    }
    async fn check_google(&self, proxy: &str, budget: Duration) -> Result<Observation> {
        if self.session.validate().is_err() {
            return Ok(observation(
                AiVerdict::SessionExpired,
                "Google session expired; sign in again",
                None,
                AI_STUDIO_URL,
            ));
        }
        let deadline = Instant::now() + budget;
        let work = async {
            let client = self.client(proxy, budget)?;
            let auth = match self.session.authorization(&self.jar) {
                Ok(auth) => auth,
                Err(_) => {
                    return Ok(observation(
                        AiVerdict::SessionExpired,
                        "Google session expired; sign in again",
                        None,
                        AI_STUDIO_URL,
                    ));
                }
            };
            let mut request = client
                .post(&self.session.request.url)
                .header(header::ORIGIN, ORIGIN)
                .header(header::REFERER, format!("{ORIGIN}/"))
                .header(header::CACHE_CONTROL, "no-cache")
                .body(self.session.request.body.clone());
            for (key, value) in &self.session.request.headers {
                let lower = key.to_ascii_lowercase();
                if !(lower.starts_with("sec-") || (lower == "authorization" && auth.is_some()))
                    && !matches!(
                        lower.as_str(),
                        "host"
                            | "cookie"
                            | "origin"
                            | "referer"
                            | "user-agent"
                            | "connection"
                            | "content-length"
                            | "accept-encoding"
                            | "transfer-encoding"
                    )
                {
                    request = request.header(key.as_str(), value.as_str());
                }
            }
            if let Some(auth) = auth {
                request = request.header(header::AUTHORIZATION, auth);
            }
            let started = Instant::now();
            let response = match request.send().await {
                Ok(r) => r,
                Err(e) => return Ok(network_failure(&e)),
            };
            let elapsed_ms = elapsed(started);
            let status = response.status().as_u16();
            if status == 401 || status == 404 {
                return Ok(observation(
                    AiVerdict::SessionExpired,
                    "Google session expired; sign in again",
                    Some(elapsed_ms),
                    AI_STUDIO_URL,
                ));
            }
            if response.status().is_redirection() {
                return self.frontend(&client, deadline).await;
            }
            let body = match read_body(response).await {
                Ok(body) => body,
                Err(error) => return Ok(error),
            };
            let reply = super::rpc::Reply {
                status,
                body,
                elapsed_ms,
                error: None,
                network_error: None,
            };
            #[cfg(test)]
            self.record_live_reply(&reply);
            let observed = rpc_observation(&reply);
            if observed.0 == AiVerdict::Inconclusive {
                Ok(observation(
                    AiVerdict::AiUnavailable,
                    &rust_i18n::t!(
                        "AI Studio: HTTP %{status}; no model response received",
                        status = status
                    ),
                    None,
                    AI_STUDIO_URL,
                ))
            } else {
                Ok(observed)
            }
        };
        match tokio::time::timeout(budget, work).await {
            Ok(result) => result,
            Err(_) => Ok(observation(
                AiVerdict::Timeout,
                "The AI Studio request timed out",
                None,
                AI_STUDIO_URL,
            )),
        }
    }
    async fn frontend(&self, client: &Client, deadline: Instant) -> Result<Observation> {
        let mut url = url::Url::parse(AI_STUDIO_URL)?;
        for _ in 0..5 {
            ensure!(frontend_url(&url), "Unexpected AI Studio redirect");
            let verdict = classify(&Evidence {
                url: url.to_string(),
                ..Default::default()
            });
            if matches!(
                verdict,
                AiVerdict::Geoblock | AiVerdict::SessionExpired | AiVerdict::GoogleChallenge
            ) {
                return Ok(observation(
                    verdict,
                    "AI Studio: page response / redirect",
                    None,
                    &public_url(&url),
                ));
            }
            let started = Instant::now();
            let response = match client
                .get(url.as_str())
                .timeout(deadline.saturating_duration_since(Instant::now()))
                .send()
                .await
            {
                Ok(response) => response,
                Err(error) => return Ok(network_failure(&error)),
            };
            let latency = elapsed(started);
            let status = response.status().as_u16();
            if response.status().is_redirection() {
                let next = response
                    .headers()
                    .get(header::LOCATION)
                    .context("Missing redirect location")?
                    .to_str()?;
                ensure!(next.len() <= 8192, "Redirect too large");
                url = url.join(next)?;
                continue;
            }
            if status == 429 {
                return Ok(observation(
                    AiVerdict::RateLimited,
                    "Google temporarily rate-limited requests",
                    Some(latency),
                    AI_STUDIO_URL,
                ));
            }
            if status == 401 {
                return Ok(observation(
                    AiVerdict::SessionExpired,
                    "Google session expired; sign in again",
                    Some(latency),
                    AI_STUDIO_URL,
                ));
            }
            // A static HTML shell may contain regional links or localized messages in
            // scripts. Only the actual redirect or model reply can establish a region.
            drop(response);
            let verdict = AiVerdict::AiUnavailable;
            return Ok(observation(
                verdict,
                "AI Studio: page responded; model access remains unconfirmed",
                Some(latency),
                &public_url(&url),
            ));
        }
        Ok(observation(
            AiVerdict::AiUnavailable,
            "AI Studio: too many redirects",
            None,
            AI_STUDIO_URL,
        ))
    }
}
fn route_without_google() -> Observation {
    observation(
        AiVerdict::AiUnavailable,
        "The proxy passes HTTPS traffic, but Google AI Studio is unavailable",
        None,
        AI_STUDIO_URL,
    )
}
#[cfg(test)]
impl HttpProbe {
    fn record_live_reply(&self, reply: &super::rpc::Reply) {
        use std::io::Write;
        let Some(path) = std::env::var_os("CHECKER_LIVE_HTTP_LOG") else {
            return;
        };
        let value = serde_json::from_str::<serde_json::Value>(&reply.body).ok();
        let error = value.as_ref().and_then(|v| v.get("error"));
        let message = error
            .and_then(|e| e.get("message"))
            .and_then(|v| v.as_str())
            .map(|s| s.chars().take(256).collect::<String>());
        let title = reply
            .body
            .split_once("<title>")
            .and_then(|(_, s)| s.split_once("</title>"))
            .map(|(s, _)| s.chars().take(100).collect::<String>());
        let record = serde_json::json!({"profile_id":self.node_id,"status":reply.status,"elapsed_ms":reply.elapsed_ms,"bytes":reply.body.len(),"json":value.is_some(),"error_code":error.and_then(|e|e.get("code")),"error_status":error.and_then(|e|e.get("status")),"message":message,"title":title,"small_reply":(reply.status!=200 && reply.body.len()<512).then_some(&reply.body)});
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let mut bytes = serde_json::to_vec(&record).unwrap();
            bytes.push(b'\n');
            let _ = file.write_all(&bytes);
        }
    }
}
fn elapsed(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}
fn confirmation_result(first: &Observation, mut result: Observation) -> Observation {
    result.1 = rust_i18n::t!(
        "Confirmation request: %{result}; first response: %{first}",
        result = &result.1,
        first = &first.1
    )
    .to_string();
    result
}
fn observation(verdict: AiVerdict, detail: &str, latency: Option<u64>, url: &str) -> Observation {
    (verdict, detail.into(), latency, Some(url.into()))
}
fn public_url(url: &url::Url) -> String {
    let mut url = url.clone();
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}
fn frontend_url(url: &url::Url) -> bool {
    url.scheme() == "https"
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && matches!(
            url.host_str(),
            Some(
                "aistudio.google.com" | "ai.google.dev" | "accounts.google.com" | "www.google.com"
            )
        )
}
fn network_failure(error: &wreq::Error) -> Observation {
    // Do not print request URLs, Authorization, API keys or raw error chains.
    let (verdict, detail) = if error.is_timeout() {
        (AiVerdict::Timeout, "The AI Studio request timed out")
    } else if error.is_connect()
        || error.is_proxy_connect()
        || error.is_tls()
        || error.is_dns()
        || error.is_connection_reset()
    {
        (
            AiVerdict::ConnectionError,
            "AI Studio: SOCKS / DNS / TCP / TLS connection failed",
        )
    } else {
        (AiVerdict::CheckError, "AI Studio: HTTP transport error")
    };
    observation(verdict, detail, None, AI_STUDIO_URL)
}
async fn read_body(response: wreq::Response) -> std::result::Result<String, Observation> {
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| network_failure(&e))?;
        if body.len().saturating_add(chunk.len()) > MAX_BODY {
            return Err(observation(
                AiVerdict::CheckError,
                "AI Studio: response too large",
                None,
                AI_STUDIO_URL,
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    struct LocalHttps {
        proxy: String,
        cert: Vec<u8>,
        requests: Arc<std::sync::Mutex<Vec<String>>>,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for LocalHttps {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    type FixtureReply = (u16, String, Option<String>);
    async fn https_fixture(replies: Vec<FixtureReply>) -> LocalHttps {
        let mut replies = std::collections::VecDeque::from(replies);
        https_responder(move |_| replies.pop_front()).await
    }
    async fn https_responder(
        reply: impl FnMut(&str) -> Option<FixtureReply> + Send + 'static,
    ) -> LocalHttps {
        https_responder_with_delay(reply, Duration::ZERO).await
    }
    async fn https_responder_with_delay(
        mut reply: impl FnMut(&str) -> Option<FixtureReply> + Send + 'static,
        delay: Duration,
    ) -> LocalHttps {
        use tokio_rustls::rustls::{ServerConfig, pki_types::PrivatePkcs8KeyDer};
        let certified = rcgen::generate_simple_self_signed(vec![
            "alkalimakersuite-pa.clients6.google.com".into(),
            "aistudio.google.com".into(),
            "www.gstatic.com".into(),
            "www.cloudflare.com".into(),
        ])
        .unwrap();
        let cert = certified.cert.der().to_vec();
        let config = ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certified.cert.der().clone()],
            PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()).into(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap().to_string();
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let task = tokio::spawn(async move {
            'connections: loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut hello = [0; 2];
                if stream.read_exact(&mut hello).await.is_err() {
                    continue;
                }
                let mut methods = vec![0; hello[1] as usize];
                if stream.read_exact(&mut methods).await.is_err() {
                    continue;
                }
                if stream.write_all(&[5, 0]).await.is_err() {
                    continue;
                }
                let mut request = [0; 5];
                if stream.read_exact(&mut request).await.is_err() {
                    continue;
                }
                assert_eq!(&request[..4], &[5, 1, 0, 3]);
                let mut target = vec![0; request[4] as usize + 2];
                if stream.read_exact(&mut target).await.is_err() {
                    continue;
                }
                let host = std::str::from_utf8(&target[..target.len() - 2]).unwrap();
                let Some((status, body, location)) = reply(host) else {
                    break;
                };
                if status == 0 {
                    stream
                        .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                        .await
                        .unwrap();
                    continue;
                }
                stream
                    .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
                    .await
                    .unwrap();
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    continue;
                };
                let mut bytes = Vec::new();
                let mut buffer = [0; 4096];
                loop {
                    let n = match tls.read(&mut buffer).await {
                        Ok(n) => n,
                        Err(_) => continue 'connections,
                    };
                    if n == 0 {
                        continue 'connections;
                    }
                    bytes.extend_from_slice(&buffer[..n]);
                    assert!(bytes.len() < 512 * 1024);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let text = String::from_utf8_lossy(&bytes[..end]);
                        let len = text
                            .lines()
                            .find_map(|line| {
                                line.split_once(':')
                                    .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                                    .map(|(_, v)| v.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if bytes.len() >= end + 4 + len {
                            break;
                        }
                    }
                }
                recorded
                    .lock()
                    .unwrap()
                    .push(String::from_utf8(bytes).unwrap());
                let location = location.map_or(String::new(), |s| format!("Location: {s}\r\n"));
                let wire = format!(
                    "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\n{location}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                tokio::time::sleep(delay).await;
                let _ = tls.write_all(wire.as_bytes()).await;
                let _ = tls.shutdown().await;
            }
        });
        LocalHttps {
            proxy,
            cert,
            requests,
            task,
        }
    }
    #[tokio::test]
    async fn slow_primary_model_response_keeps_its_full_original_deadline() {
        let fixture = https_responder_with_delay(
            |_| {
                Some((
                    200,
                    r#"{"models":[{"name":"slow-working-model"}]}"#.into(),
                    None,
                ))
            },
            Duration::from_millis(460),
        )
        .await;
        let mut probe = HttpProbe::synthetic_with_root(fixture.cert.clone()).unwrap();
        let started = Instant::now();
        let result = probe
            .check(&fixture.proxy, Duration::from_millis(600))
            .await
            .unwrap();
        assert_eq!(
            result.0,
            AiVerdict::Unlocked,
            "Do not cancel a working request after two thirds of its deadline"
        );
        assert!(started.elapsed() < Duration::from_millis(800));
    }
    #[tokio::test]
    async fn stalled_first_connector_is_hedged_without_waiting_for_the_timeout() {
        let fixture = https_responder(|host| {
            Some(if host.contains("alkalimakersuite") {
                (200, r#"{"models":[{"name":"working-model"}]}"#.into(), None)
            } else {
                (204, String::new(), None)
            })
        })
        .await;
        let target = fixture.proxy.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap().to_string();
        let relay = tokio::spawn(async move {
            let (_stalled, _) = listener.accept().await.unwrap();
            let mut clients = tokio::task::JoinSet::new();
            loop {
                let (mut incoming, _) = listener.accept().await.unwrap();
                let target = target.clone();
                clients.spawn(async move {
                    let mut outgoing = tokio::net::TcpStream::connect(target).await.unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut incoming, &mut outgoing).await;
                });
            }
        });
        let mut probe = HttpProbe::synthetic_with_root(fixture.cert.clone()).unwrap();
        let started = Instant::now();
        let result = probe.check(&proxy, Duration::from_secs(2)).await.unwrap();
        assert_eq!(result.0, AiVerdict::Unlocked);
        assert!(
            started.elapsed() < Duration::from_millis(1500),
            "A stalled TCP/SOCKS connection must not consume the entire node deadline"
        );
        assert_eq!(
            fixture
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|request| request.starts_with("POST "))
                .count(),
            1
        );
        relay.abort();
    }
    #[tokio::test]
    async fn slow_working_connectivity_control_does_not_become_a_dead_proxy() {
        let fixture = https_responder_with_delay(
            |host| {
                if host.contains("alkalimakersuite") {
                    Some((0, String::new(), None))
                } else {
                    Some((204, String::new(), None))
                }
            },
            Duration::from_millis(1200),
        )
        .await;
        let mut probe = HttpProbe::synthetic_with_root(fixture.cert.clone()).unwrap();
        let result = probe
            .check(&fixture.proxy, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(
            result.0,
            AiVerdict::AiUnavailable,
            "A working HTTPS control gets the remaining node deadline, not an arbitrary one-second cap"
        );
    }
    #[tokio::test]
    async fn a_verified_control_http_refusal_still_proves_the_proxy_is_alive() {
        let fixture = https_responder(|host| {
            Some(if host.contains("alkalimakersuite") {
                (0, String::new(), None)
            } else {
                (403, "Control-site policy refusal".into(), None)
            })
        })
        .await;
        let mut probe = HttpProbe::synthetic_with_root(fixture.cert.clone()).unwrap();
        assert_eq!(
            probe
                .check(&fixture.proxy, Duration::from_secs(2))
                .await
                .unwrap()
                .0,
            AiVerdict::AiUnavailable
        );
    }
    #[tokio::test]
    async fn compact_region_reply_is_confirmed_and_transient_region_errors_can_recover() {
        for recover in [false, true] {
            let second = if recover {
                (200, r#"{"models":[{"name":"working-model"}]}"#.into(), None)
            } else {
                (403, r#"[7,"Region not supported."]"#.into(), None)
            };
            let fixture = https_fixture(vec![
                (403, r#"[7,"Region not supported."]"#.into(), None),
                second,
            ])
            .await;
            let mut probe = HttpProbe::synthetic_with_root(fixture.cert.clone()).unwrap();
            let result = probe
                .check(&fixture.proxy, Duration::from_secs(2))
                .await
                .unwrap();
            assert_eq!(
                result.0,
                if recover {
                    AiVerdict::Unlocked
                } else {
                    AiVerdict::Geoblock
                }
            );
            assert_eq!(fixture.requests.lock().unwrap().len(), 2);
        }
    }
    #[tokio::test]
    async fn real_wreq_https_preserves_model_region_auth_and_uncertainty_verdicts() {
        let cases = [
            (vec![(200, r#"{"models":[{"name":"test-model"}]}"#.into(), None)], AiVerdict::Unlocked),
            (vec![(403, r#"{"error":{"message":"User location is not supported"}}"#.into(), None)], AiVerdict::Geoblock),
            (vec![(401, "{}".into(), None)], AiVerdict::SessionExpired),
            (vec![(429, "{}".into(), None)], AiVerdict::RateLimited),
            (vec![(503, "{}".into(), None), (503, "{}".into(), None)], AiVerdict::AiUnavailable),
            (vec![(403, "permission denied".into(), None), (403, "permission denied".into(), None)], AiVerdict::AiUnavailable),
            (vec![(302, "".into(), None), (302, "".into(), Some("https://ai.google.dev/gemini-api/docs/available-regions".into()))], AiVerdict::Geoblock),
            (vec![(302, "".into(), None), (302, "".into(), Some("https://accounts.google.com/ServiceLogin".into()))], AiVerdict::SessionExpired),
            (vec![(302, "".into(), None), (200, "<script>const regionalTemplate='available-regions';</script><a href='/available-regions'>Regions</a>".into(), None), (403, "permission denied".into(), None)], AiVerdict::AiUnavailable),
            (vec![(200, "Our systems have detected unusual traffic".into(), None)], AiVerdict::GoogleChallenge),
        ];
        for (responses, expected) in cases {
            let count = responses.len();
            let fixture = https_fixture(responses).await;
            let mut session = super::super::session::fixture_session();
            session.cookies.push(super::super::session::SessionCookie {
                name: "host-only".into(),
                value: "aistudio-only-fixture".into(),
                domain: "aistudio.google.com".into(),
                ..session.cookies[0].clone()
            });
            session
                .request
                .headers
                .insert("authorization".into(), "fixture-auth".into());
            let mut probe = HttpProbe::new(session).unwrap();
            probe.trusted_root = Some(fixture.cert.clone());
            let result = probe
                .check(&fixture.proxy, Duration::from_secs(3))
                .await
                .unwrap();
            assert_eq!(result.0, expected, "{result:?}");
            assert_eq!(fixture.requests.lock().unwrap().len(), count);
            let requests = fixture.requests.lock().unwrap();
            assert!(
                requests[0]
                    .to_ascii_lowercase()
                    .contains("authorization: fixture-auth")
            );
            assert!(requests[0].contains("synthetic-test-cookie"));
            assert!(
                !requests[0].contains("aistudio-only-fixture"),
                "Host-only cookies must not reach a sibling Google host"
            );
            if requests.len() > 1 && requests[1].starts_with("GET ") {
                assert!(
                    !requests[1].to_ascii_lowercase().contains("authorization:"),
                    "RPC authorization must not be copied to a document request"
                );
                assert!(requests[1].contains("synthetic-test-cookie"));
                assert!(requests[1].contains("aistudio-only-fixture"));
            }
        }
    }
    #[tokio::test]
    async fn transient_google_refusals_are_confirmed_without_penalizing_success_or_terminal_results()
     {
        for status in [403, 503, 200] {
            let fixture = https_fixture(vec![
                (status, "temporary incomplete reply".into(), None),
                (200, r#"{"models":[{"name":"working-model"}]}"#.into(), None),
            ])
            .await;
            let mut probe = HttpProbe::synthetic_session().unwrap();
            probe.trusted_root = Some(fixture.cert.clone());
            let result = probe
                .check(&fixture.proxy, Duration::from_secs(2))
                .await
                .unwrap();
            assert_eq!(result.0, AiVerdict::Unlocked);
            assert!(result.2.is_some());
            assert!(
                result.1.contains(&status.to_string()),
                "Keep the original HTTP failure in the saved diagnostic"
            );
            let requests = fixture.requests.lock().unwrap();
            assert_eq!(requests.len(), 2);
            assert!(requests.iter().all(|r| r.starts_with("POST ")));
        }
        // A stable generic refusal is tested twice, never turned into success.
        let fixture = https_fixture(vec![(403, "permission denied".into(), None); 2]).await;
        let mut probe = HttpProbe::synthetic_session().unwrap();
        probe.trusted_root = Some(fixture.cert.clone());
        assert_eq!(
            probe
                .check(&fixture.proxy, Duration::from_secs(2))
                .await
                .unwrap()
                .0,
            AiVerdict::AiUnavailable
        );
        assert_eq!(fixture.requests.lock().unwrap().len(), 2);

        // A failed confirmation cannot erase the first real HTTP response and
        // relabel a reachable node as disconnected.
        let fixture = https_fixture(vec![
            (403, "permission denied".into(), None),
            (0, String::new(), None),
        ])
        .await;
        let mut probe = HttpProbe::synthetic_session().unwrap();
        probe.trusted_root = Some(fixture.cert.clone());
        assert_eq!(
            probe
                .check(&fixture.proxy, Duration::from_secs(2))
                .await
                .unwrap()
                .0,
            AiVerdict::AiUnavailable
        );
        assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn transient_transport_failure_can_recover_before_connectivity_controls_finish() {
        let mut models = 0;
        let fixture = https_responder(move |host| {
            if host.starts_with("alkalimakersuite-") {
                models += 1;
                Some(if models == 1 {
                    (0, String::new(), None)
                } else {
                    (200, r#"{"models":[{"name":"recovered"}]}"#.into(), None)
                })
            } else {
                Some((0, String::new(), None))
            }
        })
        .await;
        let mut probe = HttpProbe::synthetic_session().unwrap();
        probe.trusted_root = Some(fixture.cert.clone());
        let result = probe
            .check(&fixture.proxy, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(result.0, AiVerdict::Unlocked);
        assert!(result.2.is_some());
        assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn cookie_changes_from_one_node_cannot_poison_the_next_node() {
        let fixture =
            https_fixture(vec![(200, r#"{"models":[{"name":"ok"}]}"#.into(), None); 2]).await;
        let mut probe = HttpProbe::synthetic_session().unwrap();
        probe.trusted_root = Some(fixture.cert.clone());
        assert_eq!(
            probe
                .check(&fixture.proxy, Duration::from_secs(2))
                .await
                .unwrap()
                .0,
            AiVerdict::Unlocked
        );
        probe.jar.add(
            "route-state=previous-node; Domain=google.com; Path=/; Secure",
            ORIGIN,
        );
        assert!(probe.jar.matches(ORIGIN).any(|c| c.name() == "route-state"));
        assert_eq!(
            probe
                .check(&fixture.proxy, Duration::from_secs(2))
                .await
                .unwrap()
                .0,
            AiVerdict::Unlocked
        );
        let requests = fixture.requests.lock().unwrap();
        assert_eq!(
            requests.len(),
            2,
            "Successful nodes must keep the single-request fast path"
        );
        assert!(
            requests
                .iter()
                .all(|r| r.contains("synthetic-test-cookie") && !r.contains("previous-node"))
        );
    }

    #[tokio::test]
    async fn untrusted_tls_is_rejected_without_disabling_verification() {
        let fixture =
            https_fixture(vec![(200, r#"{"models":[{"name":"test"}]}"#.into(), None)]).await;
        let mut probe = HttpProbe::new(super::super::session::fixture_session()).unwrap();
        let result = probe
            .check(&fixture.proxy, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(result.0, AiVerdict::ConnectionError);
        assert!(fixture.requests.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn google_transport_failure_with_working_https_route_is_ai_unavailable() {
        let fixture = https_responder(|host| {
            Some(if host.starts_with("alkalimakersuite-") {
                (0, String::new(), None)
            } else {
                (204, String::new(), None)
            })
        })
        .await;

        let mut session = super::super::session::fixture_session();
        session
            .request
            .headers
            .insert("authorization".into(), "fixture-auth".into());
        let mut probe = HttpProbe::new(session).unwrap();
        probe.trusted_root = Some(fixture.cert.clone());
        let result = probe
            .check(&fixture.proxy, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(result.0, AiVerdict::AiUnavailable);
        assert_eq!(result.2, None);
        let requests = fixture.requests.lock().unwrap();
        assert!(!requests.is_empty());
        assert!(requests.iter().all(|r| r.starts_with("GET ")));
        assert!(!requests[0].to_ascii_lowercase().contains("authorization:"));
        assert!(!requests[0].contains("synthetic-test-cookie"));
    }
    #[tokio::test]
    async fn renewed_authorization_is_sent_once_and_redirects_cannot_receive_it() {
        use sha1::{Digest, Sha1};
        let fixture = https_fixture(vec![
            (302, "".into(), None),
            (
                302,
                "".into(),
                Some("https://evil.test/ListModels?secret=fixture".into()),
            ),
        ])
        .await;
        let mut session = super::super::session::fixture_session();
        session.cookies.push(super::super::session::SessionCookie {
            name: "SAPISID".into(),
            value: "synthetic-signing-value".into(),
            ..session.cookies[0].clone()
        });
        let timestamp = super::super::session::now();
        let hash = format!(
            "{:x}",
            Sha1::digest(format!("{timestamp} synthetic-signing-value {ORIGIN}"))
        );
        session.request.headers.insert(
            "authorization".into(),
            format!("SAPISIDHASH {timestamp}_{hash}"),
        );
        let session =
            HttpSession::new(session.request, session.cookies, session.user_agent).unwrap();
        let mut probe = HttpProbe::new(session).unwrap();
        probe.trusted_root = Some(fixture.cert.clone());
        assert!(
            probe
                .check(&fixture.proxy, Duration::from_secs(2))
                .await
                .is_err()
        );
        let requests = fixture.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0]
                .lines()
                .filter(|line| line.to_ascii_lowercase().starts_with("authorization:"))
                .count(),
            1
        );
        assert!(!requests[1].to_ascii_lowercase().contains("authorization:"));
    }
    #[tokio::test]
    async fn wreq_socks_is_remote_dns_and_recreated_for_each_node() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            for _ in 0..8 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut hello = [0; 2];
                stream.read_exact(&mut hello).await.unwrap();
                assert_eq!(hello[0], 5);
                let mut methods = vec![0; hello[1] as usize];
                stream.read_exact(&mut methods).await.unwrap();
                stream.write_all(&[5, 0]).await.unwrap();
                let mut request = [0; 5];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(&request[..4], &[5, 1, 0, 3]);
                let mut host = vec![0; request[4] as usize];
                stream.read_exact(&mut host).await.unwrap();
                assert!(matches!(
                    String::from_utf8(host).unwrap().as_str(),
                    "alkalimakersuite-pa.clients6.google.com"
                        | "www.gstatic.com"
                        | "www.cloudflare.com"
                ));
                let mut port = [0; 2];
                stream.read_exact(&mut port).await.unwrap();
                assert_eq!(u16::from_be_bytes(port), 443);
                stream
                    .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
            }
        });
        let mut probe = HttpProbe::new(super::super::session::fixture_session()).unwrap();
        let start = Instant::now();
        for _ in 0..2 {
            let observed = probe.check(&proxy, Duration::from_secs(2)).await.unwrap();
            assert_eq!(observed.0, AiVerdict::ConnectionError);
        }
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
        println!(
            "WREQ two synthetic refused-SOCKS checks: {} ms",
            start.elapsed().as_millis()
        );
    }
    #[tokio::test]
    async fn silent_proxy_is_timeout_and_cancellation_drops_the_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap().to_string();
        let mut probe = HttpProbe::new(super::super::session::fixture_session()).unwrap();
        let check = tokio::spawn(async move { probe.check(&proxy, Duration::from_secs(2)).await });
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = [0; 64];
        assert!(stream.read(&mut bytes).await.unwrap() > 0);
        check.abort();
        let _ = check.await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), stream.read(&mut bytes))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        let mut probe = HttpProbe::new(super::super::session::fixture_session()).unwrap();
        let proxy = listener.local_addr().unwrap().to_string();
        let started = Instant::now();
        let observed = probe
            .check(&proxy, Duration::from_millis(150))
            .await
            .unwrap();
        assert_eq!(observed.0, AiVerdict::Timeout);
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "Confirmation exceeded the original 150 ms attempt deadline"
        );
    }
    #[test]
    fn redirects_are_bounded_to_google_and_diagnostics_strip_queries() {
        for bad in [
            "https://evil.test/available-regions",
            "http://aistudio.google.com",
            "https://accounts.google.com.evil.test",
            "https://user@aistudio.google.com",
        ] {
            assert!(!frontend_url(&url::Url::parse(bad).unwrap()));
        }
        let url = url::Url::parse("https://aistudio.google.com/app?token=secret#secret").unwrap();
        assert_eq!(public_url(&url), "https://aistudio.google.com/app");
    }
}
