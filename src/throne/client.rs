use crate::throne::models::{
    Group, GroupsResponse, Profile, ProfilesResponse, Status, WireRequest, WireResponse,
};
use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

type HmacSha256 = Hmac<Sha256>;

/// An authenticated server response rejecting a connection request, not a transport error.
#[derive(Debug)]
pub struct ConnectionRejected {
    pub status: u16,
    pub code: String,
    pub message: String,
}
impl std::fmt::Display for ConnectionRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Throne отклонил запуск ({} / {}): {}",
            self.status, self.code, self.message
        )
    }
}
impl std::error::Error for ConnectionRejected {}

pub struct ThroneClient {
    stream: TcpStream,
    k_c2s: [u8; 32],
    k_s2c: [u8; 32],
    counter_c2s: u64,
    counter_s2c: u64,
    valid: bool,
}

impl ThroneClient {
    pub(super) fn reusable(&self) -> bool {
        self.valid
    }
    /// Connects to Throne wire protocol server and executes cryptographic handshake
    pub async fn connect(addr: &str, key_str: &str, timeout_dur: Duration) -> Result<Self> {
        let key_bytes = parse_key(key_str)?;
        let stream = timeout(timeout_dur, TcpStream::connect(addr))
            .await
            .context("TCP connect timeout")?
            .context("Failed to connect to Throne TCP API")?;
        stream.set_nodelay(true)?;

        let mut client = Self {
            stream,
            k_c2s: [0u8; 32],
            k_s2c: [0u8; 32],
            counter_c2s: 0,
            counter_s2c: 0,
            valid: true,
        };

        timeout(timeout_dur, client.handshake(&key_bytes))
            .await
            .context("Throne handshake timeout")?
            .context("Throne handshake failed")?;

        Ok(client)
    }

    async fn handshake(&mut self, key: &[u8; 32]) -> Result<()> {
        // 1. Generate client random C (16 bytes) and send ClientHello (0x01 || C)
        let mut c = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut c);

        let mut client_hello = [0u8; 17];
        client_hello[0] = 0x01;
        client_hello[1..].copy_from_slice(&c);

        self.stream.write_all(&client_hello).await?;
        self.stream.flush().await?;

        // 2. Read ServerHello S (16 bytes)
        let mut s = [0u8; 16];
        self.stream.read_exact(&mut s).await?;

        // 3. Derive keys
        let (k_c2s, k_s2c) = derive_keys(key, &s, &c)?;
        self.k_c2s = k_c2s;
        self.k_s2c = k_s2c;
        self.counter_c2s = 0;
        self.counter_s2c = 0;

        Ok(())
    }

    /// Sends an encrypted frame with a JSON request and receives an encrypted frame with the response
    pub async fn call(&mut self, req: &WireRequest, req_timeout: Duration) -> Result<WireResponse> {
        let body_bytes = serde_json::to_vec(req)?;
        if !self.valid {
            return Err(anyhow!("Throne connection closed after a protocol error"));
        }
        // An externally cancelled exchange leaves an unread response/counter gap.
        // Only a completely authenticated response makes the stream reusable.
        self.valid = false;
        let exchange = async {
            self.send_frame(&body_bytes).await?;
            let bytes = self.recv_frame().await?;
            serde_json::from_slice(&bytes).context("Invalid JSON response")
        };
        let result = match timeout(req_timeout, exchange).await {
            Ok(result) => result,
            Err(_) => Err(anyhow!("Timeout waiting for Throne response")),
        };
        self.valid = result.is_ok();
        if result.is_err() {
            self.valid = false;
            let _ = self.stream.shutdown().await;
        }
        result
    }

    async fn send_frame(&mut self, plaintext: &[u8]) -> Result<()> {
        let wire = seal_frame(&self.k_c2s, self.counter_c2s, plaintext, 1024 * 1024)?;

        self.counter_c2s = self
            .counter_c2s
            .checked_add(1)
            .ok_or_else(|| anyhow!("Send counter overflow"))?;

        self.stream.write_all(&wire).await?;
        self.stream.flush().await?;

        Ok(())
    }

    async fn recv_frame(&mut self) -> Result<Vec<u8>> {
        let mut aad = [0u8; 4];
        self.stream.read_exact(&mut aad).await?;
        let sealed_len = u32::from_be_bytes(aad) as usize;

        if !(16..=64 * 1024 * 1024).contains(&sealed_len) {
            return Err(anyhow!("Received frame length out of bounds: {sealed_len}"));
        }

        let mut sealed = vec![0u8; sealed_len];
        self.stream.read_exact(&mut sealed).await?;

        let wire = [aad.as_slice(), sealed.as_slice()].concat();
        let plaintext = open_frame(&self.k_s2c, self.counter_s2c, &wire, 64 * 1024 * 1024)?;

        self.counter_s2c = self
            .counter_s2c
            .checked_add(1)
            .ok_or_else(|| anyhow!("Recv counter overflow"))?;

        Ok(plaintext)
    }

    pub async fn get_status(&mut self) -> Result<Status> {
        let req = WireRequest {
            method: "GET".to_string(),
            path: "/v1/status".to_string(),
            query: None,
            body: None,
        };
        let res = self.call(&req, Duration::from_secs(5)).await?;
        if res.status == 200
            && let Some(body) = res.body
        {
            let status: Status = serde_json::from_value(body)?;
            return Ok(status);
        }
        Err(anyhow!(
            "Failed to get status, error: {:?}",
            res.error.map(|e| e.message)
        ))
    }

    pub async fn get_groups(&mut self) -> Result<Vec<Group>> {
        let req = WireRequest {
            method: "GET".to_string(),
            path: "/v1/groups".to_string(),
            query: None,
            body: None,
        };
        let res = self.call(&req, Duration::from_secs(5)).await?;
        if res.status == 200
            && let Some(body) = res.body
        {
            let groups: GroupsResponse = serde_json::from_value(body)?;
            return Ok(groups.groups);
        }
        Err(anyhow!(
            "Failed to get groups, error: {:?}",
            res.error.map(|e| e.message)
        ))
    }

    pub async fn get_profiles(&mut self, group_id: Option<i64>) -> Result<Vec<Profile>> {
        let mut query = HashMap::new();
        if let Some(gid) = group_id {
            query.insert("group".to_string(), gid.to_string());
        }

        let req = WireRequest {
            method: "GET".to_string(),
            path: "/v1/profiles".to_string(),
            query: if query.is_empty() { None } else { Some(query) },
            body: None,
        };

        let res = self.call(&req, Duration::from_secs(10)).await?;
        if res.status == 200
            && let Some(body) = res.body
        {
            let profiles: ProfilesResponse = serde_json::from_value(body)?;
            return Ok(profiles.profiles);
        }
        Err(anyhow!(
            "Failed to get profiles, error: {:?}",
            res.error.map(|e| e.message)
        ))
    }

    pub async fn import(&mut self, input: &str) -> Result<usize> {
        let input = input.trim();
        if input.is_empty() {
            anyhow::bail!("Пустая подписка");
        }
        let body = if input.starts_with("https://") || input.starts_with("http://") {
            serde_json::json!({"as": "url", "url": input, "wait": true, "timeout": 60})
        } else {
            serde_json::json!({"as": "profiles", "text": input, "wait": true, "timeout": 60})
        };
        let request = WireRequest {
            method: "POST".into(),
            path: "/v1/import".into(),
            query: None,
            body: Some(body),
        };
        // beta.3 limits management import payloads to 900 KiB. A URL import is
        // fetched once by Throne and does not put the subscription in a wire frame.
        if serde_json::to_vec(&request)?.len() > 900 * 1024 {
            anyhow::bail!("Текст импорта превышает 900 КиБ; используйте URL подписки");
        }
        let response = self.call(&request, Duration::from_secs(65)).await?;
        if response.status == 200
            && let Some(body) = response.body
        {
            let imported = body["imported"]
                .as_u64()
                .context("Нет результата импорта Throne")?;
            let failed = body["failed"].as_u64().unwrap_or(0);
            if failed > 0 {
                anyhow::bail!(
                    "Импортировано {imported} нод, отклонено {failed}; проверьте исходные конфиги"
                );
            }
            if imported > 0 {
                return Ok(usize::try_from(imported)?);
            }
        }
        // Do not include the response message: it can contain a private subscription URL.
        Err(anyhow!(
            "Throne не подтвердил импорт: HTTP {}, код {}",
            response.status,
            response
                .error
                .map(|e| e.code)
                .unwrap_or_else(|| "unknown".into())
        ))
    }

    pub async fn connect_profile(&mut self, profile_id: i64, timeout_secs: u32) -> Result<Status> {
        let body = serde_json::json!({
            "profile": profile_id,
            "wait": true,
            "timeout": timeout_secs,
            "restart": true
        });

        let req = WireRequest {
            method: "PUT".to_string(),
            path: "/v1/connection".to_string(),
            query: None,
            body: Some(body),
        };

        let res = self
            .call(&req, Duration::from_secs(timeout_secs as u64 + 5))
            .await?;
        if (res.status == 200 || res.status == 202)
            && let Some(b) = res.body
        {
            let status: Status = serde_json::from_value(b)?;
            return Ok(status);
        }
        if let Some(error) = res.error.filter(|_| res.status >= 400) {
            return Err(ConnectionRejected {
                status: res.status,
                code: error.code,
                message: error.message,
            }
            .into());
        }
        Err(anyhow!(
            "Некорректный ответ Throne при запуске профиля {profile_id}: {}",
            res.status
        ))
    }

    pub async fn disconnect(&mut self) -> Result<Status> {
        let req = WireRequest {
            method: "DELETE".to_string(),
            path: "/v1/connection".to_string(),
            query: None,
            body: Some(serde_json::json!({"wait": true, "timeout": 5})),
        };

        let res = self.call(&req, Duration::from_secs(8)).await?;
        if (res.status == 200 || res.status == 202)
            && let Some(b) = res.body
        {
            let status: Status = serde_json::from_value(b)?;
            return Ok(status);
        }
        Err(anyhow!(
            "Failed to disconnect, error: {:?}",
            res.error.map(|e| e.message)
        ))
    }
}

pub(crate) fn seal_frame(
    key: &[u8; 32],
    counter: u64,
    plaintext: &[u8],
    limit: usize,
) -> Result<Vec<u8>> {
    let len = plaintext.len().checked_add(16).context("Frame too large")?;
    if len > limit {
        return Err(anyhow!("Frame length out of bounds"));
    }
    let aad = (len as u32).to_be_bytes();
    let nonce = make_nonce(counter);
    let sealed = ChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("Frame encryption failed"))?;
    Ok([aad.as_slice(), sealed.as_slice()].concat())
}

pub(crate) fn open_frame(
    key: &[u8; 32],
    counter: u64,
    wire: &[u8],
    limit: usize,
) -> Result<Vec<u8>> {
    if wire.len() < 4 {
        return Err(anyhow!("Missing frame length"));
    }
    let len = u32::from_be_bytes(wire[..4].try_into()?) as usize;
    if !(16..=limit).contains(&len) || wire.len() != len + 4 {
        return Err(anyhow!("Frame length out of bounds"));
    }
    let nonce = make_nonce(counter);
    ChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &wire[4..],
                aad: &wire[..4],
            },
        )
        .map_err(|_| anyhow!("Frame authentication failed"))
}

pub fn parse_key(key_str: &str) -> Result<[u8; 32]> {
    let clean = key_str.trim();
    // Try base64url unpadded first
    let decoded = if let Ok(bytes) = URL_SAFE_NO_PAD.decode(clean) {
        bytes
    } else {
        // Fallback to standard base64 if user pasted padded key
        use base64::engine::general_purpose::STANDARD;
        STANDARD
            .decode(clean)
            .map_err(|e| anyhow!("Invalid Throne API key base64 encoding: {e}"))?
    };

    if decoded.len() != 32 {
        return Err(anyhow!(
            "Throne key must decode to exactly 32 bytes, got {}",
            decoded.len()
        ));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

pub fn derive_keys(k: &[u8; 32], s: &[u8; 16], c: &[u8; 16]) -> Result<([u8; 32], [u8; 32])> {
    let label_c2s = b"throne-api/1 c2s";
    let label_s2c = b"throne-api/1 s2c";

    let mut msg_c2s = Vec::with_capacity(16 + 16 + 16);
    msg_c2s.extend_from_slice(label_c2s);
    msg_c2s.extend_from_slice(s);
    msg_c2s.extend_from_slice(c);

    let mut mac_c2s = <HmacSha256 as Mac>::new_from_slice(k).map_err(|e| anyhow!("{e}"))?;
    mac_c2s.update(&msg_c2s);
    let k_c2s_bytes = mac_c2s.finalize().into_bytes();

    let mut msg_s2c = Vec::with_capacity(16 + 16 + 16);
    msg_s2c.extend_from_slice(label_s2c);
    msg_s2c.extend_from_slice(s);
    msg_s2c.extend_from_slice(c);

    let mut mac_s2c = <HmacSha256 as Mac>::new_from_slice(k).map_err(|e| anyhow!("{e}"))?;
    mac_s2c.update(&msg_s2c);
    let k_s2c_bytes = mac_s2c.finalize().into_bytes();

    let mut k_c2s = [0u8; 32];
    k_c2s.copy_from_slice(&k_c2s_bytes);

    let mut k_s2c = [0u8; 32];
    k_s2c.copy_from_slice(&k_s2c_bytes);

    Ok((k_c2s, k_s2c))
}

pub fn make_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&counter.to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }
    #[test]
    fn all_official_wire_vectors_and_invalid_frames() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/throne-api-v1.json")).unwrap();
        for case in vectors["cases"].as_array().unwrap() {
            let key = parse_key(case["key"].as_str().unwrap()).unwrap();
            let s: [u8; 16] = hex(case["server_hello"].as_str().unwrap())
                .try_into()
                .unwrap();
            let c: [u8; 16] = hex(&case["client_hello"].as_str().unwrap()[2..])
                .try_into()
                .unwrap();
            let (c2s, s2c) = derive_keys(&key, &s, &c).unwrap();
            assert_eq!(c2s.as_slice(), hex(case["k_c2s"].as_str().unwrap()));
            assert_eq!(s2c.as_slice(), hex(case["k_s2c"].as_str().unwrap()));
            for frame in case["frames"].as_array().unwrap() {
                let k = if frame["dir"] == "c2s" { &c2s } else { &s2c };
                let limit = if frame["dir"] == "c2s" {
                    1024 * 1024
                } else {
                    64 * 1024 * 1024
                };
                let counter = frame["counter"].as_u64().unwrap();
                let plain = frame["plaintext"].as_str().unwrap().as_bytes();
                let wire = hex(frame["wire"].as_str().unwrap());
                assert_eq!(seal_frame(k, counter, plain, limit).unwrap(), wire);
                assert_eq!(open_frame(k, counter, &wire, limit).unwrap(), plain);
            }
            if let Some(frames) = case["invalid"].as_array() {
                for frame in frames {
                    let k = if frame["dir"] == "c2s" { &c2s } else { &s2c };
                    let limit = if frame["dir"] == "c2s" {
                        1024 * 1024
                    } else {
                        64 * 1024 * 1024
                    };
                    assert!(
                        open_frame(
                            k,
                            frame["counter"].as_u64().unwrap(),
                            &hex(frame["wire"].as_str().unwrap()),
                            limit
                        )
                        .is_err(),
                        "{}",
                        frame["name"]
                    );
                }
            }
        }
    }

    #[test]
    fn test_vector_key_derivation() {
        // Test vector from throne-api/spec/vectors/v1.json (case "two exchanges")
        let key_text = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
        let k = parse_key(key_text).unwrap();

        let s_hex = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
        let c_hex = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf";

        let mut s = [0u8; 16];
        let mut c = [0u8; 16];
        for i in 0..16 {
            s[i] = u8::from_str_radix(&s_hex[i * 2..i * 2 + 2], 16).unwrap();
            c[i] = u8::from_str_radix(&c_hex[i * 2..i * 2 + 2], 16).unwrap();
        }

        let (k_c2s, k_s2c) = derive_keys(&k, &s, &c).unwrap();

        let exp_k_c2s = "c5956664b2b29a4c000c660e12cb1dee393891d66f5a4370a963731f5d8d45e3";
        let exp_k_s2c = "82e7307aac852f6fa2fd28731b87cb7a873a35dad696bc308533bb655331bb58";

        let got_c2s_hex: String = k_c2s.iter().map(|b| format!("{:02x}", b)).collect();
        let got_s2c_hex: String = k_s2c.iter().map(|b| format!("{:02x}", b)).collect();

        assert_eq!(got_c2s_hex, exp_k_c2s);
        assert_eq!(got_s2c_hex, exp_k_s2c);
    }
}
