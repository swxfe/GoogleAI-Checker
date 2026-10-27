//! Throne beta.3 core IPC: little-endian frames containing proto2 messages.
//! Schema: throneproj/Throne@0108602/core/gen/libcore.proto (LoadConfigReq/ErrorResp).
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_MESSAGE: usize = 16 * 1024 * 1024;

#[derive(Default, Serialize, Deserialize)]
pub struct LoadConfig {
    pub core_config: String,
    pub xray_config: String,
    pub xray_full_configs: Vec<String>,
    pub xray_dns_strategy: String,
}

fn varint(mut value: u64, bytes: &mut Vec<u8>) {
    while value >= 128 {
        bytes.push(value as u8 | 128);
        value >>= 7;
    }
    bytes.push(value as u8);
}
fn string(field: u32, value: &str, bytes: &mut Vec<u8>) {
    varint(u64::from(field << 3 | 2), bytes);
    varint(value.len() as u64, bytes);
    bytes.extend_from_slice(value.as_bytes());
}
impl LoadConfig {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        string(1, &self.core_config, &mut bytes);
        // Explicit values also support core versions which dereference proto2 pointers.
        bytes.extend_from_slice(&[
            0x10,
            1,
            0x18,
            0,
            0x40,
            1,
            0x48,
            u8::from(!self.xray_config.is_empty()),
        ]);
        string(10, &self.xray_config, &mut bytes);
        string(13, &self.xray_dns_strategy, &mut bytes);
        bytes.extend_from_slice(&[0x70, 0, 0x78, 0]);
        for config in &self.xray_full_configs {
            string(16, config, &mut bytes);
        }
        bytes.extend_from_slice(&[0x88, 1, 0]);
        ensure!(
            bytes.len() <= MAX_MESSAGE,
            "Core configuration exceeds IPC limit"
        );
        Ok(bytes)
    }
}

fn read_varint(input: &mut &[u8]) -> Result<u64> {
    let mut value = 0;
    for shift in (0..70).step_by(7) {
        let (&byte, remaining) = input.split_first().context("Truncated protobuf varint")?;
        *input = remaining;
        ensure!(shift != 63 || byte <= 1, "Overflowing protobuf varint");
        value |= u64::from(byte & 127) << shift;
        if byte & 128 == 0 {
            return Ok(value);
        }
    }
    bail!("Invalid protobuf varint")
}
fn take<'a>(input: &mut &'a [u8], count: usize) -> Result<&'a [u8]> {
    ensure!(count <= input.len(), "Truncated protobuf field");
    let (value, remaining) = input.split_at(count);
    *input = remaining;
    Ok(value)
}
fn error_response(mut bytes: &[u8]) -> Result<()> {
    while !bytes.is_empty() {
        let key = read_varint(&mut bytes)?;
        ensure!(key >> 3 != 0, "Invalid protobuf field number");
        match key & 7 {
            0 => {
                read_varint(&mut bytes)?;
            }
            1 => {
                take(&mut bytes, 8)?;
            }
            2 => {
                let count = usize::try_from(read_varint(&mut bytes)?)?;
                let value = take(&mut bytes, count)?;
                if key >> 3 == 1 && !value.is_empty() {
                    bail!("ThroneCore: {}", std::str::from_utf8(value)?);
                }
            }
            5 => {
                take(&mut bytes, 4)?;
            }
            _ => bail!("Unsupported protobuf wire type"),
        }
    }
    Ok(())
}

pub async fn call(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    id: u32,
    method: &str,
    payload: &[u8],
) -> Result<()> {
    ensure!(
        method.len() <= u16::MAX as usize && payload.len() <= MAX_MESSAGE,
        "IPC request exceeds limit"
    );
    let mut request = Vec::with_capacity(10 + method.len() + payload.len());
    request.extend_from_slice(&id.to_le_bytes());
    request.extend_from_slice(&(method.len() as u16).to_le_bytes());
    request.extend_from_slice(method.as_bytes());
    request.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    request.extend_from_slice(payload);
    stream.write_all(&request).await?;
    let mut header = [0; 9];
    stream.read_exact(&mut header).await?;
    ensure!(
        u32::from_le_bytes(header[..4].try_into()?) == id,
        "Core response ID mismatch"
    );
    let count = u32::from_le_bytes(header[5..].try_into()?) as usize;
    ensure!(count <= MAX_MESSAGE, "Core response exceeds IPC limit");
    let mut response = vec![0; count];
    stream.read_exact(&mut response).await?;
    ensure!(
        header[4] == 0,
        "Core RPC failed: {}",
        String::from_utf8_lossy(&response)
    );
    error_response(&response)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protobuf_matches_the_pinned_proto2_schema() {
        let config = LoadConfig {
            core_config: "{}".into(),
            xray_config: "x".into(),
            xray_full_configs: vec!["a".into(), "b".into()],
            ..Default::default()
        };
        assert_eq!(
            config.encode().unwrap(),
            [
                10, 2, b'{', b'}', 16, 1, 24, 0, 64, 1, 72, 1, 82, 1, b'x', 106, 0, 112, 0, 120, 0,
                130, 1, 1, b'a', 130, 1, 1, b'b', 136, 1, 0
            ]
        );
        assert!(error_response(&[]).is_ok());
        assert!(error_response(&[10, 0, 16, 1, 29, 0, 0, 0, 0]).is_ok());
        assert!(
            error_response(&[10, 3, b'b', b'a', b'd'])
                .unwrap_err()
                .to_string()
                .contains("bad")
        );
        for malformed in [&[10, 128][..], &[10, 3, b'a'], &[0], &[128; 12]] {
            assert!(error_response(malformed).is_err());
        }
    }
    #[tokio::test]
    async fn framing_is_byte_exact_and_rejects_wrong_response_ids() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let task = tokio::spawn(async move {
            let mut request = [0; 16];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(
                request,
                [
                    7, 0, 0, 0, 5, 0, b'S', b't', b'a', b'r', b't', 1, 0, 0, 0, 42
                ]
            );
            server
                .write_all(&[8, 0, 0, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        assert!(
            call(&mut client, 7, "Start", &[42])
                .await
                .unwrap_err()
                .to_string()
                .contains("ID mismatch")
        );
        task.await.unwrap();
    }
}
