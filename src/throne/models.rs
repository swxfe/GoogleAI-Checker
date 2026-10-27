use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Profile {
    pub id: i64,
    #[serde(default)]
    pub group: Option<i64>,
    pub name: String,
    #[serde(rename = "type", default)]
    pub profile_type: String,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub latency_ms: Option<i64>,
    #[serde(default)]
    pub latency_at: Option<i64>,
    #[serde(default)]
    pub download_bps: Option<i64>,
    #[serde(default)]
    pub upload_bps: Option<i64>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub ip_out: Option<String>,
    #[serde(default)]
    pub traffic_up: Option<u64>,
    #[serde(default)]
    pub traffic_down: Option<u64>,
    #[serde(default)]
    pub running: Option<bool>,
    /// Additional field for disabled / excluded profiles
    #[serde(default)]
    pub disabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: i64,
    pub name: String,
    #[serde(default)]
    pub subscription: Option<bool>,
    #[serde(default)]
    pub archived: Option<bool>,
    #[serde(default)]
    pub profile_count: Option<u64>,
    #[serde(default)]
    pub updated_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InboundConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub profile: Option<Profile>,
    #[serde(default)]
    pub last_profile_id: Option<i64>,
    #[serde(default)]
    pub tun: Option<bool>,
    #[serde(default)]
    pub system_proxy: Option<bool>,
    #[serde(default)]
    pub core: Option<bool>,
    #[serde(default)]
    pub inbound: Option<InboundConfig>,
    #[serde(default)]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilesResponse {
    pub profiles: Vec<Profile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupsResponse {
    pub groups: Vec<Group>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireRequest {
    pub method: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<std::collections::HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireResponse {
    pub status: u16,
    #[serde(default)]
    pub body: Option<serde_json::Value>,
    #[serde(default)]
    pub error: Option<WireError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireError {
    pub code: String,
    pub message: String,
}
