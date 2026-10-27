use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AiVerdict {
    Pending,
    Testing,
    Unlocked,
    AiUnavailable,
    SessionExpired,
    Inconclusive,
    GoogleChallenge,
    RateLimited,
    Geoblock,
    ConnectionError,
    CheckError,
    StartFailed,
    Timeout,
}

impl AiVerdict {
    pub fn summary_label(&self) -> Option<&'static str> {
        match self {
            Self::Unlocked => Some("Works"),
            Self::Geoblock
            | Self::AiUnavailable
            | Self::Inconclusive
            | Self::GoogleChallenge
            | Self::RateLimited => Some("AI unavailable"),
            Self::ConnectionError | Self::StartFailed | Self::Timeout => Some("No connection"),
            _ => None,
        }
    }

    pub fn badge_label(&self) -> &'static str {
        match self {
            AiVerdict::Pending => "Pending",
            AiVerdict::Testing => "Checking…",
            AiVerdict::Unlocked => "Available",
            AiVerdict::AiUnavailable => "AI unavailable",
            AiVerdict::SessionExpired => "Session expired",
            AiVerdict::Inconclusive => "Unconfirmed",
            AiVerdict::GoogleChallenge => "Google verification",
            AiVerdict::RateLimited => "Google rate limit",
            AiVerdict::Geoblock => "Region blocked",
            AiVerdict::ConnectionError => "Network error",
            AiVerdict::CheckError => "Check error",
            AiVerdict::StartFailed => "Start failed",
            AiVerdict::Timeout => "Timed out",
        }
    }

    pub fn badge_colors(&self) -> (egui::Color32, egui::Color32) {
        match self {
            AiVerdict::Pending => (
                egui::Color32::from_rgb(45, 52, 64),
                egui::Color32::from_rgb(203, 213, 225),
            ),
            AiVerdict::Testing => (egui::Color32::from_rgb(29, 78, 216), egui::Color32::WHITE),
            AiVerdict::Unlocked => (egui::Color32::from_rgb(16, 149, 105), egui::Color32::WHITE),
            AiVerdict::SessionExpired | AiVerdict::Inconclusive | AiVerdict::CheckError => {
                (egui::Color32::from_rgb(71, 85, 105), egui::Color32::WHITE)
            }
            AiVerdict::Geoblock | AiVerdict::AiUnavailable => {
                (egui::Color32::from_rgb(185, 28, 28), egui::Color32::WHITE)
            }
            AiVerdict::ConnectionError
            | AiVerdict::StartFailed
            | AiVerdict::GoogleChallenge
            | AiVerdict::RateLimited => (egui::Color32::from_rgb(180, 83, 9), egui::Color32::WHITE),
            AiVerdict::Timeout => (egui::Color32::from_rgb(109, 40, 217), egui::Color32::WHITE),
        }
    }

    pub fn is_final(&self) -> bool {
        !matches!(self, AiVerdict::Pending | AiVerdict::Testing)
    }

    pub fn is_working(&self) -> bool {
        matches!(self, AiVerdict::Unlocked)
    }
}

#[cfg(test)]
mod tests {
    use super::AiVerdict;
    #[test]
    fn completed_network_and_ai_results_have_three_honest_summary_labels() {
        for verdict in [
            AiVerdict::Pending,
            AiVerdict::Testing,
            AiVerdict::SessionExpired,
            AiVerdict::CheckError,
        ] {
            assert_eq!(verdict.summary_label(), None);
        }
        assert_eq!(AiVerdict::Unlocked.summary_label(), Some("Works"));
        for verdict in [
            AiVerdict::Geoblock,
            AiVerdict::AiUnavailable,
            AiVerdict::Inconclusive,
            AiVerdict::GoogleChallenge,
            AiVerdict::RateLimited,
        ] {
            assert_eq!(verdict.summary_label(), Some("AI unavailable"));
        }
        assert_eq!(AiVerdict::Timeout.summary_label(), Some("No connection"));
        assert_eq!(
            AiVerdict::ConnectionError.summary_label(),
            Some("No connection")
        );
        assert_eq!(
            AiVerdict::StartFailed.summary_label(),
            Some("No connection")
        );
    }
}

pub fn protocol_badge_colors(proto: &str) -> (egui::Color32, egui::Color32) {
    match proto.to_lowercase().as_str() {
        "vless" | "xrayvless" => (egui::Color32::from_rgb(79, 70, 229), egui::Color32::WHITE),
        "hysteria2" | "hy2" => (egui::Color32::from_rgb(219, 39, 119), egui::Color32::WHITE),
        "tuic" => (egui::Color32::from_rgb(124, 58, 237), egui::Color32::WHITE),
        "shadowsocks" | "ss" => (egui::Color32::from_rgb(14, 116, 144), egui::Color32::WHITE),
        "trojan" => (egui::Color32::from_rgb(194, 65, 12), egui::Color32::WHITE),
        "vmess" => (egui::Color32::from_rgb(13, 148, 136), egui::Color32::WHITE),
        _ => (egui::Color32::from_rgb(71, 85, 105), egui::Color32::WHITE),
    }
}

pub fn latency_color(latency_ms: Option<u64>) -> egui::Color32 {
    match latency_ms {
        Some(lat) if lat < 250 => egui::Color32::from_rgb(34, 197, 94),
        Some(lat) if lat < 600 => egui::Color32::from_rgb(234, 179, 8),
        Some(_) => egui::Color32::from_rgb(239, 68, 68),
        None => egui::Color32::from_rgb(148, 163, 184),
    }
}

pub const AI_STUDIO_URL: &str = "https://aistudio.google.com/prompts/new_chat";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckTimings {
    pub setup_ms: u64,
    pub throne_ms: u64,
    pub google_ms: Option<u64>,
    pub cleanup_ms: u64,
    pub total_ms: u64,
    pub reused_browser: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCheckResult {
    pub profile_id: i64,
    pub profile_name: String,
    pub protocol: String,
    pub server_address: String,
    pub verdict: AiVerdict,
    pub details: String,
    pub latency_ms: Option<u64>,
    pub final_url: Option<String>,
    #[serde(default)]
    pub checked_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timings: Option<CheckTimings>,
}

impl NodeCheckResult {
    pub fn new_pending(id: i64, name: String, protocol: String, server_address: String) -> Self {
        Self {
            profile_id: id,
            profile_name: name,
            protocol,
            server_address,
            verdict: AiVerdict::Pending,
            details: "Waiting in the scan queue".to_string(),
            latency_ms: None,
            final_url: None,
            checked_at: None,
            timings: None,
        }
    }
}
