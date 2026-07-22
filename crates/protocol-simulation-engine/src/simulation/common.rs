//! 仿真运行器通用数据结构与日志上报工具。

use tracing::error;

/// 仿真交互审计日志上报草稿。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimLogDraft {
    pub rule_id: String,
    pub node_id: String,
    pub client_ip: String,
    pub client_port: u16,
    pub server_port: u16,
    pub event_type: String, // 'connection', 'http_request', 'exploit_attempt'
    pub detail_summary: String,
    pub payload_hex: Option<String>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct EngineEvent {
    instance_id: String,
    rule_id: String,
    protocol: String,
    event_type: String,
    summary: String,
    client_ip: String,
    client_port: u16,
    payload_hex: Option<String>,
    timestamp: String,
}

/// 异步向控制端上报审计日志的辅助方法。
pub(super) fn report_sim_log_async(callback_url: String, draft: SimLogDraft) {
    tokio::spawn(async move {
        let event = EngineEvent {
            instance_id: std::env::var("SECLAB_SIM_INSTANCE_ID")
                .unwrap_or_else(|_| "unknown".to_string()),
            rule_id: draft.rule_id,
            protocol: std::env::var("SECLAB_SIM_PROTOCOL")
                .unwrap_or_else(|_| "unknown".to_string()),
            event_type: draft.event_type,
            summary: draft.detail_summary,
            client_ip: draft.client_ip,
            client_port: draft.client_port,
            payload_hex: draft.payload_hex,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        let res = reqwest::Client::new()
            .post(&callback_url)
            .json(&event)
            .send()
            .await;
        if let Err(err) = res {
            error!(
                "Failed to report simulation audit log to suite API: {:?}",
                err
            );
        }
    });
}

pub(super) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
