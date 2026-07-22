use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub default_port: i64,
    pub config_json: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct RulePackageSummary {
    pub package_id: String,
    pub version: String,
    pub ruleset_format_version: i64,
    pub min_seclab_version: String,
    pub rule_count: i64,
    pub generated_at: String,
    pub imported_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRuleRequest {
    pub name: String,
    pub protocol: String,
    pub default_port: u16,
    pub config_json: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Instance {
    pub id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub protocol: String,
    pub host_port: i64,
    pub container_port: i64,
    pub status: String,
    pub workload_id: Option<String>,
    pub error_message: Option<String>,
    pub pcap_status: String,
    pub pcap_start_time: Option<i64>,
    pub pcap_capture_id: Option<String>,
    pub pcap_file_path: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployInstanceRequest {
    pub rule_id: String,
    pub host_port: u16,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct AuditLog {
    pub id: i64,
    pub instance_id: String,
    pub rule_id: String,
    pub protocol: String,
    pub event_type: String,
    pub summary: String,
    pub client_ip: String,
    pub client_port: i64,
    pub payload_hex: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventRequest {
    pub instance_id: String,
    pub rule_id: String,
    pub protocol: String,
    pub event_type: String,
    pub summary: String,
    #[serde(default = "default_client_ip")]
    pub client_ip: String,
    #[serde(default)]
    pub client_port: u16,
    #[serde(default)]
    pub payload_hex: Option<String>,
    #[serde(default)]
    pub timestamp: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiEnvelope<T>
where
    T: Serialize,
{
    pub success: bool,
    pub data: T,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorEnvelope {
    pub success: bool,
    pub message: String,
    #[serde(rename = "messageKey", skip_serializing_if = "Option::is_none")]
    pub message_key: Option<String>,
}

fn default_client_ip() -> String {
    "0.0.0.0".to_string()
}
