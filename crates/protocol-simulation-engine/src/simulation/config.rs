use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HttpExploitPathConfig {
    pub path: String,
    pub trigger_method: Option<String>,
    pub response_status: u16,
    pub response_body: String,
    pub response_headers: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SimHttpConfig {
    pub server_header: Option<String>,
    pub headers: Option<BTreeMap<String, String>>,
    pub html: Option<String>,
    pub exploit_paths: Option<Vec<HttpExploitPathConfig>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RedisCommandResponse {
    pub command: String,
    pub args_contains: Option<Vec<String>>,
    pub response: String,
    pub event_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SimRedisConfig {
    pub banner: Option<String>,
    pub require_auth: Option<bool>,
    pub password: Option<String>,
    pub server_info: Option<BTreeMap<String, String>>,
    pub keys: Option<BTreeMap<String, String>>,
    pub command_responses: Option<Vec<RedisCommandResponse>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MailCredential {
    pub username: String,
    pub password: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MailMessage {
    pub uid: Option<String>,
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    pub date: Option<String>,
    pub body: String,
    pub flags: Option<Vec<String>>,
}

pub type Mailboxes = BTreeMap<String, Vec<MailMessage>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MailCustomResponse {
    pub command: String,
    pub args_contains: Option<Vec<String>>,
    pub response: String,
    pub event_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SimSmtpConfig {
    pub banner: Option<String>,
    pub hostname: Option<String>,
    pub require_auth: Option<bool>,
    pub credentials: Option<Vec<MailCredential>>,
    pub capabilities: Option<Vec<String>>,
    pub accepted_recipients: Option<Vec<String>>,
    pub custom_responses: Option<Vec<MailCustomResponse>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SimPop3Config {
    pub banner: Option<String>,
    pub require_auth: Option<bool>,
    pub credentials: Option<Vec<MailCredential>>,
    pub capabilities: Option<Vec<String>>,
    pub messages: Option<Vec<MailMessage>>,
    pub custom_responses: Option<Vec<MailCustomResponse>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SimImapConfig {
    pub banner: Option<String>,
    pub require_auth: Option<bool>,
    pub credentials: Option<Vec<MailCredential>>,
    pub capabilities: Option<Vec<String>>,
    pub mailboxes: Option<Mailboxes>,
    pub messages: Option<Vec<MailMessage>>,
    pub custom_responses: Option<Vec<MailCustomResponse>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Credential {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SimSshConfig {
    pub banner: Option<String>,
    pub credentials: Option<Vec<Credential>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SimFtpConfig {
    pub banner: Option<String>,
    pub credentials: Option<Vec<Credential>>,
    pub server_name: Option<String>,
    pub allow_anonymous: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SimRdpConfig {
    pub flags: Option<u32>,
    pub credentials: Option<Vec<Credential>>,
}
