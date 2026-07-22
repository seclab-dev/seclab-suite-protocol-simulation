//! 协议仿真套件共享类型。
//!
//! API 服务和仿真引擎分别发布镜像，本 crate 用于沉淀两者共享的规则、事件和协议模型。

use serde::{Deserialize, Serialize};

/// 协议仿真引擎向套件 API 上报事件时使用的默认容器网络地址。
pub const DEFAULT_EVENT_CALLBACK_URL: &str =
    "http://seclab-protocol-simulation:8080/internal/events";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulationRuntimeEvent {
    pub instance_id: String,
    pub rule_id: String,
    pub protocol: String,
    pub event_type: String,
    pub summary: String,
    pub client_ip: String,
    pub client_port: u16,
    pub payload_hex: Option<String>,
    pub timestamp: String,
}

#[cfg(test)]
mod tests {
    use super::DEFAULT_EVENT_CALLBACK_URL;

    #[test]
    fn default_event_callback_uses_compose_service_dns_name() {
        assert_eq!(
            DEFAULT_EVENT_CALLBACK_URL,
            "http://seclab-protocol-simulation:8080/internal/events"
        );
    }
}
