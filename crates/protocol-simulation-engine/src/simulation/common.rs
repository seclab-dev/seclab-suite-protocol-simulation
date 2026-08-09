//! 仿真运行器通用数据结构与日志上报工具。

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{error, warn};

const REPORT_QUEUE_CAPACITY: usize = 1_024;
const REPORT_CONCURRENCY: usize = 4;

static REPORTER: OnceLock<mpsc::Sender<SimLogDraft>> = OnceLock::new();
static DROPPED_EVENTS: AtomicU64 = AtomicU64::new(0);

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
    event_type: String,
    summary: String,
    client_ip: String,
    client_port: u16,
    payload_hex: Option<String>,
    timestamp: String,
}

/// 异步向控制端上报审计日志的辅助方法。
pub(super) fn report_sim_log_async(callback_url: String, draft: SimLogDraft) {
    let reporter = REPORTER.get_or_init(|| start_reporter(callback_url));
    match reporter.try_send(draft) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            let dropped = DROPPED_EVENTS.fetch_add(1, Ordering::Relaxed) + 1;
            if dropped == 1 || dropped.is_multiple_of(100) {
                warn!(
                    dropped_count = dropped,
                    "simulation audit report queue is full; dropping events"
                );
            }
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            error!("simulation audit reporter is unavailable");
        }
    }
}

/// 启动共享 HTTP 客户端和有界上报队列。
fn start_reporter(callback_url: String) -> mpsc::Sender<SimLogDraft> {
    let (sender, receiver) = mpsc::channel(REPORT_QUEUE_CAPACITY);
    tokio::spawn(run_reporter(callback_url, receiver));
    sender
}

/// 以固定并发度消费审计事件，避免为每条事件创建无界 HTTP 任务。
async fn run_reporter(callback_url: String, mut receiver: mpsc::Receiver<SimLogDraft>) {
    let client = reqwest::Client::new();
    let instance_id =
        std::env::var("SECLAB_SIM_INSTANCE_ID").unwrap_or_else(|_| "unknown".to_string());
    let mut requests = JoinSet::new();

    loop {
        tokio::select! {
            result = requests.join_next(), if !requests.is_empty() => {
                if let Some(Err(error)) = result {
                    error!(error = %error, "simulation audit report task failed");
                }
            }
            draft = receiver.recv(), if requests.len() < REPORT_CONCURRENCY => {
                let Some(draft) = draft else {
                    break;
                };
                let client = client.clone();
                let callback_url = callback_url.clone();
                let instance_id = instance_id.clone();
                requests.spawn(async move {
                    let event = EngineEvent {
                        instance_id,
                        event_type: draft.event_type,
                        summary: draft.detail_summary,
                        client_ip: draft.client_ip,
                        client_port: draft.client_port,
                        payload_hex: draft.payload_hex,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                    };
                    match client.post(&callback_url).json(&event).send().await {
                        Ok(response) if !response.status().is_success() => {
                            warn!(
                                status = %response.status(),
                                "suite API rejected simulation audit log"
                            );
                        }
                        Ok(_) => {}
                        Err(error) => {
                            error!(
                                error = %error,
                                "failed to report simulation audit log to suite API"
                            );
                        }
                    }
                });
            }
        }
    }

    while let Some(result) = requests.join_next().await {
        if let Err(error) = result {
            error!(error = %error, "simulation audit report task failed");
        }
    }
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
