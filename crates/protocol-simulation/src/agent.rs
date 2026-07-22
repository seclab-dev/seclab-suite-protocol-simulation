use super::Config;
use anyhow::{Context, bail};
use base64::Engine;
use reqwest::{Certificate, Identity};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

#[derive(Clone)]
pub struct AgentClient {
    config: Config,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartWorkloadRequest {
    pub suite_id: String,
    pub suite_instance_id: String,
    pub workload_kind: String,
    pub workload_name: String,
    pub image: String,
    pub ports: Vec<WorkloadPort>,
    pub env: serde_json::Value,
    pub config_json: serde_json::Value,
    pub resources: WorkloadResources,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadPort {
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadResources {
    pub memory_mb: u32,
    pub cpu_shares: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartWorkloadResponse {
    pub workload_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AgentErrorEnvelope {
    message: String,
    error_code: Option<String>,
    data: Option<serde_json::Value>,
}

#[derive(Debug)]
pub struct AgentApiError {
    status: reqwest::StatusCode,
    code: Option<String>,
    message: String,
    detail: Option<serde_json::Value>,
}

impl AgentApiError {
    pub fn is_port_unavailable(&self) -> bool {
        self.status == reqwest::StatusCode::CONFLICT
            && self.code.as_deref() == Some("SUITE_WORKLOAD_PORT_UNAVAILABLE")
    }
}

impl fmt::Display for AgentApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Agent suite workload start failed: {}: {}",
            self.status, self.message
        )?;
        if let Some(detail) = &self.detail {
            write!(formatter, ": {detail}")?;
        }
        Ok(())
    }
}

impl std::error::Error for AgentApiError {}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StopWorkloadRequest {
    pub suite_id: String,
    pub suite_instance_id: String,
    pub workload_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartPcapRequest {
    pub suite_id: String,
    pub suite_instance_id: String,
    pub workload_id: String,
    pub host_port: u16,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartPcapResponse {
    pub capture_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StopPcapRequest {
    pub suite_id: String,
    pub suite_instance_id: String,
    pub workload_id: String,
    pub capture_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StopPcapResponse {
    pcap_bytes_base64: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadSummary {
    pub workload_id: String,
    pub suite_instance_id: String,
}

impl AgentClient {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub async fn start_workload(
        &self,
        payload: &StartWorkloadRequest,
    ) -> anyhow::Result<StartWorkloadResponse> {
        let client = self.http_client().await?;
        let url = self.agent_url("/api/v1/agent/suite-workloads/start");
        let response = client
            .post(&url)
            .json(payload)
            .send()
            .await
            .with_context(|| format!("Agent suite workload API not reachable: {url}"))?;
        if response.status().as_u16() == 404 {
            bail!("Agent suite workload API not found: {url}");
        }
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            let error = serde_json::from_str::<AgentErrorEnvelope>(&text).ok();
            return Err(anyhow::Error::new(AgentApiError {
                status,
                code: error.as_ref().and_then(|body| body.error_code.clone()),
                message: error
                    .as_ref()
                    .map(|body| body.message.clone())
                    .filter(|message| !message.is_empty())
                    .unwrap_or_else(|| text.clone()),
                detail: error.and_then(|body| body.data),
            }));
        }
        response
            .json::<StartWorkloadResponse>()
            .await
            .context("invalid Agent suite workload start response")
    }

    pub async fn stop_workload(&self, workload_id: &str) -> anyhow::Result<()> {
        let client = self.http_client().await?;
        let url = self.agent_url("/api/v1/agent/suite-workloads/stop");
        let payload = StopWorkloadRequest {
            suite_id: self.config.suite_id.clone(),
            suite_instance_id: self.config.suite_instance_id.clone(),
            workload_id: workload_id.to_string(),
        };
        let response = client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .with_context(|| format!("Agent suite workload API not reachable: {url}"))?;
        if response.status().as_u16() == 404 {
            bail!("Agent suite workload API not found: {url}");
        }
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            bail!("Agent suite workload stop failed at {url}: {status}: {text}");
        }
        Ok(())
    }

    pub async fn start_pcap(
        &self,
        workload_id: &str,
        host_port: u16,
    ) -> anyhow::Result<StartPcapResponse> {
        let client = self.http_client().await?;
        let url = self.agent_url("/api/v1/agent/suite-workloads/pcap/start");
        let payload = StartPcapRequest {
            suite_id: self.config.suite_id.clone(),
            suite_instance_id: self.config.suite_instance_id.clone(),
            workload_id: workload_id.to_string(),
            host_port,
        };
        let response = client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .with_context(|| format!("Agent suite pcap API not reachable: {url}"))?;
        if response.status().as_u16() == 404 {
            bail!("Agent suite pcap API not found: {url}");
        }
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            bail!("Agent suite pcap start failed at {url}: {status}: {text}");
        }
        response
            .json::<StartPcapResponse>()
            .await
            .context("invalid Agent suite pcap start response")
    }

    pub async fn stop_pcap(&self, workload_id: &str, capture_id: &str) -> anyhow::Result<Vec<u8>> {
        let client = self.http_client().await?;
        let url = self.agent_url("/api/v1/agent/suite-workloads/pcap/stop");
        let payload = StopPcapRequest {
            suite_id: self.config.suite_id.clone(),
            suite_instance_id: self.config.suite_instance_id.clone(),
            workload_id: workload_id.to_string(),
            capture_id: capture_id.to_string(),
        };
        let response = client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .with_context(|| format!("Agent suite pcap API not reachable: {url}"))?;
        if response.status().as_u16() == 404 {
            bail!("Agent suite pcap API not found: {url}");
        }
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            bail!("Agent suite pcap stop failed at {url}: {status}: {text}");
        }
        let payload = response
            .json::<StopPcapResponse>()
            .await
            .context("invalid Agent suite pcap stop response")?;
        base64::engine::general_purpose::STANDARD
            .decode(payload.pcap_bytes_base64)
            .context("invalid Agent suite pcap payload")
    }

    pub async fn list_workloads(&self) -> anyhow::Result<Vec<WorkloadSummary>> {
        let client = self.http_client().await?;
        let url = self.agent_url("/api/v1/agent/suite-workloads/list");
        let response = client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("Agent suite workload API not reachable: {url}"))?;
        if response.status().as_u16() == 404 {
            bail!("Agent suite workload API not found: {url}");
        }
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            bail!("Agent suite workload list failed at {url}: {status}: {text}");
        }
        response
            .json::<Vec<WorkloadSummary>>()
            .await
            .context("invalid Agent suite workload list response")
    }

    fn agent_url(&self, path: &str) -> String {
        if self.config.agent_socket_path.is_some() {
            return format!("http://local{path}");
        }
        format!(
            "{}{}",
            self.config.agent_base_url.trim_end_matches('/'),
            path
        )
    }

    async fn http_client(&self) -> anyhow::Result<reqwest::Client> {
        if let Some(socket_path) = &self.config.agent_socket_path {
            return reqwest::Client::builder()
                .unix_socket(socket_path.as_path())
                .no_proxy()
                .build()
                .with_context(|| {
                    format!(
                        "failed to build Agent UDS HTTP client for {}",
                        socket_path.display()
                    )
                });
        }

        let cert_dir = &self.config.agent_certs_dir;
        let cert = tokio::fs::read(cert_dir.join("agent-client.crt"))
            .await
            .with_context(|| {
                format!(
                    "Agent suite mTLS client certificate is missing: {}",
                    cert_dir.join("agent-client.crt").display()
                )
            })?;
        let key = tokio::fs::read(cert_dir.join("agent-client.key"))
            .await
            .with_context(|| {
                format!(
                    "Agent suite mTLS client key is missing: {}",
                    cert_dir.join("agent-client.key").display()
                )
            })?;
        let mut identity_pem = Vec::with_capacity(cert.len() + key.len() + 1);
        identity_pem.extend_from_slice(&cert);
        identity_pem.push(b'\n');
        identity_pem.extend_from_slice(&key);
        let identity = Identity::from_pem(&identity_pem)
            .context("failed to load Agent suite mTLS client identity")?;

        let mut builder = reqwest::Client::builder().identity(identity);
        if self.config.agent_accept_invalid_hostnames {
            builder = builder.danger_accept_invalid_hostnames(true);
        }
        let ca_path = cert_dir.join("agent-ca.crt");
        if path_exists(&ca_path).await {
            let ca = tokio::fs::read(&ca_path).await.with_context(|| {
                format!("failed to read Agent CA certificate {}", ca_path.display())
            })?;
            builder = builder.add_root_certificate(
                Certificate::from_pem(&ca).context("failed to parse Agent CA certificate")?,
            );
        }
        builder
            .build()
            .context("failed to build Agent mTLS HTTP client")
    }
}

async fn path_exists(path: &Path) -> bool {
    tokio::fs::metadata(path).await.is_ok()
}
