use super::Config;
use anyhow::{Context, bail};
use reqwest::{Certificate, Identity};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

#[derive(Clone)]
pub struct AgentClient {
    config: Config,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartWorkloadRequest {
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
pub struct StartPcapRequest {
    pub host_port: u16,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartPcapResponse {
    pub capture_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadSummary {
    pub workload_id: String,
    pub suite_instance_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AgentRuntimeDescriptor {
    schema_version: u32,
    suite_id: String,
    instance_id: String,
    endpoint: AgentRuntimeEndpoint,
    credential: AgentRuntimeCredential,
    capabilities: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "lowercase",
    rename_all_fields = "camelCase"
)]
enum AgentRuntimeEndpoint {
    Unix {
        socket_path: PathBuf,
        base_url: String,
    },
    Https {
        base_url: String,
        ca_path: PathBuf,
        client_cert_path: PathBuf,
        client_key_path: PathBuf,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AgentRuntimeCredential {
    token_path: PathBuf,
}

struct RuntimeClient {
    http: reqwest::Client,
    base_url: String,
    token: String,
}

impl AgentClient {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub async fn start_workload(
        &self,
        payload: &StartWorkloadRequest,
    ) -> anyhow::Result<StartWorkloadResponse> {
        let runtime = self.runtime_client("workloads.manage").await?;
        let url = runtime.url("/api/v1/agent/suite-runtime/workloads");
        let response = runtime
            .http
            .post(&url)
            .bearer_auth(&runtime.token)
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
        let runtime = self.runtime_client("workloads.manage").await?;
        let url = runtime.url(&format!(
            "/api/v1/agent/suite-runtime/workloads/{workload_id}"
        ));
        let response = runtime
            .http
            .delete(&url)
            .bearer_auth(&runtime.token)
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
        let runtime = self.runtime_client("captures.manage").await?;
        let url = runtime.url(&format!(
            "/api/v1/agent/suite-runtime/workloads/{workload_id}/captures"
        ));
        let payload = StartPcapRequest { host_port };
        let response = runtime
            .http
            .post(&url)
            .bearer_auth(&runtime.token)
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
        let runtime = self.runtime_client("captures.manage").await?;
        let url = runtime.url(&format!(
            "/api/v1/agent/suite-runtime/workloads/{workload_id}/captures/{capture_id}/finish"
        ));
        let response = runtime
            .http
            .post(&url)
            .bearer_auth(&runtime.token)
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
        Ok(response
            .bytes()
            .await
            .context("invalid Agent suite pcap payload")?
            .to_vec())
    }

    pub async fn list_workloads(&self) -> anyhow::Result<Vec<WorkloadSummary>> {
        let runtime = self.runtime_client("workloads.manage").await?;
        let url = runtime.url("/api/v1/agent/suite-runtime/workloads");
        let response = runtime
            .http
            .get(&url)
            .bearer_auth(&runtime.token)
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

    async fn runtime_client(&self, capability: &str) -> anyhow::Result<RuntimeClient> {
        let descriptor_text = tokio::fs::read_to_string(&self.config.agent_runtime_path)
            .await
            .with_context(|| {
                format!(
                    "Agent runtime descriptor is missing: {}",
                    self.config.agent_runtime_path.display()
                )
            })?;
        let descriptor = serde_json::from_str::<AgentRuntimeDescriptor>(&descriptor_text)
            .context("invalid Agent runtime descriptor")?;
        if descriptor.schema_version != 1
            || descriptor.suite_id != self.config.suite_id
            || descriptor.instance_id != self.config.suite_instance_id
        {
            bail!("Agent runtime descriptor identity does not match suite instance");
        }
        if !descriptor
            .capabilities
            .iter()
            .any(|value| value == capability)
        {
            bail!("Agent runtime capability is not granted: {capability}");
        }
        let token = tokio::fs::read_to_string(&descriptor.credential.token_path)
            .await
            .context("Agent runtime token is missing")?;
        let token = token.trim().to_string();
        if token.is_empty() {
            bail!("Agent runtime token is empty");
        }
        let (http, base_url) = match descriptor.endpoint {
            AgentRuntimeEndpoint::Unix {
                socket_path,
                base_url,
            } => (
                reqwest::Client::builder()
                    .unix_socket(socket_path)
                    .no_proxy()
                    .build()
                    .context("failed to build Agent UDS HTTP client")?,
                base_url,
            ),
            AgentRuntimeEndpoint::Https {
                base_url,
                ca_path,
                client_cert_path,
                client_key_path,
            } => {
                let cert = tokio::fs::read(&client_cert_path)
                    .await
                    .context("Agent suite mTLS client certificate is missing")?;
                let key = tokio::fs::read(&client_key_path)
                    .await
                    .context("Agent suite mTLS client key is missing")?;
                let mut identity_pem = Vec::with_capacity(cert.len() + key.len() + 1);
                identity_pem.extend_from_slice(&cert);
                identity_pem.push(b'\n');
                identity_pem.extend_from_slice(&key);
                let identity = Identity::from_pem(&identity_pem)
                    .context("failed to load Agent suite mTLS client identity")?;
                let ca = tokio::fs::read(&ca_path)
                    .await
                    .context("Agent CA certificate is missing")?;
                let http = reqwest::Client::builder()
                    .identity(identity)
                    .add_root_certificate(
                        Certificate::from_pem(&ca)
                            .context("failed to parse Agent CA certificate")?,
                    )
                    .build()
                    .context("failed to build Agent mTLS HTTP client")?;
                (http, base_url)
            }
        };
        Ok(RuntimeClient {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
        })
    }
}

impl RuntimeClient {
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

#[cfg(test)]
mod tests {
    use super::{AgentRuntimeDescriptor, AgentRuntimeEndpoint};

    #[test]
    fn runtime_descriptor_supports_unix_and_https_endpoints() {
        let unix = serde_json::from_str::<AgentRuntimeDescriptor>(
            r#"{
                "schemaVersion": 1,
                "suiteId": "suite.example",
                "instanceId": "instance-1",
                "endpoint": {
                    "kind": "unix",
                    "socketPath": "/run/seclab-agent.sock",
                    "baseUrl": "http://local"
                },
                "credential": {"tokenPath": "/run/seclab-agent/access-token"},
                "capabilities": ["workloads.manage"]
            }"#,
        )
        .unwrap();
        assert!(matches!(unix.endpoint, AgentRuntimeEndpoint::Unix { .. }));

        let https = serde_json::from_str::<AgentRuntimeDescriptor>(
            r#"{
                "schemaVersion": 1,
                "suiteId": "suite.example",
                "instanceId": "instance-1",
                "endpoint": {
                    "kind": "https",
                    "baseUrl": "https://host.docker.internal:7311",
                    "caPath": "/run/seclab-agent/agent-ca.crt",
                    "clientCertPath": "/run/seclab-agent/agent-client.crt",
                    "clientKeyPath": "/run/seclab-agent/agent-client.key"
                },
                "credential": {"tokenPath": "/run/seclab-agent/access-token"},
                "capabilities": ["captures.manage"]
            }"#,
        )
        .unwrap();
        assert!(matches!(https.endpoint, AgentRuntimeEndpoint::Https { .. }));
    }
}
