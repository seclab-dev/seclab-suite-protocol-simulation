mod simulation;

use anyhow::Context;
use protocol_simulation_common::DEFAULT_EVENT_CALLBACK_URL;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::{Duration, timeout};

#[derive(Debug, Clone)]
struct EngineConfig {
    protocol: String,
    rule_id: String,
    rule_name: Option<String>,
    instance_id: String,
    callback_url: String,
    node_id: String,
    port: u16,
    config_json: serde_json::Value,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "protocol_simulation_engine=info,tower_http=info".to_string()),
        )
        .init();

    let config = EngineConfig::from_env()?;
    tracing::info!(
        protocol = config.protocol,
        rule_id = config.rule_id,
        instance_id = config.instance_id,
        port = config.port,
        "starting protocol simulation engine"
    );
    let addr: SocketAddr = format!("0.0.0.0:{}", config.port)
        .parse()
        .context("invalid simulation bind address")?;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind simulation listener on {addr}"))?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let mut simulation = Box::pin(run_simulation(config, listener, shutdown_rx));

    tokio::select! {
        result = &mut simulation => result,
        _ = shutdown_signal() => {
            tracing::info!("shutdown signal received; waiting up to 5 seconds for graceful engine shutdown");
            let _ = shutdown_tx.send(());
            match timeout(Duration::from_secs(5), &mut simulation).await {
                Ok(result) => result,
                Err(_) => {
                    tracing::warn!("graceful engine shutdown timed out after 5 seconds");
                    Ok(())
                }
            }
        }
    }
}

async fn run_simulation(
    config: EngineConfig,
    listener: TcpListener,
    shutdown_rx: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    match config.protocol.as_str() {
        "http" => {
            simulation::start_http_simulation(
                config.rule_id,
                config.rule_name,
                config.port,
                config.callback_url,
                config.node_id,
                parse_rule_config(config.config_json)?,
                listener,
                shutdown_rx,
            )
            .await
        }
        "redis" => {
            simulation::start_redis_simulation(
                config.rule_id,
                config.rule_name,
                config.port,
                config.callback_url,
                config.node_id,
                parse_rule_config(config.config_json)?,
                listener,
                shutdown_rx,
            )
            .await
        }
        "smtp" => {
            simulation::start_smtp_simulation(
                config.rule_id,
                config.rule_name,
                config.port,
                config.callback_url,
                config.node_id,
                parse_rule_config(config.config_json)?,
                listener,
                shutdown_rx,
            )
            .await
        }
        "pop3" => {
            simulation::start_pop3_simulation(
                config.rule_id,
                config.rule_name,
                config.port,
                config.callback_url,
                config.node_id,
                parse_rule_config(config.config_json)?,
                listener,
                shutdown_rx,
            )
            .await
        }
        "imap" => {
            simulation::start_imap_simulation(
                config.rule_id,
                config.rule_name,
                config.port,
                config.callback_url,
                config.node_id,
                parse_rule_config(config.config_json)?,
                listener,
                shutdown_rx,
            )
            .await
        }
        "ssh" => {
            simulation::start_ssh_simulation(
                config.rule_id,
                config.rule_name,
                config.port,
                config.callback_url,
                config.node_id,
                parse_rule_config(config.config_json)?,
                listener,
                shutdown_rx,
            )
            .await
        }
        "ftp" => {
            simulation::start_ftp_simulation(
                config.rule_id,
                config.rule_name,
                config.port,
                config.callback_url,
                config.node_id,
                parse_rule_config(config.config_json)?,
                listener,
                shutdown_rx,
            )
            .await
        }
        "rdp" => {
            simulation::start_rdp_simulation(
                config.rule_id,
                config.rule_name,
                config.port,
                config.callback_url,
                config.node_id,
                parse_rule_config(config.config_json)?,
                listener,
                shutdown_rx,
            )
            .await
        }
        other => anyhow::bail!("unsupported simulation protocol: {other}"),
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

impl EngineConfig {
    fn from_env() -> anyhow::Result<Self> {
        let protocol = env_string("SECLAB_SIM_PROTOCOL", "http");
        let rule_id = env_string("SECLAB_SIM_RULE_ID", "placeholder");
        let instance_id = env_string("SECLAB_SIM_INSTANCE_ID", "engine-placeholder");
        let callback_url = env_string("SECLAB_SIM_CALLBACK_URL", DEFAULT_EVENT_CALLBACK_URL);
        let node_id = env_string("SECLAB_NODE_ID", "local");
        let port = env_string("SECLAB_SIM_PORT", "8081")
            .parse::<u16>()
            .context("SECLAB_SIM_PORT must be a valid TCP port")?;
        let config_json = std::env::var("SECLAB_SIM_CONFIG_JSON")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .context("SECLAB_SIM_CONFIG_JSON must be valid JSON")?
            .unwrap_or_else(|| serde_json::json!({}));
        let rule_name = std::env::var("SECLAB_SIM_RULE_NAME")
            .ok()
            .filter(|value| !value.trim().is_empty());

        Ok(Self {
            protocol,
            rule_id,
            rule_name,
            instance_id,
            callback_url,
            node_id,
            port,
            config_json,
        })
    }
}

fn env_string(name: &str, default_value: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default_value.to_string())
}

fn parse_rule_config<T>(value: serde_json::Value) -> anyhow::Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let config = value
        .get("behavior")
        .filter(|item| item.is_object())
        .cloned()
        .unwrap_or(value);
    serde_json::from_value(config).context("failed to parse simulation rule config")
}
