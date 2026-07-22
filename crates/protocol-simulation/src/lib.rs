mod agent;
mod db;
mod models;
mod routes;
mod rule_package;

pub use routes::router;

use anyhow::Context;
use protocol_simulation_common::DEFAULT_EVENT_CALLBACK_URL;
use sqlx::SqlitePool;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Config {
    pub http_port: u16,
    pub data_dir: PathBuf,
    pub frontend_dir: PathBuf,
    pub agent_base_url: String,
    pub agent_certs_dir: PathBuf,
    pub agent_socket_path: Option<PathBuf>,
    pub agent_accept_invalid_hostnames: bool,
    pub suite_id: String,
    pub suite_instance_id: String,
    pub engine_image: String,
    pub event_callback_url: String,
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: SqlitePool,
    pub agent: agent::AgentClient,
}

impl Config {
    pub fn from_env() -> Self {
        let http_port = env_parse("PORT", 8080);
        let data_dir = PathBuf::from(env_string("SECLAB_SUITE_DATA_DIR", "/data"));
        let frontend_dir = PathBuf::from(env_string("SECLAB_FRONTEND_DIR", "/app/public"));
        let agent_base_url = env_string("SECLAB_AGENT_BASE_URL", "https://127.0.0.1:7311");
        let agent_certs_dir =
            PathBuf::from(env_string("SECLAB_AGENT_CERTS_DIR", "/run/seclab-agent"));
        let agent_socket_path = env_optional_path("SECLAB_AGENT_SOCKET_PATH")
            .or_else(|| env_optional_path("SECLAB_AGENT_SOCKET"));
        let agent_accept_invalid_hostnames =
            env_bool("SECLAB_AGENT_ACCEPT_INVALID_HOSTNAMES", true);
        let suite_id = env_string("SECLAB_SUITE_ID", "seclab.protocol-simulation");
        let suite_instance_id = env_string("SECLAB_SUITE_INSTANCE_ID", "protocol-simulation-local");
        let engine_image = env_string(
            "SECLAB_SIM_ENGINE_IMAGE",
            "guowenju/seclab-protocol-simulation-engine:dev",
        );
        let event_callback_url = env_string("SECLAB_SIM_CALLBACK_URL", DEFAULT_EVENT_CALLBACK_URL);

        Self {
            http_port,
            data_dir,
            frontend_dir,
            agent_base_url,
            agent_certs_dir,
            agent_socket_path,
            agent_accept_invalid_hostnames,
            suite_id,
            suite_instance_id,
            engine_image,
            event_callback_url,
        }
    }
}

impl AppState {
    pub async fn initialize(config: Config) -> anyhow::Result<Arc<Self>> {
        tokio::fs::create_dir_all(&config.data_dir)
            .await
            .with_context(|| format!("failed to create data dir {}", config.data_dir.display()))?;
        let db_path = config.data_dir.join("protocol-simulation.db");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
        let db = SqlitePool::connect(&db_url)
            .await
            .with_context(|| format!("failed to open sqlite database {}", db_path.display()))?;
        db::init(&db).await?;
        let agent = agent::AgentClient::new(config.clone());
        Ok(Arc::new(Self { config, db, agent }))
    }
}

fn env_string(name: &str, default_value: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default_value.to_string())
}

fn env_optional_path(name: &str) -> Option<PathBuf> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn env_parse<T>(name: &str, default_value: T) -> T
where
    T: std::str::FromStr + Copy,
{
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<T>().ok())
        .unwrap_or(default_value)
}

fn env_bool(name: &str, default_value: bool) -> bool {
    std::env::var(name)
        .ok()
        .and_then(|value| match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
        .unwrap_or(default_value)
}
