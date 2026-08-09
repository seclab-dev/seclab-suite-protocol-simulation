mod agent;
mod db;
mod models;
mod routes;
mod rule_package;

pub use routes::router;

use anyhow::Context;
use protocol_simulation_common::DEFAULT_EVENT_CALLBACK_URL;
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const DEFAULT_AUDIT_MAX_PER_INSTANCE: usize = 10_000;

#[derive(Debug, Clone)]
pub struct Config {
    pub http_port: u16,
    pub data_dir: PathBuf,
    pub frontend_dir: PathBuf,
    pub agent_runtime_path: PathBuf,
    pub suite_id: String,
    pub suite_instance_id: String,
    pub engine_image: String,
    pub event_callback_url: String,
    pub audit_max_per_instance: usize,
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: SqlitePool,
    pub audit_logs: db::AuditLogWriter,
    pub agent: agent::AgentClient,
}

impl Config {
    pub fn from_env() -> Self {
        let http_port = env_parse("PORT", 8080);
        let data_dir = PathBuf::from(env_string("SECLAB_SUITE_DATA_DIR", "/data"));
        let frontend_dir = PathBuf::from(env_string("SECLAB_FRONTEND_DIR", "/app/public"));
        let agent_runtime_path = PathBuf::from(env_string(
            "SECLAB_AGENT_RUNTIME",
            "/run/seclab-agent/runtime.json",
        ));
        let suite_id = env_string("SECLAB_SUITE_ID", "seclab.protocol-simulation");
        let suite_instance_id = env_string("SECLAB_SUITE_INSTANCE_ID", "protocol-simulation-local");
        let engine_image = env_string(
            "SECLAB_SIM_ENGINE_IMAGE",
            "guowenju/seclab-protocol-simulation-engine:dev",
        );
        let event_callback_url = env_string("SECLAB_SIM_CALLBACK_URL", DEFAULT_EVENT_CALLBACK_URL);
        let audit_max_per_instance = audit_max_per_instance_from_env();

        Self {
            http_port,
            data_dir,
            frontend_dir,
            agent_runtime_path,
            suite_id,
            suite_instance_id,
            engine_image,
            event_callback_url,
            audit_max_per_instance,
        }
    }
}

impl AppState {
    pub async fn initialize(config: Config) -> anyhow::Result<Arc<Self>> {
        tokio::fs::create_dir_all(&config.data_dir)
            .await
            .with_context(|| format!("failed to create data dir {}", config.data_dir.display()))?;
        let db_path = config.data_dir.join("protocol-simulation.db");
        let connect_options = SqliteConnectOptions::new()
            .filename(&db_path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(10));
        let db = SqlitePoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(connect_options)
            .await
            .with_context(|| format!("failed to open sqlite database {}", db_path.display()))?;
        db::init(&db).await?;
        let audit_logs = db::AuditLogWriter::start(db.clone(), config.audit_max_per_instance);
        let agent = agent::AgentClient::new(config.clone());
        Ok(Arc::new(Self {
            config,
            db,
            audit_logs,
            agent,
        }))
    }
}

/// 读取单实例审计保留上限，并保证安全实验所需的最低容量。
fn audit_max_per_instance_from_env() -> usize {
    let value = std::env::var("SECLAB_SIM_AUDIT_MAX_PER_INSTANCE").ok();
    audit_max_per_instance(value.as_deref())
}

fn audit_max_per_instance(value: Option<&str>) -> usize {
    match value {
        Some(value) => match value.parse::<usize>() {
            Ok(limit) if limit >= DEFAULT_AUDIT_MAX_PER_INSTANCE => limit,
            Ok(limit) => {
                tracing::warn!(
                    configured_limit = limit,
                    minimum_limit = DEFAULT_AUDIT_MAX_PER_INSTANCE,
                    "configured audit log limit is below the minimum; using minimum"
                );
                DEFAULT_AUDIT_MAX_PER_INSTANCE
            }
            Err(error) => {
                tracing::warn!(
                    configured_value = value,
                    %error,
                    default_limit = DEFAULT_AUDIT_MAX_PER_INSTANCE,
                    "invalid audit log limit; using default"
                );
                DEFAULT_AUDIT_MAX_PER_INSTANCE
            }
        },
        None => DEFAULT_AUDIT_MAX_PER_INSTANCE,
    }
}

fn env_string(name: &str, default_value: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default_value.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn initialize_enables_wal_journal_mode() {
        let data_dir = tempfile::tempdir().unwrap();
        let config = Config {
            http_port: 8080,
            data_dir: data_dir.path().to_path_buf(),
            frontend_dir: data_dir.path().to_path_buf(),
            agent_runtime_path: data_dir.path().join("runtime.json"),
            suite_id: "seclab.protocol-simulation".to_string(),
            suite_instance_id: "instance-1".to_string(),
            engine_image: "protocol-simulation-engine:test".to_string(),
            event_callback_url: DEFAULT_EVENT_CALLBACK_URL.to_string(),
            audit_max_per_instance: DEFAULT_AUDIT_MAX_PER_INSTANCE,
        };

        let state = AppState::initialize(config).await.unwrap();
        let journal_mode = sqlx::query_scalar::<_, String>("PRAGMA journal_mode")
            .fetch_one(&state.db)
            .await
            .unwrap();

        assert_eq!(journal_mode, "wal");
    }

    #[test]
    fn audit_limit_uses_default_for_missing_or_invalid_values() {
        assert_eq!(audit_max_per_instance(None), DEFAULT_AUDIT_MAX_PER_INSTANCE);
        assert_eq!(
            audit_max_per_instance(Some("invalid")),
            DEFAULT_AUDIT_MAX_PER_INSTANCE
        );
    }

    #[test]
    fn audit_limit_enforces_minimum_and_accepts_higher_value() {
        assert_eq!(
            audit_max_per_instance(Some("9999")),
            DEFAULT_AUDIT_MAX_PER_INSTANCE
        );
        assert_eq!(audit_max_per_instance(Some("20000")), 20_000);
    }
}
