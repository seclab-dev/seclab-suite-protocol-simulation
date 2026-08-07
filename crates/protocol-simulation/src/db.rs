use super::models::{AuditLog, EventRequest, Instance, Rule, RulePackageSummary};
use super::rule_package::ImportedRulePackage;
use anyhow::{Context, anyhow};
use sqlx::SqlitePool;
use tokio::sync::{mpsc, oneshot};

const AUDIT_LOG_QUEUE_CAPACITY: usize = 4_096;
const AUDIT_LOG_BATCH_SIZE: usize = 128;

/// 将并发审计事件串行化并按批次写入 SQLite。
#[derive(Clone)]
pub struct AuditLogWriter {
    sender: mpsc::Sender<AuditLogWriteRequest>,
}

struct AuditLogWriteRequest {
    event: EventRequest,
    response: oneshot::Sender<anyhow::Result<AuditLog>>,
}

impl AuditLogWriter {
    /// 启动单写者后台任务，避免多个 SQLite 连接竞争写锁。
    pub fn start(db: SqlitePool) -> Self {
        let (sender, receiver) = mpsc::channel(AUDIT_LOG_QUEUE_CAPACITY);
        tokio::spawn(run_audit_log_writer(db, receiver));
        Self { sender }
    }

    /// 将一条审计事件加入有界队列并等待事务提交结果。
    pub async fn write(&self, event: EventRequest) -> anyhow::Result<AuditLog> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(AuditLogWriteRequest { event, response })
            .await
            .map_err(|_| anyhow!("audit log writer is unavailable"))?;
        result
            .await
            .context("audit log writer stopped before returning a result")?
    }
}

/// 持续收集当前已排队事件，并以有限批次提交到数据库。
async fn run_audit_log_writer(db: SqlitePool, mut receiver: mpsc::Receiver<AuditLogWriteRequest>) {
    while let Some(first) = receiver.recv().await {
        let mut requests = Vec::with_capacity(AUDIT_LOG_BATCH_SIZE);
        requests.push(first);
        while requests.len() < AUDIT_LOG_BATCH_SIZE {
            match receiver.try_recv() {
                Ok(request) => requests.push(request),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => break,
            }
        }

        let events = requests
            .iter()
            .map(|request| &request.event)
            .collect::<Vec<_>>();
        match insert_log_batch(&db, &events).await {
            Ok(logs) => {
                for (request, log) in requests.into_iter().zip(logs) {
                    let _ = request.response.send(Ok(log));
                }
            }
            Err(error) => {
                let detail = format!("{error:#}");
                for request in requests {
                    let _ = request.response.send(Err(anyhow!(detail.clone())));
                }
            }
        }
    }
}

pub async fn init(db: &SqlitePool) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS rules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            protocol TEXT NOT NULL,
            default_port INTEGER NOT NULL,
            config_json TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        );
        "#,
    )
    .execute(db)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS rule_packages (
            package_id TEXT PRIMARY KEY,
            version TEXT NOT NULL,
            ruleset_format_version INTEGER NOT NULL,
            min_seclab_version TEXT NOT NULL,
            rule_count INTEGER NOT NULL,
            generated_at TEXT NOT NULL,
            imported_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        );
        "#,
    )
    .execute(db)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS instances (
            id TEXT PRIMARY KEY,
            rule_id TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            protocol TEXT NOT NULL,
            host_port INTEGER NOT NULL,
            container_port INTEGER NOT NULL,
            status TEXT NOT NULL,
            workload_id TEXT,
            error_message TEXT,
            pcap_status TEXT NOT NULL DEFAULT 'idle',
            pcap_start_time INTEGER,
            pcap_capture_id TEXT,
            pcap_file_path TEXT,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            FOREIGN KEY(rule_id) REFERENCES rules(id) ON DELETE CASCADE
        );
        "#,
    )
    .execute(db)
    .await?;

    ensure_column(
        db,
        "instances",
        "pcap_status",
        "TEXT NOT NULL DEFAULT 'idle'",
    )
    .await?;
    ensure_column(db, "instances", "pcap_start_time", "INTEGER").await?;
    ensure_column(db, "instances", "pcap_capture_id", "TEXT").await?;
    ensure_column(db, "instances", "pcap_file_path", "TEXT").await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            instance_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            protocol TEXT NOT NULL,
            event_type TEXT NOT NULL,
            summary TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            client_port INTEGER NOT NULL,
            payload_hex TEXT,
            timestamp TEXT NOT NULL
        );
        "#,
    )
    .execute(db)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_instances_status ON instances(status);")
        .execute(db)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON audit_logs(timestamp DESC);")
        .execute(db)
        .await?;
    Ok(())
}

pub async fn list_rules(db: &SqlitePool) -> anyhow::Result<Vec<Rule>> {
    sqlx::query_as::<_, Rule>(
        "SELECT id, name, protocol, default_port, config_json, created_at, updated_at FROM rules ORDER BY created_at DESC",
    )
    .fetch_all(db)
    .await
    .context("failed to list rules")
}

pub async fn get_rule(db: &SqlitePool, id: &str) -> anyhow::Result<Option<Rule>> {
    sqlx::query_as::<_, Rule>(
        "SELECT id, name, protocol, default_port, config_json, created_at, updated_at FROM rules WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .context("failed to fetch rule")
}

pub async fn get_current_rule_package(
    db: &SqlitePool,
) -> anyhow::Result<Option<RulePackageSummary>> {
    sqlx::query_as::<_, RulePackageSummary>(
        r#"
        SELECT package_id, version, ruleset_format_version, min_seclab_version,
               rule_count, generated_at, imported_at
          FROM rule_packages
         ORDER BY imported_at DESC
         LIMIT 1
        "#,
    )
    .fetch_optional(db)
    .await
    .context("failed to fetch current rule package")
}

pub async fn import_rule_package(
    db: &SqlitePool,
    package: &ImportedRulePackage,
) -> anyhow::Result<RulePackageSummary> {
    let mut tx = db.begin().await.context("failed to begin rule import")?;
    let imported_at = chrono::Utc::now().to_rfc3339();

    sqlx::query("DELETE FROM rules WHERE id LIKE 'sim-rule-%'")
        .execute(&mut *tx)
        .await
        .context("failed to remove previous packaged rules")?;

    for rule in &package.rules {
        let config_json = rule_config_with_name_en(&rule.config_json, &rule.name_en)?;
        sqlx::query(
            r#"
            INSERT INTO rules (id, name, protocol, default_port, config_json, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
            "#,
        )
        .bind(&rule.id)
        .bind(&rule.name)
        .bind(&rule.protocol)
        .bind(i64::from(rule.default_port))
        .bind(&config_json)
        .bind(&imported_at)
        .execute(&mut *tx)
        .await
        .with_context(|| format!("failed to import rule {}", rule.id))?;
    }

    sqlx::query(
        r#"
        INSERT INTO rule_packages (
            package_id, version, ruleset_format_version, min_seclab_version,
            rule_count, generated_at, imported_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT(package_id) DO UPDATE SET
            version = excluded.version,
            ruleset_format_version = excluded.ruleset_format_version,
            min_seclab_version = excluded.min_seclab_version,
            rule_count = excluded.rule_count,
            generated_at = excluded.generated_at,
            imported_at = excluded.imported_at
        "#,
    )
    .bind(&package.package_id)
    .bind(&package.version)
    .bind(package.ruleset_format_version)
    .bind(&package.min_seclab_version)
    .bind(package.rules.len() as i64)
    .bind(&package.generated_at)
    .bind(&imported_at)
    .execute(&mut *tx)
    .await
    .context("failed to record rule package")?;

    tx.commit().await.context("failed to commit rule import")?;
    get_current_rule_package(db)
        .await?
        .context("imported rule package was not found")
}

fn rule_config_with_name_en(config_json: &str, name_en: &str) -> anyhow::Result<String> {
    let mut value = serde_json::from_str::<serde_json::Value>(config_json)
        .context("failed to parse imported rule config metadata")?;
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "nameEn".to_string(),
            serde_json::Value::String(name_en.to_string()),
        );
    }
    serde_json::to_string_pretty(&value).context("failed to encode imported rule config metadata")
}

pub async fn insert_rule(
    db: &SqlitePool,
    id: &str,
    name: &str,
    protocol: &str,
    default_port: u16,
    config_json: &str,
) -> anyhow::Result<Rule> {
    sqlx::query(
        r#"
        INSERT INTO rules (id, name, protocol, default_port, config_json)
        VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
    )
    .bind(id)
    .bind(name)
    .bind(protocol)
    .bind(i64::from(default_port))
    .bind(config_json)
    .execute(db)
    .await
    .context("failed to insert rule")?;
    get_rule(db, id)
        .await?
        .context("inserted rule was not found")
}

pub async fn delete_rule(db: &SqlitePool, id: &str) -> anyhow::Result<bool> {
    let result = sqlx::query("DELETE FROM rules WHERE id = ?1")
        .bind(id)
        .execute(db)
        .await
        .context("failed to delete rule")?;
    Ok(result.rows_affected() > 0)
}

pub async fn list_instances(db: &SqlitePool) -> anyhow::Result<Vec<Instance>> {
    sqlx::query_as::<_, Instance>(
        r#"
        SELECT id, rule_id, rule_name, protocol, host_port, container_port, status, workload_id,
               error_message, pcap_status, pcap_start_time, pcap_capture_id, pcap_file_path,
               created_at, updated_at
          FROM instances
         ORDER BY created_at DESC
        "#,
    )
    .fetch_all(db)
    .await
    .context("failed to list instances")
}

pub async fn insert_instance_if_port_available(
    db: &SqlitePool,
    instance: &Instance,
) -> anyhow::Result<bool> {
    let result = sqlx::query(
        r#"
        INSERT INTO instances (
            id, rule_id, rule_name, protocol, host_port, container_port,
            status, workload_id, error_message, pcap_status, pcap_start_time, pcap_capture_id, pcap_file_path,
            created_at, updated_at
        )
        SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15
         WHERE NOT EXISTS (
            SELECT 1
              FROM instances
             WHERE host_port = ?16
               AND status IN ('deploying', 'running')
         )
        "#,
    )
    .bind(&instance.id)
    .bind(&instance.rule_id)
    .bind(&instance.rule_name)
    .bind(&instance.protocol)
    .bind(instance.host_port)
    .bind(instance.container_port)
    .bind(&instance.status)
    .bind(&instance.workload_id)
    .bind(&instance.error_message)
    .bind(&instance.pcap_status)
    .bind(instance.pcap_start_time)
    .bind(&instance.pcap_capture_id)
    .bind(&instance.pcap_file_path)
    .bind(&instance.created_at)
    .bind(&instance.updated_at)
    .bind(instance.host_port)
    .execute(db)
    .await
    .context("failed to insert instance")?;
    Ok(result.rows_affected() == 1)
}

pub async fn get_instance(db: &SqlitePool, id: &str) -> anyhow::Result<Option<Instance>> {
    sqlx::query_as::<_, Instance>(
        r#"
        SELECT id, rule_id, rule_name, protocol, host_port, container_port, status, workload_id,
               error_message, pcap_status, pcap_start_time, pcap_capture_id, pcap_file_path,
               created_at, updated_at
          FROM instances
         WHERE id = ?1
        "#,
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .context("failed to fetch instance")
}

pub async fn delete_instance(db: &SqlitePool, id: &str) -> anyhow::Result<bool> {
    let result = sqlx::query("DELETE FROM instances WHERE id = ?1")
        .bind(id)
        .execute(db)
        .await
        .context("failed to delete instance")?;
    Ok(result.rows_affected() > 0)
}

pub async fn update_instance_status(
    db: &SqlitePool,
    id: &str,
    status: &str,
    workload_id: Option<&str>,
    error_message: Option<&str>,
) -> anyhow::Result<Option<Instance>> {
    sqlx::query(
        r#"
        UPDATE instances
           SET status = ?2,
               workload_id = COALESCE(?3, workload_id),
               error_message = ?4,
               updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE id = ?1
        "#,
    )
    .bind(id)
    .bind(status)
    .bind(workload_id)
    .bind(error_message)
    .execute(db)
    .await
    .context("failed to update instance")?;
    get_instance(db, id).await
}

pub async fn update_pcap_state(
    db: &SqlitePool,
    id: &str,
    pcap_status: &str,
    pcap_start_time: Option<i64>,
    pcap_capture_id: Option<&str>,
    pcap_file_path: Option<&str>,
) -> anyhow::Result<Option<Instance>> {
    sqlx::query(
        r#"
        UPDATE instances
           SET pcap_status = ?2,
               pcap_start_time = ?3,
               pcap_capture_id = ?4,
               pcap_file_path = ?5,
               updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE id = ?1
        "#,
    )
    .bind(id)
    .bind(pcap_status)
    .bind(pcap_start_time)
    .bind(pcap_capture_id)
    .bind(pcap_file_path)
    .execute(db)
    .await
    .context("failed to update pcap state")?;
    get_instance(db, id).await
}

async fn insert_log_batch(
    db: &SqlitePool,
    events: &[&EventRequest],
) -> anyhow::Result<Vec<AuditLog>> {
    let mut transaction = db
        .begin()
        .await
        .context("failed to begin audit log batch")?;
    let mut logs = Vec::with_capacity(events.len());
    for event in events {
        let timestamp = event
            .timestamp
            .clone()
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        let log = sqlx::query_as::<_, AuditLog>(
            r#"
            INSERT INTO audit_logs (
                instance_id, rule_id, protocol, event_type, summary,
                client_ip, client_port, payload_hex, timestamp
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            RETURNING id, instance_id, rule_id, protocol, event_type, summary,
                      client_ip, client_port, payload_hex, timestamp
            "#,
        )
        .bind(&event.instance_id)
        .bind(&event.rule_id)
        .bind(&event.protocol)
        .bind(&event.event_type)
        .bind(&event.summary)
        .bind(&event.client_ip)
        .bind(i64::from(event.client_port))
        .bind(&event.payload_hex)
        .bind(timestamp)
        .fetch_one(&mut *transaction)
        .await
        .context("failed to insert audit log")?;
        logs.push(log);
    }
    transaction
        .commit()
        .await
        .context("failed to commit audit log batch")?;
    Ok(logs)
}

pub async fn list_logs(db: &SqlitePool) -> anyhow::Result<Vec<AuditLog>> {
    sqlx::query_as::<_, AuditLog>(
        r#"
        SELECT id, instance_id, rule_id, protocol, event_type, summary,
               client_ip, client_port, payload_hex, timestamp
          FROM audit_logs
         ORDER BY timestamp DESC, id DESC
         LIMIT 500
        "#,
    )
    .fetch_all(db)
    .await
    .context("failed to list audit logs")
}

async fn ensure_column(
    db: &SqlitePool,
    table: &str,
    column: &str,
    definition: &str,
) -> anyhow::Result<()> {
    let columns =
        sqlx::query_as::<_, (String,)>(&format!("SELECT name FROM pragma_table_info('{table}')"))
            .fetch_all(db)
            .await?;
    if columns.iter().any(|(name,)| name == column) {
        return Ok(());
    }
    sqlx::query(&format!(
        "ALTER TABLE {table} ADD COLUMN {column} {definition}"
    ))
    .execute(db)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(index: usize) -> EventRequest {
        EventRequest {
            instance_id: format!("instance-{index}"),
            rule_id: "rule-1".to_string(),
            protocol: "http".to_string(),
            event_type: "connection".to_string(),
            summary: format!("event {index}"),
            client_ip: "192.0.2.1".to_string(),
            client_port: 12_345,
            payload_hex: None,
            timestamp: None,
        }
    }

    fn instance(id: &str, port: i64) -> Instance {
        Instance {
            id: id.to_string(),
            rule_id: "rule-1".to_string(),
            rule_name: "HTTP simulation".to_string(),
            protocol: "http".to_string(),
            host_port: port,
            container_port: port,
            status: "deploying".to_string(),
            workload_id: None,
            error_message: None,
            pcap_status: "idle".to_string(),
            pcap_start_time: None,
            pcap_capture_id: None,
            pcap_file_path: None,
            created_at: "2026-07-13T00:00:00Z".to_string(),
            updated_at: "2026-07-13T00:00:00Z".to_string(),
        }
    }

    #[tokio::test]
    async fn init_creates_empty_rule_table() {
        let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
        init(&db).await.unwrap();
        let rules = list_rules(&db).await.unwrap();
        assert!(rules.is_empty());
    }

    #[tokio::test]
    async fn audit_log_writer_serializes_concurrent_events() {
        let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
        init(&db).await.unwrap();
        let writer = AuditLogWriter::start(db.clone());
        let mut writes = tokio::task::JoinSet::new();

        for index in 0..256 {
            let writer = writer.clone();
            writes.spawn(async move { writer.write(event(index)).await });
        }
        while let Some(result) = writes.join_next().await {
            result.unwrap().unwrap();
        }

        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_logs")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(count, 256);
    }

    #[tokio::test]
    async fn active_instance_reserves_host_port_until_terminal_state() {
        let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
        init(&db).await.unwrap();
        sqlx::query(
            "INSERT INTO rules (id, name, protocol, default_port, config_json) \
             VALUES ('rule-1', 'HTTP simulation', 'http', 8080, '{}')",
        )
        .execute(&db)
        .await
        .unwrap();

        assert!(
            insert_instance_if_port_available(&db, &instance("instance-1", 8080))
                .await
                .unwrap()
        );
        assert!(
            !insert_instance_if_port_available(&db, &instance("instance-2", 8080))
                .await
                .unwrap()
        );
        assert!(
            insert_instance_if_port_available(&db, &instance("instance-3", 8081))
                .await
                .unwrap()
        );

        update_instance_status(&db, "instance-1", "error", None, Some("failed"))
            .await
            .unwrap();
        assert!(
            insert_instance_if_port_available(&db, &instance("instance-2", 8080))
                .await
                .unwrap()
        );
    }
}
