use super::AppState;
use super::agent::{AgentApiError, StartWorkloadRequest, WorkloadPort, WorkloadResources};
use super::db;
use super::models::{
    ApiEnvelope, CreateRuleRequest, DeployInstanceRequest, ErrorEnvelope, EventRequest, Instance,
};
use super::rule_package;
use axum::extract::{DefaultBodyLimit, Multipart, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use std::collections::HashSet;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;
use uuid::Uuid;

type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
    message_key: Option<String>,
}

pub fn router(state: Arc<AppState>) -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .route("/api/rules", get(list_rules).post(create_rule))
        .route("/api/rules/{id}", delete(delete_rule))
        .route("/api/rule-package/current", get(get_current_rule_package))
        .route("/api/rule-package/import", post(import_rule_package))
        .route("/api/instances", get(list_instances))
        .route("/api/instances/deploy", post(deploy_instance))
        .route("/api/instances/{id}/undeploy", post(undeploy_instance))
        .route("/api/instances/{id}/pcap/start", post(start_pcap))
        .route("/api/instances/{id}/pcap/stop", post(stop_pcap))
        .route("/api/instances/{id}/pcap", delete(delete_pcap))
        .route("/api/pcap/download/{file}", get(download_pcap))
        .route("/api/logs", get(list_logs))
        .route("/internal/events", post(record_event))
        .layer(DefaultBodyLimit::max(25 * 1024 * 1024));

    let frontend = ServeDir::new(&state.config.frontend_dir)
        .not_found_service(ServeFile::new(state.config.frontend_dir.join("index.html")));

    Router::new()
        .merge(api)
        .fallback_service(frontend)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": true, "service": "protocol-simulation" }))
}

async fn list_rules(State(state): State<Arc<AppState>>) -> ApiResult<impl IntoResponse> {
    let rules = db::list_rules(&state.db).await?;
    Ok(Json(ApiEnvelope {
        success: true,
        data: rules,
    }))
}

async fn create_rule(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateRuleRequest>,
) -> ApiResult<impl IntoResponse> {
    validate_protocol(&payload.protocol)?;
    if payload.name.trim().is_empty() {
        return Err(ApiError::bad_request("rule name is required"));
    }
    let id = format!("rule-{}", Uuid::now_v7());
    let config_json = serde_json::to_string_pretty(&payload.config_json)
        .map_err(|err| ApiError::bad_request(format!("invalid config JSON: {err}")))?;
    let rule = db::insert_rule(
        &state.db,
        &id,
        payload.name.trim(),
        &payload.protocol,
        payload.default_port,
        &config_json,
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(ApiEnvelope {
            success: true,
            data: rule,
        }),
    ))
}

async fn delete_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let deleted = db::delete_rule(&state.db, &id).await?;
    if !deleted {
        return Err(ApiError::not_found("rule not found"));
    }
    Ok(Json(ApiEnvelope {
        success: true,
        data: serde_json::json!({ "deleted": true }),
    }))
}

async fn get_current_rule_package(
    State(state): State<Arc<AppState>>,
) -> ApiResult<impl IntoResponse> {
    let package = db::get_current_rule_package(&state.db).await?;
    Ok(Json(ApiEnvelope {
        success: true,
        data: package,
    }))
}

async fn import_rule_package(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> ApiResult<impl IntoResponse> {
    let mut archive = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|err| ApiError::bad_request(format!("invalid multipart request: {err}")))?
    {
        if matches!(field.name(), Some("archive" | "file")) {
            archive =
                Some(field.bytes().await.map_err(|err| {
                    ApiError::bad_request(format!("failed to read upload: {err}"))
                })?);
            break;
        }
    }

    let Some(archive) = archive else {
        return Err(ApiError::bad_request("rule package file is required"));
    };
    let package = rule_package::parse_slrp(&archive)
        .map_err(|err| ApiError::bad_request(format!("invalid rule package: {err}")))?;
    for rule in &package.rules {
        validate_protocol(&rule.protocol)?;
    }
    let summary = db::import_rule_package(&state.db, &package).await?;
    Ok(Json(ApiEnvelope {
        success: true,
        data: summary,
    }))
}

async fn list_instances(State(state): State<Arc<AppState>>) -> ApiResult<impl IntoResponse> {
    let instances = reconcile_instances_with_agent(&state).await?;
    Ok(Json(ApiEnvelope {
        success: true,
        data: instances,
    }))
}

async fn deploy_instance(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<DeployInstanceRequest>,
) -> ApiResult<impl IntoResponse> {
    let Some(rule) = db::get_rule(&state.db, &payload.rule_id).await? else {
        return Err(ApiError::not_found("rule not found"));
    };
    let now = chrono::Utc::now().to_rfc3339();
    let instance_id = format!("sim-{}", Uuid::now_v7());
    let mut instance = Instance {
        id: instance_id.clone(),
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        protocol: rule.protocol.clone(),
        host_port: i64::from(payload.host_port),
        container_port: i64::from(payload.host_port),
        status: "deploying".to_string(),
        workload_id: None,
        error_message: None,
        pcap_status: "idle".to_string(),
        pcap_start_time: None,
        pcap_capture_id: None,
        pcap_file_path: None,
        created_at: now.clone(),
        updated_at: now,
    };
    if !db::insert_instance_if_port_available(&state.db, &instance).await? {
        return Err(ApiError::conflict(format!(
            "host port {} is already used by an active simulation instance",
            payload.host_port
        ))
        .with_message_key("app.simulation.deployments.messages.portOccupied"));
    }

    let config_json = serde_json::from_str::<serde_json::Value>(&rule.config_json)
        .unwrap_or_else(|_| serde_json::json!({}));
    let agent_payload = StartWorkloadRequest {
        workload_kind: "simulation-rule".to_string(),
        workload_name: rule.id.clone(),
        image: state.config.engine_image.clone(),
        ports: vec![WorkloadPort {
            host_port: payload.host_port,
            container_port: payload.host_port,
            protocol: "tcp".to_string(),
        }],
        env: serde_json::json!({
            "SECLAB_SIM_PROTOCOL": rule.protocol,
            "SECLAB_SIM_RULE_ID": rule.id,
            "SECLAB_SIM_RULE_NAME": rule.name,
            "SECLAB_SIM_INSTANCE_ID": instance_id,
            "SECLAB_SIM_PORT": payload.host_port.to_string(),
            "SECLAB_SIM_CALLBACK_URL": state.config.event_callback_url.clone()
        }),
        config_json,
        resources: WorkloadResources {
            memory_mb: 256,
            cpu_shares: 256,
        },
    };

    match state.agent.start_workload(&agent_payload).await {
        Ok(response) => {
            let workload_id = response
                .workload_id
                .unwrap_or_else(|| format!("workload-{instance_id}"));
            instance = db::update_instance_status(
                &state.db,
                &instance_id,
                "running",
                Some(&workload_id),
                None,
            )
            .await?
            .ok_or_else(|| ApiError::not_found("instance not found after deployment"))?;
        }
        Err(err)
            if err
                .downcast_ref::<AgentApiError>()
                .is_some_and(AgentApiError::is_port_unavailable) =>
        {
            db::delete_instance(&state.db, &instance_id).await?;
            return Err(ApiError::conflict(format!(
                "host port {} is unavailable on the target node",
                payload.host_port
            ))
            .with_message_key("app.simulation.deployments.messages.portOccupied"));
        }
        Err(err) => {
            let error_message = format!("{err:#}");
            instance = db::update_instance_status(
                &state.db,
                &instance_id,
                "error",
                None,
                Some(&error_message),
            )
            .await?
            .ok_or_else(|| ApiError::not_found("instance not found after deployment failure"))?;
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(ApiEnvelope {
            success: true,
            data: instance,
        }),
    ))
}

async fn undeploy_instance(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let Some(instance) = db::get_instance(&state.db, &id).await? else {
        return Err(ApiError::not_found("instance not found"));
    };
    if let Some(workload_id) = instance.workload_id.as_deref()
        && let Err(err) = state.agent.stop_workload(workload_id).await
    {
        let error_message = format!("{err:#}");
        let updated = db::update_instance_status(
            &state.db,
            &id,
            "error",
            instance.workload_id.as_deref(),
            Some(&error_message),
        )
        .await?;
        return Ok(Json(ApiEnvelope {
            success: true,
            data: updated.unwrap_or(instance),
        }));
    }
    let deleted = instance;
    db::delete_instance(&state.db, &id).await?;
    Ok(Json(ApiEnvelope {
        success: true,
        data: deleted,
    }))
}

async fn reconcile_instances_with_agent(state: &AppState) -> ApiResult<Vec<Instance>> {
    let instances = db::list_instances(&state.db).await?;
    let workloads = match state.agent.list_workloads().await {
        Ok(workloads) => workloads,
        Err(err) => {
            tracing::debug!("skip instance reconcile because Agent workload list failed: {err:#}");
            return Ok(instances);
        }
    };

    let workload_ids = workloads
        .into_iter()
        .filter(|workload| workload.suite_instance_id == state.config.suite_instance_id)
        .map(|workload| workload.workload_id)
        .collect::<HashSet<_>>();
    let mut reconciled = Vec::with_capacity(instances.len());
    for instance in instances {
        if should_mark_instance_inactive(&instance, &workload_ids) {
            let updated =
                db::update_instance_status(&state.db, &instance.id, "inactive", None, None)
                    .await?
                    .unwrap_or(instance);
            reconciled.push(updated);
        } else {
            reconciled.push(instance);
        }
    }
    Ok(reconciled)
}

fn should_mark_instance_inactive(instance: &Instance, workload_ids: &HashSet<String>) -> bool {
    matches!(instance.status.as_str(), "deploying" | "running")
        && instance
            .workload_id
            .as_ref()
            .is_some_and(|workload_id| !workload_ids.contains(workload_id))
}

async fn start_pcap(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let Some(instance) = db::get_instance(&state.db, &id).await? else {
        return Err(ApiError::not_found("instance not found"));
    };
    if instance.status != "running" {
        return Err(ApiError::bad_request("instance is not running"));
    }
    if instance.pcap_status == "capturing" {
        return Ok(Json(ApiEnvelope {
            success: true,
            data: instance,
        }));
    }
    let workload_id = instance
        .workload_id
        .as_deref()
        .ok_or_else(|| ApiError::bad_request("instance workload is missing"))?;
    let host_port = u16::try_from(instance.host_port)
        .map_err(|_| ApiError::bad_request("invalid instance host port"))?;
    let capture = state.agent.start_pcap(workload_id, host_port).await?;
    let started_at = chrono::Utc::now().timestamp();
    let updated = db::update_pcap_state(
        &state.db,
        &id,
        "capturing",
        Some(started_at),
        Some(&capture.capture_id),
        None,
    )
    .await?
    .unwrap_or(instance);
    Ok(Json(ApiEnvelope {
        success: true,
        data: updated,
    }))
}

async fn stop_pcap(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let Some(instance) = db::get_instance(&state.db, &id).await? else {
        return Err(ApiError::not_found("instance not found"));
    };
    if instance.pcap_status != "capturing" {
        return Ok(Json(ApiEnvelope {
            success: true,
            data: instance,
        }));
    }
    let workload_id = instance
        .workload_id
        .as_deref()
        .ok_or_else(|| ApiError::bad_request("instance workload is missing"))?;
    let capture_id = instance
        .pcap_capture_id
        .as_deref()
        .ok_or_else(|| ApiError::bad_request("pcap capture id is missing"))?;
    let pcap_bytes = state.agent.stop_pcap(workload_id, capture_id).await?;
    if pcap_bytes.len() <= 24 {
        let updated = db::update_pcap_state(&state.db, &id, "idle", None, None, None)
            .await?
            .unwrap_or(instance);
        return Ok(Json(ApiEnvelope {
            success: true,
            data: updated,
        }));
    }
    let pcap_dir = state.config.data_dir.join("pcap");
    tokio::fs::create_dir_all(&pcap_dir)
        .await
        .map_err(anyhow::Error::from)?;
    let file_name = format!("pcap_{id}.pcap");
    let file_path = pcap_dir.join(&file_name);
    tokio::fs::write(&file_path, pcap_bytes)
        .await
        .map_err(anyhow::Error::from)?;
    let updated = db::update_pcap_state(&state.db, &id, "ready", None, None, Some(&file_name))
        .await?
        .unwrap_or(instance);
    Ok(Json(ApiEnvelope {
        success: true,
        data: updated,
    }))
}

async fn delete_pcap(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let Some(instance) = db::get_instance(&state.db, &id).await? else {
        return Err(ApiError::not_found("instance not found"));
    };
    if let Some(file) = instance.pcap_file_path.as_deref() {
        let _ = tokio::fs::remove_file(state.config.data_dir.join("pcap").join(file)).await;
    }
    if instance.pcap_status == "capturing"
        && let (Some(workload_id), Some(capture_id)) = (
            instance.workload_id.as_deref(),
            instance.pcap_capture_id.as_deref(),
        )
    {
        let _ = state.agent.stop_pcap(workload_id, capture_id).await;
    }
    let updated = db::update_pcap_state(&state.db, &id, "idle", None, None, None)
        .await?
        .unwrap_or(instance);
    Ok(Json(ApiEnvelope {
        success: true,
        data: updated,
    }))
}

async fn download_pcap(
    State(state): State<Arc<AppState>>,
    Path(file): Path<String>,
) -> ApiResult<impl IntoResponse> {
    if file.contains('/') || file.contains('\\') || file == "." || file == ".." {
        return Err(ApiError::bad_request("invalid pcap file path"));
    }
    let bytes = tokio::fs::read(state.config.data_dir.join("pcap").join(&file))
        .await
        .map_err(|_| ApiError::not_found("pcap file not found"))?;
    Ok((
        [
            ("content-type", "application/vnd.tcpdump.pcap"),
            ("content-disposition", "attachment"),
        ],
        bytes,
    ))
}

async fn list_logs(State(state): State<Arc<AppState>>) -> ApiResult<impl IntoResponse> {
    let logs = db::list_logs(&state.db).await?;
    Ok(Json(ApiEnvelope {
        success: true,
        data: logs,
    }))
}

async fn record_event(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<EventRequest>,
) -> ApiResult<impl IntoResponse> {
    let log = db::insert_log(&state.db, &payload).await?;
    Ok((
        StatusCode::CREATED,
        Json(ApiEnvelope {
            success: true,
            data: log,
        }),
    ))
}

fn validate_protocol(protocol: &str) -> ApiResult<()> {
    if matches!(
        protocol,
        "http" | "redis" | "ssh" | "ftp" | "smtp" | "pop3" | "imap" | "rdp"
    ) {
        Ok(())
    } else {
        Err(ApiError::bad_request(format!(
            "unsupported simulation protocol: {protocol}"
        )))
    }
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
            message_key: None,
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
            message_key: None,
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
            message_key: None,
        }
    }

    fn with_message_key(mut self, message_key: impl Into<String>) -> Self {
        self.message_key = Some(message_key.into());
        self
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(value: anyhow::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: value.to_string(),
            message_key: None,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorEnvelope {
                success: false,
                message: self.message,
                message_key: self.message_key,
            }),
        )
            .into_response()
    }
}
