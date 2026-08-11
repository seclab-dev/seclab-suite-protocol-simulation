use super::AppState;
use super::agent::{
    AgentApiError, StartWorkloadRequest, WorkloadPort, WorkloadResources, WorkloadTransport,
};
use super::db;
use super::models::{
    ApiEnvelope, AuditLogPage, CreateRuleRequest, DeployInstanceRequest, ErrorEnvelope,
    EventRequest, Instance,
};
use super::rule_package;
use axum::extract::{DefaultBodyLimit, Multipart, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use protocol_simulation_common::{
    BoundEndpoint, EngineLaunchConfig, ProtocolId, TransportProtocol, protocol_descriptor,
    protocol_descriptors, validate_behavior,
};
use seclab_suite_runtime::{
    OperationEvent, OperationImpact, OperationOutcome, OperationTarget, ParameterValue,
};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tracing::Level;
use uuid::Uuid;

type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
    message_key: Option<String>,
    cause: Option<anyhow::Error>,
}

pub fn router(state: Arc<AppState>) -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .route("/api/capabilities", get(get_capabilities))
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
        .route("/api/instances/{id}/pcap/download", post(download_pcap))
        .route("/api/instances/{id}/audit-logs", get(list_instance_logs))
        .route("/internal/events", post(record_event))
        .layer(DefaultBodyLimit::max(25 * 1024 * 1024));

    let frontend = ServeDir::new(&state.config.frontend_dir)
        .not_found_service(ServeFile::new(state.config.frontend_dir.join("index.html")));

    Router::new()
        .merge(api)
        .fallback_service(frontend)
        .layer(CorsLayer::permissive())
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_failure(()),
        )
        .with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": true, "service": "protocol-simulation" }))
}

async fn get_capabilities() -> Json<ApiEnvelope<serde_json::Value>> {
    Json(ApiEnvelope {
        success: true,
        data: serde_json::json!({
            "schemaVersion": 1,
            "protocols": protocol_descriptors(),
            "features": {
                "multiEndpoint": true,
                "wholeWorkloadCapture": true,
                "guidedRuleEditor": true,
                "advancedJsonEditor": true
            }
        }),
    })
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
    headers: HeaderMap,
    Json(payload): Json<CreateRuleRequest>,
) -> ApiResult<impl IntoResponse> {
    let operation_context = operation_context(&headers);
    let protocol = parse_protocol(&payload.protocol)?;
    if payload.name.trim().is_empty() {
        return Err(ApiError::bad_request("rule name is required"));
    }
    let id = format!("rule-{}", Uuid::now_v7());
    let behavior = payload
        .config_json
        .get("behavior")
        .cloned()
        .unwrap_or_else(|| payload.config_json.clone());
    let behavior = validate_behavior(protocol, behavior)
        .map_err(|error| ApiError::bad_request(format!("invalid protocol behavior: {error}")))?;
    let config_json = serde_json::to_string_pretty(&serde_json::json!({"behavior": behavior}))
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
    emit_operation_event(
        &state,
        operation_event(
            "rule_created",
            "创建仿真规则",
            "Create simulation rule",
            "simulation_rule",
            &rule.id,
            (OperationOutcome::Success, OperationImpact::Info),
            operation_context.as_deref(),
        ),
    )
    .await;
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
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let operation_context = operation_context(&headers);
    let deleted = db::delete_rule(&state.db, &id).await?;
    if !deleted {
        return Err(ApiError::not_found("rule not found"));
    }
    emit_operation_event(
        &state,
        operation_event(
            "rule_deleted",
            "删除仿真规则",
            "Delete simulation rule",
            "simulation_rule",
            &id,
            (OperationOutcome::Success, OperationImpact::Warning),
            operation_context.as_deref(),
        ),
    )
    .await;
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
    headers: HeaderMap,
    mut multipart: Multipart,
) -> ApiResult<impl IntoResponse> {
    let operation_context = operation_context(&headers);
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
    let platform_version = state.agent.platform_version().await?;
    let minimum_version = semver::Version::parse(&package.min_seclab_version)
        .map_err(|error| ApiError::bad_request(format!("invalid minSeclabVersion: {error}")))?;
    if platform_version < minimum_version {
        return Err(ApiError::bad_request(format!(
            "rule package requires SecLab {minimum_version} or newer; current version is {platform_version}"
        )));
    }
    for rule in &package.rules {
        parse_protocol(&rule.protocol)?;
    }
    let summary = db::import_rule_package(&state.db, &package).await?;
    emit_operation_event(
        &state,
        operation_event_builder(
            "rule_package_imported",
            "导入规则包",
            "Import rule package",
            "rule_package",
            &summary.package_id,
            (OperationOutcome::Success, OperationImpact::Warning),
            operation_context.as_deref(),
        )
        .parameter(
            "ruleCount",
            ParameterValue::Number(summary.rule_count as f64),
        )
        .build()
        .expect("static operation event must be valid"),
    )
    .await;
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
    headers: HeaderMap,
    Json(payload): Json<DeployInstanceRequest>,
) -> ApiResult<impl IntoResponse> {
    let operation_context = operation_context(&headers);
    let Some(rule) = db::get_rule(&state.db, &payload.rule_id).await? else {
        return Err(ApiError::not_found("rule not found"));
    };
    let protocol = parse_protocol(&rule.protocol)?;
    let descriptor = protocol_descriptor(protocol);
    let mut requested = HashMap::new();
    for binding in payload.endpoint_bindings {
        if binding.host_port == 0 {
            return Err(ApiError::bad_request(
                "endpoint host port must be between 1 and 65535",
            ));
        }
        if requested
            .insert(binding.endpoint_id.clone(), binding.host_port)
            .is_some()
        {
            return Err(ApiError::bad_request(format!(
                "duplicate endpoint binding: {}",
                binding.endpoint_id
            )));
        }
    }
    let known = descriptor
        .endpoints
        .iter()
        .map(|endpoint| endpoint.id.as_str())
        .collect::<HashSet<_>>();
    if let Some(unknown) = requested.keys().find(|id| !known.contains(id.as_str())) {
        return Err(ApiError::bad_request(format!(
            "unknown endpoint binding: {unknown}"
        )));
    }
    let endpoints = descriptor
        .endpoints
        .iter()
        .filter_map(|endpoint| {
            requested
                .get(&endpoint.id)
                .map(|host_port| super::models::InstanceEndpoint {
                    instance_id: String::new(),
                    endpoint_id: endpoint.id.clone(),
                    transport: endpoint.transport.as_str().to_string(),
                    host_port: i64::from(*host_port),
                    container_port: i64::from(endpoint.container_port),
                })
        })
        .collect::<Vec<_>>();
    if let Some(missing) = descriptor
        .endpoints
        .iter()
        .find(|endpoint| endpoint.required && !requested.contains_key(&endpoint.id))
    {
        return Err(ApiError::bad_request(format!(
            "required endpoint binding is missing: {}",
            missing.id
        )));
    }
    let now = chrono::Utc::now().to_rfc3339();
    let instance_id = format!("sim-{}", Uuid::now_v7());
    let callback_token = Uuid::now_v7().to_string();
    let mut instance = Instance {
        id: instance_id.clone(),
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        protocol: rule.protocol.clone(),
        endpoints: endpoints
            .into_iter()
            .map(|mut endpoint| {
                endpoint.instance_id.clone_from(&instance_id);
                endpoint
            })
            .collect(),
        callback_token: callback_token.clone(),
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
        return Err(ApiError::conflict(
            "one or more endpoint bindings are already used by an active simulation instance",
        )
        .with_message_key("app.simulation.deployments.messages.portOccupied"));
    }

    let config_json = serde_json::from_str::<serde_json::Value>(&rule.config_json)
        .unwrap_or_else(|_| serde_json::json!({}));
    let behavior = config_json.get("behavior").cloned().unwrap_or(config_json);
    let launch_config = EngineLaunchConfig {
        schema_version: 1,
        protocol,
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        instance_id: instance_id.clone(),
        callback_url: state.config.event_callback_url.clone(),
        callback_token,
        endpoints: instance
            .endpoints
            .iter()
            .map(|endpoint| BoundEndpoint {
                endpoint_id: endpoint.endpoint_id.clone(),
                transport: if endpoint.transport == "udp" {
                    TransportProtocol::Udp
                } else {
                    TransportProtocol::Tcp
                },
                host_port: endpoint.host_port as u16,
                container_port: endpoint.container_port as u16,
            })
            .collect(),
        behavior,
    };
    let agent_payload = StartWorkloadRequest {
        workload_kind: "simulation-rule".to_string(),
        workload_name: rule.id.clone(),
        image: state.config.engine_image.clone(),
        ports: instance
            .endpoints
            .iter()
            .map(|endpoint| WorkloadPort {
                endpoint_id: endpoint.endpoint_id.clone(),
                host_port: endpoint.host_port as u16,
                container_port: endpoint.container_port as u16,
                protocol: if endpoint.transport == "udp" {
                    WorkloadTransport::Udp
                } else {
                    WorkloadTransport::Tcp
                },
            })
            .collect(),
        env: serde_json::json!({}),
        config_json: serde_json::to_value(launch_config)
            .map_err(|error| ApiError::bad_request(format!("invalid launch config: {error}")))?,
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
            emit_operation_event(
                &state,
                operation_event_builder(
                    "instance_deployed",
                    "部署仿真实例",
                    "Deploy simulation instance",
                    "simulation_instance",
                    &instance_id,
                    (OperationOutcome::Failure, OperationImpact::Error),
                    operation_context.as_deref(),
                )
                .error("PORT_UNAVAILABLE", "Requested host port is unavailable")
                .build()
                .expect("static operation event must be valid"),
            )
            .await;
            return Err(ApiError::conflict(
                "one or more endpoint bindings are unavailable on the target node",
            )
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

    let (outcome, impact) = if instance.status == "running" {
        (OperationOutcome::Success, OperationImpact::Info)
    } else {
        (OperationOutcome::Failure, OperationImpact::Error)
    };
    let mut audit = operation_event_builder(
        "instance_deployed",
        "部署仿真实例",
        "Deploy simulation instance",
        "simulation_instance",
        &instance_id,
        (outcome, impact),
        operation_context.as_deref(),
    );
    if instance.status != "running" {
        audit = audit.error("INSTANCE_DEPLOY_FAILED", "Simulation deployment failed");
    }
    emit_operation_event(
        &state,
        audit.build().expect("static operation event must be valid"),
    )
    .await;

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
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let operation_context = operation_context(&headers);
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
        emit_operation_event(
            &state,
            operation_event_builder(
                "instance_undeployed",
                "撤销仿真实例",
                "Undeploy simulation instance",
                "simulation_instance",
                &id,
                (OperationOutcome::Failure, OperationImpact::Error),
                operation_context.as_deref(),
            )
            .error("INSTANCE_UNDEPLOY_FAILED", "Simulation undeployment failed")
            .build()
            .expect("static operation event must be valid"),
        )
        .await;
        return Ok(Json(ApiEnvelope {
            success: true,
            data: updated.unwrap_or(instance),
        }));
    }
    let deleted = instance;
    db::delete_instance(&state.db, &id).await?;
    emit_operation_event(
        &state,
        operation_event(
            "instance_undeployed",
            "撤销仿真实例",
            "Undeploy simulation instance",
            "simulation_instance",
            &id,
            (OperationOutcome::Success, OperationImpact::Warning),
            operation_context.as_deref(),
        ),
    )
    .await;
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
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let operation_context = operation_context(&headers);
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
    let capture = match state.agent.start_pcap(workload_id).await {
        Ok(capture) => capture,
        Err(error) => {
            emit_operation_event(
                &state,
                operation_event_builder(
                    "capture_started",
                    "开始抓包",
                    "Start capture",
                    "simulation_instance",
                    &id,
                    (OperationOutcome::Failure, OperationImpact::Error),
                    operation_context.as_deref(),
                )
                .error("CAPTURE_START_FAILED", "Capture start failed")
                .build()
                .expect("static operation event must be valid"),
            )
            .await;
            return Err(error.into());
        }
    };
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
    emit_operation_event(
        &state,
        operation_event(
            "capture_started",
            "开始抓包",
            "Start capture",
            "simulation_instance",
            &id,
            (OperationOutcome::Success, OperationImpact::Info),
            operation_context.as_deref(),
        ),
    )
    .await;
    Ok(Json(ApiEnvelope {
        success: true,
        data: updated,
    }))
}

async fn stop_pcap(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let operation_context = operation_context(&headers);
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
    let pcap_bytes = match state.agent.stop_pcap(workload_id, capture_id).await {
        Ok(bytes) => bytes,
        Err(error) => {
            emit_operation_event(
                &state,
                operation_event_builder(
                    "capture_stopped",
                    "停止抓包",
                    "Stop capture",
                    "simulation_instance",
                    &id,
                    (OperationOutcome::Failure, OperationImpact::Error),
                    operation_context.as_deref(),
                )
                .error("CAPTURE_STOP_FAILED", "Capture stop failed")
                .build()
                .expect("static operation event must be valid"),
            )
            .await;
            return Err(error.into());
        }
    };
    if pcap_bytes.len() <= 24 {
        let updated = db::update_pcap_state(&state.db, &id, "idle", None, None, None)
            .await?
            .unwrap_or(instance);
        emit_operation_event(
            &state,
            operation_event(
                "capture_stopped",
                "停止抓包",
                "Stop capture",
                "simulation_instance",
                &id,
                (OperationOutcome::Success, OperationImpact::Info),
                operation_context.as_deref(),
            ),
        )
        .await;
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
    emit_operation_event(
        &state,
        operation_event(
            "capture_stopped",
            "停止抓包",
            "Stop capture",
            "simulation_instance",
            &id,
            (OperationOutcome::Success, OperationImpact::Info),
            operation_context.as_deref(),
        ),
    )
    .await;
    Ok(Json(ApiEnvelope {
        success: true,
        data: updated,
    }))
}

async fn delete_pcap(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let operation_context = operation_context(&headers);
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
    emit_operation_event(
        &state,
        operation_event(
            "capture_deleted",
            "删除抓包",
            "Delete capture",
            "simulation_instance",
            &id,
            (OperationOutcome::Success, OperationImpact::Warning),
            operation_context.as_deref(),
        ),
    )
    .await;
    Ok(Json(ApiEnvelope {
        success: true,
        data: updated,
    }))
}

async fn download_pcap(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let operation_context = operation_context(&headers);
    let instance = match db::get_instance(&state.db, &id).await {
        Ok(Some(instance)) => instance,
        Ok(None) => {
            emit_capture_download_failure(
                &state,
                &id,
                operation_context.as_deref(),
                "INSTANCE_NOT_FOUND",
                "Simulation instance not found",
            )
            .await;
            return Err(ApiError::not_found("instance not found"));
        }
        Err(error) => {
            emit_capture_download_failure(
                &state,
                &id,
                operation_context.as_deref(),
                "INSTANCE_READ_FAILED",
                "Simulation instance lookup failed",
            )
            .await;
            return Err(error.into());
        }
    };
    let Some(file) = instance.pcap_file_path.as_deref() else {
        emit_capture_download_failure(
            &state,
            &id,
            operation_context.as_deref(),
            "CAPTURE_NOT_READY",
            "Capture is not ready for download",
        )
        .await;
        return Err(ApiError::not_found("pcap file not found"));
    };
    let bytes = match tokio::fs::read(state.config.data_dir.join("pcap").join(file)).await {
        Ok(bytes) => bytes,
        Err(_) => {
            emit_capture_download_failure(
                &state,
                &id,
                operation_context.as_deref(),
                "CAPTURE_READ_FAILED",
                "Capture file could not be read",
            )
            .await;
            return Err(ApiError::not_found("pcap file not found"));
        }
    };
    emit_operation_event(
        &state,
        operation_event(
            "capture_downloaded",
            "下载抓包",
            "Download capture",
            "simulation_instance",
            &id,
            (OperationOutcome::Success, OperationImpact::Info),
            operation_context.as_deref(),
        ),
    )
    .await;
    Ok((
        [
            ("content-type", "application/vnd.tcpdump.pcap"),
            ("content-disposition", "attachment"),
        ],
        bytes,
    )
        .into_response())
}

async fn emit_capture_download_failure(
    state: &AppState,
    instance_id: &str,
    operation_context_id: Option<&str>,
    error_code: &str,
    error_summary: &str,
) {
    let event = operation_event_builder(
        "capture_downloaded",
        "下载抓包",
        "Download capture",
        "simulation_instance",
        instance_id,
        (OperationOutcome::Failure, OperationImpact::Error),
        operation_context_id,
    )
    .error(error_code, error_summary)
    .build()
    .expect("static operation event must be valid");
    emit_operation_event(state, event).await;
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuditLogQuery {
    #[serde(default = "default_audit_log_page")]
    page: u32,
    #[serde(default = "default_audit_log_page_size")]
    page_size: u32,
}

fn default_audit_log_page() -> u32 {
    1
}

fn default_audit_log_page_size() -> u32 {
    50
}

async fn list_instance_logs(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<AuditLogQuery>,
) -> ApiResult<impl IntoResponse> {
    if query.page == 0 {
        return Err(ApiError::bad_request("page must be greater than zero"));
    }
    if query.page_size == 0 || query.page_size > 200 {
        return Err(ApiError::bad_request("pageSize must be between 1 and 200"));
    }
    if db::get_instance(&state.db, &id).await?.is_none() {
        return Err(ApiError::not_found("simulation instance not found"));
    }
    let (total, records) =
        db::list_instance_logs(&state.db, &id, query.page, query.page_size).await?;
    Ok(Json(ApiEnvelope {
        success: true,
        data: AuditLogPage {
            total,
            page: query.page,
            page_size: query.page_size,
            records,
        },
    }))
}

async fn record_event(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<EventRequest>,
) -> ApiResult<impl IntoResponse> {
    validate_runtime_event(&payload)?;
    let Some(instance) = db::get_instance(&state.db, &payload.instance_id).await? else {
        return Err(ApiError::not_found("simulation instance not found"));
    };
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if !presented.is_some_and(|token| {
        constant_time_eq::constant_time_eq(token.as_bytes(), instance.callback_token.as_bytes())
    }) {
        return Err(ApiError::unauthorized("invalid simulation callback token"));
    }
    if !instance
        .endpoints
        .iter()
        .any(|endpoint| endpoint.endpoint_id == payload.endpoint_id)
    {
        return Err(ApiError::bad_request(
            "event endpoint does not belong to instance",
        ));
    }
    let log = match state.audit_logs.write(payload).await {
        Ok(log) => log,
        Err(db::AuditLogWriteError::InstanceNotFound) => {
            return Err(ApiError::not_found("simulation instance not found"));
        }
        Err(db::AuditLogWriteError::Internal(error)) => return Err(error.into()),
    };
    Ok((
        StatusCode::CREATED,
        Json(ApiEnvelope {
            success: true,
            data: log,
        }),
    ))
}

fn validate_runtime_event(event: &EventRequest) -> ApiResult<()> {
    if event.schema_version != 1 {
        return Err(ApiError::bad_request(
            "only simulation runtime event schemaVersion 1 is supported",
        ));
    }
    Uuid::parse_str(&event.event_id)
        .map_err(|_| ApiError::bad_request("eventId must be a UUID"))?;
    if event.event_type.is_empty()
        || event.event_type.len() > 64
        || !event
            .event_type
            .chars()
            .all(|value| value.is_ascii_lowercase() || value.is_ascii_digit() || value == '_')
    {
        return Err(ApiError::bad_request("eventType is invalid"));
    }
    if event.summary.is_empty() || event.summary.len() > 2_048 {
        return Err(ApiError::bad_request(
            "event summary must contain between 1 and 2048 bytes",
        ));
    }
    if !event.metadata.is_object()
        || serde_json::to_vec(&event.metadata).is_ok_and(|value| value.len() > 16 * 1024)
    {
        return Err(ApiError::bad_request(
            "event metadata is invalid or too large",
        ));
    }
    if let Some(payload) = event.payload_hex.as_deref()
        && (payload.len() > 8 * 1024
            || !payload.len().is_multiple_of(2)
            || !payload.chars().all(|value| value.is_ascii_hexdigit()))
    {
        return Err(ApiError::bad_request(
            "event payloadHex is invalid or too large",
        ));
    }
    if let Some(timestamp) = event.timestamp.as_deref() {
        chrono::DateTime::parse_from_rfc3339(timestamp)
            .map_err(|_| ApiError::bad_request("event timestamp must be RFC 3339"))?;
    }
    Ok(())
}

fn parse_protocol(protocol: &str) -> ApiResult<ProtocolId> {
    ProtocolId::from_str(protocol).map_err(ApiError::bad_request)
}

fn operation_event(
    code: &str,
    zh_cn: &str,
    en_us: &str,
    target_kind: &str,
    target_id: &str,
    result: (OperationOutcome, OperationImpact),
    operation_context_id: Option<&str>,
) -> OperationEvent {
    operation_event_builder(
        code,
        zh_cn,
        en_us,
        target_kind,
        target_id,
        result,
        operation_context_id,
    )
    .build()
    .expect("static operation event must be valid")
}

fn operation_event_builder(
    code: &str,
    zh_cn: &str,
    en_us: &str,
    target_kind: &str,
    target_id: &str,
    result: (OperationOutcome, OperationImpact),
    operation_context_id: Option<&str>,
) -> seclab_suite_runtime::OperationEventBuilder {
    let builder =
        OperationEvent::builder(code, zh_cn, en_us, result.0, result.1).target(OperationTarget {
            kind: target_kind.to_string(),
            id: target_id.to_string(),
            display_name: None,
            ownership: None,
        });
    match operation_context_id {
        Some(value) => builder.operation_context_id(value),
        None => builder,
    }
}

fn operation_context(headers: &HeaderMap) -> Option<String> {
    seclab_suite_runtime::operation_context_from_header(
        headers
            .get(seclab_suite_runtime::OPERATION_CONTEXT_HEADER)
            .and_then(|value| value.to_str().ok()),
    )
}

async fn emit_operation_event(state: &AppState, event: OperationEvent) {
    if let Err(error) = state.agent.submit_operation_event(&event).await {
        tracing::error!(event_id = %event.event_id, %error, "operation audit event was not accepted");
    }
}

impl ApiError {
    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
            message_key: None,
            cause: None,
        }
    }
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
            message_key: None,
            cause: None,
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
            message_key: None,
            cause: None,
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
            message_key: None,
            cause: None,
        }
    }

    fn with_message_key(mut self, message_key: impl Into<String>) -> Self {
        self.message_key = Some(message_key.into());
        self
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(value: anyhow::Error) -> Self {
        let message = value.to_string();
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message,
            message_key: None,
            cause: Some(value),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if self.status.is_server_error() {
            tracing::error!(
                status = %self.status,
                message = %self.message,
                error = %error_detail(self.cause.as_ref(), &self.message),
                "HTTP request handling failed"
            );
        }
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

/// 生成用于服务端日志的完整错误链，同时为无底层错误的 500 保留可诊断消息。
fn error_detail(cause: Option<&anyhow::Error>, message: &str) -> String {
    cause
        .map(|error| format!("{error:#}"))
        .unwrap_or_else(|| message.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_error_detail_contains_complete_error_chain() {
        let error = anyhow::anyhow!("database is locked").context("failed to list rules");
        let detail = error_detail(Some(&error), "fallback");

        assert!(detail.contains("failed to list rules"));
        assert!(detail.contains("database is locked"));
    }

    #[tokio::test]
    async fn internal_error_response_keeps_existing_envelope() {
        let response = ApiError::from(anyhow::anyhow!("database unavailable")).into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value = serde_json::from_slice::<serde_json::Value>(&body).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "success": false,
                "message": "database unavailable"
            })
        );
    }

    #[test]
    fn operation_event_contains_only_trusted_semantic_fields() {
        let event = operation_event(
            "instance_deployed",
            "部署仿真实例",
            "Deploy simulation instance",
            "simulation_instance",
            "sim-1",
            (OperationOutcome::Success, OperationImpact::Info),
            Some("context-1"),
        );
        let value = serde_json::to_value(event).unwrap();
        assert_eq!(value["eventCode"], "instance_deployed");
        assert_eq!(value["operationContextId"], "context-1");
        assert_eq!(value["target"]["id"], "sim-1");
        assert!(value.get("actor").is_none());
        assert!(value.get("module").is_none());
    }

    #[test]
    fn capture_download_event_targets_instance_without_task_id_or_file_path() {
        let event = operation_event(
            "capture_downloaded",
            "下载抓包",
            "Download capture",
            "simulation_instance",
            "sim-1",
            (OperationOutcome::Success, OperationImpact::Info),
            Some("context-1"),
        );
        let value = serde_json::to_value(event).unwrap();
        assert_eq!(value["eventCode"], "capture_downloaded");
        assert_eq!(value["target"]["id"], "sim-1");
        assert!(value["taskId"].is_null());
        assert!(
            value["parameters"]
                .as_object()
                .is_some_and(|value| value.is_empty())
        );
    }

    #[test]
    fn runtime_event_validation_rejects_oversized_or_non_hex_payloads() {
        let mut event = EventRequest {
            schema_version: 1,
            event_id: Uuid::now_v7().to_string(),
            instance_id: "instance-1".to_string(),
            endpoint_id: "main".to_string(),
            event_type: "connection".to_string(),
            summary: "client connected".to_string(),
            client_ip: "192.0.2.1".to_string(),
            client_port: 12345,
            payload_hex: Some("00ff".to_string()),
            metadata: serde_json::json!({"protocol": "http"}),
            timestamp: Some("2026-08-11T00:00:00Z".to_string()),
        };
        assert!(validate_runtime_event(&event).is_ok());
        event.payload_hex = Some("not-hex".to_string());
        assert!(validate_runtime_event(&event).is_err());
    }
}
