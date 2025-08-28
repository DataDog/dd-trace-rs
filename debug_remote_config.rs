// Quick debug script to see what JSON our remote config client generates
use dd_trace::Config;
use std::sync::{Arc, Mutex};

// Copy the relevant structs and logic from remote_config.rs to test serialization
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
struct ClientState {
    root_version: u64,
    targets_version: u64,
    config_states: Vec<ConfigState>,
    has_error: bool,
    error: Option<String>,
    backend_client_state: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ConfigState {
    id: String,
    version: u64,
    product: String,
    apply_state: u64,
    apply_error: Option<String>,
}

#[derive(Debug, Serialize)]
struct ConfigRequest {
    client: ClientInfo,
    cached_target_files: Vec<CachedTargetFile>,
}

#[derive(Debug, Serialize)]
struct ClientInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<ClientState>,
    id: String,
    products: Vec<String>,
    is_tracer: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_tracer: Option<ClientTracer>,
    capabilities: String,
}

#[derive(Debug, Serialize)]
struct ClientTracer {
    runtime_id: String,
    language: String,
    tracer_version: String,
    service: String,
    #[serde(default)]
    extra_services: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    app_version: Option<String>,
    tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct CachedTargetFile {
    path: String,
    length: u64,
    hashes: Vec<Hash>,
}

#[derive(Debug, Clone, Serialize)]
struct Hash {
    algorithm: String,
    hash: String,
}

fn main() {
    let config = Arc::new(Mutex::new(
        Config::builder()
            .set_service("dd-trace-rs-rc-test-service".to_string())
            .set_env("dd-trace-rs-test-env".to_string())
            .set_version("1.0.0".to_string())
            .build()
    ));
    
    let cfg = config.lock().unwrap();
    
    let state = ClientState {
        root_version: 1,
        targets_version: 0,
        config_states: Vec::new(),
        has_error: false,
        error: None,
        backend_client_state: None,
    };

    let client_info = ClientInfo {
        state: Some(state),
        id: "test-client-id".to_string(),
        products: vec!["APM_TRACING".to_string()],
        is_tracer: true,
        client_tracer: Some(ClientTracer {
            runtime_id: cfg.runtime_id().to_string(),
            language: "rust".to_string(),
            tracer_version: cfg.tracer_version().to_string(),
            service: cfg.service().to_string(),
            extra_services: cfg.get_extra_services(),
            env: cfg.env().map(|s| s.to_string()),
            app_version: cfg.version().map(|s| s.to_string()),
            tags: cfg.global_tags().map(|s| s.to_string()).collect(),
        }),
        capabilities: "test-capabilities".to_string(), // Simplified for testing
    };

    let request = ConfigRequest {
        client: client_info,
        cached_target_files: Vec::new(),
    };

    let json = serde_json::to_string_pretty(&request).unwrap();
    println!("Request JSON:");
    println!("{}", json);
} 