// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use crate::configuration::Config;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// HTTP client imports
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Method, Request, Uri};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;

const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5); // 5 seconds is the highest interval allowed by the spec
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3); // lowest timeout with no failures

/// Capabilities that the client supports
#[derive(Debug, Clone)]
struct ClientCapabilities(u64);

impl ClientCapabilities {
    /// APM_TRACING_SAMPLE_RULES capability bit position
    const APM_TRACING_SAMPLE_RULES: u64 = 1 << 29;

    fn new() -> Self {
        Self(Self::APM_TRACING_SAMPLE_RULES)
    }

    /// Encode capabilities as base64 string
    fn encode(&self) -> String {
        use base64::Engine;
        let bytes = self.0.to_be_bytes();
        // Find first non-zero byte to minimize encoding size
        let start = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        base64::engine::general_purpose::STANDARD.encode(&bytes[start..])
    }
}

/// Client state sent to the agent
#[derive(Debug, Clone, Serialize)]
struct ClientState {
    /// Root version of the configuration
    root_version: u64,
    /// Versions of individual targets
    targets_version: u64,
    /// Configuration states
    config_states: Vec<ConfigState>,
    /// Whether the client has an error
    has_error: bool,
    /// Error message if any
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// Backend client state (opaque string from server)
    #[serde(skip_serializing_if = "Option::is_none")]
    backend_client_state: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ConfigState {
    /// ID of the configuration
    id: String,
    /// Version of the configuration
    version: u64,
    /// Product that owns this config
    product: String,
    /// Hash of the applied config
    apply_state: u64,
    /// Error if any while applying
    apply_error: Option<String>,
}

/// Request sent to get configuration
#[derive(Debug, Serialize)]
struct ConfigRequest {
    /// Client information
    client: ClientInfo,
    /// Cached target files
    cached_target_files: Vec<CachedTargetFile>,
}

#[derive(Debug, Serialize)]
struct ClientInfo {
    /// State of the client
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<ClientState>,
    /// Client ID (runtime ID)
    id: String,
    /// Products this client is interested in
    products: Vec<String>,
    /// Is this a tracer client
    is_tracer: bool,
    /// Tracer specific info
    #[serde(skip_serializing_if = "Option::is_none")]
    client_tracer: Option<ClientTracer>,
    /// Client capabilities (base64 encoded)
    capabilities: String,
}

#[derive(Debug, Serialize)]
struct ClientTracer {
    /// Runtime ID
    runtime_id: String,
    /// Language (rust)
    language: String,
    /// Tracer version
    tracer_version: String,
    /// Service name
    service: String,
    /// Additional services this tracer is monitoring
    #[serde(default)]
    extra_services: Vec<String>,
    /// Environment
    #[serde(skip_serializing_if = "Option::is_none")]
    env: Option<String>,
    /// App version
    #[serde(skip_serializing_if = "Option::is_none")]
    app_version: Option<String>,
    /// Global tags
    tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct CachedTargetFile {
    /// Path of the target file
    path: String,
    /// Length of the file
    length: u64,
    /// Hashes of the file
    hashes: Vec<Hash>,
}

#[derive(Debug, Clone, Serialize)]
struct Hash {
    /// Algorithm used (e.g., "sha256")
    algorithm: String,
    /// Hash value
    hash: String,
}

/// Response from the configuration endpoint
#[derive(Debug, Deserialize)]
struct ConfigResponse {
    /// Root metadata (TUF roots) - base64 encoded
    #[serde(default)]
    #[allow(dead_code)] // Part of TUF specification but not used in current implementation
    roots: Option<Vec<String>>,
    /// Targets metadata - base64 encoded JSON
    #[serde(default)]
    targets: Option<String>,
    /// Target files containing actual config data
    #[serde(default)]
    target_files: Option<Vec<TargetFile>>,
    /// Client configs to apply
    #[serde(default)]
    client_configs: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct TargetFile {
    /// Path of the file
    path: String,
    /// Raw content (base64 encoded in responses)
    raw: String,
}

#[derive(Debug, Clone, Deserialize)]
struct LibConfig {
    /// Based on the apm-tracing.json schema from dd-go
    /// See: https://github.com/DataDog/dd-go/blob/prod/remote-config/apps/rc-schema-validation/schemas/apm-tracing.json
    #[serde(default, rename = "tracing_sampling_rules")]
    tracing_sampling_rules: Option<serde_json::Value>,
}

/// TUF targets metadata
/// This is just an alias for SignedTargets to match the JSON structure
type TargetsMetadata = SignedTargets;

#[derive(Debug, Deserialize, Serialize)]
struct TargetDesc {
    /// Length of the target file
    length: u64,
    /// Hashes of the target file (algorithm -> hash)
    hashes: HashMap<String, String>,
    /// Custom metadata for this target
    custom: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct Targets {
    /// Type of the targets (usually "targets")
    #[serde(rename = "_type")]
    #[allow(dead_code)] // Part of TUF specification but not used in current implementation
    target_type: String,
    /// Custom metadata
    custom: Option<serde_json::Value>,
    /// Expiration time
    #[allow(dead_code)] // Part of TUF specification but not used in current implementation
    expires: String,
    /// Specification version
    #[allow(dead_code)] // Part of TUF specification but not used in current implementation
    spec_version: String,
    /// Target descriptions (path -> TargetDesc)
    targets: HashMap<String, TargetDesc>,
    /// Version of the targets
    version: u64,
}

#[derive(Debug, Deserialize)]
struct SignedTargets {
    /// Signatures (we don't validate these currently)
    #[allow(dead_code)] // Part of TUF specification but not used in current implementation
    signatures: Option<Vec<serde_json::Value>>,
    /// The signed targets data
    signed: Targets,
    /// Version of the signed targets
    #[allow(dead_code)] // Part of TUF specification but not used in current implementation
    version: Option<u64>,
}

/// Remote configuration client that polls the Datadog Agent for configuration updates.
///
/// This client is responsible for:
/// - Fetching remote configuration from the Datadog Agent
/// - Processing APM_TRACING product updates (specifically sampling rules)
/// - Maintaining client state and capabilities
/// - Providing a callback mechanism for configuration updates
///
/// The client currently handles a single product type (APM_TRACING)
/// that defines sampling rules.
pub struct RemoteConfigClient {
    /// Unique identifier for this client instance
    /// Different from runtime_id - each RemoteConfigClient gets its own UUID
    client_id: String,
    config: Arc<Mutex<Config>>,
    agent_url: String,
    // HTTP client timeout configuration
    client_timeout: Duration,
    state: Arc<Mutex<ClientState>>,
    capabilities: ClientCapabilities,
    poll_interval: Duration,
    // Cache of successfully applied configurations
    cached_target_files: Arc<Mutex<Vec<CachedTargetFile>>>,
    // Registry of product handlers for processing different config types
    product_registry: ProductRegistry,
}

impl RemoteConfigClient {
    /// Creates a new remote configuration client
    pub fn new(config: Arc<Mutex<Config>>) -> Result<Self> {
        let agent_url = format!("{}/v0.7/config", config.lock().unwrap().trace_agent_url());

        let state = Arc::new(Mutex::new(ClientState {
            root_version: 1, // Agent requires >= 1 (base TUF director root)
            targets_version: 0,
            config_states: Vec::new(),
            has_error: false,
            error: None,
            backend_client_state: None,
        }));

        Ok(Self {
            client_id: uuid::Uuid::new_v4().to_string(),
            config,
            agent_url,
            client_timeout: DEFAULT_TIMEOUT,
            state,
            capabilities: ClientCapabilities::new(),
            poll_interval: DEFAULT_POLL_INTERVAL,
            cached_target_files: Arc::new(Mutex::new(Vec::new())),
            product_registry: ProductRegistry::new(),
        })
    }

    /// Starts the remote configuration client in a background thread
    pub fn start(self) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            self.run();
        })
    }

    /// Main polling loop
    fn run(self) {
        // Create Tokio runtime in the background thread
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                crate::dd_debug!("RemoteConfigClient: Failed to create Tokio runtime: {}", e);
                return;
            }
        };

        let mut last_poll = Instant::now();

        loop {
            // Wait for next poll interval
            let elapsed = last_poll.elapsed();
            if elapsed < self.poll_interval {
                thread::sleep(self.poll_interval - elapsed);
            }
            last_poll = Instant::now();

            // Fetch and apply configuration
            match rt.block_on(self.fetch_and_apply_config()) {
                Ok(_) => {
                    // Clear any previous errors
                    if let Ok(mut state) = self.state.lock() {
                        state.has_error = false;
                        state.error = None;
                    }
                }
                Err(e) => {
                    crate::dd_debug!("RemoteConfigClient: Failed to fetch config: {}", e);
                    // Record error in state
                    if let Ok(mut state) = self.state.lock() {
                        state.has_error = true;
                        state.error = Some(format!("{e}"));
                    }
                }
            }
        }
    }

    /// Fetches configuration from the agent and applies it
    async fn fetch_and_apply_config(&self) -> Result<()> {
        // Create HTTP connector with timeout configuration
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(self.client_timeout));

        // Create HTTP client for this request
        let client = Client::builder(TokioExecutor::new()).build(connector);

        let request_payload = self.build_request()?;

        // Serialize the request to JSON
        let json_body = serde_json::to_string(&request_payload)
            .map_err(|e| anyhow::anyhow!("Failed to serialize request: {}", e))?;

        // Parse the agent URL
        let uri: Uri = self
            .agent_url
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid agent URL: {}", e))?;

        // Build HTTP request
        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/json")
            .header("user-agent", "dd-trace-rs")
            .body(Full::new(Bytes::from(json_body)))
            .map_err(|e| anyhow::anyhow!("Failed to build request: {}", e))?;

        // Send request to agent
        let response = client
            .request(req)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send request: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Agent returned error status: {}",
                response.status()
            ));
        }

        // Collect the response body
        let body_bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read response body: {}", e))?
            .to_bytes();

        // Parse JSON response
        let config_response: ConfigResponse = serde_json::from_slice(&body_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse response: {}", e))?;

        // Process the configuration response
        self.process_response(config_response)?;

        Ok(())
    }

    /// Builds the configuration request
    fn build_request(&self) -> Result<ConfigRequest> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Failed to lock state"))?;

        let config = self
            .config
            .lock()
            .map_err(|_| anyhow::anyhow!("Failed to lock config"))?;

        let client_info = ClientInfo {
            state: Some(state.clone()),
            id: self.client_id.clone(),
            products: vec!["APM_TRACING".to_string()],
            is_tracer: true,
            client_tracer: Some(ClientTracer {
                runtime_id: config.runtime_id().to_string(),
                language: "rust".to_string(),
                tracer_version: config.tracer_version().to_string(),
                service: config.service().to_string(),
                extra_services: config.get_extra_services(),
                env: config.env().map(|s| s.to_string()),
                app_version: config.version().map(|s| s.to_string()),
                tags: config.global_tags().map(|s| s.to_string()).collect(),
            }),
            capabilities: self.capabilities.encode(),
        };

        let cached_files = self
            .cached_target_files
            .lock()
            .map_err(|_| anyhow::anyhow!("Failed to lock cached files"))?
            .clone();

        Ok(ConfigRequest {
            client: client_info,
            cached_target_files: cached_files,
        })
    }

    /// Processes the configuration response
    fn process_response(&self, response: ConfigResponse) -> Result<()> {
        // Process targets metadata to update backend state and version
        let mut path_to_custom: HashMap<String, (Option<String>, Option<u64>)> = HashMap::new();
        let mut signed_targets: Option<serde_json::Value> = None;

        if let Some(targets_str) = response.targets {
            use base64::Engine;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&targets_str)
                .map_err(|e| anyhow::anyhow!("Failed to decode targets: {}", e))?;

            let targets_json = String::from_utf8(decoded)
                .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in targets: {}", e))?;

            let targets: TargetsMetadata = serde_json::from_str(&targets_json)
                .map_err(|e| anyhow::anyhow!("Failed to parse targets metadata: {}", e))?;

            // Store signed targets for validation
            let targets_map = targets
                .signed
                .targets
                .iter()
                .map(|(k, v)| (k.clone(), serde_json::to_value(v).unwrap()))
                .collect();
            signed_targets = Some(serde_json::Value::Object(targets_map));

            // Build lookup for per-path id and version from targets.signed.targets[*].custom
            for (path, desc) in &targets.signed.targets {
                let custom = &desc.custom;
                let id = custom
                    .as_ref()
                    .and_then(|c| c.get("id"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                // Datadog RC uses custom.v (int). Fallback to custom.version if needed
                let version = custom
                    .as_ref()
                    .and_then(|c| c.get("v"))
                    .and_then(|v| v.as_u64())
                    .or_else(|| {
                        custom
                            .as_ref()
                            .and_then(|c| c.get("version"))
                            .and_then(|v| v.as_u64())
                    });
                path_to_custom.insert(path.clone(), (id, version));
            }

            // Update state with backend state and version
            if let Ok(mut state) = self.state.lock() {
                state.targets_version = targets.signed.version;

                if let Some(custom) = &targets.signed.custom {
                    if let Some(backend_state) =
                        custom.get("opaque_backend_state").and_then(|v| v.as_str())
                    {
                        state.backend_client_state = Some(backend_state.to_string());
                    }
                }
            }
        }

        // Validate target files against signed targets and client configs
        if let Some(target_files) = &response.target_files {
            self.validate_signed_target_files(
                target_files,
                &signed_targets,
                &response.client_configs,
            )?;
        }

        // Parse target files if present
        if let Some(target_files) = response.target_files {
            // Build a new cache
            let mut new_cache = Vec::new();
            let mut any_failure = false;
            let mut config_states_cleared = false;

            for file in target_files {
                // Extract product and config_id from path to determine which handler to use
                // Path format is like "datadog/2/{PRODUCT}/{config_id}/config"
                let (product, derived_config_id) =
                    match extract_product_and_id_from_path(&file.path) {
                        Some((p, id)) => (p, Some(id)),
                        None => {
                            crate::dd_debug!(
                                "RemoteConfigClient: Failed to extract product from path: {}",
                                file.path
                            );
                            continue;
                        }
                    };

                // Check if we have a handler for this product
                let handler = match self.product_registry.get_handler(&product) {
                    Some(h) => h,
                    None => {
                        continue;
                    }
                };

                // Target files contain base64 encoded JSON configs
                use base64::Engine;
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(&file.raw)
                    .map_err(|e| anyhow::anyhow!("Failed to decode config: {}", e))?;

                let config_str = String::from_utf8(decoded.clone())
                    .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in config: {}", e))?;

                // Determine config id and version for state reporting (do this before applying)
                let derived_id = derived_config_id;
                let (meta_id, meta_version) = path_to_custom
                    .get(&file.path)
                    .cloned()
                    .unwrap_or((None, None));
                let config_id = derived_id
                    .or(meta_id)
                    .unwrap_or_else(|| format!("{}-config", product.to_lowercase()));
                let config_version = meta_version.unwrap_or(1);

                // Apply the config and record success or failure state
                // Right now we only support APM_TRACING handler, but in the future we will support
                // other products
                match handler.process_config(&config_str, &self.config) {
                    Ok(_) => {
                        // Calculate SHA256 hash of the raw content
                        use sha2::{Digest, Sha256};
                        let mut hasher = Sha256::new();
                        hasher.update(&file.raw);
                        let hash_result = hasher.finalize();
                        let hash_hex = format!("{hash_result:x}");

                        new_cache.push(CachedTargetFile {
                            path: file.path.clone(),
                            length: file.raw.len() as u64,
                            hashes: vec![Hash {
                                algorithm: "sha256".to_string(),
                                hash: hash_hex,
                            }],
                        });

                        // Update state to reflect successful application with accurate id/version
                        if let Ok(mut state) = self.state.lock() {
                            if !config_states_cleared {
                                state.config_states.clear();
                                config_states_cleared = true;
                            }
                            state.config_states.push(ConfigState {
                                id: config_id,
                                version: config_version,
                                product: product.clone(),
                                apply_state: 2, // 2 denotes success
                                apply_error: None,
                            });
                        }
                    }
                    Err(e) => {
                        any_failure = true;
                        crate::dd_debug!(
                            "RemoteConfigClient: Failed to apply {} config {}: {}",
                            product,
                            config_id,
                            e
                        );
                        if let Ok(mut state) = self.state.lock() {
                            if !config_states_cleared {
                                state.config_states.clear();
                                config_states_cleared = true;
                            }
                            // 3 denotes error
                            state.config_states.push(ConfigState {
                                id: config_id,
                                version: config_version,
                                product,
                                apply_state: 3, // 3 denotes error
                                apply_error: Some(format!("{e}")),
                            });
                        }
                        // Do not add to cache on failure
                        continue;
                    }
                }
            }

            // Only update the cache if we successfully processed all configs
            // This ensures we don't lose our previous cache state on errors
            if let Ok(mut cache) = self.cached_target_files.lock() {
                if !any_failure {
                    *cache = new_cache;
                }
            }
        }

        Ok(())
    }

    /// Validates that target files exist in either signed targets or client configs
    fn validate_signed_target_files(
        &self,
        payload_target_files: &[TargetFile],
        payload_targets_signed: &Option<serde_json::Value>,
        client_configs: &Option<Vec<String>>,
    ) -> Result<()> {
        for target in payload_target_files {
            let exists_in_signed_targets = payload_targets_signed
                .as_ref()
                .and_then(|targets| targets.get(&target.path))
                .is_some();

            let exists_in_client_configs = client_configs
                .as_ref()
                .map(|configs| configs.contains(&target.path))
                .unwrap_or(false);

            if !exists_in_signed_targets && !exists_in_client_configs {
                return Err(anyhow::anyhow!(
                    "target file {} not exists in client_config and signed targets",
                    target.path
                ));
            }
        }

        Ok(())
    }
}

/// Product handler trait for processing different remote config products
/// Each product (APM_TRACING, AGENT_CONFIG, etc.) implements this trait to handle their specific
/// configuration format
trait ProductHandler {
    /// Process the configuration for this product
    fn process_config(&self, lib_config: &str, config: &Arc<Mutex<Config>>) -> Result<()>;

    /// Get the product name this handler supports
    fn product_name(&self) -> &'static str;
}

struct ApmTracingHandler;

impl ProductHandler for ApmTracingHandler {
    fn process_config(&self, lib_config: &str, config: &Arc<Mutex<Config>>) -> Result<()> {
        let lib_config_parsed: LibConfig = serde_json::from_str(lib_config)
            .map_err(|e| anyhow::anyhow!("Failed to parse lib config: {}", e))?;

        // Extract sampling rules if present
        if let Some(rules_value) = lib_config_parsed.tracing_sampling_rules {
            if !rules_value.is_null() {
                // Convert the raw JSON value to string for the config method
                let rules_json = serde_json::to_string(&rules_value)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize sampling rules: {}", e))?;

                if let Ok(mut cfg) = config.lock() {
                    match cfg.update_sampling_rules_from_remote(&rules_json) {
                        Ok(()) => {
                            crate::dd_debug!(
                                "RemoteConfigClient: Applied sampling rules from remote config"
                            );
                        }
                        Err(e) => {
                            crate::dd_debug!(
                                "RemoteConfigClient: Failed to update sampling rules: {}",
                                e
                            );
                        }
                    }
                } else {
                    crate::dd_debug!(
                        "RemoteConfigClient: Failed to lock config to update sampling rules"
                    );
                }
            } else {
                crate::dd_debug!(
                    "RemoteConfigClient: Lib config received but tracing_sampling_rules is null"
                );
            }
        } else {
            crate::dd_debug!(
                "RemoteConfigClient: Lib config received but no tracing_sampling_rules present"
            );
        }

        Ok(())
    }

    fn product_name(&self) -> &'static str {
        "APM_TRACING"
    }
}

/// Product registry that maps product names to their handlers
/// This makes it easy to add new products without modifying the main processing logic
struct ProductRegistry {
    handlers: HashMap<String, Box<dyn ProductHandler + Send + Sync>>,
}

impl ProductRegistry {
    fn new() -> Self {
        let mut registry = Self {
            handlers: HashMap::new(),
        };

        // Register all supported products
        registry.register(Box::new(ApmTracingHandler));

        registry
    }

    fn register(&mut self, handler: Box<dyn ProductHandler + Send + Sync>) {
        self.handlers
            .insert(handler.product_name().to_string(), handler);
    }

    fn get_handler(&self, product: &str) -> Option<&(dyn ProductHandler + Send + Sync)> {
        self.handlers.get(product).map(|handler| handler.as_ref())
    }
}

/// Extract product name and id from remote config path
/// Path format is: datadog/2/{PRODUCT}/{config_id}/config
fn extract_product_and_id_from_path(path: &str) -> Option<(String, String)> {
    let mut components = path
        .strip_prefix("datadog/2/")?
        .strip_suffix("/config")?
        .split("/");
    let (product, config_id) = (
        components.next()?.to_string(),
        components.next()?.to_string(),
    );
    // Check if there are any remaining components after product and config_id
    if components.next().is_some() {
        return None;
    }
    Some((product, config_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_capabilities() {
        let caps = ClientCapabilities::new();
        // Check that the encoded capabilities is a non-empty base64 string
        let encoded = caps.encode();
        assert!(!encoded.is_empty());

        // The encoded value should decode to contain our capability bit
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .unwrap();

        // Reconstruct the u64 from the variable-length big-endian bytes
        let mut bytes = [0u8; 8];
        let offset = 8 - decoded.len();
        bytes[offset..].copy_from_slice(&decoded);
        let value = u64::from_be_bytes(bytes);

        // Verify the capability bit is set
        assert_eq!(value, ClientCapabilities::APM_TRACING_SAMPLE_RULES);
        assert_eq!(
            value & ClientCapabilities::APM_TRACING_SAMPLE_RULES,
            ClientCapabilities::APM_TRACING_SAMPLE_RULES
        );
    }

    #[test]
    fn test_request_serialization() {
        // Test that our request format matches the expected structure
        let state = ClientState {
            root_version: 1,
            targets_version: 122282776,
            config_states: vec![],
            has_error: false,
            error: None,
            backend_client_state: Some("test_backend_state".to_string()),
        };

        let client_info = ClientInfo {
            state: Some(state),
            id: "test-client-id".to_string(),
            products: vec!["APM_TRACING".to_string()],
            is_tracer: true,
            client_tracer: Some(ClientTracer {
                runtime_id: "test-runtime-id".to_string(),
                language: "rust".to_string(),
                tracer_version: "0.0.1".to_string(),
                service: "test-service".to_string(),
                extra_services: vec![],
                env: Some("test-env".to_string()),
                app_version: Some("1.0.0".to_string()),
                tags: vec![],
            }),
            capabilities: ClientCapabilities::new().encode(),
        };

        let request = ConfigRequest {
            client: client_info,
            cached_target_files: Vec::new(),
        };

        // Serialize and verify the structure
        let json = serde_json::to_value(&request).unwrap();

        // Check top-level structure
        assert!(json.get("client").is_some());
        // cached_target_files should be an empty array when empty
        assert_eq!(
            json.get("cached_target_files"),
            Some(&serde_json::json!([]))
        );

        let client = &json["client"];

        // Check client structure
        assert_eq!(client["id"], "test-client-id");
        assert_eq!(client["products"], serde_json::json!(["APM_TRACING"]));
        assert_eq!(client["is_tracer"], true);

        // Check client_tracer structure
        let client_tracer = &client["client_tracer"];
        assert_eq!(client_tracer["runtime_id"], "test-runtime-id");
        assert_eq!(client_tracer["language"], "rust");
        assert_eq!(client_tracer["service"], "test-service");
        assert_eq!(client_tracer["extra_services"], serde_json::json!([]));
        assert_eq!(client_tracer["env"], "test-env");
        assert_eq!(client_tracer["app_version"], "1.0.0");

        // Check state structure
        let state = &client["state"];
        assert_eq!(state["root_version"], 1);
        assert_eq!(state["targets_version"], 122282776);
        assert_eq!(state["has_error"], false);
        assert_eq!(state["backend_client_state"], "test_backend_state");

        // Check capabilities is a base64 encoded string
        let capabilities = &client["capabilities"];
        assert!(capabilities.is_string());
        assert!(!capabilities.as_str().unwrap().is_empty());
    }

    #[test]
    fn test_request_serialization_with_error() {
        // Test that error field is included when has_error is true
        let state = ClientState {
            root_version: 1,
            targets_version: 1,
            config_states: vec![],
            has_error: true,
            error: Some("Test error message".to_string()),
            backend_client_state: None,
        };

        let client_info = ClientInfo {
            state: Some(state),
            id: "test-client-id".to_string(),
            products: vec!["APM_TRACING".to_string()],
            is_tracer: true,
            client_tracer: Some(ClientTracer {
                runtime_id: "test-runtime-id".to_string(),
                language: "rust".to_string(),
                tracer_version: "0.0.1".to_string(),
                service: "test-service".to_string(),
                extra_services: vec!["service1".to_string(), "service2".to_string()],
                env: None,
                app_version: None,
                tags: vec![],
            }),
            capabilities: ClientCapabilities::new().encode(),
        };

        let request = ConfigRequest {
            client: client_info,
            cached_target_files: Vec::new(),
        };

        let json = serde_json::to_value(&request).unwrap();
        let state = &json["client"]["state"];

        // Verify error field is present when has_error is true
        assert_eq!(state["has_error"], true);
        assert_eq!(state["error"], "Test error message");

        // Verify extra_services is populated
        let client_tracer = &json["client"]["client_tracer"];
        assert_eq!(
            client_tracer["extra_services"],
            serde_json::json!(["service1", "service2"])
        );

        // Verify None values are not included in JSON
        assert!(client_tracer.get("env").is_none());
        assert!(client_tracer.get("app_version").is_none());
        assert!(state.get("backend_client_state").is_none());
    }

    #[test]
    fn test_lib_config_parsing() {
        // Test parsing the LibConfig structure
        let json = r#"{
            "tracing_sampling_rules": [
                {
                    "sample_rate": 0.5,
                    "service": "test-service",
                    "provenance": "dynamic"
                }
            ]
        }"#;

        let config: LibConfig = serde_json::from_str(json).unwrap();
        assert!(config.tracing_sampling_rules.is_some());
        let rules_value = config.tracing_sampling_rules.unwrap();

        // Parse the raw JSON value to verify the content
        let rules: Vec<serde_json::Value> = serde_json::from_value(rules_value).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["sample_rate"], 0.5);
        assert_eq!(rules[0]["service"], "test-service");
        assert_eq!(rules[0]["provenance"], "dynamic");
    }

    #[test]
    fn test_lib_config_full_schema() {
        // Test parsing a more complete LibConfig structure
        let json = r#"{
            "tracing_sampling_rules": [
                {
                    "sample_rate": 0.3,
                    "service": "web-api",
                    "name": "GET /users/*",
                    "resource": "UserController.list",
                    "tags": {
                        "environment": "production",
                        "region": "us-east-1"
                    },
                    "provenance": "customer"
                },
                {
                    "sample_rate": 1.0,
                    "service": "auth-service",
                    "provenance": "dynamic"
                }
            ]
        }"#;

        let config: LibConfig = serde_json::from_str(json).unwrap();
        assert!(config.tracing_sampling_rules.is_some());
        let rules_value = config.tracing_sampling_rules.unwrap();

        // Parse the raw JSON value to verify the content
        let rules: Vec<serde_json::Value> = serde_json::from_value(rules_value).unwrap();
        assert_eq!(rules.len(), 2);

        // Check first rule
        assert_eq!(rules[0]["sample_rate"], 0.3);
        assert_eq!(rules[0]["service"], "web-api");
        assert_eq!(rules[0]["name"], "GET /users/*");
        assert_eq!(rules[0]["resource"], "UserController.list");
        assert_eq!(rules[0]["tags"].as_object().unwrap().len(), 2);
        assert_eq!(rules[0]["tags"]["environment"], "production");
        assert_eq!(rules[0]["tags"]["region"], "us-east-1");
        assert_eq!(rules[0]["provenance"], "customer");

        // Check second rule
        assert_eq!(rules[1]["sample_rate"], 1.0);
        assert_eq!(rules[1]["service"], "auth-service");
        assert_eq!(rules[1]["provenance"], "dynamic");
    }

    #[test]
    fn test_lib_config_empty() {
        let json = r#"{}"#;

        let config: LibConfig = serde_json::from_str(json).unwrap();
        assert!(config.tracing_sampling_rules.is_none());
    }

    #[test]
    fn test_cached_target_files() {
        // Test that cached_target_files is properly serialized
        let cached_file = CachedTargetFile {
            path: "datadog/2/APM_TRACING/config123/config".to_string(),
            length: 256,
            hashes: vec![Hash {
                algorithm: "sha256".to_string(),
                hash: "abc123def456".to_string(),
            }],
        };

        let request = ConfigRequest {
            client: ClientInfo {
                state: None,
                id: "test-id".to_string(),
                products: vec!["APM_TRACING".to_string()],
                is_tracer: true,
                client_tracer: None,
                capabilities: ClientCapabilities::new().encode(),
            },
            cached_target_files: vec![cached_file.clone()],
        };

        let json = serde_json::to_value(&request).unwrap();
        let cached = &json["cached_target_files"][0];

        assert_eq!(cached["path"], "datadog/2/APM_TRACING/config123/config");
        assert_eq!(cached["length"], 256);
        assert_eq!(cached["hashes"][0]["algorithm"], "sha256");
        assert_eq!(cached["hashes"][0]["hash"], "abc123def456");
    }

    #[test]
    fn test_validate_signed_target_files() {
        // Create a mock RemoteConfigClient for testing
        let config = Arc::new(Mutex::new(Config::builder().build()));
        let client = RemoteConfigClient::new(config).unwrap();

        // Test case 1: Target file exists in signed targets
        let target_files = vec![TargetFile {
            path: "datadog/2/APM_TRACING/config123/config".to_string(),
            raw: "base64_encoded_content".to_string(),
        }];

        let signed_targets = serde_json::json!({
            "datadog/2/APM_TRACING/config123/config": {
                "custom": {"id": "config123", "v": 1}
            }
        });

        let client_configs = None;

        // Should pass validation
        assert!(client
            .validate_signed_target_files(&target_files, &Some(signed_targets), &client_configs)
            .is_ok());

        // Test case 2: Target file exists in client configs
        let target_files = vec![TargetFile {
            path: "datadog/2/APM_TRACING/config456/config".to_string(),
            raw: "base64_encoded_content".to_string(),
        }];

        let signed_targets = None;
        let client_configs = Some(vec!["datadog/2/APM_TRACING/config456/config".to_string()]);

        // Should pass validation
        assert!(client
            .validate_signed_target_files(&target_files, &signed_targets, &client_configs)
            .is_ok());

        // Test case 3: Target file exists in both signed targets and client configs
        let target_files = vec![TargetFile {
            path: "datadog/2/APM_TRACING/config789/config".to_string(),
            raw: "base64_encoded_content".to_string(),
        }];

        let signed_targets = serde_json::json!({
            "datadog/2/APM_TRACING/config789/config": {
                "custom": {"id": "config789", "v": 1}
            }
        });
        let client_configs = Some(vec!["datadog/2/APM_TRACING/config789/config".to_string()]);

        // Should pass validation
        assert!(client
            .validate_signed_target_files(&target_files, &Some(signed_targets), &client_configs)
            .is_ok());

        // Test case 4: Target file exists in neither signed targets nor client configs
        let target_files = vec![TargetFile {
            path: "datadog/2/APM_TRACING/invalid_config/config".to_string(),
            raw: "base64_encoded_content".to_string(),
        }];

        let signed_targets = serde_json::json!({
            "datadog/2/APM_TRACING/other_config/config": {
                "custom": {"id": "other_config", "v": 1}
            }
        });
        let client_configs = Some(vec![
            "datadog/2/APM_TRACING/another_config/config".to_string()
        ]);

        // Should fail validation
        let result = client.validate_signed_target_files(
            &target_files,
            &Some(signed_targets),
            &client_configs,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("target file datadog/2/APM_TRACING/invalid_config/config not exists in client_config and signed targets"));

        // Test case 5: Empty target files should pass validation
        let target_files = vec![];
        let signed_targets = None;
        let client_configs = None;

        // Should pass validation
        assert!(client
            .validate_signed_target_files(&target_files, &signed_targets, &client_configs)
            .is_ok());
    }

    #[test]
    fn test_parse_example_response() {
        // Create a ConfigResponse object that represents the example response
        let config_response = ConfigResponse {
            roots: None,
            targets: Some("eyJzaWduZWQiOiB7Il90eXBlIjogInRhcmdldHMiLCAiY3VzdG9tIjogeyJvcGFxdWVfYmFja2VuZF9zdGF0ZSI6ICJleUpmb29JT2lBaVltRm9JbjA9In0sICJleHBpcmVzIjogIjIwMjQtMTItMzFUMjM6NTk6NTlaIiwgInNwZWNfdmVyc2lvbiI6ICIxLjAuMCIsICJ0YXJnZXRzIjoge30sICJ2ZXJzaW9uIjogM319Cg==".to_string()), // base64 encoded targets with proper structure
            target_files: Some(vec![
                TargetFile {
                    path: "datadog/2/APM_TRACING/apm-tracing-sampling/config".to_string(),
                    raw: "eyJ0cmFjaW5nX3NhbXBsaW5nX3J1bGVzIjogW3sic2FtcGxlX3JhdGUiOiAwLjUsICJzZXJ2aWNlIjogInRlc3Qtc2VydmljZSJ9XX0K".to_string(), // base64 encoded lib_config with tracing_sampling_rules at top level
                },
            ]),
            client_configs: Some(vec![
                "datadog/2/APM_TRACING/apm-tracing-sampling/config".to_string(),
            ]),
        };

        let config = Arc::new(Mutex::new(Config::builder().build()));
        let client = RemoteConfigClient::new(config).unwrap();

        // For testing purposes, we'll verify the config was updated by checking the rules

        // Process the response - this should update the client's state and process APM_TRACING
        // configs
        let result = client.process_response(config_response);
        assert!(result.is_ok(), "process_response should succeed");

        // Verify that the client's state was updated correctly
        let state = client.state.lock().unwrap();
        assert_eq!(state.targets_version, 3);
        assert_eq!(
            state.backend_client_state,
            Some("eyJfooIOiAiYmFoIn0=".to_string())
        );
        assert!(!state.has_error);

        // Verify that APM_TRACING config states were added
        assert_eq!(state.config_states.len(), 1);
        let config_state = &state.config_states[0];
        assert_eq!(config_state.product, "APM_TRACING");
        assert_eq!(config_state.apply_state, 2); // success

        // Verify that APM_TRACING cached files were added
        let cached_files = client.cached_target_files.lock().unwrap();
        assert_eq!(cached_files.len(), 1);
        assert_eq!(
            cached_files[0].path,
            "datadog/2/APM_TRACING/apm-tracing-sampling/config"
        );
        assert_eq!(cached_files[0].length, 104);
        assert_eq!(cached_files[0].hashes.len(), 1);
        assert_eq!(cached_files[0].hashes[0].algorithm, "sha256");

        // Verify that the config was updated with the processed rules
        let config = client.config.lock().unwrap();
        let rules = config.trace_sampling_rules();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].sample_rate, 0.5);
        assert_eq!(rules[0].service, Some("test-service".to_string()));
    }

    #[test]
    fn test_parse_multi_product_response() {
        // This test verifies that our implementation correctly skips non-APM_TRACING
        // configs and only processes APM_TRACING configs. The multi-product response contains
        // ASM_FEATURES and LIVE_DEBUGGING configs which should be ignored.

        // Create a ConfigResponse object that represents a multi-product response
        let config_response = ConfigResponse {
            roots: None,
            targets: Some("eyJzaWduZWQiOiB7Il90eXBlIjogInRhcmdldHMiLCAiY3VzdG9tIjogeyJvcGFxdWVfYmFja2VuZF9zdGF0ZSI6ICJleUpmb29JT2lBaVltRm9JbjA9In0sICJleHBpcmVzIjogIjIwMjQtMTItMzFUMjM6NTk6NTlaIiwgInNwZWNfdmVyc2lvbiI6ICIxLjAuMCIsICJ0YXJnZXRzIjoge30sICJ2ZXJzaW9uIjogMn19Cg==".to_string()), // base64 encoded targets with proper structure
            target_files: Some(vec![
                TargetFile {
                    path: "datadog/2/ASM_FEATURES/ASM_FEATURES-base/config".to_string(),
                    raw: "eyJhc20tZmVhdHVyZXMiOiB7ImVuYWJsZWQiOiB0cnVlfX0=".to_string(), // base64 encoded config
                },
                TargetFile {
                    path: "datadog/2/LIVE_DEBUGGING/LIVE_DEBUGGING-base/config".to_string(),
                    raw: "eyJsaXZlLWRlYnVnZ2luZyI6IHsiZW5hYmxlZCI6IGZhbHNlfX0=".to_string(), // base64 encoded config
                },
            ]),
            client_configs: Some(vec![
                "datadog/2/ASM_FEATURES/ASM_FEATURES-base/config".to_string(),
                "datadog/2/LIVE_DEBUGGING/LIVE_DEBUGGING-base/config".to_string(),
            ]),
        };

        // Create a RemoteConfigClient and process the response
        let config = Arc::new(Mutex::new(Config::builder().build()));
        let client = RemoteConfigClient::new(config).unwrap();

        // Process the response - this should update the client's state
        let result = client.process_response(config_response);
        assert!(result.is_ok(), "process_response should succeed");

        // Verify that the client's state was updated correctly
        let state = client.state.lock().unwrap();
        assert_eq!(state.targets_version, 2);
        assert_eq!(
            state.backend_client_state,
            Some("eyJfooIOiAiYmFoIn0=".to_string())
        );
        assert!(!state.has_error);

        // Verify that no config states were added since we don't process non-APM_TRACING products
        assert_eq!(state.config_states.len(), 0);

        // Verify that cached target files were not added since they're not APM_TRACING
        let cached_files = client.cached_target_files.lock().unwrap();
        assert_eq!(cached_files.len(), 0);
    }

    #[test]
    fn test_config_update_from_remote() {
        // Test that the config is updated when sampling rules are received
        let config = Arc::new(Mutex::new(Config::builder().build()));
        let client = RemoteConfigClient::new(config).unwrap();

        // Process a config response with sampling rules
        let config_response = ConfigResponse {
            roots: None,
            targets: Some("eyJzaWduZWQiOiB7Il90eXBlIjogInRhcmdldHMiLCAiY3VzdG9tIjogeyJvcGFxdWVfYmFja2VuZF9zdGF0ZSI6ICJleUpmb29JT2lBaVltRm9JbjA9In0sICJleHBpcmVzIjogIjIwMjQtMTItMzFUMjM6NTk6NTlaIiwgInNwZWNfdmVyc2lvbiI6ICIxLjAuMCIsICJ0YXJnZXRzIjoge30sICJ2ZXJzaW9uIjogM319Cg==".to_string()),
            target_files: Some(vec![
                TargetFile {
                    path: "datadog/2/APM_TRACING/test-config/config".to_string(),
                    raw: "eyJ0cmFjaW5nX3NhbXBsaW5nX3J1bGVzIjogW3sic2FtcGxlX3JhdGUiOiAwLjUsICJzZXJ2aWNlIjogInRlc3Qtc2VydmljZSJ9XX0K".to_string(),
                },
            ]),
            client_configs: Some(vec![
                "datadog/2/APM_TRACING/test-config/config".to_string(),
            ]),
        };

        let result = client.process_response(config_response);
        assert!(result.is_ok(), "process_response should succeed");

        // Verify that the config was updated with the sampling rules
        let config = client.config.lock().unwrap();
        let rules = config.trace_sampling_rules();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].sample_rate, 0.5);
        assert_eq!(rules[0].service, Some("test-service".to_string()));
    }

    #[test]
    fn test_tuf_targets_parsing() {
        // Test parsing of a realistic TUF targets file structure
        // Based on the example provided in the user query
        let tuf_targets_json = r#"{
   "signatures": [
       {
           "keyid": "5c4ece41241a1bb513f6e3e5df74ab7d5183dfffbd71bfd43127920d880569fd",
           "sig": "4dd483db8b4aff81a9afd2ed4eaeb23fe3aca9a148a7a8942e24e8c5ef911e2692f94492b882727b257dacfbf6bcea09d6e26ea28ac145fcb4254ea046be3b03"
       }
   ],
   "signed": {
       "_type": "targets",
       "custom": {
           "opaque_backend_state": "eyJ2ZXJzaW9uIjoxLCJzdGF0ZSI6eyJmaWxlX2hhc2hlcyI6WyJGZXJOT1FyMStmTThKWk9TY0crZllucnhXMWpKN0w0ZlB5aGtxUWVCT3dJPSIsInd1aW9BVm1Qcy9oNEpXMDh1dnI1bi9meERLQ3lKdG1sQmRjaDNOcFdLZDg9IiwiOGFDYVJFc3hIV3R3SFNFWm5SV0pJYmtENXVBNUtETENoZG8vZ0RNdnJJMD0iXX19"
       },
       "expires": "2022-09-22T09:01:04Z",
       "spec_version": "1.0.0",
       "targets": {
           "datadog/2/APM_SAMPLING/dynamic_rates/config": {
               "custom": {
                   "v": 27423
               },
               "hashes": {
                   "sha256": "c2e8a801598fb3f878256d3cbafaf99ff7f10ca0b226d9a505d721dcda5629df"
               },
               "length": 58409
           },
           "employee/ASM_DD/1.recommended.json/config": {
               "custom": {
                   "v": 1
               },
               "hashes": {
                   "sha256": "15eacd390af5f9f33c259392706f9f627af15b58c9ecbe1f3f2864a907813b02"
               },
               "length": 235228
           },
           "employee/CWS_DD/4.default.policy/config": {
               "custom": {
                   "v": 1
               },
               "hashes": {
                   "sha256": "f1a09a444b311d6b701d21199d158921b903e6e0392832c285da3f80332fac8d"
               },
               "length": 34777
           }
       },
       "version": 23755701
   }
}"#;

        // Parse the TUF targets structure
        let targets: SignedTargets = serde_json::from_str(tuf_targets_json)
            .expect("Should successfully parse TUF targets JSON");

        // Verify signatures array is parsed correctly
        assert!(targets.signatures.is_some());
        let signatures = targets.signatures.unwrap();
        assert_eq!(signatures.len(), 1);

        // Verify the signed targets structure
        assert_eq!(targets.signed.target_type, "targets");
        assert_eq!(targets.signed.expires, "2022-09-22T09:01:04Z");
        assert_eq!(targets.signed.spec_version, "1.0.0");
        assert_eq!(targets.signed.version, 23755701);

        // Verify custom metadata with opaque_backend_state
        assert!(targets.signed.custom.is_some());
        let custom = targets.signed.custom.unwrap();
        let backend_state = custom
            .get("opaque_backend_state")
            .and_then(|v| v.as_str())
            .expect("Should have opaque_backend_state");
        assert_eq!(backend_state, "eyJ2ZXJzaW9uIjoxLCJzdGF0ZSI6eyJmaWxlX2hhc2hlcyI6WyJGZXJOT1FyMStmTThKWk9TY0crZllucnhXMWpKN0w0ZlB5aGtxUWVCT3dJPSIsInd1aW9BVm1Qcy9oNEpXMDh1dnI1bi9meERLQ3lKdG1sQmRjaDNOcFdLZDg9IiwiOGFDYVJFc3hIV3R3SFNFWm5SV0pJYmtENXVBNUtETENoZG8vZ0RNdnJJMD0iXX19");

        // Verify targets parsing
        assert_eq!(targets.signed.targets.len(), 3);

        // Test APM_SAMPLING target
        let apm_sampling = targets
            .signed
            .targets
            .get("datadog/2/APM_SAMPLING/dynamic_rates/config")
            .expect("Should have APM_SAMPLING target");
        assert_eq!(apm_sampling.length, 58409);
        assert_eq!(
            apm_sampling.hashes.get("sha256").unwrap(),
            "c2e8a801598fb3f878256d3cbafaf99ff7f10ca0b226d9a505d721dcda5629df"
        );
        let apm_custom = apm_sampling.custom.as_ref().unwrap();
        assert_eq!(apm_custom.get("v").unwrap().as_u64().unwrap(), 27423);

        // Test ASM_DD target
        let asm_dd = targets
            .signed
            .targets
            .get("employee/ASM_DD/1.recommended.json/config")
            .expect("Should have ASM_DD target");
        assert_eq!(asm_dd.length, 235228);
        assert_eq!(
            asm_dd.hashes.get("sha256").unwrap(),
            "15eacd390af5f9f33c259392706f9f627af15b58c9ecbe1f3f2864a907813b02"
        );
        let asm_custom = asm_dd.custom.as_ref().unwrap();
        assert_eq!(asm_custom.get("v").unwrap().as_u64().unwrap(), 1);

        // Test CWS_DD target
        let cws_dd = targets
            .signed
            .targets
            .get("employee/CWS_DD/4.default.policy/config")
            .expect("Should have CWS_DD target");
        assert_eq!(cws_dd.length, 34777);
        assert_eq!(
            cws_dd.hashes.get("sha256").unwrap(),
            "f1a09a444b311d6b701d21199d158921b903e6e0392832c285da3f80332fac8d"
        );
        let cws_custom = cws_dd.custom.as_ref().unwrap();
        assert_eq!(cws_custom.get("v").unwrap().as_u64().unwrap(), 1);
    }

    #[test]
    fn test_extract_product_from_path() {
        // Test APM_TRACING path
        assert_eq!(
            extract_product_and_id_from_path("datadog/2/APM_TRACING/config123/config")
                .map(|(p, _)| p),
            Some("APM_TRACING".to_string())
        );

        // Test LIVE_DEBUGGING path
        assert_eq!(
            extract_product_and_id_from_path("datadog/2/LIVE_DEBUGGING/LIVE_DEBUGGING-base/config")
                .map(|(p, _)| p),
            Some("LIVE_DEBUGGING".to_string())
        );

        // Test AGENT_CONFIG path
        assert_eq!(
            extract_product_and_id_from_path("datadog/2/AGENT_CONFIG/dynamic_rates/config")
                .map(|(p, _)| p),
            Some("AGENT_CONFIG".to_string())
        );

        // Test invalid paths
        assert_eq!(
            extract_product_and_id_from_path("invalid/path").map(|(p, _)| p),
            None
        );
        assert_eq!(
            extract_product_and_id_from_path("datadog/1/APM_TRACING/config").map(|(p, _)| p),
            None
        );
        assert_eq!(
            extract_product_and_id_from_path("datadog/APM_TRACING/config").map(|(p, _)| p),
            None
        );
        assert_eq!(extract_product_and_id_from_path("").map(|(p, _)| p), None);
    }

    #[test]
    fn test_extract_config_id_from_path() {
        // Test APM_TRACING path
        assert_eq!(
            extract_product_and_id_from_path("datadog/2/APM_TRACING/config123/config")
                .map(|(_, id)| id),
            Some("config123".to_string())
        );

        // Test ASM_FEATURES path
        assert_eq!(
            extract_product_and_id_from_path("datadog/2/ASM_FEATURES/ASM_FEATURES-base/config")
                .map(|(_, id)| id),
            Some("ASM_FEATURES-base".to_string())
        );

        // Test invalid paths
        assert_eq!(
            extract_product_and_id_from_path("invalid/path").map(|(_, id)| id),
            None
        );
        assert_eq!(
            extract_product_and_id_from_path("datadog/2/APM_TRACING/config").map(|(_, id)| id),
            None
        ); // Missing /config at end
        assert_eq!(
            extract_product_and_id_from_path("datadog/2/APM_TRACING").map(|(_, id)| id),
            None
        ); // Too short
        assert_eq!(extract_product_and_id_from_path("").map(|(_, id)| id), None);
    }

    #[test]
    fn test_product_registry() {
        let registry = ProductRegistry::new();

        // Should have APM_TRACING handler registered
        assert!(registry.get_handler("APM_TRACING").is_some());

        // Should not have unknown products
        assert!(registry.get_handler("UNKNOWN_PRODUCT").is_none());
    }

    #[test]
    fn test_apm_tracing_handler() {
        let handler = ApmTracingHandler;
        assert_eq!(handler.product_name(), "APM_TRACING");

        // Test processing config - this should not panic for valid JSON
        let config = Arc::new(Mutex::new(Config::builder().build()));
        let lib_config_json =
            r#"{"tracing_sampling_rules": [{"sample_rate": 0.5, "service": "test"}]}"#;

        // This should succeed
        let result = handler.process_config(lib_config_json, &config);
        assert!(result.is_ok());

        // Test invalid JSON
        let invalid_json = "invalid json";
        let result = handler.process_config(invalid_json, &config);
        assert!(result.is_err());

        // Test lib_config without tracing_sampling_rules (should succeed but do nothing)
        let empty_lib_config = r#"{}"#;
        let result = handler.process_config(empty_lib_config, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_end_to_end_lib_config_sampling_rules_processing() {
        // Test the full end-to-end flow: ConfigResponse -> process_response -> sampling rules
        // applied
        let config = Arc::new(Mutex::new(Config::builder().build()));
        let client = RemoteConfigClient::new(config.clone()).unwrap();

        // Create lib_config JSON with sampling rules
        let lib_config_json = r#"{
            "tracing_sampling_rules": [
                {
                    "sample_rate": 0.75,
                    "service": "web-service",
                    "env": "production"
                },
                {
                    "sample_rate": 0.25,
                    "service": "background-worker",
                    "operation_name": "process_job"
                }
            ]
        }"#;

        // Base64 encode the lib_config
        use base64::Engine;
        let encoded_lib_config =
            base64::engine::general_purpose::STANDARD.encode(lib_config_json.as_bytes());

        // Create a ConfigResponse with the lib_config
        let config_response = ConfigResponse {
            roots: None,
            targets: Some("eyJzaWduZWQiOiB7Il90eXBlIjogInRhcmdldHMiLCAiY3VzdG9tIjogeyJvcGFxdWVfYmFja2VuZF9zdGF0ZSI6ICJleUpmb29JT2lBaVltRm9JbjA9In0sICJleHBpcmVzIjogIjIwMjQtMTItMzFUMjM6NTk6NTlaIiwgInNwZWNfdmVyc2lvbiI6ICIxLjAuMCIsICJ0YXJnZXRzIjoge30sICJ2ZXJzaW9uIjogM319Cg==".to_string()),
            target_files: Some(vec![
                TargetFile {
                    path: "datadog/2/APM_TRACING/test-lib-config/config".to_string(),
                    raw: encoded_lib_config,
                },
            ]),
            client_configs: Some(vec![
                "datadog/2/APM_TRACING/test-lib-config/config".to_string(),
            ]),
        };

        // Process the response - this should extract and apply the sampling rules
        let result = client.process_response(config_response);
        assert!(
            result.is_ok(),
            "process_response should succeed: {result:?}"
        );

        // Verify that the sampling rules were actually applied to the config
        let config_guard = config.lock().unwrap();
        let applied_rules = config_guard.trace_sampling_rules();

        // Should have 2 rules applied
        assert_eq!(applied_rules.len(), 2);

        // Verify the first rule
        assert_eq!(applied_rules[0].sample_rate, 0.75);
        assert_eq!(applied_rules[0].service, Some("web-service".to_string()));

        // Verify the second rule
        assert_eq!(applied_rules[1].sample_rate, 0.25);
        assert_eq!(
            applied_rules[1].service,
            Some("background-worker".to_string())
        );
    }

    #[test]
    fn test_config_states_cleared_between_processing_cycles() {
        // Test that config_states are cleared before adding new ones to prevent memory leak
        let config = Arc::new(Mutex::new(Config::builder().build()));
        let client = RemoteConfigClient::new(config).unwrap();

        // First processing cycle - add one config
        let config_response_1 = ConfigResponse {
            roots: None,
            targets: Some("eyJzaWduZWQiOiB7Il90eXBlIjogInRhcmdldHMiLCAiY3VzdG9tIjogeyJvcGFxdWVfYmFja2VuZF9zdGF0ZSI6ICJleUpmb29JT2lBaVltRm9JbjA9In0sICJleHBpcmVzIjogIjIwMjQtMTItMzFUMjM6NTk6NTlaIiwgInNwZWNfdmVyc2lvbiI6ICIxLjAuMCIsICJ0YXJnZXRzIjoge30sICJ2ZXJzaW9uIjogMX19Cg==".to_string()),
            target_files: Some(vec![
                TargetFile {
                    path: "datadog/2/APM_TRACING/config1/config".to_string(),
                    raw: "eyJ0cmFjaW5nX3NhbXBsaW5nX3J1bGVzIjogW3sic2FtcGxlX3JhdGUiOiAwLjUsICJzZXJ2aWNlIjogInRlc3Qtc2VydmljZS0xIn1dfQ==".to_string(),
                },
            ]),
            client_configs: Some(vec![
                "datadog/2/APM_TRACING/config1/config".to_string(),
            ]),
        };

        // Process first response
        let result = client.process_response(config_response_1);
        assert!(result.is_ok(), "First process_response should succeed");

        // Verify first config state was added
        {
            let state = client.state.lock().unwrap();
            assert_eq!(state.config_states.len(), 1);
            assert_eq!(state.config_states[0].id, "config1");
            assert_eq!(state.config_states[0].apply_state, 2); // success
        }

        // Second processing cycle - add different configs
        let config_response_2 = ConfigResponse {
            roots: None,
            targets: Some("eyJzaWduZWQiOiB7Il90eXBlIjogInRhcmdldHMiLCAiY3VzdG9tIjogeyJvcGFxdWVfYmFja2VuZF9zdGF0ZSI6ICJleUpmb29JT2lBaVltRm9JbjA9In0sICJleHBpcmVzIjogIjIwMjQtMTItMzFUMjM6NTk6NTlaIiwgInNwZWNfdmVyc2lvbiI6ICIxLjAuMCIsICJ0YXJnZXRzIjoge30sICJ2ZXJzaW9uIjogMn19Cg==".to_string()),
            target_files: Some(vec![
                TargetFile {
                    path: "datadog/2/APM_TRACING/config2/config".to_string(),
                    raw: "eyJ0cmFjaW5nX3NhbXBsaW5nX3J1bGVzIjogW3sic2FtcGxlX3JhdGUiOiAwLjc1LCAic2VydmljZSI6ICJ0ZXN0LXNlcnZpY2UtMiJ9XX0=".to_string(),
                },
                TargetFile {
                    path: "datadog/2/APM_TRACING/config3/config".to_string(),
                    raw: "eyJ0cmFjaW5nX3NhbXBsaW5nX3J1bGVzIjogW3sic2FtcGxlX3JhdGUiOiAwLjI1LCAic2VydmljZSI6ICJ0ZXN0LXNlcnZpY2UtMyJ9XX0=".to_string(),
                },
            ]),
            client_configs: Some(vec![
                "datadog/2/APM_TRACING/config2/config".to_string(),
                "datadog/2/APM_TRACING/config3/config".to_string(),
            ]),
        };

        // Process second response
        let result = client.process_response(config_response_2);
        assert!(result.is_ok(), "Second process_response should succeed");

        // Verify config_states were cleared and only contains the new configs
        {
            let state = client.state.lock().unwrap();
            // Should have exactly 2 configs (config2 and config3), not 3 (which would include
            // config1)
            assert_eq!(state.config_states.len(), 2);

            // Check that we only have the new config IDs, not the old one
            let config_ids: Vec<String> =
                state.config_states.iter().map(|cs| cs.id.clone()).collect();
            assert!(config_ids.contains(&"config2".to_string()));
            assert!(config_ids.contains(&"config3".to_string()));
            assert!(!config_ids.contains(&"config1".to_string())); // Should not contain old config

            // All should be successful
            for config_state in &state.config_states {
                assert_eq!(config_state.apply_state, 2); // success
                assert_eq!(config_state.product, "APM_TRACING");
            }
        }

        // Third processing cycle - empty target files
        let config_response_3 = ConfigResponse {
            roots: None,
            targets: Some("eyJzaWduZWQiOiB7Il90eXBlIjogInRhcmdldHMiLCAiY3VzdG9tIjogeyJvcGFxdWVfYmFja2VuZF9zdGF0ZSI6ICJleUpmb29JT2lBaVltRm9JbjA9In0sICJleHBpcmVzIjogIjIwMjQtMTItMzFUMjM6NTk6NTlaIiwgInNwZWNfdmVyc2lvbiI6ICIxLjAuMCIsICJ0YXJnZXRzIjoge30sICJ2ZXJzaW9uIjogM319Cg==".to_string()),
            target_files: Some(vec![]), // Empty target files
            client_configs: Some(vec![]),
        };

        // Process third response
        let result = client.process_response(config_response_3);
        assert!(result.is_ok(), "Third process_response should succeed");

        // Verify config_states remain unchanged when no configs are processed
        // (since clearing only happens when we're about to add new config states)
        {
            let state = client.state.lock().unwrap();
            assert_eq!(state.config_states.len(), 2); // Should still have config2 and config3

            let config_ids: Vec<String> =
                state.config_states.iter().map(|cs| cs.id.clone()).collect();
            assert!(config_ids.contains(&"config2".to_string()));
            assert!(config_ids.contains(&"config3".to_string()));
        }
    }

    #[test]
    fn test_config_states_cleared_on_error_configs() {
        // Test that config_states are cleared even when processing results in errors
        let config = Arc::new(Mutex::new(Config::builder().build()));
        let client = RemoteConfigClient::new(config).unwrap();

        // First processing cycle - add successful config
        let config_response_1 = ConfigResponse {
            roots: None,
            targets: Some("eyJzaWduZWQiOiB7Il90eXBlIjogInRhcmdldHMiLCAiY3VzdG9tIjogeyJvcGFxdWVfYmFja2VuZF9zdGF0ZSI6ICJleUpmb29JT2lBaVltRm9JbjA9In0sICJleHBpcmVzIjogIjIwMjQtMTItMzFUMjM6NTk6NTlaIiwgInNwZWNfdmVyc2lvbiI6ICIxLjAuMCIsICJ0YXJnZXRzIjoge30sICJ2ZXJzaW9uIjogMX19Cg==".to_string()),
            target_files: Some(vec![
                TargetFile {
                    path: "datadog/2/APM_TRACING/good_config/config".to_string(),
                    raw: "eyJ0cmFjaW5nX3NhbXBsaW5nX3J1bGVzIjogW3sic2FtcGxlX3JhdGUiOiAwLjUsICJzZXJ2aWNlIjogInRlc3Qtc2VydmljZSJ9XX0=".to_string(),
                },
            ]),
            client_configs: Some(vec![
                "datadog/2/APM_TRACING/good_config/config".to_string(),
            ]),
        };

        // Process first response
        let result = client.process_response(config_response_1);
        assert!(result.is_ok(), "First process_response should succeed");

        // Verify first config state was added
        {
            let state = client.state.lock().unwrap();
            assert_eq!(state.config_states.len(), 1);
            assert_eq!(state.config_states[0].id, "good_config");
            assert_eq!(state.config_states[0].apply_state, 2); // success
        }

        // Second processing cycle - add config with invalid JSON (will cause error)
        let config_response_2 = ConfigResponse {
            roots: None,
            targets: Some("eyJzaWduZWQiOiB7Il90eXBlIjogInRhcmdldHMiLCAiY3VzdG9tIjogeyJvcGFxdWVfYmFja2VuZF9zdGF0ZSI6ICJleUpmb29JT2lBaVltRm9JbjA9In0sICJleHBpcmVzIjogIjIwMjQtMTItMzFUMjM6NTk6NTlaIiwgInNwZWNfdmVyc2lvbiI6ICIxLjAuMCIsICJ0YXJnZXRzIjoge30sICJ2ZXJzaW9uIjogMn19Cg==".to_string()),
            target_files: Some(vec![
                TargetFile {
                    path: "datadog/2/APM_TRACING/bad_config/config".to_string(),
                    raw: "aW52YWxpZCBqc29u".to_string(), // "invalid json" in base64
                },
            ]),
            client_configs: Some(vec![
                "datadog/2/APM_TRACING/bad_config/config".to_string(),
            ]),
        };

        // Process second response
        let result = client.process_response(config_response_2);
        assert!(
            result.is_ok(),
            "Second process_response should succeed (even with config errors)"
        );

        // Verify config_states were cleared and only contains the new error config
        {
            let state = client.state.lock().unwrap();
            assert_eq!(state.config_states.len(), 1); // Should have only the error config
            assert_eq!(state.config_states[0].id, "bad_config");
            assert_eq!(state.config_states[0].apply_state, 3); // error
            assert!(state.config_states[0].apply_error.is_some());

            // Should not contain the previous successful config
            assert_ne!(state.config_states[0].id, "good_config");
        }
    }

    #[test]
    fn test_tuf_targets_integration_with_remote_config() {
        // Test that we can process a TUF targets response through the remote config system
        let config = Arc::new(Mutex::new(Config::builder().build()));
        let client = RemoteConfigClient::new(config).unwrap();

        // Create a realistic TUF targets JSON and base64 encode it
        let tuf_targets_json = r#"{
   "signatures": [
       {
           "keyid": "5c4ece41241a1bb513f6e3e5df74ab7d5183dfffbd71bfd43127920d880569fd",
           "sig": "4dd483db8b4aff81a9afd2ed4eaeb23fe3aca9a148a7a8942e24e8c5ef911e2692f94492b882727b257dacfbf6bcea09d6e26ea28ac145fcb4254ea046be3b03"
       }
   ],
   "signed": {
       "_type": "targets",
       "custom": {
           "opaque_backend_state": "eyJ2ZXJzaW9uIjoxLCJzdGF0ZSI6eyJmaWxlX2hhc2hlcyI6WyJGZXJOT1FyMStmTThKWk9TY0crZllucnhXMWpKN0w0ZlB5aGtxUWVCT3dJPSIsInd1aW9BVm1Qcy9oNEpXMDh1dnI1bi9meERLQ3lKdG1sQmRjaDNOcFdLZDg9IiwiOGFDYVJFc3hIV3R3SFNFWm5SV0pJYmtENXVBNUtETENoZG8vZ0RNdnJJMD0iXX19"
       },
       "expires": "2022-09-22T09:01:04Z",
       "spec_version": "1.0.0",
       "targets": {
           "datadog/2/APM_TRACING/test-sampling/config": {
               "custom": {
                   "v": 100
               },
               "hashes": {
                   "sha256": "c2e8a801598fb3f878256d3cbafaf99ff7f10ca0b226d9a505d721dcda5629df"
               },
               "length": 58409
           }
       },
       "version": 23755701
   }
}"#;

        use base64::Engine;
        let encoded_targets =
            base64::engine::general_purpose::STANDARD.encode(tuf_targets_json.as_bytes());

        // Create a config response with the TUF targets and a corresponding target file
        let config_response = ConfigResponse {
            roots: None,
            targets: Some(encoded_targets),
            target_files: Some(vec![
                TargetFile {
                    path: "datadog/2/APM_TRACING/test-sampling/config".to_string(),
                    raw: "eyJ0cmFjaW5nX3NhbXBsaW5nX3J1bGVzIjogW3sic2FtcGxlX3JhdGUiOiAwLjc1LCAic2VydmljZSI6ICJ0ZXN0LWFwcC1zZXJ2aWNlIn1dfQo=".to_string(), // base64 encoded lib_config with tracing_sampling_rules at top level
                },
            ]),
            client_configs: Some(vec![
                "datadog/2/APM_TRACING/test-sampling/config".to_string()
            ]),
        };

        // Process the response
        let result = client.process_response(config_response);
        assert!(
            result.is_ok(),
            "process_response should succeed: {result:?}"
        );

        // Verify state was updated with targets metadata
        let state = client.state.lock().unwrap();
        assert_eq!(state.targets_version, 23755701);
        assert_eq!(
            state.backend_client_state,
            Some("eyJ2ZXJzaW9uIjoxLCJzdGF0ZSI6eyJmaWxlX2hhc2hlcyI6WyJGZXJOT1FyMStmTThKWk9TY0crZllucnhXMWpKN0w0ZlB5aGtxUWVCT3dJPSIsInd1aW9BVm1Qcy9oNEpXMDh1dnI1bi9meERLQ3lKdG1sQmRjaDNOcFdLZDg9IiwiOGFDYVJFc3hIV3R3SFNFWm5SV0pJYmtENXVBNUtETENoZG8vZ0RNdnJJMD0iXX19".to_string())
        );

        // Verify config states were updated with version from targets custom.v
        assert_eq!(state.config_states.len(), 1);
        let config_state = &state.config_states[0];
        assert!(config_state.id == "test-sampling" || config_state.id == "apm-tracing-sampling");
        assert_eq!(config_state.version, 100); // From custom.v in targets
        assert_eq!(config_state.product, "APM_TRACING");

        // Verify that the sampling rules were applied to the config
        let config = client.config.lock().unwrap();
        let rules = config.trace_sampling_rules();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].sample_rate, 0.75);
        assert_eq!(rules[0].service, Some("test-app-service".to_string()));
    }
}
