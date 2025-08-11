// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use crate::configuration::{Config, SamplingRuleConfig};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

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

/// Configuration payload for APM tracing
/// Based on the apm-tracing.json schema from dd-go
/// See: https://github.com/DataDog/dd-go/blob/main/remote-config/apps/rc-product/schemas/apm-tracing.json
#[derive(Debug, Clone, Deserialize)]
struct ApmTracingConfig {
    /// Sampling rules to apply
    /// This field contains an array of sampling rules that can match based on service, name, resource, tags
    #[serde(default, rename = "tracing_sampling_rules")]
    tracing_sampling_rules: Option<Vec<SamplingRuleConfig>>,
    // Add other APM tracing config fields as needed (e.g., tracing_header_tags, etc.)
}

/// TUF targets metadata
/// AIDEV-NOTE: This is just an alias for SignedTargets to match the JSON structure
type TargetsMetadata = SignedTargets;

/// Target description matching Python's TargetDesc
#[derive(Debug, Deserialize, Serialize)]
struct TargetDesc {
    /// Length of the target file
    length: u64,
    /// Hashes of the target file (algorithm -> hash)
    hashes: HashMap<String, String>,
    /// Custom metadata for this target
    custom: Option<serde_json::Value>,
}

/// Targets structure matching Python's Targets
#[derive(Debug, Deserialize)]
struct Targets {
    /// Type of the targets (usually "targets")
    #[serde(rename = "_type")]
    target_type: String,
    /// Custom metadata
    custom: Option<serde_json::Value>,
    /// Expiration time
    expires: String,
    /// Specification version
    spec_version: String,
    /// Target descriptions (path -> TargetDesc)
    targets: HashMap<String, TargetDesc>,
    /// Version of the targets
    version: u64,
}

#[derive(Debug, Deserialize)]
struct SignedTargets {
    /// Signatures (we don't validate these currently)
    signatures: Option<Vec<serde_json::Value>>,
    /// The signed targets data
    signed: Targets,
    /// Version of the signed targets
    version: Option<u64>,
}

/// Remote configuration client
///
/// This client polls the Datadog Agent for configuration updates and applies them to the tracer.
/// Currently supports APM tracing sampling rules from the APM_TRACING product.
///
/// The client expects to receive configuration files with paths like:
/// `datadog/2/APM_TRACING/{config_id}/config`
///
/// These files contain JSON with a `tracing_sampling_rules` field that defines sampling rules.
///
/// # Example
/// ```no_run
/// use std::sync::{Arc, Mutex};
/// use dd_trace::{Config, ConfigBuilder};
/// use dd_trace::configuration::remote_config::RemoteConfigClient;
///
/// let config = Arc::new(Mutex::new(ConfigBuilder::new().build()));
///
/// let client = RemoteConfigClient::new(config).unwrap();
///
/// // The client directly updates the config when new rules arrive
///
/// // Start the client in a background thread
/// let handle = client.start();
/// ```
pub struct RemoteConfigClient {
    /// Unique identifier for this client instance
    /// AIDEV-NOTE: Different from runtime_id - each RemoteConfigClient gets its own UUID
    client_id: String,
    config: Arc<Mutex<Config>>,
    agent_url: String,
    client: reqwest::blocking::Client,
    state: Arc<Mutex<ClientState>>,
    capabilities: ClientCapabilities,
    poll_interval: Duration,
    // Cache of successfully applied configurations
    cached_target_files: Arc<Mutex<Vec<CachedTargetFile>>>,
}

impl RemoteConfigClient {
    /// Creates a new remote configuration client
    pub fn new(config: Arc<Mutex<Config>>) -> Result<Self> {
        let agent_url = format!("{}/v0.7/config", config.lock().unwrap().trace_agent_url());

        // Create HTTP client with timeout
        let client = reqwest::blocking::Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to create HTTP client: {}", e))?;

        let state = Arc::new(Mutex::new(ClientState {
            root_version: 1, // AIDEV-NOTE: Agent requires >= 1 (base TUF director root)
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
            client,
            state,
            capabilities: ClientCapabilities::new(),
            poll_interval: DEFAULT_POLL_INTERVAL,
            cached_target_files: Arc::new(Mutex::new(Vec::new())),
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
        let mut last_poll = Instant::now();

        loop {
            // Wait for next poll interval
            let elapsed = last_poll.elapsed();
            if elapsed < self.poll_interval {
                thread::sleep(self.poll_interval - elapsed);
            }
            last_poll = Instant::now();

            // Fetch and apply configuration
            match self.fetch_and_apply_config() {
                Ok(_) => {
                    // Clear any previous errors
                    if let Ok(mut state) = self.state.lock() {
                        state.has_error = false;
                        state.error = None;
                    }
                }
                Err(e) => {
                    crate::dd_warn!("RemoteConfigClient: Failed to fetch config: {}", e);
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
    fn fetch_and_apply_config(&self) -> Result<()> {
        let request = self.build_request()?;

        // Send request to agent
        let response = self
            .client
            .post(&self.agent_url)
            .json(&request)
            .send()
            .map_err(|e| anyhow::anyhow!("Failed to send request: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Agent returned error status: {}",
                response.status()
            ));
        }

        let config_response: ConfigResponse = response
            .json()
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

        let config = self.config.lock().map_err(|_| anyhow::anyhow!("Failed to lock config"))?;

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
            // Build a new cache - don't clear the old one yet!
            let mut new_cache = Vec::new();
            let mut any_failure = false;

            for file in target_files {
                // Check if this is an APM tracing config first - skip non-APM_TRACING configs
                // Path format is like "datadog/2/APM_TRACING/{config_id}/config"
                if !file.path.contains("APM_TRACING") {
                    // Skip non-APM_TRACING configs - we only support APM_TRACING currently
                    continue;
                }

                // Target files contain base64 encoded JSON configs
                use base64::Engine;
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(&file.raw)
                    .map_err(|e| anyhow::anyhow!("Failed to decode config: {}", e))?;

                let config_str = String::from_utf8(decoded.clone())
                    .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in config: {}", e))?;

                // Determine config id and version for state reporting (do this before applying)
                let derived_id = extract_config_id_from_path(&file.path);
                let (meta_id, meta_version) = path_to_custom
                    .get(&file.path)
                    .cloned()
                    .unwrap_or((None, None));
                let config_id = derived_id
                    .or(meta_id)
                    .unwrap_or_else(|| "apm-tracing-sampling".to_string());
                let config_version = meta_version.unwrap_or(1);

                // Apply the config and record success or failure state
                match self.process_apm_tracing_config(&config_str) {
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
                            state.config_states.push(ConfigState {
                                id: config_id,
                                version: config_version,
                                product: "APM_TRACING".to_string(),
                                apply_state: 2, // 2 denotes success
                                apply_error: None,
                            });
                        }
                    }
                    Err(e) => {
                        any_failure = true;
                        crate::dd_warn!(
                            "RemoteConfigClient: Failed to apply APM_TRACING config {}: {}",
                            config_id,
                            e
                        );
                        if let Ok(mut state) = self.state.lock() {
                            // 3 denotes error
                            state.config_states.push(ConfigState {
                                id: config_id,
                                version: config_version,
                                product: "APM_TRACING".to_string(),
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
    /// This validation ensures security by preventing unauthorized config files from being applied
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

    /// Processes APM tracing configuration
    fn process_apm_tracing_config(&self, config_json: &str) -> Result<()> {
        let tracing_config: ApmTracingConfig = serde_json::from_str(config_json)
            .map_err(|e| anyhow::anyhow!("Failed to parse APM tracing config: {}", e))?;

        // Extract sampling rules if present
        if let Some(rules) = tracing_config.tracing_sampling_rules {
            // Directly update the config with new rules from remote configuration
            if let Ok(mut config) = self.config.lock() {
                config.update_sampling_rules_from_remote(rules.clone());
                crate::dd_info!(
                    "RemoteConfigClient: Applied {} sampling rules from remote config",
                    rules.len()
                );
            } else {
                crate::dd_warn!("RemoteConfigClient: Failed to lock config to update sampling rules");
            }
        } else {
            crate::dd_info!(
                "RemoteConfigClient: APM tracing config received but no sampling rules present"
            );
        }

        Ok(())
    }
}

// Helper to extract config id from known RC path pattern
fn extract_config_id_from_path(path: &str) -> Option<String> {
    // Expected: datadog/2/APM_TRACING/{config_id}/config
    let parts: Vec<&str> = path.split('/').collect();
    for i in 0..parts.len() {
        if parts[i] == "APM_TRACING" {
            return parts.get(i + 1).map(|s| s.to_string());
        }
    }
    None
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
        // Test that our request format matches the expected structure from Python
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
    fn test_apm_tracing_config_parsing() {
        let json = r#"{
            "tracing_sampling_rules": [
                {
                    "sample_rate": 0.5,
                    "service": "test-service",
                    "provenance": "dynamic"
                }
            ]
        }"#;

        let config: ApmTracingConfig = serde_json::from_str(json).unwrap();
        assert!(config.tracing_sampling_rules.is_some());
        let rules = config.tracing_sampling_rules.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].sample_rate, 0.5);
        assert_eq!(rules[0].service, Some("test-service".to_string()));
        assert_eq!(rules[0].provenance, "dynamic");
    }

    #[test]
    fn test_apm_tracing_config_full_schema() {
        // Test parsing a more complete configuration
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

        let config: ApmTracingConfig = serde_json::from_str(json).unwrap();
        assert!(config.tracing_sampling_rules.is_some());
        let rules = config.tracing_sampling_rules.unwrap();
        assert_eq!(rules.len(), 2);

        // Check first rule
        assert_eq!(rules[0].sample_rate, 0.3);
        assert_eq!(rules[0].service, Some("web-api".to_string()));
        assert_eq!(rules[0].name, Some("GET /users/*".to_string()));
        assert_eq!(rules[0].resource, Some("UserController.list".to_string()));
        assert_eq!(rules[0].tags.len(), 2);
        assert_eq!(
            rules[0].tags.get("environment"),
            Some(&"production".to_string())
        );
        assert_eq!(rules[0].tags.get("region"), Some(&"us-east-1".to_string()));
        assert_eq!(rules[0].provenance, "customer");

        // Check second rule
        assert_eq!(rules[1].sample_rate, 1.0);
        assert_eq!(rules[1].service, Some("auth-service".to_string()));
        assert_eq!(rules[1].provenance, "dynamic");
    }

    #[test]
    fn test_apm_tracing_config_empty() {
        let json = r#"{}"#;

        let config: ApmTracingConfig = serde_json::from_str(json).unwrap();
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
                    raw: "eyJ0cmFjaW5nX3NhbXBsaW5nX3J1bGVzIjogW3sic2FtcGxlX3JhdGUiOiAwLjUsICJzZXJ2aWNlIjogInRlc3Qtc2VydmljZSJ9XX0=".to_string(), // base64 encoded APM config
                },
            ]),
            client_configs: Some(vec![
                "datadog/2/APM_TRACING/apm-tracing-sampling/config".to_string(),
            ]),
        };

        let config = Arc::new(Mutex::new(Config::builder().build()));
        let client = RemoteConfigClient::new(config).unwrap();

        // For testing purposes, we'll verify the config was updated by checking the rules

        // Process the response - this should update the client's state and process APM_TRACING configs
        let result = client.process_response(config_response);
        assert!(result.is_ok(), "process_response should succeed");

        // Verify that the client's state was updated correctly
        let state = client.state.lock().unwrap();
        assert_eq!(state.targets_version, 3);
        assert_eq!(
            state.backend_client_state,
            Some("eyJfooIOiAiYmFoIn0=".to_string())
        );
        assert_eq!(state.has_error, false);

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
        assert_eq!(state.has_error, false);

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
                    raw: "eyJ0cmFjaW5nX3NhbXBsaW5nX3J1bGVzIjogW3sic2FtcGxlX3JhdGUiOiAwLjUsICJzZXJ2aWNlIjogInRlc3Qtc2VydmljZSJ9XX0=".to_string(),
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
}
