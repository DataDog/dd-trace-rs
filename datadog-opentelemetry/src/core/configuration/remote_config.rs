// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Remote Configuration client.
//!
//! Drives [`libdd_remote_config::fetch::SingleChangesFetcher`] from a dedicated
//! std thread running a single-threaded Tokio runtime, parses delivered files
//! via a custom [`ApmTracingConfig`] parser (registered through
//! [`RemoteConfigContent`]), and routes parsed payloads into
//! [`Config::update_sampling_rules_from_remote`] / [`Config::clear_remote_sampling_rules`].

use crate::core::configuration::Config;
use crate::core::utils::{ShutdownSignaler, WorkerHandle};

use anyhow::Result;
use core::fmt;
use libdd_common_5::{tag::Tag, Endpoint};
use libdd_remote_config::fetch::{
    ConfigApplyState, ConfigInvariants, ConfigOptions, SingleChangesFetcher,
};
use libdd_remote_config::file_change_tracker::Change;
use libdd_remote_config::file_storage::ParsedFileStorage;
use libdd_remote_config::parse::{
    ParseError, ParserRegistry, RemoteConfigContent, RemoteConfigParsed,
};
use libdd_remote_config::{RemoteConfigCapabilities, RemoteConfigProduct, Target};
use serde::Deserialize;
use std::sync::Arc;
use std::thread::{self};
use std::time::Duration;

/// HTTP timeout for a single RC fetch. Matches the historical in-tree client.
const FETCH_TIMEOUT_MS: u64 = 3_000;

// Custom deserializer that preserves explicit null as Some(Value::Null)
fn missing_field_and_null_value<'de, D>(
    deserializer: D,
) -> Result<Option<serde_json::Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Some(serde_json::Value::deserialize(deserializer)?))
}

/// Configuration payload for APM tracing.
///
/// Based on the apm-tracing.json schema from dd-go.
/// See: https://github.com/DataDog/dd-go/blob/prod/remote-config/apps/rc-schema-validation/schemas/apm-tracing.json
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ApmTracingConfig {
    id: String,
    lib_config: LibConfig, // lib_config is a required property
    /// The service/env this config targets. The backend RC predicate already
    /// filters delivery by target, so this is a defense-in-depth guard: a
    /// stale or mistargeted payload must never install another service's or
    /// env's sampling policy on this tracer. A `*` (or absent) component
    /// applies regardless of the tracer's value. Mirrors dd-trace-py/go.
    #[serde(default)]
    service_target: Option<ServiceTarget>,
}

/// `service_target` block of an APM_TRACING RC payload (apm-tracing.json). Both
/// fields are optional here so a malformed/partial target degrades to "applies"
/// for the missing component rather than erroring the whole update.
#[derive(Debug, Clone, Deserialize)]
struct ServiceTarget {
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    env: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct LibConfig {
    /// `None` = field absent (no change intended).
    /// `Some(Value::Null)` = explicit null (clear the override).
    /// `Some(Value::Array(_))` = concrete rule list.
    #[serde(
        deserialize_with = "missing_field_and_null_value",
        default,
        rename = "tracing_sampling_rules"
    )]
    tracing_sampling_rules: Option<serde_json::Value>,

    /// Global trace sample rate (0.0–1.0) pushed via Remote Config.
    /// `None` = field absent (no change intended).
    /// `Some(Value::Null)` = explicit null (clear the override).
    /// `Some(Value::Number)` = concrete rate.
    #[serde(
        deserialize_with = "missing_field_and_null_value",
        default,
        rename = "tracing_sampling_rate"
    )]
    tracing_sampling_rate: Option<serde_json::Value>,
}

impl RemoteConfigContent for ApmTracingConfig {
    const PRODUCT: RemoteConfigProduct = RemoteConfigProduct::ApmTracing;

    fn parse(data: &[u8]) -> std::result::Result<Self, ParseError> {
        Ok(serde_json::from_slice(data)?)
    }
}

/// Apply a parsed APM_TRACING config to the tracer's sampling state.
///
/// Returns `Err` on malformed payloads (out-of-range rate, non-numeric rate,
/// non-array rules, or downstream rule-rejection by libdd-sampling) so the
/// caller can report `ConfigApplyState::Error` to the agent and leave any
/// prior remote override in place.
fn apply_apm_tracing(tracing_config: &ApmTracingConfig, config: &Arc<Config>) -> Result<()> {
    // Defense-in-depth target check: only apply a config whose service_target
    // matches this tracer's service/env. The backend predicate already scopes
    // delivery, but a stale or mistargeted payload must never install another
    // service's/env's policy. A `*` (or absent) component applies regardless.
    // Mismatch => ignore (no sampler mutation), mirroring dd-trace-py.
    if let Some(target) = &tracing_config.service_target {
        if let Some(svc) = target.service.as_deref() {
            if svc != "*" && !config.rc_service_target_matches(svc) {
                crate::dd_debug!(
                    "RemoteConfigClient: ignoring APM_TRACING config targeting service {:?} (not this tracer's service or extra services)",
                    svc
                );
                return Ok(());
            }
        }
        if let Some(target_env) = target.env.as_deref() {
            let tracer_env = config.env().unwrap_or("");
            if target_env != "*" && !target_env.eq_ignore_ascii_case(tracer_env) {
                crate::dd_debug!(
                    "RemoteConfigClient: ignoring APM_TRACING config targeting env {:?} (tracer env is {:?})",
                    target_env,
                    tracer_env
                );
                return Ok(());
            }
        }
    }

    let lib = &tracing_config.lib_config;

    let any_field_present =
        lib.tracing_sampling_rules.is_some() || lib.tracing_sampling_rate.is_some();

    // tracing_sampling_rate must be either null (clear) or a JSON number.
    // Any other present-but-non-numeric value (string, bool, object) is a
    // malformed payload — reject rather than silently treating it as a
    // clear, which would wipe an active remote sampling policy.
    let rate: Option<f64> = match &lib.tracing_sampling_rate {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Number(n)) => match n.as_f64() {
            Some(r) if r.is_finite() && (0.0..=1.0).contains(&r) => Some(r),
            Some(r) => {
                return Err(anyhow::anyhow!(
                    "tracing_sampling_rate must be in [0.0, 1.0], got: {}",
                    r
                ));
            }
            None => {
                return Err(anyhow::anyhow!(
                    "tracing_sampling_rate is not representable as f64"
                ));
            }
        },
        Some(other) => {
            return Err(anyhow::anyhow!(
                "tracing_sampling_rate must be a JSON number or null, got: {}",
                other
            ));
        }
    };
    let rules_value = match &lib.tracing_sampling_rules {
        Some(v) if !v.is_null() => Some(v.clone()),
        _ => None,
    };

    match (rules_value, rate) {
        (None, None) => {
            if any_field_present {
                crate::dd_debug!(
                    "RemoteConfigClient: APM tracing config received with null sampling fields, clearing remote override"
                );
                config.clear_remote_sampling_rules(Some(tracing_config.id.clone()));
            } else {
                crate::dd_debug!(
                    "RemoteConfigClient: APM tracing config received but no tracing_sampling_rules or tracing_sampling_rate present"
                );
            }
        }
        (rules_opt, rate_opt) => {
            // An explicit empty `tracing_sampling_rules: []` is treated the
            // same as null/absent: RC has no rules to deliver, so env-side
            // rules survive. Operators clear remote rules by sending
            // `tracing_sampling_rules: null` (the conventional RC clear);
            // an empty array is an unusual edge case and the lenient
            // interpretation is safer than wiping env config silently.
            let rc_has_explicit_rules = matches!(
                rules_opt,
                Some(serde_json::Value::Array(ref arr)) if !arr.is_empty()
            );

            let mut rules: Vec<serde_json::Value> = match rules_opt {
                Some(serde_json::Value::Array(arr)) => arr,
                Some(other) => {
                    return Err(anyhow::anyhow!(
                        "tracing_sampling_rules must be a JSON array, got: {}",
                        other
                    ));
                }
                None => Vec::new(),
            };

            // Multi-source precedence:
            // - If RC delivered explicit rules, env rules are replaced.
            // - If RC delivered only a rate, env rules survive and apply in front of the synthetic
            //   catch-all.
            if !rc_has_explicit_rules {
                let env_rules = config.local_trace_sampling_rules();
                if !env_rules.is_empty() {
                    let env_json = serde_json::to_value(&*env_rules).map_err(|e| {
                        anyhow::anyhow!("Failed to serialize env sampling rules: {}", e)
                    })?;
                    let serde_json::Value::Array(env_arr) = env_json else {
                        return Err(anyhow::anyhow!(
                            "BUG: serialized env sampling rules are not a JSON array"
                        ));
                    };
                    let mut composed = env_arr;
                    composed.append(&mut rules);
                    rules = composed;
                }
            }

            // Effective catch-all rate: RC rate wins; otherwise fall back
            // to DD_TRACE_SAMPLE_RATE if it's set (Option distinguishes
            // unset from explicit 1.0).
            let env_rate = config.trace_sample_rate();
            let catch_all_rate: Option<f64> = match rate_opt {
                Some(r) => Some(r),
                None => env_rate.filter(|r| r.is_finite()),
            };
            if let Some(r) = catch_all_rate {
                // The global RC rate is a "local-user-like" fallback: it must
                // produce DM "-3" (LOCAL_USER), not "-12" (REMOTE_DYNAMIC).
                // Omit `provenance`; libdd-sampling deserializes it as
                // "default" via its serde default, which maps to DM -3.
                rules.push(serde_json::json!({ "sample_rate": r }));
            }

            let rules_json = serde_json::to_string(&serde_json::Value::Array(rules))
                .map_err(|e| anyhow::anyhow!("Failed to serialize sampling rules: {}", e))?;

            config
                .update_sampling_rules_from_remote(&rules_json, Some(tracing_config.id.clone()))
                .map_err(|e| {
                    anyhow::anyhow!("Failed to update sampling rules from remote: {}", e)
                })?;
            crate::dd_debug!("RemoteConfigClient: Applied sampling rules from remote config");
        }
    }

    Ok(())
}

#[derive(Debug, Clone)]
pub enum RemoteConfigClientError {
    InvalidAgentUri,
    HandleMutexPoisoned,
    WorkerPanicked(String),
    ShutdownTimedOut,
}

impl fmt::Display for RemoteConfigClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAgentUri => write!(f, "invalid agent URI"),
            Self::HandleMutexPoisoned => write!(f, "handle mutex poisoned"),
            Self::WorkerPanicked(msg) => write!(f, "remote config worker panicked: {}", msg),
            Self::ShutdownTimedOut => write!(f, "shutdown timed out"),
        }
    }
}

pub struct RemoteConfigClientHandle {
    cancel_token: tokio_util::sync::CancellationToken,
    worker_handle: WorkerHandle,
}

impl Drop for RemoteConfigClientHandle {
    fn drop(&mut self) {
        self.trigger_shutdown();
    }
}

impl RemoteConfigClientHandle {
    pub fn trigger_shutdown(&self) {
        self.cancel_token.cancel();
    }

    pub fn wait_for_shutdown(&self, timeout: Duration) -> Result<(), RemoteConfigClientError> {
        use crate::core::utils::WorkerError::*;
        if let Err(e) = self.worker_handle.wait_for_shutdown(timeout) {
            Err(match e {
                ShutdownTimedOut => RemoteConfigClientError::ShutdownTimedOut,
                HandleMutexPoisoned => RemoteConfigClientError::HandleMutexPoisoned,
                WorkerPanicked(p) => RemoteConfigClientError::WorkerPanicked(p),
            })
        } else {
            Ok(())
        }
    }
}

/// Receiver for shutdown signals through the cancellation token.
///
/// When this struct is dropped, it signals that the worker has finished to the
/// matching [`WorkerHandle`].
struct RemoteConfigClientShutdownReceiver {
    cancel_token: tokio_util::sync::CancellationToken,
    shutdown_finished: Arc<ShutdownSignaler>,
}

impl Drop for RemoteConfigClientShutdownReceiver {
    fn drop(&mut self) {
        self.shutdown_finished.signal_shutdown();
    }
}

pub struct RemoteConfigClientWorker {
    config: Arc<Config>,
    endpoint: Endpoint,
    shutdown_receiver: RemoteConfigClientShutdownReceiver,
}

impl RemoteConfigClientWorker {
    pub fn start(config: Arc<Config>) -> Result<RemoteConfigClientHandle, RemoteConfigClientError> {
        let endpoint = build_endpoint(&config)?;
        let cancel_token = tokio_util::sync::CancellationToken::new();
        let shutdown_finished = ShutdownSignaler::new();
        let shutdown_receiver = RemoteConfigClientShutdownReceiver {
            cancel_token: cancel_token.clone(),
            shutdown_finished: shutdown_finished.clone(),
        };
        let worker = Self {
            config,
            endpoint,
            shutdown_receiver,
        };
        let join_handle = thread::spawn(move || worker.run());
        Ok(RemoteConfigClientHandle {
            cancel_token,
            worker_handle: WorkerHandle::new(shutdown_finished, join_handle),
        })
    }

    fn run(self) {
        crate::dd_debug!("RemoteConfigClient: started client worker");

        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                crate::dd_debug!("RemoteConfigClient: Failed to create Tokio runtime: {}", e);
                return;
            }
        };

        rt.block_on(self.run_loop());
    }

    async fn run_loop(self) {
        let poll_interval = Duration::from_secs_f64(self.config.remote_config_poll_interval());

        let registry = match ParserRegistry::new().with::<ApmTracingConfig>() {
            Ok(r) => r,
            Err(e) => {
                crate::dd_debug!(
                    "RemoteConfigClient: failed to register ApmTracingConfig parser: {}",
                    e
                );
                return;
            }
        };
        let storage = ParsedFileStorage::with_registry(Arc::new(registry));

        let target = build_target(&self.config);
        let runtime_id = self.config.runtime_id().to_string();

        let options = ConfigOptions {
            invariants: ConfigInvariants {
                language: self.config.language().to_string(),
                tracer_version: self.config.tracer_version().to_string(),
                endpoint: self.endpoint.clone(),
            },
            products: vec![RemoteConfigProduct::ApmTracing],
            capabilities: vec![
                RemoteConfigCapabilities::ApmTracingSampleRate,
                RemoteConfigCapabilities::ApmTracingSampleRules,
            ],
        };

        let mut fetcher = SingleChangesFetcher::new(storage, target, runtime_id, options);

        loop {
            fetcher.set_extra_services(self.config.get_extra_services());

            match fetcher.fetch_changes().await {
                Ok(changes) => apply_changes(changes, &self.config, &fetcher),
                Err(e) => crate::dd_debug!("RemoteConfigClient: fetch failed: {}", e),
            }

            tokio::select! {
                _ = self.shutdown_receiver.cancel_token.cancelled() => break,
                _ = tokio::time::sleep(poll_interval) => {}
            }
        }
    }
}

fn build_endpoint(config: &Config) -> Result<Endpoint, RemoteConfigClientError> {
    let agent_url = libdd_common::parse_uri(&config.trace_agent_url())
        .map_err(|_| RemoteConfigClientError::InvalidAgentUri)?;
    Ok(Endpoint {
        url: agent_url,
        api_key: None,
        timeout_ms: FETCH_TIMEOUT_MS,
        ..Default::default()
    })
}

/// Translate `Config` identity (service / env / version / global tags) into the
/// [`Target`] used by `libdd-remote-config` for server-side scoping.
fn build_target(config: &Config) -> Target {
    Target {
        service: config.service().to_string(),
        env: config.env().unwrap_or_default().to_string(),
        app_version: config.version().unwrap_or_default().to_string(),
        tags: convert_global_tags(config),
        process_tags: vec![],
    }
}

/// Convert the tracer's `global_tags` iterator into `libdd-common` [`Tag`]
/// values.
fn convert_global_tags(config: &Config) -> Vec<Tag> {
    config
        .global_tags()
        .filter_map(|(key, value)| match Tag::new(key, value) {
            Ok(tag) => Some(tag),
            Err(e) => {
                crate::dd_debug!(
                    "RemoteConfigClient: skipping invalid global tag {key}:{value}: {e}"
                );
                None
            }
        })
        .collect()
}

type StoredApmFile =
    libdd_remote_config::file_storage::RawFile<anyhow::Result<Option<RemoteConfigParsed>>>;

/// Dispatcher invoked once per fetcher poll. Routes each [`Change`] to the
/// matching application path and reports the apply state back to the fetcher
/// so the agent learns about successful / failed application.
fn apply_changes(
    changes: Vec<Change<Arc<StoredApmFile>, anyhow::Result<Option<RemoteConfigParsed>>>>,
    config: &Arc<Config>,
    fetcher: &SingleChangesFetcher<ParsedFileStorage>,
) {
    for change in changes {
        match change {
            Change::Add(file) | Change::Update(file, _) => apply_one(&file, config, fetcher),
            Change::Remove(file) => apply_remove(&file, config),
        }
    }
}

fn apply_one(
    file: &Arc<StoredApmFile>,
    config: &Arc<Config>,
    fetcher: &SingleChangesFetcher<ParsedFileStorage>,
) {
    let contents = file.contents();
    let state = match &*contents {
        Ok(Some(parsed)) => match parsed.downcast::<ApmTracingConfig>() {
            Some(cfg) => match apply_apm_tracing(cfg, config) {
                Ok(()) => ConfigApplyState::Acknowledged,
                Err(e) => ConfigApplyState::Error(e.to_string()),
            },
            None => {
                crate::dd_debug!(
                    "RemoteConfigClient: parsed file is not ApmTracingConfig, skipping"
                );
                return;
            }
        },
        Ok(None) => {
            crate::dd_debug!("RemoteConfigClient: file has no parsed contents, skipping");
            return;
        }
        Err(e) => ConfigApplyState::Error(e.to_string()),
    };
    drop(contents);
    fetcher.set_config_state(file, state);
}

fn apply_remove(file: &Arc<StoredApmFile>, config: &Arc<Config>) {
    use libdd_remote_config::file_change_tracker::FilePath;
    let config_id = file.path().config_id.clone();
    crate::dd_debug!(
        "RemoteConfigClient: removing APM_TRACING config {}",
        config_id
    );
    config.clear_remote_sampling_rules(Some(config_id));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::configuration::SamplingRuleConfig;
    use pretty_assertions::assert_eq;
    use std::sync::Mutex;

    fn build_config_for_handler() -> Arc<Config> {
        Arc::new(Config::builder().build())
    }

    fn build_config_for_handler_with_target(service: &str, env: &str) -> Arc<Config> {
        let mut builder = Config::builder();
        builder.set_service(service.to_string());
        builder.set_env(env.to_string());
        Arc::new(builder.build())
    }

    /// Parse a JSON payload with [`ApmTracingConfig::parse`] and apply it
    /// through the same code path the worker uses. Used by handler tests so
    /// they exercise the registry-facing parser and the application step
    /// together.
    fn apply_payload(payload: &[u8], config: &Arc<Config>) -> Result<()> {
        let cfg = ApmTracingConfig::parse(payload).map_err(|e| anyhow::anyhow!("parse: {e}"))?;
        apply_apm_tracing(&cfg, config)
    }

    // ── Parser tests (ApmTracingConfig / LibConfig) ──────────────────────

    #[test]
    fn test_apm_tracing_config_parsing() {
        let json = r#"{
            "id": "42",
            "lib_config": {
                "tracing_sampling_rules": [
                    {
                        "sample_rate": 0.5,
                        "service": "test-service",
                        "provenance": "dynamic"
                    }
                ]
            }
        }"#;

        let config: ApmTracingConfig = serde_json::from_str(json).unwrap();
        assert!(config.lib_config.tracing_sampling_rules.is_some());
        let rules_value = config.lib_config.tracing_sampling_rules.unwrap();

        let rules: Vec<serde_json::Value> = serde_json::from_value(rules_value).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["sample_rate"], 0.5);
        assert_eq!(rules[0]["service"], "test-service");
        assert_eq!(rules[0]["provenance"], "dynamic");
    }

    #[test]
    fn test_apm_tracing_config_full_schema() {
        let json = r#"{
            "id": "42",
            "lib_config": {
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
            }
        }"#;

        let config: ApmTracingConfig = serde_json::from_str(json).unwrap();
        let rules_value = config.lib_config.tracing_sampling_rules.unwrap();
        let rules: Vec<serde_json::Value> = serde_json::from_value(rules_value).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["sample_rate"], 0.3);
        assert_eq!(rules[0]["service"], "web-api");
        assert_eq!(rules[0]["name"], "GET /users/*");
        assert_eq!(rules[0]["resource"], "UserController.list");
        assert_eq!(rules[0]["tags"]["environment"], "production");
        assert_eq!(rules[0]["tags"]["region"], "us-east-1");
        assert_eq!(rules[0]["provenance"], "customer");
        assert_eq!(rules[1]["sample_rate"], 1.0);
        assert_eq!(rules[1]["service"], "auth-service");
        assert_eq!(rules[1]["provenance"], "dynamic");
    }

    #[test]
    fn test_apm_tracing_config_empty() {
        let json = r#"{}"#;
        let config: LibConfig = serde_json::from_str(json).unwrap();
        assert!(config.tracing_sampling_rules.is_none());
    }

    #[test]
    fn test_deserialize_tracing_sampling_rules_null() {
        let config_json = r#"{"id": "42", "lib_config": {"tracing_sampling_rules": null}}"#;
        let tracing_config: ApmTracingConfig = serde_json::from_str(config_json).unwrap();
        assert!(tracing_config.lib_config.tracing_sampling_rules.is_some());
        assert!(tracing_config
            .lib_config
            .tracing_sampling_rules
            .unwrap()
            .is_null());
    }

    #[test]
    fn test_deserialize_tracing_sampling_rules_missing() {
        let config_json = r#"{"id": "42", "lib_config": {}}"#;
        let tracing_config: ApmTracingConfig = serde_json::from_str(config_json).unwrap();
        assert!(tracing_config.lib_config.tracing_sampling_rules.is_none());
    }

    #[test]
    fn test_deserialize_tracing_sampling_rate_concrete() {
        let config_json = r#"{"id": "42", "lib_config": {"tracing_sampling_rate": 0.25}}"#;
        let tracing_config: ApmTracingConfig = serde_json::from_str(config_json).unwrap();
        assert_eq!(
            tracing_config.lib_config.tracing_sampling_rate,
            Some(serde_json::json!(0.25))
        );
    }

    #[test]
    fn test_deserialize_tracing_sampling_rate_null() {
        let config_json = r#"{"id": "42", "lib_config": {"tracing_sampling_rate": null}}"#;
        let tracing_config: ApmTracingConfig = serde_json::from_str(config_json).unwrap();
        assert_eq!(
            tracing_config.lib_config.tracing_sampling_rate,
            Some(serde_json::Value::Null)
        );
    }

    #[test]
    fn test_deserialize_tracing_sampling_rate_missing() {
        let config_json = r#"{"id": "42", "lib_config": {}}"#;
        let tracing_config: ApmTracingConfig = serde_json::from_str(config_json).unwrap();
        assert!(tracing_config.lib_config.tracing_sampling_rate.is_none());
    }

    // ── Registry round-trip ──────────────────────────────────────────────

    #[test]
    fn test_registry_round_trip_apm_tracing() {
        // The registry-driven parse path (used by ParsedFileStorage) must
        // yield the same fields as the direct serde_json::from_slice path
        // that today's apply_apm_tracing reads.
        let registry = ParserRegistry::new()
            .with::<ApmTracingConfig>()
            .expect("registry registration");
        let payload = br#"{
            "id": "rc-roundtrip",
            "lib_config": {"tracing_sampling_rate": 0.25}
        }"#;
        let parsed = registry
            .parse(RemoteConfigProduct::ApmTracing, payload)
            .expect("registry parse")
            .expect("ApmTracing parser registered");
        let cfg = parsed
            .downcast::<ApmTracingConfig>()
            .expect("downcast to ApmTracingConfig");
        assert_eq!(cfg.id, "rc-roundtrip");
        assert_eq!(
            cfg.lib_config.tracing_sampling_rate,
            Some(serde_json::json!(0.25))
        );
    }

    // ── apply_apm_tracing tests (formerly handler tests) ─────────────────

    #[test]
    fn test_handler_applies_only_rate_as_wildcard_rule() {
        // RC sends only tracing_sampling_rate -> handler installs a single
        // wildcard rule with the libdd default provenance ("default", DM -3).
        let config = build_config_for_handler();
        let payload = br#"{
            "id": "rc-rate-only",
            "lib_config": {"tracing_sampling_rate": 0.25}
        }"#;
        apply_payload(payload, &config).unwrap();
        let rules = config.trace_sampling_rules().to_vec();
        assert_eq!(
            rules.len(),
            1,
            "expected exactly one synthesized wildcard rule"
        );
        assert_eq!(rules[0].sample_rate, 0.25);
        assert!(rules[0].service.is_none());
        assert!(rules[0].name.is_none());
        assert!(rules[0].resource.is_none());
        assert!(rules[0].tags.is_empty());
    }

    #[test]
    fn test_handler_synthetic_rate_rule_uses_default_provenance() {
        // The synthetic catch-all built from RC's tracing_sampling_rate must
        // produce DM "-3" (LOCAL_USER), not "-12" (REMOTE_DYNAMIC). Assert via
        // the callback path: libdatadog converts the JSON to its internal
        // SamplingRuleConfig, whose `provenance` must be the libdd default
        // ("default"), not "dynamic".
        use crate::core::configuration::RemoteConfigUpdate;
        let config = build_config_for_handler();
        let received = Arc::new(Mutex::new(Vec::<libdd_sampling::SamplingRuleConfig>::new()));
        let clone = received.clone();
        config.set_sampling_rules_callback(move |update| {
            let RemoteConfigUpdate::SamplingRules(rules) = update;
            *clone.lock().unwrap() = rules.clone();
        });

        let payload = br#"{
            "id": "rc-rate-only-provenance",
            "lib_config": {"tracing_sampling_rate": 0.25}
        }"#;
        apply_payload(payload, &config).unwrap();

        let got = received.lock().unwrap();
        let catch_all = got.last().expect("expected at least one rule");
        assert_eq!(catch_all.sample_rate, 0.25);
        assert_eq!(
            catch_all.provenance, "default",
            "synthetic catch-all must use default provenance"
        );
    }

    #[test]
    fn test_handler_appends_rate_after_rules() {
        let config = build_config_for_handler();
        let payload = br#"{
            "id": "rc-both",
            "lib_config": {
                "tracing_sampling_rate": 0.1,
                "tracing_sampling_rules": [
                    {"sample_rate": 0.9, "service": "auth"}
                ]
            }
        }"#;
        apply_payload(payload, &config).unwrap();
        let rules = config.trace_sampling_rules().to_vec();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].sample_rate, 0.9);
        assert_eq!(rules[0].service.as_deref(), Some("auth"));
        assert_eq!(rules[1].sample_rate, 0.1);
        assert!(rules[1].service.is_none());
        assert!(rules[1].tags.is_empty());
    }

    #[test]
    fn test_handler_null_fields_clear_prior_override() {
        let config = build_config_for_handler();
        let install = br#"{
            "id": "rc-install",
            "lib_config": {"tracing_sampling_rate": 0.5}
        }"#;
        apply_payload(install, &config).unwrap();
        assert_eq!(config.trace_sampling_rules().len(), 1);

        let clear = br#"{
            "id": "rc-clear",
            "lib_config": {
                "tracing_sampling_rate": null,
                "tracing_sampling_rules": null
            }
        }"#;
        apply_payload(clear, &config).unwrap();
        assert_eq!(config.trace_sampling_rules().len(), 0);
    }

    #[test]
    fn test_handler_null_rate_only_clears_prior_override() {
        let config = build_config_for_handler();
        let install = br#"{
            "id": "rc-install",
            "lib_config": {"tracing_sampling_rate": 0.5}
        }"#;
        apply_payload(install, &config).unwrap();
        assert_eq!(config.trace_sampling_rules().len(), 1);

        let clear = br#"{
            "id": "rc-clear",
            "lib_config": {"tracing_sampling_rate": null}
        }"#;
        apply_payload(clear, &config).unwrap();
        assert_eq!(config.trace_sampling_rules().len(), 0);
    }

    #[test]
    fn test_handler_rc_rules_with_list_tags_applied() {
        let config = build_config_for_handler();
        let payload = br#"{
            "id": "rc-list-tags",
            "lib_config": {
                "tracing_sampling_rules": [
                    {
                        "sample_rate": 0.5,
                        "service": "svc",
                        "tags": [
                            {"key": "env", "value_glob": "prod"},
                            {"key": "region", "value_glob": "us-east-1"}
                        ]
                    }
                ]
            }
        }"#;
        apply_payload(payload, &config).unwrap();
        let rules = config.trace_sampling_rules().to_vec();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].sample_rate, 0.5);
        assert_eq!(rules[0].service.as_deref(), Some("svc"));
        assert_eq!(rules[0].tags.get("env").map(String::as_str), Some("prod"));
        assert_eq!(
            rules[0].tags.get("region").map(String::as_str),
            Some("us-east-1")
        );
    }

    #[test]
    fn test_handler_malformed_tags_rejects_update() {
        let config = build_config_for_handler();
        let install = br#"{
            "id": "rc-install",
            "lib_config": {"tracing_sampling_rate": 0.5}
        }"#;
        apply_payload(install, &config).unwrap();
        assert_eq!(config.trace_sampling_rules().len(), 1);

        let bad = br#"{
            "id": "rc-bad-tags",
            "lib_config": {
                "tracing_sampling_rules": [
                    {
                        "sample_rate": 0.0,
                        "service": "svc",
                        "tags": [
                            {"key": "env", "value_glob": "prod"},
                            {"key": "region"}
                        ]
                    }
                ]
            }
        }"#;
        let result = apply_payload(bad, &config);
        assert!(result.is_err(), "malformed tags must propagate as Err");
        let rules = config.trace_sampling_rules().to_vec();
        assert_eq!(rules.len(), 1, "prior override must remain installed");
        assert_eq!(rules[0].sample_rate, 0.5);
    }

    #[test]
    fn test_handler_malformed_tags_returns_error_to_dispatcher() {
        let config = build_config_for_handler();
        let payload = br#"{
            "id": "rc-bad-tags",
            "lib_config": {
                "tracing_sampling_rules": [
                    {
                        "sample_rate": 0.5,
                        "service": "svc",
                        "tags": [
                            {"key": "env", "value_glob": "prod"},
                            {"key": "region"}
                        ]
                    }
                ]
            }
        }"#;
        let result = apply_payload(payload, &config);
        assert!(result.is_err(), "malformed tags must propagate as Err");
    }

    #[test]
    fn test_handler_rejects_negative_rate() {
        let config = build_config_for_handler();
        let payload = br#"{
            "id": "rc-neg-rate",
            "lib_config": {"tracing_sampling_rate": -0.1}
        }"#;
        assert!(apply_payload(payload, &config).is_err());
    }

    #[test]
    fn test_handler_rejects_rate_above_one() {
        let config = build_config_for_handler();
        let payload = br#"{
            "id": "rc-high-rate",
            "lib_config": {"tracing_sampling_rate": 1.5}
        }"#;
        assert!(apply_payload(payload, &config).is_err());
    }

    #[test]
    fn test_handler_non_numeric_rate_rejects_update() {
        let config = build_config_for_handler();
        let install = br#"{
            "id": "rc-install",
            "lib_config": {"tracing_sampling_rate": 0.5}
        }"#;
        apply_payload(install, &config).unwrap();
        assert_eq!(config.trace_sampling_rules().len(), 1);

        let bad = br#"{
            "id": "rc-bad-rate",
            "lib_config": {"tracing_sampling_rate": "0.5"}
        }"#;
        let result = apply_payload(bad, &config);
        assert!(result.is_err(), "non-numeric rate must be rejected");
        // Prior override survives.
        assert_eq!(config.trace_sampling_rules().len(), 1);
        assert_eq!(config.trace_sampling_rules()[0].sample_rate, 0.5);
    }

    #[test]
    fn test_handler_rate_only_preserves_env_rules() {
        let env_rule = SamplingRuleConfig {
            sample_rate: 0.55,
            name: Some("env_name".to_string()),
            ..SamplingRuleConfig::default()
        };
        let config = Arc::new(
            Config::builder()
                .set_trace_sampling_rules(vec![env_rule.clone()])
                .build(),
        );

        let payload = br#"{
            "id": "rc-rate-only-with-env-rules",
            "lib_config": {"tracing_sampling_rate": 0.70}
        }"#;
        apply_payload(payload, &config).unwrap();

        let rules = config.trace_sampling_rules().to_vec();
        assert_eq!(rules.len(), 2, "expected env rule + synthetic catch-all");
        assert_eq!(rules[0].sample_rate, 0.55);
        assert_eq!(rules[0].name.as_deref(), Some("env_name"));
        assert_eq!(rules[1].sample_rate, 0.70);
        assert!(rules[1].name.is_none());
        assert!(rules[1].service.is_none());
        assert!(rules[1].resource.is_none());
        assert!(rules[1].tags.is_empty());
    }

    #[test]
    fn test_handler_rc_rules_replace_env_rules() {
        let env_rule = SamplingRuleConfig {
            sample_rate: 0.55,
            name: Some("env_name".to_string()),
            ..SamplingRuleConfig::default()
        };
        let config = Arc::new(
            Config::builder()
                .set_trace_sampling_rules(vec![env_rule.clone()])
                .build(),
        );

        let payload = br#"{
            "id": "rc-rules-replace-env",
            "lib_config": {
                "tracing_sampling_rate": 0.9,
                "tracing_sampling_rules": [
                    {"sample_rate": 0.8, "service": "svc", "provenance": "customer"}
                ]
            }
        }"#;
        apply_payload(payload, &config).unwrap();

        let rules = config.trace_sampling_rules().to_vec();
        assert_eq!(
            rules.len(),
            2,
            "env rule must be excluded when RC has rules"
        );
        assert_eq!(rules[0].sample_rate, 0.8);
        assert_eq!(rules[0].service.as_deref(), Some("svc"));
        assert_eq!(rules[1].sample_rate, 0.9);
        assert!(rules[1].service.is_none());
        assert!(rules.iter().all(|r| r.name.as_deref() != Some("env_name")));
    }

    #[test]
    fn test_handler_rc_rules_only_falls_back_to_env_rate_catch_all() {
        let mut builder = Config::builder();
        builder.set_trace_sample_rate(0.1);
        let config = Arc::new(builder.build());

        let payload = br#"{
            "id": "rc-rules-only-with-env-rate",
            "lib_config": {
                "tracing_sampling_rules": [
                    {"sample_rate": 0.8, "service": "svc", "provenance": "customer"}
                ]
            }
        }"#;
        apply_payload(payload, &config).unwrap();

        let rules = config.trace_sampling_rules().to_vec();
        assert_eq!(rules.len(), 2, "expected rc rule + env-rate catch-all");
        assert_eq!(rules[0].sample_rate, 0.8);
        assert_eq!(rules[0].service.as_deref(), Some("svc"));
        assert_eq!(rules[1].sample_rate, 0.1);
        assert!(rules[1].service.is_none());
    }

    #[test]
    fn test_handler_empty_rc_rules_array_preserves_env_rules() {
        let env_rule = SamplingRuleConfig {
            sample_rate: 0.55,
            name: Some("env_name".to_string()),
            ..SamplingRuleConfig::default()
        };
        let config = Arc::new(
            Config::builder()
                .set_trace_sampling_rules(vec![env_rule.clone()])
                .build(),
        );

        let payload = br#"{
            "id": "rc-empty-rules",
            "lib_config": {
                "tracing_sampling_rate": 0.70,
                "tracing_sampling_rules": []
            }
        }"#;
        apply_payload(payload, &config).unwrap();

        let rules = config.trace_sampling_rules().to_vec();
        assert_eq!(rules.len(), 2, "expected env rule + synthetic catch-all");
        assert_eq!(rules[0].sample_rate, 0.55);
        assert_eq!(rules[0].name.as_deref(), Some("env_name"));
        assert_eq!(rules[1].sample_rate, 0.70);
        assert!(rules[1].name.is_none());
    }

    // ── service_target gating tests ──────────────────────────────────────

    #[test]
    fn test_handler_service_target_match_applies() {
        let config = build_config_for_handler_with_target("svc-a", "env-a");
        let payload = br#"{
            "id": "rc-target-match",
            "service_target": {"service": "svc-a", "env": "env-a"},
            "lib_config": {"tracing_sampling_rate": 0.5}
        }"#;
        apply_payload(payload, &config).unwrap();
        assert_eq!(
            config.trace_sampling_rules().len(),
            1,
            "matching service_target must apply"
        );
    }

    #[test]
    fn test_handler_service_target_service_mismatch_ignored() {
        let config = build_config_for_handler_with_target("svc-a", "env-a");
        let payload = br#"{
            "id": "rc-other-svc",
            "service_target": {"service": "svc-b", "env": "env-a"},
            "lib_config": {"tracing_sampling_rate": 0.5}
        }"#;
        apply_payload(payload, &config).unwrap();
        assert_eq!(
            config.trace_sampling_rules().len(),
            0,
            "config for another service must be ignored"
        );
    }

    #[test]
    fn test_handler_service_target_env_mismatch_ignored() {
        let config = build_config_for_handler_with_target("svc-a", "env-a");
        let payload = br#"{
            "id": "rc-other-env",
            "service_target": {"service": "svc-a", "env": "env-b"},
            "lib_config": {"tracing_sampling_rate": 0.5}
        }"#;
        apply_payload(payload, &config).unwrap();
        assert_eq!(
            config.trace_sampling_rules().len(),
            0,
            "config for another env must be ignored"
        );
    }

    #[test]
    fn test_handler_service_target_wildcard_applies() {
        let config = build_config_for_handler_with_target("svc-a", "env-a");
        let payload = br#"{
            "id": "rc-wildcard",
            "service_target": {"service": "*", "env": "*"},
            "lib_config": {"tracing_sampling_rate": 0.5}
        }"#;
        apply_payload(payload, &config).unwrap();
        assert_eq!(
            config.trace_sampling_rules().len(),
            1,
            "wildcard service_target must apply"
        );
    }

    #[test]
    fn test_handler_absent_service_target_applies() {
        let config = build_config_for_handler_with_target("svc-a", "env-a");
        let payload = br#"{
            "id": "rc-no-target",
            "lib_config": {"tracing_sampling_rate": 0.5}
        }"#;
        apply_payload(payload, &config).unwrap();
        assert_eq!(
            config.trace_sampling_rules().len(),
            1,
            "payload without service_target must apply"
        );
    }

    #[test]
    fn test_handler_service_target_case_insensitive_applies() {
        let config = build_config_for_handler_with_target("svc-a", "env-a");
        let payload = br#"{
            "id": "rc-case",
            "service_target": {"service": "SVC-A", "env": "ENV-A"},
            "lib_config": {"tracing_sampling_rate": 0.5}
        }"#;
        apply_payload(payload, &config).unwrap();
        assert_eq!(
            config.trace_sampling_rules().len(),
            1,
            "case-only service/env difference must still apply"
        );
    }

    #[test]
    fn test_handler_service_target_extra_service_applies() {
        let config = build_config_for_handler_with_target("svc-a", "env-a");
        config.add_extra_services(["svc-extra"].into_iter());
        let payload = br#"{
            "id": "rc-extra",
            "service_target": {"service": "svc-extra", "env": "*"},
            "lib_config": {"tracing_sampling_rate": 0.5}
        }"#;
        apply_payload(payload, &config).unwrap();
        assert_eq!(
            config.trace_sampling_rules().len(),
            1,
            "config for an advertised extra service must apply"
        );
    }
}
