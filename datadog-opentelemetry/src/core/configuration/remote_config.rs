// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use crate::core::configuration::Config;
use crate::core::utils::{ShutdownSignaler, WorkerHandle};

use anyhow::Result;
use core::fmt;
use datadog_remote_config::fetch::{
    ConfigApplyState, ConfigInvariants, ConfigOptions, SingleChangesFetcher,
};
use datadog_remote_config::file_change_tracker::Change;
use datadog_remote_config::file_storage::ParsedFileStorage;
use datadog_remote_config::{
    ParserRegistry, RemoteConfigCapabilities, RemoteConfigContent, RemoteConfigParsedData,
    RemoteConfigProduct, Target,
};
use libdd_common::Endpoint;
use serde::Deserialize;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Per-call timeout for the agent's `/v0.7/config` endpoint.
const DEFAULT_TIMEOUT_MS: u64 = 3000;

// ── Product parser ────────────────────────────────────────────────────────────

/// Configuration payload for APM tracing.
/// Based on the apm-tracing.json schema from dd-go.
/// See: <https://github.com/DataDog/dd-go/blob/prod/remote-config/apps/rc-schema-validation/schemas/apm-tracing.json>
#[derive(Debug, Clone, Deserialize)]
struct ApmTracingConfig {
    id: String,
    lib_config: LibConfig,
}

#[derive(Debug, Clone, Deserialize)]
struct LibConfig {
    #[serde(
        deserialize_with = "missing_field_and_null_value",
        default,
        rename = "tracing_sampling_rules"
    )]
    tracing_sampling_rules: Option<serde_json::Value>,
}

/// Custom deserializer that preserves explicit `null` as `Some(Value::Null)`,
/// so the handler can distinguish "field absent" (no-op) from "field is null" (clear rules).
fn missing_field_and_null_value<'de, D>(
    deserializer: D,
) -> Result<Option<serde_json::Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Some(serde_json::Value::deserialize(deserializer)?))
}

impl RemoteConfigContent for ApmTracingConfig {
    const PRODUCT: RemoteConfigProduct = RemoteConfigProduct::ApmTracing;

    fn parse(data: &[u8]) -> anyhow::Result<Self> {
        Ok(serde_json::from_slice(data)?)
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

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
            Self::WorkerPanicked(msg) => write!(f, "remote config worker panicked: {msg}"),
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
        match self.worker_handle.wait_for_shutdown(timeout) {
            Ok(()) => Ok(()),
            Err(ShutdownTimedOut) => Err(RemoteConfigClientError::ShutdownTimedOut),
            Err(HandleMutexPoisoned) => Err(RemoteConfigClientError::HandleMutexPoisoned),
            Err(WorkerPanicked(p)) => Err(RemoteConfigClientError::WorkerPanicked(p)),
        }
    }
}

/// Receiver that signals shutdown completion when dropped.
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
    shutdown_receiver: RemoteConfigClientShutdownReceiver,
}

impl RemoteConfigClientWorker {
    pub fn start(config: Arc<Config>) -> Result<RemoteConfigClientHandle, RemoteConfigClientError> {
        // Validate the agent URI eagerly so callers see configuration errors before the worker
        // thread is spawned.
        build_agent_endpoint(&config)?;

        let cancel_token = tokio_util::sync::CancellationToken::new();
        let shutdown_finished = ShutdownSignaler::new();
        let shutdown_receiver = RemoteConfigClientShutdownReceiver {
            cancel_token: cancel_token.clone(),
            shutdown_finished: shutdown_finished.clone(),
        };
        let worker = Self {
            config,
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
                crate::dd_debug!("RemoteConfigClient: Failed to create Tokio runtime: {e}");
                return;
            }
        };

        let mut fetcher = match build_fetcher(&self.config) {
            Ok(f) => f,
            Err(e) => {
                crate::dd_debug!("RemoteConfigClient: Failed to build fetcher: {e}");
                return;
            }
        };

        let poll_interval = Duration::from_secs_f64(self.config.remote_config_poll_interval());

        let run_loop = async {
            let mut last_poll = Instant::now();
            loop {
                fetcher.set_extra_services(self.config.get_extra_services());
                match fetcher.fetch_changes().await {
                    Ok(changes) => apply_changes(&self.config, &fetcher, changes),
                    Err(e) => {
                        crate::dd_debug!("RemoteConfigClient: fetch failed: {e}");
                    }
                }

                let elapsed = last_poll.elapsed();
                if elapsed < poll_interval {
                    tokio::time::sleep(poll_interval - elapsed).await;
                }
                last_poll = Instant::now();
            }
        };

        rt.block_on(async {
            tokio::select! {
                _ = self.shutdown_receiver.cancel_token.cancelled() => {},
                _ = run_loop => {},
            }
        });
    }
}

// ── Wiring helpers ────────────────────────────────────────────────────────────

fn build_agent_endpoint(config: &Config) -> Result<Endpoint, RemoteConfigClientError> {
    // Reject obviously-broken URIs early so callers get a typed error before the worker spawns.
    libdd_common::parse_uri(&config.trace_agent_url())
        .map_err(|_| RemoteConfigClientError::InvalidAgentUri)?;

    let url = format!(
        "{}/v0.7/config",
        config.trace_agent_url().trim_end_matches('/')
    );
    Ok(Endpoint::from_slice(&url).with_timeout(DEFAULT_TIMEOUT_MS))
}

fn build_fetcher(
    config: &Config,
) -> Result<SingleChangesFetcher<ParsedFileStorage>, RemoteConfigClientError> {
    let endpoint = build_agent_endpoint(config)?;

    let registry = ParserRegistry::new().with::<ApmTracingConfig>();
    let storage = ParsedFileStorage::with_registry(Arc::new(registry));

    let target = Target {
        service: config.service().to_string(),
        env: config.env().map(str::to_owned).unwrap_or_default(),
        app_version: config.version().map(str::to_owned).unwrap_or_default(),
        tags: vec![],
        process_tags: vec![],
    };

    let options = ConfigOptions {
        invariants: ConfigInvariants {
            language: config.language().to_string(),
            tracer_version: config.tracer_version().to_string(),
            endpoint,
        },
        products: vec![RemoteConfigProduct::ApmTracing],
        capabilities: vec![RemoteConfigCapabilities::ApmTracingSampleRules],
    };

    Ok(SingleChangesFetcher::new(
        storage,
        target,
        config.runtime_id().to_string(),
        options,
    ))
}

type StoredFile = <ParsedFileStorage as datadog_remote_config::fetch::FileStorage>::StoredFile;
type Updated = anyhow::Result<Option<Box<dyn RemoteConfigParsedData>>>;

fn apply_changes(
    config: &Arc<Config>,
    fetcher: &SingleChangesFetcher<ParsedFileStorage>,
    changes: Vec<Change<Arc<StoredFile>, Updated>>,
) {
    for change in changes {
        match change {
            Change::Add(file) | Change::Update(file, _) => {
                let state = match apply_file(config, &file) {
                    Ok(()) => ConfigApplyState::Acknowledged,
                    Err(e) => {
                        crate::dd_debug!("RemoteConfigClient: failed to apply config: {e}");
                        ConfigApplyState::Error(e)
                    }
                };
                fetcher.set_config_state(&file, state);
            }
            // Remove events don't get an apply state: the file is gone from the fetcher's view.
            Change::Remove(file) => apply_remove(config, &file),
        }
    }
}

fn apply_file(config: &Arc<Config>, file: &Arc<StoredFile>) -> Result<(), String> {
    let contents = file.contents();
    let parsed = contents.as_ref().map_err(|e| format!("parse error: {e}"))?;
    // `None` means no parser is registered for this product, so treat as a no-op success so the
    // agent doesn't keep retrying.
    let Some(parsed) = parsed.as_ref() else {
        return Ok(());
    };
    let Some(apm) = parsed.as_any().downcast_ref::<ApmTracingConfig>() else {
        return Ok(());
    };
    apply_apm_tracing(config, apm)
}

fn apply_remove(config: &Arc<Config>, file: &Arc<StoredFile>) {
    let contents = file.contents();
    let parsed = match contents.as_ref() {
        Ok(p) => p,
        Err(e) => {
            crate::dd_debug!("RemoteConfigClient: skipping remove for unparseable config: {e}");
            return;
        }
    };
    let Some(parsed) = parsed.as_ref() else {
        return;
    };
    let Some(apm) = parsed.as_any().downcast_ref::<ApmTracingConfig>() else {
        return;
    };
    config.clear_remote_sampling_rules(Some(apm.id.clone()));
}

fn apply_apm_tracing(config: &Arc<Config>, apm: &ApmTracingConfig) -> Result<(), String> {
    let Some(rules_value) = &apm.lib_config.tracing_sampling_rules else {
        crate::dd_debug!(
            "RemoteConfigClient: APM tracing config received but no tracing_sampling_rules present"
        );
        return Ok(());
    };

    if rules_value.is_null() {
        crate::dd_debug!(
            "RemoteConfigClient: APM tracing config received but tracing_sampling_rules is null"
        );
        config.clear_remote_sampling_rules(Some(apm.id.clone()));
        return Ok(());
    }

    let rules_json = serde_json::to_string(rules_value)
        .map_err(|e| format!("failed to serialize sampling rules: {e}"))?;

    config.update_sampling_rules_from_remote(&rules_json, Some(apm.id.clone()))?;
    crate::dd_debug!("RemoteConfigClient: Applied sampling rules from remote config");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn make_apm_config(id: &str, body: &str) -> ApmTracingConfig {
        let json = format!(r#"{{"id":"{id}","lib_config":{body}}}"#);
        serde_json::from_str(&json).expect("valid ApmTracingConfig")
    }

    #[test]
    fn test_apm_tracing_config_parses_with_rules() {
        let cfg = make_apm_config(
            "42",
            r#"{"tracing_sampling_rules":[{"sample_rate":0.5,"service":"svc","provenance":"dynamic"}]}"#,
        );
        assert!(cfg.lib_config.tracing_sampling_rules.is_some());
        let rules = cfg.lib_config.tracing_sampling_rules.unwrap();
        assert!(rules.is_array());
        assert_eq!(rules[0]["sample_rate"], 0.5);
        assert_eq!(rules[0]["service"], "svc");
    }

    #[test]
    fn test_apm_tracing_config_null_rules_preserved() {
        let cfg = make_apm_config("42", r#"{"tracing_sampling_rules":null}"#);
        let rules = cfg
            .lib_config
            .tracing_sampling_rules
            .expect("explicit null preserved as Some(Null)");
        assert!(rules.is_null());
    }

    #[test]
    fn test_apm_tracing_config_missing_rules() {
        let cfg = make_apm_config("42", r#"{}"#);
        assert!(cfg.lib_config.tracing_sampling_rules.is_none());
    }

    #[test]
    fn test_apply_apm_tracing_updates_rules() {
        let config = Arc::new(Config::builder().build());
        let apm = make_apm_config(
            "config-id-1",
            r#"{"tracing_sampling_rules":[{"sample_rate":0.25,"service":"svc"}]}"#,
        );
        apply_apm_tracing(&config, &apm).expect("apply should succeed");

        let stored: Vec<_> = config.trace_sampling_rules().to_vec();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].sample_rate, 0.25);
    }

    #[test]
    fn test_apply_apm_tracing_null_clears_rules() {
        let config = Arc::new(Config::builder().build());
        // Seed rules first.
        apply_apm_tracing(
            &config,
            &make_apm_config(
                "id-1",
                r#"{"tracing_sampling_rules":[{"sample_rate":0.5,"service":"svc"}]}"#,
            ),
        )
        .expect("apply should succeed");
        assert_eq!(config.trace_sampling_rules().len(), 1);

        // Null clears.
        apply_apm_tracing(
            &config,
            &make_apm_config("id-1", r#"{"tracing_sampling_rules":null}"#),
        )
        .expect("clear should succeed");
        assert!(config.trace_sampling_rules().is_empty());
    }

    #[test]
    fn test_apm_tracing_parser_round_trip() {
        let json =
            br#"{"id":"42","lib_config":{"tracing_sampling_rules":[{"sample_rate":1.0,"service":"x"}]}}"#;
        let apm = ApmTracingConfig::parse(json).expect("parser should accept valid JSON");
        assert_eq!(apm.id, "42");
        assert_eq!(ApmTracingConfig::PRODUCT, RemoteConfigProduct::ApmTracing);
    }
}
