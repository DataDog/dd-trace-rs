// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::time::Duration;

#[cfg(any(feature = "logs-grpc", feature = "logs-http"))]
use opentelemetry_otlp::{LogExporter, WithExportConfig};
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::Resource;

use crate::core::configuration::Config;
use crate::dd_warn;
use crate::otlp_utils::{
    build_otel_resource, get_otlp_logs_endpoint, get_otlp_logs_protocol, get_otlp_logs_timeout,
    is_unsupported_protocol, OtlpProtocol,
};
use crate::telemetry_logs_exporter::TelemetryTrackingLogExporter;

/// Creates a logger provider with the given configuration.
///
/// Returns a no-op logger provider if logs are disabled or if initialization fails.
/// Errors are logged but not returned to ensure logs functionality is always available.
pub fn create_logger_provider(
    config: Arc<Config>,
    resource: Option<Resource>,
) -> SdkLoggerProvider {
    create_logger_provider_with_protocol(config, resource, None)
}

/// Creates a logger provider with the given configuration and protocol override.
///
/// Returns a no-op logger provider if logs are disabled or if initialization fails.
/// Errors are logged but not returned to ensure logs functionality is always available.
#[doc(hidden)]
pub fn create_logger_provider_with_protocol(
    config: Arc<Config>,
    resource: Option<Resource>,
    protocol: Option<OtlpProtocol>,
) -> SdkLoggerProvider {
    let logs_enabled = config.logs_otel_enabled();
    if !logs_enabled {
        return SdkLoggerProvider::builder().build();
    }

    if config.otel_logs_exporter() == "none" {
        dd_warn!("OTEL_LOGS_EXPORTER is set to 'none'. Logs will not be exported.");
        return SdkLoggerProvider::builder().build();
    }

    #[cfg(not(any(feature = "logs-grpc", feature = "logs-http")))]
    {
        dd_warn!("Logs export requested but no transport feature is enabled. Enable 'logs-grpc' or 'logs-http' feature to export logs.");
        return SdkLoggerProvider::builder().build();
    }

    #[cfg(any(feature = "logs-grpc", feature = "logs-http"))]
    {
        let protocol = protocol.unwrap_or_else(|| get_otlp_logs_protocol(&config));

        if is_unsupported_protocol(protocol) {
            dd_warn!("UNSUPPORTED PROTOCOL: HTTP/JSON protocol is not natively supported by opentelemetry-otlp. Logs will not be exported. Use 'grpc' or 'http/protobuf' instead.");
            return SdkLoggerProvider::builder().build();
        }

        #[cfg(not(feature = "logs-grpc"))]
        if matches!(protocol, OtlpProtocol::Grpc) {
            dd_warn!("FEATURE MISMATCH: Protocol 'grpc' configured but 'logs-grpc' feature is not enabled. Logs will not be exported. Enable 'logs-grpc' in Cargo.toml or set OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf.");
            return SdkLoggerProvider::builder().build();
        }

        #[cfg(not(feature = "logs-http"))]
        if matches!(protocol, OtlpProtocol::HttpProtobuf) {
            dd_warn!("FEATURE MISMATCH: Protocol 'http/protobuf' configured but 'logs-http' feature is not enabled. Logs will not be exported. Enable 'logs-http' in Cargo.toml or set OTEL_EXPORTER_OTLP_PROTOCOL=grpc.");
            return SdkLoggerProvider::builder().build();
        }

        let mut endpoint = match get_otlp_logs_endpoint(&config, &protocol) {
            Ok(endpoint) => endpoint,
            Err(err) => {
                dd_warn!(
                    "Failed to get OTLP logs endpoint: {}. Logs will not be exported.",
                    err
                );
                return SdkLoggerProvider::builder().build();
            }
        };

        if matches!(protocol, OtlpProtocol::HttpProtobuf) && !endpoint.ends_with("/v1/logs") {
            endpoint = endpoint.trim_end_matches('/').to_string();
            if !endpoint.is_empty() {
                endpoint.push_str("/v1/logs");
            }
        }

        let timeout = Duration::from_millis(get_otlp_logs_timeout(&config) as u64);

        let exporter = match build_logs_exporter(protocol, endpoint.clone(), timeout) {
            Ok(exporter) => exporter,
            Err(err) => {
                dd_warn!(
                    "Failed to create logs exporter: {}. Logs will not be exported.",
                    err
                );
                return SdkLoggerProvider::builder().build();
            }
        };

        let telemetry_exporter = TelemetryTrackingLogExporter::new(exporter, protocol);

        let final_resource = build_otel_resource(&config, resource);

        SdkLoggerProvider::builder()
            .with_log_processor(
                opentelemetry_sdk::logs::BatchLogProcessor::builder(telemetry_exporter).build(),
            )
            .with_resource(final_resource)
            .build()
    }
}

#[cfg(any(feature = "logs-grpc", feature = "logs-http"))]
fn build_logs_exporter(
    protocol: OtlpProtocol,
    endpoint: String,
    timeout: Duration,
) -> Result<LogExporter, String> {
    match protocol {
        #[cfg(feature = "logs-grpc")]
        OtlpProtocol::Grpc => opentelemetry_otlp::LogExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .with_timeout(timeout)
            .build()
            .map_err(|e| format!("Failed to build OTLP gRPC exporter: {e}")),
        #[cfg(not(feature = "logs-grpc"))]
        OtlpProtocol::Grpc => Err("gRPC protocol requires 'logs-grpc' feature".to_string()),
        #[cfg(feature = "logs-http")]
        OtlpProtocol::HttpProtobuf => opentelemetry_otlp::LogExporter::builder()
            .with_http()
            .with_endpoint(endpoint)
            .with_timeout(timeout)
            .build()
            .map_err(|e| format!("Failed to build OTLP HTTP/protobuf exporter: {e}")),
        #[cfg(not(feature = "logs-http"))]
        OtlpProtocol::HttpProtobuf => {
            Err("HTTP/protobuf protocol requires 'logs-http' feature".to_string())
        }
        OtlpProtocol::HttpJson => Err("HTTP/JSON protocol not supported".to_string()),
    }
}
