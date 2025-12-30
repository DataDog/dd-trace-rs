// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::time::Duration;

#[cfg(any(feature = "metrics-grpc", feature = "metrics-http"))]
use opentelemetry_otlp::{MetricExporter, WithExportConfig};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::Resource;

use crate::core::configuration::Config;
use crate::metrics_exporter::{
    get_otlp_metrics_endpoint, get_otlp_metrics_timeout, get_otlp_protocol, OtlpProtocol,
};
use crate::telemetry_metrics_exporter::TelemetryTrackingExporter;

use crate::dd_warn;

/// Creates a meter provider with the given configuration.
///
/// Returns a no-op meter provider if metrics are disabled or if initialization fails.
/// Errors are logged but not returned to ensure metrics functionality is always available.
pub fn create_meter_provider(
    config: Arc<Config>,
    resource: Option<Resource>,
    export_interval: Option<Duration>,
) -> SdkMeterProvider {
    create_meter_provider_with_protocol(config, resource, export_interval, None)
}

/// Creates a meter provider with the given configuration and protocol override.
///
/// Returns a no-op meter provider if metrics are disabled or if initialization fails.
/// Errors are logged but not returned to ensure metrics functionality is always available.
#[doc(hidden)]
pub fn create_meter_provider_with_protocol(
    config: Arc<Config>,
    resource: Option<Resource>,
    export_interval: Option<Duration>,
    protocol: Option<OtlpProtocol>,
) -> SdkMeterProvider {
    let metrics_enabled = config.metrics_otel_enabled();
    if !metrics_enabled {
        return SdkMeterProvider::builder().build();
    }

    if config.otel_metrics_exporter() == "none" {
        dd_warn!("OTEL_METRICS_EXPORTER is set to 'none'. Metrics will not be exported.");
        return SdkMeterProvider::builder().build();
    }

    #[cfg(not(any(feature = "metrics-grpc", feature = "metrics-http")))]
    {
        dd_warn!("Metrics export requested but no transport feature is enabled. Enable 'metrics-grpc' or 'metrics-http' feature to export metrics.");
        return SdkMeterProvider::builder().build();
    }

    #[cfg(any(feature = "metrics-grpc", feature = "metrics-http"))]
    {
        let protocol = protocol.unwrap_or_else(|| get_otlp_protocol(&config));

        if matches!(protocol, OtlpProtocol::HttpJson) {
            dd_warn!("UNSUPPORTED PROTOCOL: HTTP/JSON protocol is not natively supported by opentelemetry-otlp. Metrics will not be exported. Use 'grpc' or 'http/protobuf' instead.");
            return SdkMeterProvider::builder().build();
        }

        // Check for feature flag mismatches at runtime
        #[cfg(not(feature = "metrics-grpc"))]
        if matches!(protocol, OtlpProtocol::Grpc) {
            dd_warn!("FEATURE MISMATCH: Protocol 'grpc' configured but 'metrics-grpc' feature is not enabled. Metrics will not be exported. Enable 'metrics-grpc' in Cargo.toml or set OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf.");
            return SdkMeterProvider::builder().build();
        }

        #[cfg(not(feature = "metrics-http"))]
        if matches!(protocol, OtlpProtocol::HttpProtobuf) {
            dd_warn!("FEATURE MISMATCH: Protocol 'http/protobuf' configured but 'metrics-http' feature is not enabled. Metrics will not be exported. Enable 'metrics-http' in Cargo.toml or set OTEL_EXPORTER_OTLP_PROTOCOL=grpc.");
            return SdkMeterProvider::builder().build();
        }

        let mut endpoint = match get_otlp_metrics_endpoint(&config, &protocol) {
            Ok(endpoint) => endpoint,
            Err(err) => {
                dd_warn!(
                    "Failed to get OTLP metrics endpoint: {}. Metrics will not be exported.",
                    err
                );
                return SdkMeterProvider::builder().build();
            }
        };

        if matches!(protocol, OtlpProtocol::HttpProtobuf) && !endpoint.ends_with("/v1/metrics") {
            endpoint = endpoint.trim_end_matches('/').to_string();
            if !endpoint.is_empty() {
                endpoint.push_str("/v1/metrics");
            }
        }

        let temporality = config
            .otel_metrics_temporality_preference()
            .unwrap_or(opentelemetry_sdk::metrics::Temporality::Delta);
        let timeout = Duration::from_millis(get_otlp_metrics_timeout(&config) as u64);

        let exporter = match build_exporter(protocol, endpoint.clone(), timeout, temporality) {
            Ok(exporter) => exporter,
            Err(err) => {
                dd_warn!(
                    "Failed to create metrics exporter: {}. Metrics will not be exported.",
                    err
                );
                return SdkMeterProvider::builder().build();
            }
        };

        let interval = export_interval
            .unwrap_or_else(|| Duration::from_millis(config.metric_export_interval() as u64));

        let telemetry_exporter = TelemetryTrackingExporter::new(exporter, protocol);

        let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(telemetry_exporter)
            .with_interval(interval)
            .build();

        let final_resource = build_metrics_resource(&config, resource);

        SdkMeterProvider::builder()
            .with_reader(reader)
            .with_resource(final_resource)
            .build()
    }
}

/// Builds the OpenTelemetry Resource for metrics by merging Datadog config with provided resource.
///
/// Priority order (highest to lowest):
/// 1. Config service/env/version (if explicitly set)
/// 2. Provided resource attributes
/// 3. Global tags (with DD -> OTel key mapping)
/// 4. OTel resource attributes from config
fn build_metrics_resource(config: &Config, resource: Option<Resource>) -> Resource {
    let mut resource_attrs: Vec<opentelemetry::KeyValue> = Vec::new();

    // Start with OTel resource attributes from config (lowest priority)
    for (key, value) in config.otel_resource_attributes() {
        resource_attrs.push(opentelemetry::KeyValue::new(
            key.to_string(),
            value.to_string(),
        ));
    }

    // Add global tags with DD -> OTel key mapping
    for (key, value) in config.global_tags() {
        let otel_key = match key {
            "service" => "service.name",
            "env" => "deployment.environment",
            "version" => "service.version",
            _ => key,
        };

        resource_attrs.retain(|kv| kv.key.as_str() != otel_key);
        resource_attrs.push(opentelemetry::KeyValue::new(
            otel_key.to_string(),
            value.to_string(),
        ));
    }

    // Merge with provided resource
    if let Some(resource) = resource {
        for (k, v) in resource.iter() {
            resource_attrs.push(opentelemetry::KeyValue::new(k.clone(), v.clone()));
        }
    }

    // Set service.name with proper precedence
    if !config.service_is_default() {
        resource_attrs.retain(|kv| kv.key.as_str() != "service.name");
        resource_attrs.push(opentelemetry::KeyValue::new(
            "service.name",
            config.service().to_string(),
        ));
    } else if !resource_attrs
        .iter()
        .any(|kv| kv.key.as_str() == "service.name")
    {
        resource_attrs.push(opentelemetry::KeyValue::new(
            "service.name",
            config.service().to_string(),
        ));
    }

    // Set deployment.environment if configured
    if let Some(env) = config.env() {
        resource_attrs.retain(|kv| kv.key.as_str() != "deployment.environment");
        resource_attrs.push(opentelemetry::KeyValue::new(
            "deployment.environment",
            env.to_string(),
        ));
    }

    // Set service.version if configured
    if let Some(version) = config.version() {
        resource_attrs.retain(|kv| kv.key.as_str() != "service.version");
        resource_attrs.push(opentelemetry::KeyValue::new(
            "service.version",
            version.to_string(),
        ));
    }

    Resource::builder_empty()
        .with_attributes(resource_attrs)
        .build()
}

#[cfg(any(feature = "metrics-grpc", feature = "metrics-http"))]
fn build_exporter(
    protocol: OtlpProtocol,
    endpoint: String,
    timeout: Duration,
    temporality: opentelemetry_sdk::metrics::Temporality,
) -> Result<MetricExporter, String> {
    match protocol {
        #[cfg(feature = "metrics-grpc")]
        OtlpProtocol::Grpc => opentelemetry_otlp::MetricExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .with_timeout(timeout)
            .with_temporality(temporality)
            .build()
            .map_err(|e| format!("Failed to build OTLP gRPC exporter: {e}")),
        #[cfg(not(feature = "metrics-grpc"))]
        OtlpProtocol::Grpc => Err("gRPC protocol requires 'metrics-grpc' feature".to_string()),
        #[cfg(feature = "metrics-http")]
        OtlpProtocol::HttpProtobuf => opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .with_endpoint(endpoint)
            .with_timeout(timeout)
            .with_temporality(temporality)
            .build()
            .map_err(|e| format!("Failed to build OTLP HTTP/protobuf exporter: {e}")),
        #[cfg(not(feature = "metrics-http"))]
        OtlpProtocol::HttpProtobuf => Err("HTTP/protobuf protocol requires 'metrics-http' feature".to_string()),
        OtlpProtocol::HttpJson => Err("HTTP/JSON protocol not supported".to_string()),
    }
}
