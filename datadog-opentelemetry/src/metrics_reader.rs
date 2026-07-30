// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::time::Duration;

use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::Resource;

#[cfg(any(feature = "metrics-grpc", feature = "metrics-http"))]
use libdd_otel_telemetry::{build_datadog_metric_exporter, OtlpExporterConfig, Temporality};
#[cfg(any(feature = "metrics-grpc", feature = "metrics-http"))]
use libdd_shared_runtime::{BasicRuntime, BlockingRuntime};

#[cfg(any(feature = "metrics-grpc", feature = "metrics-http"))]
use crate::configuration::OtlpProtocol;
use crate::core::configuration::Config;
#[cfg(any(feature = "metrics-grpc", feature = "metrics-http"))]
use crate::otlp_utils::{
    build_otel_resource, get_otlp_metrics_endpoint, get_otlp_metrics_timeout, get_otlp_protocol,
};

use crate::dd_warn;

/// A view function used to customize instrument aggregation, naming, etc.
#[cfg(any(feature = "metrics-grpc", feature = "metrics-http", docsrs))]
pub(crate) type MetricView = Arc<
    dyn Fn(&opentelemetry_sdk::metrics::Instrument) -> Option<opentelemetry_sdk::metrics::Stream>
        + Send
        + Sync,
>;

/// Creates a meter provider with the given configuration.
///
/// Returns a no-op meter provider if metrics are disabled or if initialization fails.
/// Errors are logged but not returned to ensure metrics functionality is always available.
///
/// The OTLP metrics exporter is now provided by libdatadog
/// (`libdd_otel_telemetry::DatadogMetricExporter`), which also tracks export
/// attempts/successes/failures. dd-trace-rs keeps ownership of the `SdkMeterProvider`,
/// `PeriodicReader`, resource, and views.
///
/// TODO: wire `DatadogMetricExporter::counters()` into `crate::core::telemetry` (the old
/// `TelemetryTrackingExporter`'s job). Export counts are now available via that snapshot; feeding
/// them into DD telemetry is a follow-up.
#[cfg(any(feature = "metrics-grpc", feature = "metrics-http"))]
pub fn create_meter_provider(
    config: Arc<Config>,
    resource: Option<Resource>,
    export_interval: Option<Duration>,
    views: Vec<MetricView>,
) -> SdkMeterProvider {
    let metrics_enabled = config.metrics_otel_enabled();
    if !metrics_enabled {
        return SdkMeterProvider::builder().build();
    }

    if config.otel_metrics_exporter() == "none" {
        dd_warn!("OTEL_METRICS_EXPORTER is set to 'none'. Metrics will not be exported.");
        return SdkMeterProvider::builder().build();
    }

    let protocol = get_otlp_protocol(&config);

    if crate::otlp_utils::is_unsupported_protocol(protocol) {
        dd_warn!("UNSUPPORTED PROTOCOL: HTTP/JSON protocol is not supported. Metrics will not be exported. Use 'grpc' or 'http/protobuf' instead.");
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

    let temporality = to_libdd_temporality(config.otel_metrics_temporality_preference());
    let timeout = Duration::from_millis(get_otlp_metrics_timeout(&config) as u64);

    let exporter_config =
        OtlpExporterConfig::new(endpoint, to_libdd_protocol(protocol)).with_timeout(timeout);

    let exporter = match build_exporter(exporter_config, temporality) {
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

    let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter)
        .with_interval(interval)
        .build();

    let final_resource = build_otel_resource(&config, resource);

    let mut builder = SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(final_resource);

    for view in views {
        builder = builder.with_view(move |instrument| view(instrument));
    }

    builder.build()
}

/// Builds the libdatadog OTLP metrics exporter.
///
/// `build_datadog_metric_exporter` is `async` because the underlying `opentelemetry-otlp`
/// exporter initializes its transport within a tokio context. It's driven on a dedicated std
/// thread's single-worker runtime (mirroring `span_exporter`) so it works whether or not the
/// caller is already inside a tokio runtime — `BasicRuntime::block_on` would otherwise panic if
/// called from within an existing runtime.
#[cfg(any(feature = "metrics-grpc", feature = "metrics-http"))]
fn build_exporter(
    config: OtlpExporterConfig,
    temporality: Temporality,
) -> Result<libdd_otel_telemetry::DatadogMetricExporter, String> {
    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                let runtime = BasicRuntime::with_worker_threads(1)
                    .map_err(|e| format!("failed to create metrics exporter runtime: {e}"))?;
                runtime
                    .block_on(build_datadog_metric_exporter(&config, temporality))
                    .map_err(|e| format!("metrics exporter runtime unavailable: {e}"))?
                    .map_err(|warning| warning.to_string())
            })
            .join()
            .unwrap_or_else(|_| Err("metrics exporter build thread panicked".to_string()))
    })
}

#[cfg(any(feature = "metrics-grpc", feature = "metrics-http"))]
fn to_libdd_protocol(protocol: OtlpProtocol) -> libdd_otel_telemetry::OtlpProtocol {
    match protocol {
        OtlpProtocol::Grpc => libdd_otel_telemetry::OtlpProtocol::Grpc,
        // HttpJson is filtered out earlier; treat it as HttpProtobuf defensively.
        OtlpProtocol::HttpProtobuf | OtlpProtocol::HttpJson => {
            libdd_otel_telemetry::OtlpProtocol::HttpProtobuf
        }
    }
}

#[cfg(any(feature = "metrics-grpc", feature = "metrics-http"))]
fn to_libdd_temporality(
    temporality: Option<opentelemetry_sdk::metrics::Temporality>,
) -> Temporality {
    match temporality {
        Some(opentelemetry_sdk::metrics::Temporality::Cumulative) => Temporality::Cumulative,
        _ => Temporality::Delta,
    }
}
