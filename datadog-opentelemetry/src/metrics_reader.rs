// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::time::Duration;

use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::SdkMeterProvider;

use crate::core::configuration::Config;
use crate::metrics_exporter::{get_metric_export_interval_ms, get_otlp_metrics_endpoint, get_otlp_metrics_timeout, OtlpProtocol};

use crate::dd_warn;

fn is_metrics_enabled() -> bool {
    #[allow(clippy::disallowed_methods)]
    std::env::var("DD_METRICS_OTEL_ENABLED")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(false)
}

fn get_otlp_protocol() -> OtlpProtocol {
    #[allow(clippy::disallowed_methods)]
    if let Ok(protocol) = std::env::var("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL") {
        match protocol.to_lowercase().as_str() {
            "http/protobuf" => return OtlpProtocol::HttpProtobuf,
            "http/json" => return OtlpProtocol::HttpJson,
            _ => {}
        }
    }

    #[allow(clippy::disallowed_methods)]
    if let Ok(protocol) = std::env::var("OTEL_EXPORTER_OTLP_PROTOCOL") {
        match protocol.to_lowercase().as_str() {
            "http/protobuf" => return OtlpProtocol::HttpProtobuf,
            "http/json" => return OtlpProtocol::HttpJson,
            _ => {}
        }
    }

    OtlpProtocol::Grpc
}

pub fn create_meter_provider(
    config: Arc<Config>,
    resource: Option<Resource>,
    export_interval: Option<Duration>,
) -> Result<SdkMeterProvider, String> {
    create_meter_provider_with_protocol(config, resource, export_interval, None)
}

pub fn create_meter_provider_with_protocol(
    config: Arc<Config>,
    resource: Option<Resource>,
    export_interval: Option<Duration>,
    protocol: Option<OtlpProtocol>,
) -> Result<SdkMeterProvider, String> {
    if !is_metrics_enabled() {
        return Ok(SdkMeterProvider::builder().build());
    }

    let protocol = protocol.unwrap_or_else(get_otlp_protocol);
    let endpoint = get_otlp_metrics_endpoint(&config, &protocol)?;

    let temporality = opentelemetry_sdk::metrics::Temporality::Delta;
    let timeout = Duration::from_millis(get_otlp_metrics_timeout());
    
    let exporter = match protocol {
        OtlpProtocol::Grpc => {
            #[cfg(feature = "metrics-grpc")]
            {
                opentelemetry_otlp::MetricExporter::builder()
                    .with_tonic()
                    .with_endpoint(endpoint)
                    .with_timeout(timeout)
                    .with_temporality(temporality)
                    .build()
                    .map_err(|e| format!("Failed to build OTLP exporter: {e}"))?
            }
            #[cfg(not(feature = "metrics-grpc"))]
            {
                dd_warn!("gRPC metrics export requested but 'metrics-grpc' feature is not enabled. Metrics will not be exported. Enable the 'metrics-grpc' feature to use gRPC transport.");
                return Ok(SdkMeterProvider::builder().build());
            }
        }
        OtlpProtocol::HttpProtobuf => {
            #[cfg(feature = "metrics-http")]
            {
                opentelemetry_otlp::MetricExporter::builder()
                    .with_http()
                    .with_endpoint(endpoint)
                    .with_timeout(timeout)
                    .with_temporality(temporality)
                    .build()
                    .map_err(|e| format!("Failed to build OTLP exporter: {e}"))?
            }
            #[cfg(not(feature = "metrics-http"))]
            {
                dd_warn!("HTTP/protobuf metrics export requested but 'metrics-http' feature is not enabled. Metrics will not be exported. Enable the 'metrics-http' feature to use HTTP/protobuf transport.");
                return Ok(SdkMeterProvider::builder().build());
            }
        }
        OtlpProtocol::HttpJson => {
            dd_warn!("HTTP/JSON protocol is not natively supported by opentelemetry-otlp. Metrics will not be exported.");
            return Ok(SdkMeterProvider::builder().build());
        }
    };

    let interval = export_interval.unwrap_or_else(|| {
        Duration::from_millis(get_metric_export_interval_ms())
    });

    let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter)
        .with_interval(interval)
        .build();

    let resource = resource.unwrap_or_else(|| {
        Resource::builder_empty()
            .with_attributes(vec![
                opentelemetry::KeyValue::new("service.name", config.service().to_string()),
            ])
            .build()
    });

    let mut resource_builder = Resource::builder_empty()
        .with_attributes(resource.iter().map(|(k, v)| opentelemetry::KeyValue::new(k.clone(), v.clone())));

    if let Some(env) = config.env() {
        resource_builder = resource_builder.with_attributes(vec![
            opentelemetry::KeyValue::new("deployment.environment", env.to_string()),
        ]);
    }

    if let Some(version) = config.version() {
        resource_builder = resource_builder.with_attributes(vec![
            opentelemetry::KeyValue::new("service.version", version.to_string()),
        ]);
    }

    let final_resource = resource_builder.build();

    let provider = SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(final_resource)
        .build();

    Ok(provider)
}
