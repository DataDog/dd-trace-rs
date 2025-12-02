// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use crate::core::configuration::Config;

const DEFAULT_OTLP_GRPC_PORT: u16 = 4317;
const DEFAULT_OTLP_HTTP_PORT: u16 = 4318;
const DEFAULT_EXPORT_INTERVAL_MS: u64 = 60000;
const DEFAULT_EXPORT_TIMEOUT_MS: u64 = 10000;

pub enum OtlpProtocol {
    Grpc,
    HttpProtobuf,
    HttpJson,
}

pub fn get_otlp_metrics_endpoint(config: &Config, protocol: &OtlpProtocol) -> Result<String, String> {
    #[allow(clippy::disallowed_methods)]
    if let Ok(endpoint) = std::env::var("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT") {
        return Ok(endpoint);
    }

    #[allow(clippy::disallowed_methods)]
    if let Ok(endpoint) = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
        return Ok(endpoint);
    }

    let agent_url = config.trace_agent_url();
    let url = agent_url
        .parse::<hyper::http::Uri>()
        .map_err(|e| format!("Invalid agent URL: {e}"))?;

    let scheme = url.scheme_str().unwrap_or("http");
    let host = url
        .host()
        .ok_or_else(|| "Missing host in agent URL".to_string())?;
    
    let port = match protocol {
        OtlpProtocol::Grpc => url.port_u16().unwrap_or(DEFAULT_OTLP_GRPC_PORT),
        OtlpProtocol::HttpProtobuf | OtlpProtocol::HttpJson => {
            url.port_u16().unwrap_or(DEFAULT_OTLP_HTTP_PORT)
        }
    };

    Ok(format!("{scheme}://{host}:{port}"))
}

pub fn get_otlp_metrics_timeout() -> u64 {
    #[allow(clippy::disallowed_methods)]
    if let Ok(timeout) = std::env::var("OTEL_EXPORTER_OTLP_METRICS_TIMEOUT") {
        if let Ok(timeout_ms) = timeout.parse::<u64>() {
            return timeout_ms;
        }
    }

    #[allow(clippy::disallowed_methods)]
    if let Ok(timeout) = std::env::var("OTEL_EXPORTER_OTLP_TIMEOUT") {
        if let Ok(timeout_ms) = timeout.parse::<u64>() {
            return timeout_ms;
        }
    }

    DEFAULT_EXPORT_TIMEOUT_MS
}

pub fn get_metric_export_interval_ms() -> u64 {
    #[allow(clippy::disallowed_methods)]
    if let Ok(interval) = std::env::var("OTEL_METRIC_EXPORT_INTERVAL") {
        if let Ok(interval_ms) = interval.parse::<u64>() {
            return interval_ms;
        }
    }

    DEFAULT_EXPORT_INTERVAL_MS
}
