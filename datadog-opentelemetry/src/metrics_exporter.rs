// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use crate::core::configuration::Config;

const DEFAULT_OTLP_GRPC_PORT: u16 = 4317;
const DEFAULT_OTLP_HTTP_PORT: u16 = 4318;

/// OTLP protocol types for metrics export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtlpProtocol {
    /// gRPC protocol
    Grpc,
    /// HTTP with protobuf encoding
    HttpProtobuf,
    /// HTTP with JSON encoding
    HttpJson,
}

impl FromStr for OtlpProtocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("grpc") {
            Ok(OtlpProtocol::Grpc)
        } else if s.eq_ignore_ascii_case("http/protobuf") {
            Ok(OtlpProtocol::HttpProtobuf)
        } else if s.eq_ignore_ascii_case("http/json") {
            Ok(OtlpProtocol::HttpJson)
        } else {
            Err(format!("Invalid OTLP protocol: {}", s))
        }
    }
}

impl OtlpProtocol {
    /// Parse a protocol string, returning None for empty strings
    pub(crate) fn parse_optional(s: String) -> Option<Self> {
        if s.trim().is_empty() {
            None
        } else {
            s.parse().ok()
        }
    }
}

pub fn get_otlp_protocol(config: &Config) -> OtlpProtocol {
    config
        .otlp_metrics_protocol()
        .or_else(|| config.otlp_protocol())
        .unwrap_or(OtlpProtocol::Grpc)
}

pub fn get_otlp_metrics_endpoint(
    config: &Config,
    protocol: &OtlpProtocol,
) -> Result<String, String> {
    let endpoint = config.otlp_metrics_endpoint();
    if !endpoint.is_empty() {
        return Ok(endpoint.to_string());
    }

    let endpoint = config.otlp_endpoint();
    if !endpoint.is_empty() {
        return Ok(endpoint.to_string());
    }

    let agent_url = config.trace_agent_url();
    let url = agent_url
        .parse::<hyper::http::Uri>()
        .map_err(|e| format!("Invalid agent URL: {e}"))?;

    let scheme = url.scheme_str().unwrap_or("http");
    let host = url
        .host()
        .ok_or_else(|| "Missing host in agent URL".to_string())?;

    // When falling back to agent URL, use the host but replace with OTLP default ports
    let port = match protocol {
        OtlpProtocol::Grpc => DEFAULT_OTLP_GRPC_PORT,
        OtlpProtocol::HttpProtobuf | OtlpProtocol::HttpJson => DEFAULT_OTLP_HTTP_PORT,
    };

    Ok(format!("{scheme}://{host}:{port}"))
}

pub fn get_otlp_metrics_timeout(config: &Config) -> u32 {
    let timeout = config.otlp_metrics_timeout();
    if timeout != 0 {
        return timeout;
    }
    config.otlp_timeout()
}

/// Parse a temporality preference string to Temporality enum
pub(crate) fn parse_temporality(s: String) -> Option<opentelemetry_sdk::metrics::Temporality> {
    let s = s.trim().to_lowercase();
    if s == "cumulative" {
        Some(opentelemetry_sdk::metrics::Temporality::Cumulative)
    } else if s == "delta" || s.is_empty() {
        Some(opentelemetry_sdk::metrics::Temporality::Delta)
    } else {
        None
    }
}
