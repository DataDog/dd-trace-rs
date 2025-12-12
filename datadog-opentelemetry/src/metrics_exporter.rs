// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use crate::core::configuration::Config;

const DEFAULT_OTLP_GRPC_PORT: u16 = 4317;
const DEFAULT_OTLP_HTTP_PORT: u16 = 4318;

#[derive(Debug, Clone, Copy)]
pub enum OtlpProtocol {
    Grpc,
    HttpProtobuf,
    HttpJson,
}

pub fn get_otlp_protocol(config: &Config) -> OtlpProtocol {
    let protocol = config.otlp_metrics_protocol();
    if !protocol.is_empty() {
        match protocol {
            s if s.eq_ignore_ascii_case("http/protobuf") => return OtlpProtocol::HttpProtobuf,
            s if s.eq_ignore_ascii_case("http/json") => return OtlpProtocol::HttpJson,
            _ => {}
        }
    }

    let protocol = config.otlp_protocol();
    if !protocol.is_empty() {
        match protocol {
            s if s.eq_ignore_ascii_case("http/protobuf") => return OtlpProtocol::HttpProtobuf,
            s if s.eq_ignore_ascii_case("http/json") => return OtlpProtocol::HttpJson,
            _ => {}
        }
    }

    OtlpProtocol::Grpc
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

pub fn get_metric_export_interval_ms(config: &Config) -> u32 {
    config.metric_export_interval()
}
