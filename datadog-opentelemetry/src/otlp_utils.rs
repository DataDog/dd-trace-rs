// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use opentelemetry_sdk::Resource;

use crate::{configuration::OtlpProtocol, core::configuration::Config};

pub(crate) const DEFAULT_OTLP_GRPC_PORT: u16 = 4317;
pub(crate) const DEFAULT_OTLP_HTTP_PORT: u16 = 4318;

/// Builds the OpenTelemetry Resource by merging Datadog config with provided resource.
///
/// Priority order (highest to lowest):
/// 1. Config service/env/version (if explicitly set)
/// 2. Provided resource attributes
/// 3. Global tags (with DD -> OTel key mapping)
/// 4. OTel resource attributes from config
pub(crate) fn build_otel_resource(config: &Config, resource: Option<Resource>) -> Resource {
    let mut resource_attrs: Vec<opentelemetry::KeyValue> = Vec::new();

    for (key, value) in config.otel_resource_attributes() {
        resource_attrs.push(opentelemetry::KeyValue::new(
            key.to_string(),
            value.to_string(),
        ));
    }

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

    if let Some(resource) = resource {
        for (k, v) in resource.iter() {
            resource_attrs.push(opentelemetry::KeyValue::new(k.clone(), v.clone()));
        }
    }

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

    if let Some(env) = config.env() {
        resource_attrs.retain(|kv| kv.key.as_str() != "deployment.environment");
        resource_attrs.push(opentelemetry::KeyValue::new(
            "deployment.environment",
            env.to_string(),
        ));
    }

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

/// Validates that the protocol is not HttpJson (which is unsupported).
///
/// Returns `true` if protocol is unsupported (HttpJson), `false` otherwise.
pub(crate) fn is_unsupported_protocol(protocol: OtlpProtocol) -> bool {
    matches!(protocol, OtlpProtocol::HttpJson)
}

pub(crate) fn get_otlp_protocol(config: &Config) -> OtlpProtocol {
    config
        .otlp_metrics_protocol()
        .or_else(|| config.otlp_protocol())
        .unwrap_or(OtlpProtocol::Grpc)
}

pub(crate) fn get_otlp_metrics_endpoint(
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
    let host = agent_url
        .parse::<hyper::http::Uri>()
        .ok()
        .and_then(|url| url.host().map(|h| h.to_string()))
        .unwrap_or_else(|| "localhost".to_string());

    let port = match protocol {
        OtlpProtocol::Grpc => DEFAULT_OTLP_GRPC_PORT,
        OtlpProtocol::HttpProtobuf | OtlpProtocol::HttpJson => DEFAULT_OTLP_HTTP_PORT,
    };

    Ok(format!("http://{host}:{port}"))
}

pub(crate) fn get_otlp_metrics_timeout(config: &Config) -> u32 {
    let timeout = config.otlp_metrics_timeout();
    if timeout != 0 {
        return timeout;
    }
    config.otlp_timeout()
}

pub(crate) fn get_otlp_logs_protocol(config: &Config) -> OtlpProtocol {
    config
        .otlp_logs_protocol()
        .or_else(|| config.otlp_protocol())
        .unwrap_or(OtlpProtocol::Grpc)
}

pub(crate) fn get_otlp_logs_endpoint(
    config: &Config,
    protocol: &OtlpProtocol,
) -> Result<String, String> {
    let endpoint = config.otlp_logs_endpoint();
    if !endpoint.is_empty() {
        return Ok(endpoint.to_string());
    }

    let endpoint = config.otlp_endpoint();
    if !endpoint.is_empty() {
        return Ok(endpoint.to_string());
    }

    let agent_url = config.trace_agent_url();
    let host = agent_url
        .parse::<hyper::http::Uri>()
        .ok()
        .and_then(|url| url.host().map(|h| h.to_string()))
        .unwrap_or_else(|| "localhost".to_string());

    let port = match protocol {
        OtlpProtocol::Grpc => DEFAULT_OTLP_GRPC_PORT,
        OtlpProtocol::HttpProtobuf | OtlpProtocol::HttpJson => DEFAULT_OTLP_HTTP_PORT,
    };

    Ok(format!("http://{host}:{port}"))
}

pub(crate) fn get_otlp_logs_timeout(config: &Config) -> u32 {
    let timeout = config.otlp_logs_timeout();
    if timeout != 0 {
        return timeout;
    }
    config.otlp_timeout()
}
