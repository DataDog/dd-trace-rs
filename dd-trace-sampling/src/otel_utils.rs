// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;

use super::{attribute_keys::*, sem_convs, utils};

use opentelemetry::trace::SpanKind;
use opentelemetry::KeyValue;
use opentelemetry_sdk::Resource;
extern crate opentelemetry_semantic_conventions as semconv;

/// The Span trait is used to implement utils function is a way that is generic
/// and could be ported to multiple Span models
pub trait OtelSpan {
    fn name(&self) -> Cow<'static, str>;
    fn span_kind(&self) -> SpanKind;
    fn has_attr(&self, attr_key: AttributeKey) -> bool;
    fn get_attr_str_opt(&self, attr_key: AttributeKey) -> Option<Cow<'static, str>>;
    fn get_attr_num<T: TryFrom<i64>>(&self, attr_key: AttributeKey) -> Option<T>;

    fn get_attr_str(&self, attr_key: AttributeKey) -> Cow<'static, str> {
        self.get_attr_str_opt(attr_key).unwrap_or_default()
    }
}

/// Returns the datadog operation name based on the span kind and attributes
/// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/traceutil/otel_util.go#L405
pub fn get_otel_operation_name_v2(
    attributes: &[KeyValue],
    span_kind: &opentelemetry::trace::SpanKind,
) -> Cow<'static, str> {
    // Look for operation name in attributes
    if let Some(op_name) = attributes
        .iter()
        .find(|kv| kv.key.as_str() == OPERATION_NAME.key())
        .and_then(|kv| utils::extract_string_value(&kv.value))
    {
        return Cow::Owned(op_name);
    }

    let is_client = matches!(span_kind, SpanKind::Client);
    let is_server = matches!(span_kind, SpanKind::Server);

    // http
    let has_http_method = attributes.iter().any(|kv| {
        kv.key.as_str() == HTTP_METHOD.key() || kv.key.as_str() == HTTP_REQUEST_METHOD.key()
    });

    if has_http_method {
        if is_client {
            return Cow::Borrowed("http.client.request");
        } else if is_server {
            return Cow::Borrowed("http.server.request");
        }
    }

    // database
    let db_system = attributes
        .iter()
        .find(|kv| kv.key.as_str() == DB_SYSTEM.key())
        .and_then(|kv| utils::extract_string_value(&kv.value))
        .unwrap_or_default();

    if !db_system.is_empty() && is_client {
        return Cow::Owned(format!("{}.query", db_system));
    }

    // messaging
    let messaging_system = attributes
        .iter()
        .find(|kv| kv.key.as_str() == MESSAGING_SYSTEM.key())
        .and_then(|kv| utils::extract_string_value(&kv.value))
        .unwrap_or_default();

    let messaging_operation = attributes
        .iter()
        .find(|kv| kv.key.as_str() == MESSAGING_OPERATION.key())
        .and_then(|kv| utils::extract_string_value(&kv.value))
        .unwrap_or_default();

    if !messaging_system.is_empty()
        && !messaging_operation.is_empty()
        && matches!(
            span_kind,
            SpanKind::Client | SpanKind::Server | SpanKind::Consumer | SpanKind::Producer
        )
    {
        return Cow::Owned(format!("{}.{}", messaging_system, messaging_operation));
    }

    // RPC & AWS
    let rpc_system = attributes
        .iter()
        .find(|kv| kv.key.as_str() == RPC_SYSTEM.key())
        .and_then(|kv| utils::extract_string_value(&kv.value))
        .unwrap_or_default();

    let is_rpc = !rpc_system.is_empty();
    let is_aws = rpc_system == "aws-api";

    if is_client && is_aws {
        let rpc_service = attributes
            .iter()
            .find(|kv| kv.key.as_str() == RPC_SERVICE.key())
            .and_then(|kv| utils::extract_string_value(&kv.value))
            .unwrap_or_default();

        if !rpc_service.is_empty() {
            return Cow::Owned(format!("aws.{}.request", rpc_service));
        }
        return Cow::Borrowed("aws.client.request");
    }

    if is_client && is_rpc {
        return Cow::Owned(format!("{}.client.request", rpc_system));
    }

    if is_server && is_rpc {
        return Cow::Owned(format!("{}.server.request", rpc_system));
    }

    // FAAS client
    let faas_invoked_provider = attributes
        .iter()
        .find(|kv| kv.key.as_str() == FAAS_INVOKED_PROVIDER.key())
        .and_then(|kv| utils::extract_string_value(&kv.value))
        .unwrap_or_default();

    let faas_invoked_name = attributes
        .iter()
        .find(|kv| kv.key.as_str() == FAAS_INVOKED_NAME.key())
        .and_then(|kv| utils::extract_string_value(&kv.value))
        .unwrap_or_default();

    if is_client && !faas_invoked_provider.is_empty() && !faas_invoked_name.is_empty() {
        return Cow::Owned(format!(
            "{}.{}.invoke",
            faas_invoked_provider, faas_invoked_name
        ));
    }

    // FAAS server
    let faas_trigger = attributes
        .iter()
        .find(|kv| kv.key.as_str() == FAAS_TRIGGER.key())
        .and_then(|kv| utils::extract_string_value(&kv.value))
        .unwrap_or_default();

    if !faas_trigger.is_empty() && is_server {
        return Cow::Owned(format!("{}.invoke", faas_trigger));
    }

    // GraphQL
    let graphql_operation_type = attributes
        .iter()
        .find(|kv| kv.key.as_str() == GRAPHQL_OPERATION_TYPE.key())
        .and_then(|kv| utils::extract_string_value(&kv.value))
        .unwrap_or_default();

    if !graphql_operation_type.is_empty() {
        return Cow::Borrowed("graphql.server.request");
    }

    // Generic HTTP server/client
    let protocol = attributes
        .iter()
        .find(|kv| kv.key.as_str() == NETWORK_PROTOCOL_NAME.key())
        .and_then(|kv| utils::extract_string_value(&kv.value))
        .unwrap_or_default();

    if is_server {
        if !protocol.is_empty() {
            return Cow::Owned(format!("{}.server.request", protocol));
        }
        return Cow::Borrowed("server.request");
    } else if is_client {
        if !protocol.is_empty() {
            return Cow::Owned(format!("{}.client.request", protocol));
        }
        return Cow::Borrowed("client.request");
    }

    // Fallback in span kind
    Cow::Borrowed(match span_kind {
        SpanKind::Client => "Client",
        SpanKind::Server => "Server",
        SpanKind::Producer => "Producer",
        SpanKind::Consumer => "Consumer",
        SpanKind::Internal => "Internal",
    })
}

pub fn get_otel_resource_v2(
    span_attributes: &[KeyValue],
    name: Cow<'static, str>,
    span_kind: SpanKind,
    res: &Resource,
) -> Cow<'static, str> {
    let m = get_res_span_attributes(span_attributes, res, &[RESOURCE_NAME]);
    if !m.is_empty() {
        return m;
    }

    let mut m = get_res_span_attributes(span_attributes, res, &[HTTP_REQUEST_METHOD, HTTP_METHOD]);
    if !m.is_empty() {
        if m == "_OTHER" {
            m = Cow::Borrowed("HTTP");
        }
        if matches!(span_kind, SpanKind::Server) {
            let route = get_res_span_attributes(span_attributes, res, &[HTTP_ROUTE]);
            if !route.is_empty() {
                return Cow::Owned(format!("{} {}", m, route));
            }
        }
        return m;
    }

    let messaging_operation = get_res_span_attributes(span_attributes, res, &[MESSAGING_OPERATION]);
    if !messaging_operation.is_empty() {
        let mut res_name = messaging_operation;
        let messaging_destination = get_res_span_attributes(
            span_attributes,
            res,
            &[MESSAGING_DESTINATION, MESSAGING_DESTINATION_NAME],
        );
        if !messaging_destination.is_empty() {
            res_name = Cow::Owned(format!("{} {}", res_name, messaging_destination));
        }
        return res_name;
    }

    let rpc_method = get_res_span_attributes(span_attributes, res, &[RPC_METHOD]);
    if !rpc_method.is_empty() {
        let mut res_name = rpc_method;
        let rpc_service = get_res_span_attributes(span_attributes, res, &[RPC_SERVICE]);
        if !rpc_service.is_empty() {
            res_name = Cow::Owned(format!("{} {}", res_name, rpc_service));
        }
        return res_name;
    }

    let graphql_operation_type =
        get_res_span_attributes(span_attributes, res, &[GRAPHQL_OPERATION_TYPE]);
    if !graphql_operation_type.is_empty() {
        let mut res_name = graphql_operation_type;
        let graphql_operation_name =
            get_res_span_attributes(span_attributes, res, &[GRAPHQL_OPERATION_NAME]);
        if !graphql_operation_name.is_empty() {
            res_name = Cow::Owned(format!("{} {}", res_name, graphql_operation_name));
        }
        return res_name;
    }

    let db_system = get_res_span_attributes(span_attributes, res, &[DB_SYSTEM]);
    if !db_system.is_empty() {
        let db_statement = get_res_span_attributes(span_attributes, res, &[DB_STATEMENT]);
        if !db_statement.is_empty() {
            return db_statement;
        }
        let db_query = get_res_span_attributes(span_attributes, res, &[DB_QUERY_TEXT]);
        if !db_query.is_empty() {
            return db_query;
        }
    }
    name
}

fn get_res_span_attributes(
    span_attributes: &[KeyValue],
    res: &Resource,
    attributes: &[AttributeKey],
) -> Cow<'static, str> {
    for &attr_key in attributes {
        // First check the resource for the attribute
        let res_attr = get_res_attribute(res, &attr_key);
        if !res_attr.is_empty() {
            return res_attr;
        }

        // Then check the span attributes
        if let Some(attr) = span_attributes
            .iter()
            .find(|kv| kv.key.as_str() == attr_key.key())
            .and_then(|kv| utils::extract_string_value(&kv.value))
        {
            return Cow::Owned(attr);
        }
    }
    Cow::Borrowed("")
}

fn get_res_attribute(res: &Resource, attr: &AttributeKey) -> Cow<'static, str> {
    let Some(value) = res.get(&opentelemetry::Key::from_static_str(attr.key())) else {
        return Cow::Borrowed("");
    };
    Cow::Owned(value.to_string())
}

pub const DEFAULT_OTLP_SERVICE_NAME: &str = "otlpresourcenoservicename";

/// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/traceutil/otel_util.go#L272
pub fn get_otel_service(res: &Resource) -> Cow<'static, str> {
    let service = res.get(&opentelemetry::Key::from_static_str(
        semconv::resource::SERVICE_NAME,
    ));
    if let Some(service) = service {
        if !service.as_str().is_empty() {
            return Cow::Owned(service.to_string());
        }
    }
    Cow::Borrowed(DEFAULT_OTLP_SERVICE_NAME)
}

// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/traceutil/otel_util.go#L571
pub fn get_otel_status_code(span_attributes: &[KeyValue]) -> u32 {
    // Try to get HTTP_RESPONSE_STATUS_CODE
    if let Some(code) = span_attributes
        .iter()
        .find(|kv| kv.key.as_str() == HTTP_RESPONSE_STATUS_CODE.key())
        .and_then(|kv| extract_numeric_value(&kv.value))
    {
        return code;
    }

    // Try to get HTTP_STATUS_CODE
    if let Some(code) = span_attributes
        .iter()
        .find(|kv| kv.key.as_str() == HTTP_STATUS_CODE.key())
        .and_then(|kv| extract_numeric_value(&kv.value))
    {
        return code;
    }

    0
}

fn extract_numeric_value<T: TryFrom<i64>>(value: &opentelemetry::Value) -> Option<T> {
    use opentelemetry::Value;
    match value {
        Value::I64(n) => T::try_from(*n).ok(),
        Value::F64(f) => T::try_from(f.round() as i64).ok(),
        _ => None,
    }
}

// https://github.com/DataDog/opentelemetry-mapping-go/blob/67e66831012599082cc42cf877ea340266d95bb4/pkg/otlp/attributes/attributes.go#L175
fn http_mappings(k: &str) -> Option<&'static str> {
    match k {
        sem_convs::ATTRIBUTE_CLIENT_ADDRESS => Some("http.client_ip"),
        sem_convs::ATTRIBUTE_HTTP_RESPONSE_BODY_SIZE => Some("http.response.content_length"),
        sem_convs::ATTRIBUTE_HTTP_RESPONSE_STATUS_CODE => Some("http.status_code"),
        sem_convs::ATTRIBUTE_HTTP_REQUEST_BODY_SIZE => Some("http.request.content_length"),
        "http.request.header.referrer" => Some("http.referrer"),
        sem_convs::ATTRIBUTE_HTTP_REQUEST_METHOD => Some("http.method"),
        sem_convs::ATTRIBUTE_HTTP_ROUTE => Some("http.route"),
        sem_convs::ATTRIBUTE_NETWORK_PROTOCOL_VERSION => Some("http.version"),
        sem_convs::ATTRIBUTE_SERVER_ADDRESS => Some("http.server_name"),
        sem_convs::ATTRIBUTE_URL_FULL => Some("http.url"),
        sem_convs::ATTRIBUTE_USER_AGENT_ORIGINAL => Some("http.useragent"),
        _ => None,
    }
}

fn is_datadog_convention_key(k: &str) -> bool {
    matches!(
        k,
        "service.name" | "operation.name" | "resource.name" | "span.type"
    ) || k.starts_with("datadog.")
}

pub fn get_dd_key_for_otlp_attribute(k: &str) -> Cow<'static, str> {
    if let Some(mapped_key) = http_mappings(k) {
        return Cow::Borrowed(mapped_key);
    }
    if let Some(suffix) = k.strip_prefix("http.request.header.") {
        return Cow::Owned(format!("http.request.headers.{}", suffix));
    }
    if is_datadog_convention_key(k) {
        return Cow::Owned(k.to_owned());
    }
    Cow::Owned(k.to_owned())
}
