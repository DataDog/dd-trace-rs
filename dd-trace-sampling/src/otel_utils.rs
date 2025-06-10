// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;

use super::{attribute_keys::*, sem_convs, utils};

use opentelemetry::trace::SpanKind;
use opentelemetry::KeyValue;
use opentelemetry_sdk::Resource;
extern crate opentelemetry_semantic_conventions as semconv;

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

#[cfg(test)]
mod tests {
    use super::semconv;
    use super::*; // Imports everything from the parent module (otel_utils.rs)
    use opentelemetry::trace::SpanKind;
    use opentelemetry::{KeyValue, Value};
    use opentelemetry_sdk::Resource; // Added import for Resource SDK type // Added import for the aliased semconv crate

    #[test]
    fn test_get_otel_operation_name_v2_explicit_operation_name() {
        let attributes = vec![KeyValue::new(OPERATION_NAME.key(), "custom.op")];
        let span_kind = SpanKind::Internal;
        assert_eq!(
            get_otel_operation_name_v2(&attributes, &span_kind),
            "custom.op"
        );
    }

    #[test]
    fn test_get_otel_operation_name_v2_http() {
        let client_attrs = vec![KeyValue::new(HTTP_METHOD.key(), "GET")];
        assert_eq!(
            get_otel_operation_name_v2(&client_attrs, &SpanKind::Client),
            "http.client.request"
        );

        let server_attrs = vec![KeyValue::new(HTTP_REQUEST_METHOD.key(), "POST")];
        assert_eq!(
            get_otel_operation_name_v2(&server_attrs, &SpanKind::Server),
            "http.server.request"
        );

        // Test without client/server span kind, should not produce http op name
        let internal_attrs = vec![KeyValue::new(HTTP_METHOD.key(), "PUT")];
        assert_ne!(
            get_otel_operation_name_v2(&internal_attrs, &SpanKind::Internal),
            "http.internal.request"
        ); // Fallback to Internal
        assert_eq!(
            get_otel_operation_name_v2(&internal_attrs, &SpanKind::Internal),
            "Internal"
        );
    }

    #[test]
    fn test_get_otel_operation_name_v2_db() {
        let attributes = vec![KeyValue::new(DB_SYSTEM.key(), "postgresql")];
        let span_kind = SpanKind::Client;
        assert_eq!(
            get_otel_operation_name_v2(&attributes, &span_kind),
            "postgresql.query"
        );

        // Should only work for client spans
        let server_span_kind = SpanKind::Server;
        assert_ne!(
            get_otel_operation_name_v2(&attributes, &server_span_kind),
            "postgresql.query"
        );
        assert_eq!(
            get_otel_operation_name_v2(&attributes, &server_span_kind),
            "server.request"
        );
    }

    #[test]
    fn test_get_otel_operation_name_v2_messaging() {
        let attributes = vec![
            KeyValue::new(MESSAGING_SYSTEM.key(), "kafka"),
            KeyValue::new(MESSAGING_OPERATION.key(), "receive"),
        ];
        assert_eq!(
            get_otel_operation_name_v2(&attributes, &SpanKind::Consumer),
            "kafka.receive"
        );
        assert_eq!(
            get_otel_operation_name_v2(&attributes, &SpanKind::Producer),
            "kafka.receive"
        ); // function uses MESSAGING_OPERATION for both
        assert_eq!(
            get_otel_operation_name_v2(&attributes, &SpanKind::Client),
            "kafka.receive"
        );
        assert_eq!(
            get_otel_operation_name_v2(&attributes, &SpanKind::Server),
            "kafka.receive"
        );

        let attributes_no_op = vec![KeyValue::new(MESSAGING_SYSTEM.key(), "rabbitmq")];
        assert_eq!(
            get_otel_operation_name_v2(&attributes_no_op, &SpanKind::Consumer),
            "Consumer"
        ); // Fallback, missing operation
    }

    #[test]
    fn test_get_otel_operation_name_v2_rpc_general() {
        let client_attrs = vec![KeyValue::new(RPC_SYSTEM.key(), "grpc")];
        assert_eq!(
            get_otel_operation_name_v2(&client_attrs, &SpanKind::Client),
            "grpc.client.request"
        );

        let server_attrs = vec![KeyValue::new(RPC_SYSTEM.key(), "jsonrpc")];
        assert_eq!(
            get_otel_operation_name_v2(&server_attrs, &SpanKind::Server),
            "jsonrpc.server.request"
        );
    }

    #[test]
    fn test_get_otel_operation_name_v2_rpc_aws() {
        let client_attrs_aws_with_service = vec![
            KeyValue::new(RPC_SYSTEM.key(), "aws-api"),
            KeyValue::new(RPC_SERVICE.key(), "s3"),
        ];
        assert_eq!(
            get_otel_operation_name_v2(&client_attrs_aws_with_service, &SpanKind::Client),
            "aws.s3.request"
        );

        let client_attrs_aws_no_service = vec![KeyValue::new(RPC_SYSTEM.key(), "aws-api")];
        assert_eq!(
            get_otel_operation_name_v2(&client_attrs_aws_no_service, &SpanKind::Client),
            "aws.client.request"
        );

        // Non-client span kind for AWS RPC
        assert_ne!(
            get_otel_operation_name_v2(&client_attrs_aws_with_service, &SpanKind::Server),
            "aws.s3.request"
        );
        assert_eq!(
            get_otel_operation_name_v2(&client_attrs_aws_with_service, &SpanKind::Server),
            "aws-api.server.request"
        ); // general rpc.server
    }

    #[test]
    fn test_get_otel_operation_name_v2_faas() {
        let client_attrs = vec![
            KeyValue::new(FAAS_INVOKED_PROVIDER.key(), "aws"),
            KeyValue::new(FAAS_INVOKED_NAME.key(), "myLambda"),
        ];
        assert_eq!(
            get_otel_operation_name_v2(&client_attrs, &SpanKind::Client),
            "aws.myLambda.invoke"
        );

        let server_attrs = vec![KeyValue::new(FAAS_TRIGGER.key(), "http")];
        assert_eq!(
            get_otel_operation_name_v2(&server_attrs, &SpanKind::Server),
            "http.invoke"
        );
    }

    #[test]
    fn test_get_otel_operation_name_v2_graphql() {
        let attributes = vec![KeyValue::new(GRAPHQL_OPERATION_TYPE.key(), "query")];
        // GraphQL operation name is generic, not dependent on span kind as per current logic
        assert_eq!(
            get_otel_operation_name_v2(&attributes, &SpanKind::Server),
            "graphql.server.request"
        );
        assert_eq!(
            get_otel_operation_name_v2(&attributes, &SpanKind::Client),
            "graphql.server.request"
        ); // Still graphql.server.request
    }

    #[test]
    fn test_get_otel_operation_name_v2_generic_protocol() {
        let client_attrs = vec![KeyValue::new(NETWORK_PROTOCOL_NAME.key(), "amqp")];
        assert_eq!(
            get_otel_operation_name_v2(&client_attrs, &SpanKind::Client),
            "amqp.client.request"
        );

        let server_attrs = vec![KeyValue::new(NETWORK_PROTOCOL_NAME.key(), "ftp")];
        assert_eq!(
            get_otel_operation_name_v2(&server_attrs, &SpanKind::Server),
            "ftp.server.request"
        );

        let server_attrs_no_protocol = vec![];
        assert_eq!(
            get_otel_operation_name_v2(&server_attrs_no_protocol, &SpanKind::Server),
            "server.request"
        );

        let client_attrs_no_protocol = vec![];
        assert_eq!(
            get_otel_operation_name_v2(&client_attrs_no_protocol, &SpanKind::Client),
            "client.request"
        );
    }

    #[test]
    fn test_get_otel_operation_name_v2_fallback_to_span_kind() {
        let attributes = vec![];
        assert_eq!(
            get_otel_operation_name_v2(&attributes, &SpanKind::Internal),
            "Internal"
        );
        assert_eq!(
            get_otel_operation_name_v2(&attributes, &SpanKind::Producer),
            "Producer"
        );
        assert_eq!(
            get_otel_operation_name_v2(&attributes, &SpanKind::Consumer),
            "Consumer"
        );
    }

    #[test]
    fn test_get_otel_status_code() {
        // Case 1: HTTP_RESPONSE_STATUS_CODE present
        let attrs1 = vec![KeyValue::new(HTTP_RESPONSE_STATUS_CODE.key(), 200)];
        assert_eq!(get_otel_status_code(&attrs1), 200);

        // Case 2: HTTP_STATUS_CODE present (when HTTP_RESPONSE_STATUS_CODE is not)
        let attrs2 = vec![KeyValue::new(HTTP_STATUS_CODE.key(), 404)];
        assert_eq!(get_otel_status_code(&attrs2), 404);

        // Case 3: Both present (HTTP_RESPONSE_STATUS_CODE takes precedence)
        let attrs3 = vec![
            KeyValue::new(HTTP_RESPONSE_STATUS_CODE.key(), 201),
            KeyValue::new(HTTP_STATUS_CODE.key(), 500),
        ];
        assert_eq!(get_otel_status_code(&attrs3), 201);

        // Case 4: Neither present
        let attrs4 = vec![KeyValue::new("other.key", "value")];
        assert_eq!(get_otel_status_code(&attrs4), 0);

        // Case 5: Value is non-numeric string
        let attrs5 = vec![KeyValue::new(HTTP_RESPONSE_STATUS_CODE.key(), "OK")];
        assert_eq!(get_otel_status_code(&attrs5), 0);

        // Case 6: Value is float (should be rounded)
        let attrs6 = vec![KeyValue::new(
            HTTP_RESPONSE_STATUS_CODE.key(),
            Value::F64(200.7),
        )];
        assert_eq!(get_otel_status_code(&attrs6), 201); // .7 rounds up
        let attrs7 = vec![KeyValue::new(
            HTTP_RESPONSE_STATUS_CODE.key(),
            Value::F64(404.3),
        )];
        assert_eq!(get_otel_status_code(&attrs7), 404); // .3 rounds down

        // Case 7: Value is I64
        let attrs8 = vec![KeyValue::new(HTTP_STATUS_CODE.key(), Value::I64(302))];
        assert_eq!(get_otel_status_code(&attrs8), 302);
    }

    #[test]
    fn test_get_dd_key_for_otlp_attribute() {
        // Case 1: Known HTTP mapping (http.response.status_code -> http.status_code)
        assert_eq!(
            get_dd_key_for_otlp_attribute(sem_convs::ATTRIBUTE_HTTP_RESPONSE_STATUS_CODE),
            "http.status_code"
        );
        // Case 1.1: Another known HTTP mapping (http.request.method -> http.method)
        assert_eq!(
            get_dd_key_for_otlp_attribute(sem_convs::ATTRIBUTE_HTTP_REQUEST_METHOD),
            "http.method"
        );

        // Case 2: HTTP request header mapping
        assert_eq!(
            get_dd_key_for_otlp_attribute("http.request.header.user-agent"),
            "http.request.headers.user-agent"
        );
        assert_eq!(
            get_dd_key_for_otlp_attribute("http.request.header.x-custom"),
            "http.request.headers.x-custom"
        );

        // Case 3: Datadog convention key (e.g., "service.name")
        assert_eq!(
            get_dd_key_for_otlp_attribute("service.name"),
            "service.name"
        );
        assert_eq!(get_dd_key_for_otlp_attribute("span.type"), "span.type");
        assert_eq!(
            get_dd_key_for_otlp_attribute("datadog.custom.tag"),
            "datadog.custom.tag"
        );

        // Case 4: Unmapped key (should return the original key)
        assert_eq!(
            get_dd_key_for_otlp_attribute("my.custom.attribute"),
            "my.custom.attribute"
        );
        assert_eq!(
            get_dd_key_for_otlp_attribute("http.other.thing"),
            "http.other.thing"
        ); // Not a mapped http prefix
    }

    #[test]
    fn test_get_otel_service() {
        // Case 1: SERVICE_NAME present in resource
        let res1_attrs = vec![KeyValue::new(semconv::resource::SERVICE_NAME, "my-app")];
        let res1 = Resource::builder().with_attributes(res1_attrs).build();
        assert_eq!(get_otel_service(&res1), "my-app");

        // Case 2: SERVICE_NAME present but empty string in resource
        let res2_attrs = vec![KeyValue::new(semconv::resource::SERVICE_NAME, "")];
        let res2 = Resource::builder().with_attributes(res2_attrs).build();
        assert_eq!(get_otel_service(&res2), DEFAULT_OTLP_SERVICE_NAME); // falls back to default

        // Case 3: SERVICE_NAME not present in resource
        let res3_attrs = vec![KeyValue::new("other.attr", "value")];
        let res3 = Resource::builder().with_attributes(res3_attrs).build();
        assert_eq!(get_otel_service(&res3), "unknown_service");

        // Case 4: Empty resource
        let res4 = Resource::builder().build();
        assert_eq!(get_otel_service(&res4), "unknown_service");
    }

    #[test]
    fn test_get_otel_resource_v2_fallback_to_name() {
        let attributes = vec![];
        let resource = Resource::builder().build(); // Corrected
        let name_arg = Cow::Borrowed("default.name.arg");
        assert_eq!(
            get_otel_resource_v2(&attributes, name_arg.clone(), SpanKind::Internal, &resource),
            name_arg
        );
    }

    #[test]
    fn test_get_otel_resource_v2_resource_name_attr() {
        let span_attrs1 = vec![KeyValue::new(RESOURCE_NAME.key(), "span_resource_op")];
        let resource1 = Resource::builder().build(); // Corrected
        assert_eq!(
            get_otel_resource_v2(
                &span_attrs1,
                Cow::Borrowed("name"),
                SpanKind::Internal,
                &resource1
            ),
            "span_resource_op"
        );

        let res_attrs2 = vec![KeyValue::new(RESOURCE_NAME.key(), "actual_resource_op")];
        let resource2 = Resource::builder().with_attributes(res_attrs2).build(); // Corrected
        let span_attrs2 = vec![KeyValue::new(
            RESOURCE_NAME.key(),
            "ignored_span_resource_op",
        )];
        assert_eq!(
            get_otel_resource_v2(
                &span_attrs2,
                Cow::Borrowed("name"),
                SpanKind::Internal,
                &resource2
            ),
            "actual_resource_op"
        );

        let resource3 = Resource::builder().build(); // Corrected
        let span_attrs3 = vec![KeyValue::new(RESOURCE_NAME.key(), "span_res_only")];
        assert_eq!(
            get_otel_resource_v2(
                &span_attrs3,
                Cow::Borrowed("name"),
                SpanKind::Internal,
                &resource3
            ),
            "span_res_only"
        );
    }

    #[test]
    fn test_get_otel_resource_v2_http() {
        let resource = Resource::builder().build(); // Corrected
        let name_arg = Cow::Borrowed("fallback.name");

        // HTTP method in span_attributes, server, with route
        let attrs1 = vec![
            KeyValue::new(HTTP_METHOD.key(), "GET"),
            KeyValue::new(HTTP_ROUTE.key(), "/users/:id"),
        ];
        assert_eq!(
            get_otel_resource_v2(&attrs1, name_arg.clone(), SpanKind::Server, &resource),
            "GET /users/:id"
        );

        // HTTP method in span_attributes, server, no route
        let attrs2 = vec![KeyValue::new(HTTP_REQUEST_METHOD.key(), "POST")];
        assert_eq!(
            get_otel_resource_v2(&attrs2, name_arg.clone(), SpanKind::Server, &resource),
            "POST"
        );

        // HTTP method in span_attributes, client
        let attrs3 = vec![KeyValue::new(HTTP_METHOD.key(), "PUT")];
        assert_eq!(
            get_otel_resource_v2(&attrs3, name_arg.clone(), SpanKind::Client, &resource),
            "PUT"
        );

        // HTTP method as _OTHER
        let attrs4 = vec![KeyValue::new(HTTP_METHOD.key(), "_OTHER")];
        assert_eq!(
            get_otel_resource_v2(&attrs4, name_arg.clone(), SpanKind::Server, &resource),
            "HTTP"
        ); // _OTHER becomes HTTP
    }

    #[test]
    fn test_get_otel_resource_v2_messaging() {
        let resource = Resource::builder().build();
        let name_arg = Cow::Borrowed("fallback.name");
        let span_kind = SpanKind::Producer;

        let attrs1 = vec![KeyValue::new(MESSAGING_OPERATION.key(), "send")];
        assert_eq!(
            get_otel_resource_v2(&attrs1, name_arg.clone(), span_kind.clone(), &resource),
            "send"
        );

        let attrs2 = vec![
            KeyValue::new(MESSAGING_OPERATION.key(), "process"),
            KeyValue::new(MESSAGING_DESTINATION.key(), "myQueue"),
        ];
        assert_eq!(
            get_otel_resource_v2(&attrs2, name_arg.clone(), span_kind.clone(), &resource),
            "process myQueue"
        );

        let attrs3 = vec![
            KeyValue::new(MESSAGING_OPERATION.key(), "receive"),
            KeyValue::new(MESSAGING_DESTINATION_NAME.key(), "anotherQueue"),
        ];
        assert_eq!(
            get_otel_resource_v2(&attrs3, name_arg.clone(), span_kind.clone(), &resource),
            "receive anotherQueue"
        );

        let attrs4 = vec![
            KeyValue::new(MESSAGING_OPERATION.key(), "publish"),
            KeyValue::new(MESSAGING_DESTINATION.key(), "topicA"),
            KeyValue::new(MESSAGING_DESTINATION_NAME.key(), "ignoredTopic"),
        ];
        assert_eq!(
            get_otel_resource_v2(&attrs4, name_arg.clone(), span_kind.clone(), &resource),
            "publish topicA"
        );
    }

    #[test]
    fn test_get_otel_resource_v2_rpc() {
        let resource = Resource::builder().build();
        let name_arg = Cow::Borrowed("fallback.name");
        let span_kind = SpanKind::Client;

        let attrs1 = vec![KeyValue::new(RPC_METHOD.key(), "getUser")];
        assert_eq!(
            get_otel_resource_v2(&attrs1, name_arg.clone(), span_kind.clone(), &resource),
            "getUser"
        );

        let attrs2 = vec![
            KeyValue::new(RPC_METHOD.key(), "updateOrder"),
            KeyValue::new(RPC_SERVICE.key(), "OrderService"),
        ];
        assert_eq!(
            get_otel_resource_v2(&attrs2, name_arg.clone(), span_kind.clone(), &resource),
            "updateOrder OrderService"
        );
    }

    #[test]
    fn test_get_otel_resource_v2_graphql() {
        let resource = Resource::builder().build();
        let name_arg = Cow::Borrowed("fallback.name");
        let span_kind = SpanKind::Server;

        let attrs1 = vec![KeyValue::new(GRAPHQL_OPERATION_TYPE.key(), "query")];
        assert_eq!(
            get_otel_resource_v2(&attrs1, name_arg.clone(), span_kind.clone(), &resource),
            "query"
        );

        let attrs2 = vec![
            KeyValue::new(GRAPHQL_OPERATION_TYPE.key(), "mutation"),
            KeyValue::new(GRAPHQL_OPERATION_NAME.key(), "createPost"),
        ];
        assert_eq!(
            get_otel_resource_v2(&attrs2, name_arg.clone(), span_kind.clone(), &resource),
            "mutation createPost"
        );
    }

    #[test]
    fn test_get_otel_resource_v2_db() {
        let resource = Resource::builder().build();
        let name_arg = Cow::Borrowed("fallback.name");
        let span_kind = SpanKind::Client;

        let attrs1 = vec![
            KeyValue::new(DB_SYSTEM.key(), "mysql"),
            KeyValue::new(DB_STATEMENT.key(), "SELECT * FROM users"),
        ];
        assert_eq!(
            get_otel_resource_v2(&attrs1, name_arg.clone(), span_kind.clone(), &resource),
            "SELECT * FROM users"
        );

        let attrs2 = vec![
            KeyValue::new(DB_SYSTEM.key(), "postgresql"),
            KeyValue::new(DB_QUERY_TEXT.key(), "INSERT INTO products ..."),
        ];
        assert_eq!(
            get_otel_resource_v2(&attrs2, name_arg.clone(), span_kind.clone(), &resource),
            "INSERT INTO products ..."
        );

        let attrs3 = vec![
            KeyValue::new(DB_SYSTEM.key(), "mssql"),
            KeyValue::new(DB_STATEMENT.key(), "EXEC get_report"),
            KeyValue::new(DB_QUERY_TEXT.key(), "ignored query text"),
        ];
        assert_eq!(
            get_otel_resource_v2(&attrs3, name_arg.clone(), span_kind.clone(), &resource),
            "EXEC get_report"
        );

        let attrs4 = vec![KeyValue::new(DB_SYSTEM.key(), "sqlite")];
        assert_eq!(
            get_otel_resource_v2(&attrs4, name_arg.clone(), span_kind.clone(), &resource),
            name_arg
        );
    }
}
