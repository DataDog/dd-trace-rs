// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Operation and resource naming: single-family rules, aliases and precedence.

use opentelemetry::{propagation::TextMapPropagator, trace::SpanKind, KeyValue};
use opentelemetry_sdk::trace::SdkTracerProvider;

use super::{emit, resource, start_span, MappingCase};

pub(super) const CASES: &[MappingCase] = &[
    // Operation name fallbacks and competing families
    MappingCase {
        name: "naming__http_server_new_semconv",
        configure: None,
        resource: None,
        run: naming_http_server_new_semconv,
    },
    MappingCase {
        name: "naming__http_client_old_semconv",
        configure: None,
        resource: None,
        run: naming_http_client_old_semconv,
    },
    MappingCase {
        name: "naming__http_with_route",
        configure: None,
        resource: None,
        run: naming_http_with_route,
    },
    MappingCase {
        name: "naming__http_other_method",
        configure: None,
        resource: None,
        run: naming_http_other_method,
    },
    MappingCase {
        name: "naming__db_postgres",
        configure: None,
        resource: None,
        run: naming_db_postgres,
    },
    MappingCase {
        name: "naming__db_cassandra_mixed_case",
        configure: None,
        resource: None,
        run: naming_db_cassandra_mixed_case,
    },
    MappingCase {
        name: "naming__db_redis",
        configure: None,
        resource: None,
        run: naming_db_redis,
    },
    MappingCase {
        name: "naming__db_unmapped",
        configure: None,
        resource: None,
        run: naming_db_unmapped,
    },
    MappingCase {
        name: "naming__messaging",
        configure: None,
        resource: None,
        run: naming_messaging,
    },
    MappingCase {
        name: "naming__messaging_operation_type",
        configure: None,
        resource: None,
        run: naming_messaging_operation_type,
    },
    MappingCase {
        name: "naming__rpc_grpc_client",
        configure: None,
        resource: None,
        run: naming_rpc_grpc_client,
    },
    MappingCase {
        name: "naming__rpc_grpc_server",
        configure: None,
        resource: None,
        run: naming_rpc_grpc_server,
    },
    MappingCase {
        name: "naming__rpc_aws_with_service",
        configure: None,
        resource: None,
        run: naming_rpc_aws_with_service,
    },
    MappingCase {
        name: "naming__rpc_aws_without_service",
        configure: None,
        resource: None,
        run: naming_rpc_aws_without_service,
    },
    MappingCase {
        name: "naming__faas_client",
        configure: None,
        resource: None,
        run: naming_faas_client,
    },
    MappingCase {
        name: "naming__faas_trigger",
        configure: None,
        resource: None,
        run: naming_faas_trigger,
    },
    MappingCase {
        name: "naming__graphql",
        configure: None,
        resource: None,
        run: naming_graphql,
    },
    MappingCase {
        name: "naming__network_protocol_server",
        configure: None,
        resource: None,
        run: naming_network_protocol_server,
    },
    MappingCase {
        name: "naming__network_protocol_client",
        configure: None,
        resource: None,
        run: naming_network_protocol_client,
    },
    MappingCase {
        name: "naming__generic_server_fallback",
        configure: None,
        resource: None,
        run: naming_generic_server_fallback,
    },
    MappingCase {
        name: "naming__generic_client_fallback",
        configure: None,
        resource: None,
        run: naming_generic_client_fallback,
    },
    MappingCase {
        name: "naming__kind_internal",
        configure: None,
        resource: None,
        run: naming_kind_internal,
    },
    MappingCase {
        name: "naming__kind_producer",
        configure: None,
        resource: None,
        run: naming_kind_producer,
    },
    MappingCase {
        name: "naming__kind_consumer",
        configure: None,
        resource: None,
        run: naming_kind_consumer,
    },
    MappingCase {
        name: "naming__operation_name_attribute",
        configure: None,
        resource: None,
        run: naming_operation_name_attribute,
    },
    MappingCase {
        name: "naming__family_precedence_and_kind_guards",
        configure: None,
        resource: None,
        run: naming_precedence,
    },
    // Resource name fallbacks and aliases
    MappingCase {
        name: "resource_name__attribute",
        configure: None,
        resource: None,
        run: resource_name_attribute,
    },
    MappingCase {
        name: "resource_name__messaging_destination",
        configure: None,
        resource: None,
        run: resource_name_messaging_destination,
    },
    MappingCase {
        name: "resource_name__rpc_method_service",
        configure: None,
        resource: None,
        run: resource_name_rpc_method_service,
    },
    MappingCase {
        name: "resource_name__db_statement",
        configure: None,
        resource: None,
        run: resource_name_db_statement,
    },
    MappingCase {
        name: "resource_name__db_query_text",
        configure: None,
        resource: None,
        run: resource_name_db_query_text,
    },
    MappingCase {
        name: "resource_name__fallback_span_name",
        configure: None,
        resource: None,
        run: resource_name_fallback_span_name,
    },
    MappingCase {
        name: "resource_name__aliases_empty_and_graphql",
        configure: None,
        resource: None,
        run: resource_aliases,
    },
    MappingCase {
        name: "resource_name__resource_beats_span_http",
        configure: None,
        resource: Some(|| {
            resource(vec![
                KeyValue::new("http.request.method", "PATCH"),
                KeyValue::new("http.route", "/resource"),
            ])
        }),
        run: |p, _| {
            emit(
                p,
                "span-http",
                SpanKind::Server,
                vec![
                    KeyValue::new("http.request.method", "GET"),
                    KeyValue::new("http.route", "/span"),
                ],
            )
        },
    },
    MappingCase {
        name: "resource_name__empty_resource_uses_span",
        configure: None,
        resource: Some(|| {
            resource(vec![
                KeyValue::new("http.request.method", ""),
                KeyValue::new("http.route", ""),
            ])
        }),
        run: |p, _| {
            emit(
                p,
                "span-http",
                SpanKind::Server,
                vec![
                    KeyValue::new("http.request.method", "GET"),
                    KeyValue::new("http.route", "/span"),
                ],
            )
        },
    },
];

fn naming_http_server_new_semconv(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Server,
        vec![KeyValue::new("http.request.method", "GET")],
    ));
}

fn naming_http_client_old_semconv(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Client,
        vec![KeyValue::new("http.method", "POST")],
    ));
}

/// An HTTP server span with a route maps the resource name to `METHOD /route`.
fn naming_http_with_route(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Server,
        vec![
            KeyValue::new("http.request.method", "GET"),
            KeyValue::new("http.route", "/users/:id"),
        ],
    ));
}

/// The `_OTHER` HTTP method renders as the resource name `HTTP`.
fn naming_http_other_method(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Server,
        vec![KeyValue::new("http.request.method", "_OTHER")],
    ));
}

/// A client span over a SQL database is named `<system>.query` and typed `sql`.
fn naming_db_postgres(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Client,
        vec![KeyValue::new("db.system", "postgresql")],
    ));
}

/// Operation naming lowercases `Cassandra`, but exact-case type lookup yields `db`.
fn naming_db_cassandra_mixed_case(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Client,
        vec![KeyValue::new("db.system.name", "Cassandra")],
    ));
}

fn naming_db_redis(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Client,
        vec![KeyValue::new("db.system", "redis")],
    ));
}

/// A database system without a dedicated mapping is typed `db`.
fn naming_db_unmapped(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Client,
        vec![KeyValue::new("db.system", "trino")],
    ));
}

/// A messaging span is named `<system>.<operation>`, lowercasing both; the span kind
/// must be one of client/server/producer/consumer.
fn naming_messaging(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Producer,
        vec![
            KeyValue::new("messaging.system", "Kafka"),
            KeyValue::new("messaging.operation", "Publish"),
        ],
    ));
}

/// `messaging.operation.type` is the newer semconv for the messaging operation.
fn naming_messaging_operation_type(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Consumer,
        vec![
            KeyValue::new("messaging.system", "sqs"),
            KeyValue::new("messaging.operation.type", "receive"),
        ],
    ));
}

fn naming_rpc_grpc_client(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Client,
        vec![KeyValue::new("rpc.system", "grpc")],
    ));
}

fn naming_rpc_grpc_server(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Server,
        vec![KeyValue::new("rpc.system", "grpc")],
    ));
}

/// An `aws-api` RPC client span with a service maps to `aws.<service>.request`.
fn naming_rpc_aws_with_service(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Client,
        vec![
            KeyValue::new("rpc.system", "aws-api"),
            KeyValue::new("rpc.service", "DynamoDB"),
        ],
    ));
}

/// An `aws-api` RPC client span without a service maps to `aws.client.request`.
fn naming_rpc_aws_without_service(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Client,
        vec![KeyValue::new("rpc.system", "aws-api")],
    ));
}

/// A client FaaS invocation is named `<provider>.<name>.invoke`.
fn naming_faas_client(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Client,
        vec![
            KeyValue::new("faas.invoked_provider", "aws"),
            KeyValue::new("faas.invoked_name", "S3"),
        ],
    ));
}

/// A server FaaS span is named `<trigger>.invoke`.
fn naming_faas_trigger(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Server,
        vec![KeyValue::new("faas.trigger", "PubSub")],
    ));
}

/// A GraphQL server span is named `graphql.server.request`.
fn naming_graphql(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Server,
        vec![KeyValue::new("graphql.operation.type", "query")],
    ));
}

/// A server span with `network.protocol.name` is named `<protocol>.server.request`,
/// lowercased.
fn naming_network_protocol_server(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Server,
        vec![KeyValue::new("network.protocol.name", "HTTP/2")],
    ));
}

fn naming_network_protocol_client(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Client,
        vec![KeyValue::new("network.protocol.name", "AMQP")],
    ));
}

/// A server span with no naming attribute falls back to `server.request`.
fn naming_generic_server_fallback(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Server,
        vec![KeyValue::new("some.attribute", "value")],
    ));
}

/// A client span with no naming attribute falls back to `client.request`.
fn naming_generic_client_fallback(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Client,
        vec![KeyValue::new("some.attribute", "value")],
    ));
}

fn naming_kind_internal(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![],
    ));
}

/// Producer and client spans are `_dd.measured`.
fn naming_kind_producer(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Producer,
        vec![],
    ));
}

fn naming_kind_consumer(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Consumer,
        vec![],
    ));
}

/// The `operation.name` attribute overrides the operation name.
fn naming_operation_name_attribute(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![KeyValue::new("operation.name", "custom-operation")],
    ));
}

/// HTTP > DB > messaging > RPC > FaaS > GraphQL > network; each removal
/// exposes the next family. GraphQL itself is deliberately not kind-guarded.
fn naming_precedence(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let families = [
        vec![KeyValue::new("http.request.method", "")],
        vec![
            KeyValue::new("db.system", "Redis"),
            KeyValue::new("db.system.name", "postgresql"),
        ],
        vec![
            KeyValue::new("messaging.system", "Kafka"),
            KeyValue::new("messaging.operation", "old"),
            KeyValue::new("messaging.operation.type", "new"),
        ],
        vec![KeyValue::new("rpc.system", "grpc")],
        vec![
            KeyValue::new("faas.invoked_provider", "AWS"),
            KeyValue::new("faas.invoked_name", "S3"),
        ],
        vec![
            KeyValue::new("graphql.operation.type", "query"),
            KeyValue::new("graphql.operation.name", "GetUser"),
        ],
        vec![KeyValue::new("network.protocol.name", "AMQP")],
    ];
    for (index, _) in families.iter().enumerate() {
        let attrs: Vec<_> = families[index..].iter().flatten().cloned().collect();
        for kind in [
            SpanKind::Client,
            SpanKind::Server,
            SpanKind::Internal,
            SpanKind::Producer,
            SpanKind::Consumer,
        ] {
            emit(
                provider,
                &format!("family={index},kind={kind:?}"),
                kind,
                attrs.clone(),
            );
        }
    }
}

fn resource_name_attribute(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![KeyValue::new("resource.name", "custom-resource")],
    ));
}

/// A messaging span's resource is `<operation> <destination>`.
fn resource_name_messaging_destination(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Producer,
        vec![
            KeyValue::new("messaging.system", "kafka"),
            KeyValue::new("messaging.operation.type", "send"),
            KeyValue::new("messaging.destination.name", "orders-topic"),
        ],
    ));
}

/// An RPC span's resource is `<method> <service>`.
fn resource_name_rpc_method_service(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Client,
        vec![
            KeyValue::new("rpc.system", "grpc"),
            KeyValue::new("rpc.method", "GetUser"),
            KeyValue::new("rpc.service", "UserService"),
        ],
    ));
}

/// A database span's resource is the statement (or query text).
fn resource_name_db_statement(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Client,
        vec![
            KeyValue::new("db.system", "postgresql"),
            KeyValue::new("db.statement", "SELECT 1"),
        ],
    ));
}

fn resource_name_db_query_text(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Client,
        vec![
            KeyValue::new("db.system", "postgresql"),
            KeyValue::new("db.query.text", "SELECT 2"),
        ],
    ));
}

/// Without any resource-name attribute the resource falls back to the span name.
fn resource_name_fallback_span_name(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "fallback-resource",
        SpanKind::Internal,
        vec![],
    ));
}

fn resource_aliases(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let cases = resource_alias_inputs();
    for (label, mut attrs) in cases {
        attrs.push(KeyValue::new("case", label));
        let kind = if label == "wrong-faas-keys" {
            SpanKind::Client
        } else {
            SpanKind::Server
        };
        emit(provider, label, kind, attrs);
    }
}

fn resource_alias_inputs() -> Vec<(&'static str, Vec<KeyValue>)> {
    let mut cases = vec![
        (
            "graphql-operation",
            vec![
                KeyValue::new("graphql.operation.type", "query"),
                KeyValue::new("graphql.operation.name", "GetUser"),
            ],
        ),
        (
            "rpc-method-only",
            vec![KeyValue::new("rpc.method", "GetUser")],
        ),
        (
            "http-aliases",
            vec![
                KeyValue::new("http.request.method", "PATCH"),
                KeyValue::new("http.method", "DELETE"),
                KeyValue::new("http.route", "/new"),
            ],
        ),
        (
            "empty-new-http",
            vec![
                KeyValue::new("http.request.method", ""),
                KeyValue::new("http.method", "DELETE"),
            ],
        ),
        (
            "messaging-aliases",
            vec![
                KeyValue::new("messaging.operation.type", "send"),
                KeyValue::new("messaging.operation", "publish"),
                KeyValue::new("messaging.destination", "old-topic"),
                KeyValue::new("messaging.destination.name", "new-topic"),
            ],
        ),
        (
            "empty-new-messaging",
            vec![
                KeyValue::new("messaging.operation.type", ""),
                KeyValue::new("messaging.operation", "publish"),
            ],
        ),
        (
            "db-aliases",
            vec![
                KeyValue::new("db.system", "redis"),
                KeyValue::new("db.system.name", "postgresql"),
                KeyValue::new("db.statement", "old statement"),
                KeyValue::new("db.query.text", "new query"),
            ],
        ),
    ];
    cases.extend(empty_override_inputs());
    cases
}

fn empty_override_inputs() -> Vec<(&'static str, Vec<KeyValue>)> {
    vec![
        (
            "empty-statement",
            vec![
                KeyValue::new("db.system", "postgresql"),
                KeyValue::new("db.statement", ""),
                KeyValue::new("db.query.text", "new query"),
            ],
        ),
        (
            "wrong-faas-keys",
            vec![
                KeyValue::new("faas.invoked.provider", "aws"),
                KeyValue::new("faas.invoked.name", "S3"),
            ],
        ),
        (
            "empty-operation-override",
            vec![
                KeyValue::new("datadog.name", ""),
                KeyValue::new("operation.name", ""),
                KeyValue::new("http.method", "GET"),
            ],
        ),
        (
            "typed-dd-overrides",
            vec![
                KeyValue::new("datadog.name", 42),
                KeyValue::new("datadog.resource", true),
                KeyValue::new("datadog.service", 123),
                KeyValue::new("datadog.type", false),
            ],
        ),
    ]
}
