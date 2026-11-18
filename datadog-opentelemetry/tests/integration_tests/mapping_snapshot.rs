// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Exhaustive mapping snapshot tests for the OTel -> Datadog span conversion.
//!
//! Every case in the [`CASES`] table builds spans through the public OpenTelemetry API
//! (`SpanBuilder`, `Span::set_status`, `Span::add_event`, links, instrumentation scopes,
//! extracted contexts) and asserts the resulting Datadog spans against a test-agent
//! snapshot, one session per case.
//!
//! The point of the table is regression coverage of the whole pipeline (span processor
//! -> `otel_span_to_dd_span` -> trace chunk -> trace writer): each case exerts a
//! specific path of the mapping code (datadog.* field overrides, operation name and
//! resource name fallbacks, span type inference, env/version resolution, semconv key
//! mapping, numeric/string/array attributes, error statuses, span events, links,
//! chunk-level metadata and config metadata).
//!
//! The test agent normalizes the payloads it receives to the v0.4 snapshot format, so
//! the snapshots it generates for a v1.0-protocol tracer (this crate with the v1 trace
//! writer) are directly comparable with the ones generated for a v0.4 tracer. The
//! migration from the v0.4 to the v1 span model in `datadog-opentelemetry` can
//! therefore be verified by generating the snapshots on both versions and diffing
//! `tests/snapshots/opentelemetry_api/mapping/`.
//!
//! To (re-)generate the snapshots, delete them and run the test with a local docker
//! daemon (the agent writes missing snapshots when `SNAPSHOT_CI=0`, which
//! [`make_test_agent`] sets).

use std::{str::FromStr, time::Duration, time::SystemTime};

use datadog_opentelemetry::{
    configuration::{Config, ConfigBuilder},
    TracingComponents,
};
use opentelemetry::{
    propagation::TextMapPropagator,
    trace::{
        Link, Span as _, SpanBuilder, SpanContext, SpanKind, Status, TraceFlags, TraceState,
        TracerProvider,
    },
    InstrumentationScope, KeyValue, SpanId, TraceId, Value,
};
use opentelemetry_sdk::{trace::SdkTracerProvider, Resource};

use crate::integration_tests::{make_extractor, make_test_agent};

/// A single span case: one snapshot session, one mapping scenario.
struct MappingCase {
    /// Snapshot session name under `opentelemetry_api/mapping/`, `group__case`.
    name: &'static str,
    /// Tracer configuration for the case, `None` for the default configuration.
    configure: Option<fn(&mut ConfigBuilder)>,
    /// OTel resource of the case, `None` for the default resource.
    resource: Option<fn() -> Resource>,
    /// Emits the span(s) of the case through the OpenTelemetry API.
    run: fn(&SdkTracerProvider, &dyn TextMapPropagator),
}

/// A tracer provider (plus its propagator) shared by all cases that don't need their
/// own resource or configuration.
struct ProviderBundle {
    provider: SdkTracerProvider,
    propagator: Box<dyn TextMapPropagator>,
}

fn build_bundle(
    agent_uri: &str,
    configure: Option<fn(&mut ConfigBuilder)>,
    resource: Option<Resource>,
) -> ProviderBundle {
    let mut cfg = Config::builder();
    // Only `force_flush` delivers the queued traces: nothing is sent while the spans of
    // a case are being built, keeping each session to exactly its own case.
    cfg.set_trace_agent_url(agent_uri.to_string())
        .set_trace_writer_max_flush_interval(Duration::from_secs(1_000_000_000));
    if let Some(configure) = configure {
        configure(&mut cfg);
    }
    let builder = datadog_opentelemetry::tracing().with_config(cfg.build());
    let TracingComponents {
        tracer_provider,
        propagator,
        ..
    } = match resource {
        Some(resource) => builder.with_resource(resource).init_local(),
        None => builder.init_local(),
    };
    ProviderBundle {
        provider: tracer_provider,
        propagator: Box::new(propagator),
    }
}

/// Starts a span with the given name, kind and attributes, through the OpenTelemetry
/// API. The span ends when dropped.
fn start_span(
    provider: &SdkTracerProvider,
    name: &'static str,
    kind: SpanKind,
    attributes: Vec<KeyValue>,
) -> opentelemetry_sdk::trace::Span {
    SpanBuilder::from_name(name)
        .with_kind(kind)
        .with_attributes(attributes)
        .start(&provider.tracer("mapping"))
}

/// A case resource with the given attributes.
fn resource(attributes: Vec<KeyValue>) -> Resource {
    Resource::builder_empty()
        .with_attributes(attributes)
        .build()
}

// ---------------------------------------------------------------------------
// datadog.* span attributes -> dedicated Datadog span fields
// ---------------------------------------------------------------------------

/// `datadog.{service,name,resource,type,version,env}` override the dedicated fields;
/// the service override keeps a `_dd.base_service` reference to the application
/// service.
fn dd_fields_all_overrides(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "dd-field-overrides",
        SpanKind::Server,
        vec![
            KeyValue::new("datadog.service", "span-service"),
            KeyValue::new("datadog.name", "span-operation"),
            KeyValue::new("datadog.resource", "span-resource"),
            KeyValue::new("datadog.type", "queue"),
            KeyValue::new("datadog.version", "3.2.1"),
            KeyValue::new("datadog.env", "span-env"),
        ],
    ));
}

/// `datadog.error=1` marks the span as an error.
fn dd_fields_error_flag_set(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "error-flag",
        SpanKind::Internal,
        vec![KeyValue::new("datadog.error", 1)],
    ));
}

/// `datadog.error=0` leaves the span a non-error.
fn dd_fields_error_flag_zero(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "error-flag-zero",
        SpanKind::Internal,
        vec![KeyValue::new("datadog.error", 0)],
    ));
}

/// `datadog.span.kind` overrides the API span kind with libdatadog's exact-case values.
fn dd_fields_span_kind_attribute(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "span-kind-attribute",
        SpanKind::Internal,
        vec![KeyValue::new("datadog.span.kind", "producer")],
    ));
}

/// `datadog.span.kind` only recognizes the lowercase v0.4 values: a wrong case falls
/// back to `Internal`.
fn dd_fields_span_kind_attribute_case_sensitive(
    provider: &SdkTracerProvider,
    _: &dyn TextMapPropagator,
) {
    drop(start_span(
        provider,
        "span-kind-attribute-case",
        SpanKind::Internal,
        vec![KeyValue::new("datadog.span.kind", "Server")],
    ));
}

/// `datadog.error.{msg,type,stack}` map to the `error.{message,type,stack}` tags.
/// They don't set the error flag on their own.
fn dd_fields_error_semconv(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "error-semconv-fields",
        SpanKind::Internal,
        vec![
            KeyValue::new("datadog.error.msg", "semconv boom"),
            KeyValue::new("datadog.error.type", "ValueError"),
            KeyValue::new(
                "datadog.error.stack",
                "ValueError: semconv boom\n  at mapping",
            ),
        ],
    ));
}

/// `datadog.http_status_code` sets the `http.status_code` tag; on a server span a 503
/// is also an error per the default HTTP server error statuses.
fn dd_fields_http_status_code(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "http-status-semconv",
        SpanKind::Server,
        vec![KeyValue::new("datadog.http_status_code", 503)],
    ));
}

// ---------------------------------------------------------------------------
// Operation name fallbacks (get_otel_operation_name_v2)
// ---------------------------------------------------------------------------

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

/// `db.system.name` is lowercased for the operation name and the span type; Cassandra
/// has a dedicated span type.
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
            KeyValue::new("faas.invoked.provider", "aws"),
            KeyValue::new("faas.invoked.name", "S3"),
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

// ---------------------------------------------------------------------------
// Resource name fallbacks (get_otel_resource_v2)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Span type inference (get_otel_span_type)
// ---------------------------------------------------------------------------

/// The `span.type` attribute overrides the inferred span type.
fn span_type_attribute(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![KeyValue::new("span.type", "queue")],
    ));
}

/// `span.type` is read from the resource attributes as well.
fn span_type_resource_attribute(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![],
    ));
}

fn span_type_resource_attribute_resource() -> Resource {
    resource(vec![KeyValue::new("span.type", "custom-resource-type")])
}

// ---------------------------------------------------------------------------
// env / version resolution
// ---------------------------------------------------------------------------

/// `datadog.env` on the span sets the env.
fn env_version_dd_env_attribute(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![KeyValue::new("datadog.env", "span-env")],
    ));
}

fn env_version_deployment_environment_resource(
    provider: &SdkTracerProvider,
    _: &dyn TextMapPropagator,
) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![],
    ));
}

fn env_version_deployment_environment_resource_res() -> Resource {
    resource(vec![KeyValue::new("deployment.environment", "prod")])
}

fn env_version_deployment_environment_name_resource(
    provider: &SdkTracerProvider,
    _: &dyn TextMapPropagator,
) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![],
    ));
}

fn env_version_deployment_environment_name_resource_res() -> Resource {
    resource(vec![KeyValue::new(
        "deployment.environment.name",
        "staging",
    )])
}

/// `datadog.env` on the span wins over the resource's `deployment.environment.name`.
fn env_version_dd_env_beats_resource(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![KeyValue::new("datadog.env", "span-env")],
    ));
}

fn env_version_dd_env_beats_resource_res() -> Resource {
    resource(vec![KeyValue::new(
        "deployment.environment.name",
        "resource-env",
    )])
}

/// `service.version` on the resource sets the span version.
fn env_version_service_version_resource(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![],
    ));
}

fn env_version_service_version_resource_res() -> Resource {
    resource(vec![KeyValue::new("service.version", "1.2.3")])
}

/// The configured version is applied as the `version` tag when the span service is
/// the resource's `service.name`.
fn env_version_config_version(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![],
    ));
}

fn env_version_config_version_res() -> Resource {
    resource(vec![KeyValue::new("service.name", "svc-r")])
}

fn env_version_config_version_config(cfg: &mut ConfigBuilder) {
    cfg.set_version("5.5.5".to_string());
}

// ---------------------------------------------------------------------------
// Span attribute -> Datadog attribute mapping
// ---------------------------------------------------------------------------

/// String and boolean span attributes map to string tags.
fn attributes_string_and_bool_meta(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![
            KeyValue::new("custom.string", "a string"),
            KeyValue::new("custom.bool_true", true),
            KeyValue::new("custom.bool_false", false),
        ],
    ));
}

/// Integer and float span attributes map to numeric tags.
fn attributes_numeric_metrics(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![
            KeyValue::new("custom.int", 42),
            KeyValue::new("custom.float", 1.5),
            KeyValue::new("custom.negative", -3),
        ],
    ));
}

/// Array attributes are flattened to `key.0`, `key.1`, ...: numbers become numeric
/// tags, strings and booleans become string tags.
fn attributes_arrays_all_types(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![
            KeyValue::new(
                "arr.strings",
                Value::Array(vec![opentelemetry::StringValue::from("a"), "b".into()].into()),
            ),
            KeyValue::new("arr.ints", Value::Array(vec![1_i64, 2].into())),
            KeyValue::new("arr.floats", Value::Array(vec![1.5, 2.5].into())),
            KeyValue::new("arr.bools", Value::Array(vec![true, false].into())),
        ],
    ));
}

/// OTel semconv HTTP attribute keys are mapped to their Datadog equivalents
/// (http.client_ip, http.url, http.useragent, http.version, ...), including the
/// `http.request.header.*` prefix rewrite.
fn attributes_http_semconv_mappings(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Server,
        vec![
            KeyValue::new("http.request.method", "GET"),
            KeyValue::new("client.address", "10.0.0.1"),
            KeyValue::new("http.response.body_size", 1024),
            KeyValue::new("url.full", "https://example.com/path"),
            KeyValue::new("user_agent.original", "test-agent/1.0"),
            KeyValue::new("server.address", "example.com"),
            KeyValue::new("network.protocol.version", "1.1"),
            KeyValue::new("http.request.header.x_custom", "header-value"),
        ],
    ));
}

/// Unknown `datadog.*` attributes are skipped entirely.
fn attributes_datadog_prefix_skipped(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![
            KeyValue::new("datadog.custom", "value"),
            KeyValue::new("datadog.other", 1),
        ],
    ));
}

/// The Datadog convention attributes `service.name`, `operation.name`,
/// `resource.name` and `span.type` override the dedicated span fields.
fn attributes_dd_convention_fields(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![
            KeyValue::new("service.name", "conv-service"),
            KeyValue::new("operation.name", "conv-operation"),
            KeyValue::new("resource.name", "conv-resource"),
            KeyValue::new("span.type", "conv-type"),
        ],
    ));
}

/// Plain `env`, `version`, `component` and `span.kind` attributes are promoted to the
/// dedicated span fields.
fn attributes_promoted_meta_keys(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![
            KeyValue::new("env", "attr-env"),
            KeyValue::new("version", "9.9.9"),
            KeyValue::new("component", "my-component"),
            KeyValue::new("span.kind", "server"),
        ],
    ));
}

/// A numeric `http.response.status_code` must not override the string
/// `http.status_code` tag synthesized from it: v1 spans have a single attribute
/// namespace, unlike v0.4's separate `meta` and `metrics`.
fn attributes_http_status_code_meta_protection(
    provider: &SdkTracerProvider,
    _: &dyn TextMapPropagator,
) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Server,
        vec![KeyValue::new("http.response.status_code", 500)],
    ));
}

/// A zero `http.response.status_code` synthesizes no string tag, so the numeric
/// attribute survives as a metric under the mapped `http.status_code` key.
fn attributes_http_status_code_zero_metric(
    provider: &SdkTracerProvider,
    _: &dyn TextMapPropagator,
) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Server,
        vec![KeyValue::new("http.response.status_code", 0)],
    ));
}

/// `sampling.priority` is remapped to `_sampling_priority_v1`.
fn attributes_sampling_priority_metric(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![KeyValue::new("sampling.priority", 0)],
    ));
}

/// `analytics.event=true` sets the analytics sample rate to 1.
fn attributes_analytics_event_true(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![KeyValue::new("analytics.event", "true")],
    ));
}

/// `analytics.event` is parsed case-insensitively.
fn attributes_analytics_event_false(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![KeyValue::new("analytics.event", "FALSE")],
    ));
}

/// An unparseable `analytics.event` value is ignored: no tag at all.
fn attributes_analytics_event_invalid(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![KeyValue::new("analytics.event", "maybe")],
    ));
}

/// A string `_dd.measured` attribute must not shadow the numeric `_dd.measured` flag
/// synthesized for client spans: libdatadog reads the flag as numeric-only.
fn attributes_measured_string_protection(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Client,
        vec![KeyValue::new("_dd.measured", "1")],
    ));
}

/// `_dd.measured=1` sets the measured flag on spans that don't get it from their kind.
fn attributes_dd_measured_explicit(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Server,
        vec![KeyValue::new("_dd.measured", 1)],
    ));
}

/// A `service.name` span attribute overrides the service; the application service
/// is kept in `_dd.base_service`.
fn attributes_service_name_span_attribute(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![KeyValue::new("service.name", "span-svc")],
    ));
}

// ---------------------------------------------------------------------------
// Span status -> error mapping
// ---------------------------------------------------------------------------

fn status_ok(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let mut span = start_span(provider, "ok-span", SpanKind::Server, vec![]);
    span.set_status(Status::Ok);
    drop(span);
}

/// An error status with a description becomes `error.message` and
/// `otel.status_description`.
fn status_error_description(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let mut span = start_span(provider, "error-span", SpanKind::Client, vec![]);
    span.set_status(Status::error("disk full"));
    drop(span);
}

/// An error status without a description and without exception events falls back to
/// the HTTP status code for `error.message`.
fn status_error_http_code_no_text(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let mut span = start_span(
        provider,
        "error-span",
        SpanKind::Client,
        vec![KeyValue::new("http.response.status_code", 404)],
    );
    span.set_status(Status::error(""));
    drop(span);
}

/// `http.status_text` is appended to the status code in `error.message`.
fn status_error_http_code_with_text(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let mut span = start_span(
        provider,
        "error-span",
        SpanKind::Client,
        vec![
            KeyValue::new("http.response.status_code", 404),
            KeyValue::new("http.status_text", "Not Found"),
        ],
    );
    span.set_status(Status::error(""));
    drop(span);
}

/// An error status with no description, no exception event and no HTTP status code
/// marks the span as an error without an `error.message` tag.
fn status_error_no_message(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let mut span = start_span(provider, "error-span", SpanKind::Producer, vec![]);
    span.set_status(Status::error(""));
    drop(span);
}

/// A server span with a 4xx status code is not an error per the default HTTP server
/// error statuses: the error set by the OTel status is cleared, together with the
/// error tags it produced.
fn status_http_server_error_cleared_tags(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let mut span = start_span(
        provider,
        "error-span",
        SpanKind::Server,
        vec![KeyValue::new("http.response.status_code", 404)],
    );
    span.set_status(Status::error("gone"));
    drop(span);
}

/// A server span with a 5xx status code keeps the error and its tags.
fn status_http_server_error_kept(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let mut span = start_span(
        provider,
        "error-span",
        SpanKind::Server,
        vec![KeyValue::new("http.response.status_code", 500)],
    );
    span.set_status(Status::error("boom"));
    drop(span);
}

/// A client span with a 4xx status code is an error per the default HTTP client
/// error statuses, even with an unset OTel status.
fn status_http_client_error_status(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "client-error-span",
        SpanKind::Client,
        vec![KeyValue::new("http.response.status_code", 404)],
    ));
}

// ---------------------------------------------------------------------------
// Span events
// ---------------------------------------------------------------------------

/// An `exception` event on an errored span provides the error tags and sets
/// `_dd.span_events.has_exception`.
fn events_exception_with_error_status(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let mut span = start_span(provider, "exception-span", SpanKind::Client, vec![]);
    span.add_event(
        "exception",
        vec![
            KeyValue::new("exception.message", "event boom"),
            KeyValue::new("exception.type", "TypeError"),
            KeyValue::new(
                "exception.stacktrace",
                "TypeError: event boom\n  at mapping",
            ),
        ],
    );
    span.set_status(Status::error(""));
    drop(span);
}

/// The `exception` event name is matched case-insensitively, and without an error
/// status the error tags are not set.
fn events_exception_without_error_status(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let mut span = start_span(provider, "exception-span", SpanKind::Internal, vec![]);
    span.add_event(
        "Exception",
        vec![
            KeyValue::new("exception.message", "event boom"),
            KeyValue::new("exception.type", "TypeError"),
            KeyValue::new(
                "exception.stacktrace",
                "TypeError: event boom\n  at mapping",
            ),
        ],
    );
    drop(span);
}

/// Span events keep their typed attribute values (numbers stay numbers), unlike span
/// and link attributes which are flattened or stringified.
///
/// Note: array-valued event attributes are mapped by the tracer (they would stay
/// arrays in the v1 payload), but the test agent's v1 -> v0.4 downgrade rejects them
/// (`Array of strings values are not supported yet`), so they can't be pinned down
/// in a snapshot yet.
fn events_typed_attributes(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let mut span = start_span(provider, "events-span", SpanKind::Internal, vec![]);
    span.add_event_with_timestamp(
        "custom.event",
        SystemTime::now(),
        vec![
            KeyValue::new("event.string", "value"),
            KeyValue::new("event.int", 7),
            KeyValue::new("event.float", 0.25),
            KeyValue::new("event.bool", true),
        ],
    );
    span.add_event("bare.event", vec![]);
    drop(span);
}

// ---------------------------------------------------------------------------
// Span links
// ---------------------------------------------------------------------------

/// Links keep stringified, flattened attributes, their tracestate and W3C trace
/// flags; the 128-bit trace id is preserved.
fn links_variants(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let sampled_context = |trace_state: TraceState| {
        SpanContext::new(
            TraceId::from_hex("fedcba98765432100123456789abcdef").unwrap(),
            SpanId::from_hex("abcdef0123456789").unwrap(),
            TraceFlags::SAMPLED,
            false,
            trace_state,
        )
    };
    let links = vec![
        Link::new(
            sampled_context(TraceState::from_str("dd=s:2,ee=jkl;128").unwrap()),
            vec![KeyValue::new("link.attr", "value")],
            0,
        ),
        Link::new(
            sampled_context(TraceState::default()),
            vec![
                KeyValue::new(
                    "strings",
                    Value::Array(vec![opentelemetry::StringValue::from("a"), "b".into()].into()),
                ),
                KeyValue::new("bools", Value::Array(vec![true, false].into())),
                KeyValue::new("ints", Value::Array(vec![1_i64, 2].into())),
                KeyValue::new("floats", Value::Array(vec![1.5].into())),
            ],
            0,
        ),
        Link::new(
            SpanContext::new(
                TraceId::from_hex("abcdef0123456789abcdef0123456789").unwrap(),
                SpanId::from_hex("fedcba9876543210").unwrap(),
                TraceFlags::default(),
                false,
                TraceState::default(),
            ),
            vec![],
            0,
        ),
    ];
    drop(
        SpanBuilder::from_name("span-with-links")
            .with_kind(SpanKind::Internal)
            .with_links(links)
            .start(&provider.tracer("mapping")),
    );
}

// ---------------------------------------------------------------------------
// Trace context and instrumentation scope
// ---------------------------------------------------------------------------

/// A span continuing an extracted W3C context inherits its tracestate, exposed as
/// the `w3c.tracestate` tag.
fn context_w3c_tracestate_inherited(
    provider: &SdkTracerProvider,
    propagator: &dyn TextMapPropagator,
) {
    let parent = propagator.extract(&make_extractor([
        (
            "traceparent",
            "00-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-01",
        ),
        (
            "tracestate",
            "dd=p:00f067aa0ba902b7;s:2;o:rum;t.dm:-4;t.usr.id:baz64",
        ),
    ]));
    let _guard = parent.attach();
    drop(
        SpanBuilder::from_name("tracestate-child")
            .with_kind(SpanKind::Server)
            .start(&provider.tracer("mapping")),
    );
}

/// The instrumentation scope name and version become `otel.scope.name` and
/// `otel.scope.version`, and the scope attributes are mapped as span tags.
fn context_scope_name_version_attributes(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let scope = InstrumentationScope::builder("my-lib")
        .with_version("4.5.6")
        .with_attributes(vec![
            KeyValue::new("scope.attr", "scope-value"),
            KeyValue::new("scope.team", "platform"),
        ])
        .build();
    drop(
        SpanBuilder::from_name("scoped-span")
            .with_kind(SpanKind::Internal)
            .start(&provider.tracer_with_scope(scope)),
    );
}

// ---------------------------------------------------------------------------
// Chunk-level fields
// ---------------------------------------------------------------------------

/// `_dd.origin` and `_dd.p.dm` on the local root are lifted to chunk-level fields;
/// the `_dd.p.tid` high bits of the trace id are consumed into the chunk trace id and
/// removed from the span tags.
fn chunk_origin_and_tid(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![
            KeyValue::new("_dd.origin", "synthetics"),
            KeyValue::new("_dd.p.tid", "00000000000000ff"),
        ],
    ));
}

// ---------------------------------------------------------------------------
// Tracer configuration metadata
// ---------------------------------------------------------------------------

/// Global tags from the configuration are applied to every span.
fn config_global_tags(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![],
    ));
}

fn config_global_tags_config(cfg: &mut ConfigBuilder) {
    cfg.set_global_tags(vec![
        ("team".to_string(), "apm".to_string()),
        ("custom.gtag".to_string(), "gv".to_string()),
    ]);
}

/// The configured env is applied to the resource, which resolves the span env.
fn config_env(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![],
    ));
}

fn config_env_config(cfg: &mut ConfigBuilder) {
    cfg.set_env("config-env".to_string());
}

// ---------------------------------------------------------------------------
// Resource attribute mapping
// ---------------------------------------------------------------------------

/// Resource attributes go through the same semconv key mapping as span attributes
/// (`url.full` -> `http.url`, ...); unknown keys are kept as-is.
fn resource_attribute_mapping(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![],
    ));
}

fn resource_attribute_mapping_res() -> Resource {
    resource(vec![
        KeyValue::new("url.full", "https://datadoghq.com"),
        KeyValue::new("custom.resource_attr", "resource-value"),
        KeyValue::new("http.request.header.x_res", "res-header"),
    ])
}

/// The resource `service.name` resolves the span service; a matching configured
/// version is applied.
fn resource_service_name_resolution(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![],
    ));
}

fn resource_service_name_resolution_res() -> Resource {
    resource(vec![KeyValue::new("service.name", "otel-svc")])
}

// ---------------------------------------------------------------------------
// The case table
// ---------------------------------------------------------------------------

const CASES: &[MappingCase] = &[
    // datadog.* span attributes -> dedicated Datadog span fields
    MappingCase {
        name: "dd_fields__all_overrides",
        configure: None,
        resource: None,
        run: dd_fields_all_overrides,
    },
    MappingCase {
        name: "dd_fields__error_flag_set",
        configure: None,
        resource: None,
        run: dd_fields_error_flag_set,
    },
    MappingCase {
        name: "dd_fields__error_flag_zero",
        configure: None,
        resource: None,
        run: dd_fields_error_flag_zero,
    },
    MappingCase {
        name: "dd_fields__span_kind_attribute",
        configure: None,
        resource: None,
        run: dd_fields_span_kind_attribute,
    },
    MappingCase {
        name: "dd_fields__span_kind_attribute_case_sensitive",
        configure: None,
        resource: None,
        run: dd_fields_span_kind_attribute_case_sensitive,
    },
    MappingCase {
        name: "dd_fields__error_semconv_fields",
        configure: None,
        resource: None,
        run: dd_fields_error_semconv,
    },
    MappingCase {
        name: "dd_fields__http_status_code",
        configure: None,
        resource: None,
        run: dd_fields_http_status_code,
    },
    // Operation name fallbacks
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
    // Resource name fallbacks
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
    // Span type inference
    MappingCase {
        name: "span_type__span_attribute",
        configure: None,
        resource: None,
        run: span_type_attribute,
    },
    MappingCase {
        name: "span_type__resource_attribute",
        configure: None,
        resource: Some(span_type_resource_attribute_resource),
        run: span_type_resource_attribute,
    },
    // env / version resolution
    MappingCase {
        name: "env_version__dd_env_attribute",
        configure: None,
        resource: None,
        run: env_version_dd_env_attribute,
    },
    MappingCase {
        name: "env_version__deployment_environment_resource",
        configure: None,
        resource: Some(env_version_deployment_environment_resource_res),
        run: env_version_deployment_environment_resource,
    },
    MappingCase {
        name: "env_version__deployment_environment_name_resource",
        configure: None,
        resource: Some(env_version_deployment_environment_name_resource_res),
        run: env_version_deployment_environment_name_resource,
    },
    MappingCase {
        name: "env_version__dd_env_beats_resource",
        configure: None,
        resource: Some(env_version_dd_env_beats_resource_res),
        run: env_version_dd_env_beats_resource,
    },
    MappingCase {
        name: "env_version__service_version_resource",
        configure: None,
        resource: Some(env_version_service_version_resource_res),
        run: env_version_service_version_resource,
    },
    MappingCase {
        name: "env_version__config_version",
        configure: Some(env_version_config_version_config),
        resource: Some(env_version_config_version_res),
        run: env_version_config_version,
    },
    // Span attribute -> Datadog attribute mapping
    MappingCase {
        name: "attributes__string_and_bool_meta",
        configure: None,
        resource: None,
        run: attributes_string_and_bool_meta,
    },
    MappingCase {
        name: "attributes__numeric_metrics",
        configure: None,
        resource: None,
        run: attributes_numeric_metrics,
    },
    MappingCase {
        name: "attributes__arrays_all_types",
        configure: None,
        resource: None,
        run: attributes_arrays_all_types,
    },
    MappingCase {
        name: "attributes__http_semconv_mappings",
        configure: None,
        resource: None,
        run: attributes_http_semconv_mappings,
    },
    MappingCase {
        name: "attributes__datadog_prefix_skipped",
        configure: None,
        resource: None,
        run: attributes_datadog_prefix_skipped,
    },
    MappingCase {
        name: "attributes__dd_convention_fields",
        configure: None,
        resource: None,
        run: attributes_dd_convention_fields,
    },
    MappingCase {
        name: "attributes__promoted_meta_keys",
        configure: None,
        resource: None,
        run: attributes_promoted_meta_keys,
    },
    MappingCase {
        name: "attributes__http_status_code_meta_protection",
        configure: None,
        resource: None,
        run: attributes_http_status_code_meta_protection,
    },
    MappingCase {
        name: "attributes__http_status_code_zero_metric",
        configure: None,
        resource: None,
        run: attributes_http_status_code_zero_metric,
    },
    MappingCase {
        name: "attributes__sampling_priority_metric",
        configure: None,
        resource: None,
        run: attributes_sampling_priority_metric,
    },
    MappingCase {
        name: "attributes__analytics_event_true",
        configure: None,
        resource: None,
        run: attributes_analytics_event_true,
    },
    MappingCase {
        name: "attributes__analytics_event_false",
        configure: None,
        resource: None,
        run: attributes_analytics_event_false,
    },
    MappingCase {
        name: "attributes__analytics_event_invalid",
        configure: None,
        resource: None,
        run: attributes_analytics_event_invalid,
    },
    MappingCase {
        name: "attributes__measured_string_protection",
        configure: None,
        resource: None,
        run: attributes_measured_string_protection,
    },
    MappingCase {
        name: "attributes__dd_measured_explicit",
        configure: None,
        resource: None,
        run: attributes_dd_measured_explicit,
    },
    MappingCase {
        name: "attributes__service_name_span_attribute",
        configure: None,
        resource: None,
        run: attributes_service_name_span_attribute,
    },
    // Span status -> error mapping
    MappingCase {
        name: "status__ok",
        configure: None,
        resource: None,
        run: status_ok,
    },
    MappingCase {
        name: "status__error_description",
        configure: None,
        resource: None,
        run: status_error_description,
    },
    MappingCase {
        name: "status__error_http_code_no_text",
        configure: None,
        resource: None,
        run: status_error_http_code_no_text,
    },
    MappingCase {
        name: "status__error_http_code_with_text",
        configure: None,
        resource: None,
        run: status_error_http_code_with_text,
    },
    MappingCase {
        name: "status__error_no_message",
        configure: None,
        resource: None,
        run: status_error_no_message,
    },
    MappingCase {
        name: "status__http_server_error_cleared_tags",
        configure: None,
        resource: None,
        run: status_http_server_error_cleared_tags,
    },
    MappingCase {
        name: "status__http_server_error_kept",
        configure: None,
        resource: None,
        run: status_http_server_error_kept,
    },
    MappingCase {
        name: "status__http_client_error_status",
        configure: None,
        resource: None,
        run: status_http_client_error_status,
    },
    // Span events
    MappingCase {
        name: "events__exception_with_error_status",
        configure: None,
        resource: None,
        run: events_exception_with_error_status,
    },
    MappingCase {
        name: "events__exception_without_error_status",
        configure: None,
        resource: None,
        run: events_exception_without_error_status,
    },
    MappingCase {
        name: "events__typed_attributes",
        configure: None,
        resource: None,
        run: events_typed_attributes,
    },
    // Span links
    MappingCase {
        name: "links__variants",
        configure: None,
        resource: None,
        run: links_variants,
    },
    // Trace context and instrumentation scope
    MappingCase {
        name: "context__w3c_tracestate_inherited",
        configure: None,
        resource: None,
        run: context_w3c_tracestate_inherited,
    },
    MappingCase {
        name: "context__scope_name_version_attributes",
        configure: None,
        resource: None,
        run: context_scope_name_version_attributes,
    },
    // Chunk-level fields
    MappingCase {
        name: "chunk__origin_and_tid",
        configure: None,
        resource: None,
        run: chunk_origin_and_tid,
    },
    // Tracer configuration metadata
    MappingCase {
        name: "config__global_tags",
        configure: Some(config_global_tags_config),
        resource: None,
        run: config_global_tags,
    },
    MappingCase {
        name: "config__env",
        configure: Some(config_env_config),
        resource: None,
        run: config_env,
    },
    // Resource attribute mapping
    MappingCase {
        name: "resource__attribute_mapping",
        configure: None,
        resource: Some(resource_attribute_mapping_res),
        run: resource_attribute_mapping,
    },
    MappingCase {
        name: "resource__service_name_resolution",
        configure: None,
        resource: Some(resource_service_name_resolution_res),
        run: resource_service_name_resolution,
    },
];

/// Exhaustively exerts the OTel -> Datadog mapping through the OpenTelemetry API,
/// asserting a test-agent snapshot per case.
///
/// Cases without a custom resource or configuration share a single tracer provider;
/// the others get their own so that resource attributes and tracer configuration can
/// vary per case.
#[tokio::test]
async fn test_otel_to_datadog_mapping_paths() {
    let test_agent = make_test_agent("opentelemetry_api/mapping").await;
    let agent_uri = test_agent.get_base_uri().await.to_string();

    let mut default_bundle: Option<ProviderBundle> = None;

    for case in CASES {
        let token = format!("opentelemetry_api/mapping/{}", case.name);
        // Starting the session clears anything the previous case left behind.
        test_agent.start_session(&token, None).await;

        let resource = case.resource.map(|make| make());
        let needs_own_provider = resource.is_some() || case.configure.is_some();
        let owned = needs_own_provider.then(|| build_bundle(&agent_uri, case.configure, resource));
        if default_bundle.is_none() {
            default_bundle = Some(build_bundle(&agent_uri, None, None));
        }
        let bundle = owned
            .as_ref()
            .unwrap_or_else(|| default_bundle.as_ref().unwrap());

        (case.run)(&bundle.provider, bundle.propagator.as_ref());
        bundle
            .provider
            .force_flush()
            .expect("failed to force flush the tracer provider");
        test_agent.assert_snapshot(&token).await;

        if let Some(bundle) = owned {
            bundle.provider.shutdown().expect("failed to shutdown");
        }
    }

    default_bundle
        .unwrap()
        .provider
        .shutdown()
        .expect("failed to shutdown the default tracer provider");
}
