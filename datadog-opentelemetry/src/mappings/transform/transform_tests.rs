// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]

use std::{
    collections::HashMap,
    str::FromStr,
    time::{Duration, SystemTime},
    vec,
};

use libdd_trace_utils::span::v04::{AttributeAnyValue as Any, AttributeArrayValue as Scalar};
use libdd_trace_utils::span::vec_map::VecMap;
use libdd_trace_utils::span::SpanText as _;

use crate::{
    core::constants::SAMPLING_RATE_EVENT_EXTRACTION_KEY, mappings::transform::SPAN_LINK_FLAGS_SET,
};
use opentelemetry::{
    trace::{Event, Link, SpanContext, SpanKind, Status, TraceState},
    InstrumentationScope, KeyValue, SpanId, TraceFlags, TraceId,
};

use super::{
    super::sdk_span::SdkSpan,
    super::transform::{CowStr, DdSpanEvent, DdSpanLink},
    DdSpan,
};

fn timestamp_nano(nanos: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_nanos(nanos)
}

impl From<&'static str> for CowStr<'static> {
    fn from(s: &'static str) -> Self {
        CowStr::from_static_str(s)
    }
}

fn make_test_span_events() -> (Vec<Event>, Vec<DdSpanEvent<'static>>) {
    (
        vec![
            Event::new(
                "boom",
                timestamp_nano(100),
                vec![
                    KeyValue::new("key", "Out of memory"),
                    KeyValue::new("accuracy", 2.4),
                ],
                2,
            ),
            Event::new(
                "exception",
                timestamp_nano(400),
                vec![
                    KeyValue::new("exception.message", "Out of memory"),
                    KeyValue::new("exception.type", "mem"),
                    KeyValue::new("exception.stacktrace", "1/2/3"),
                ],
                2,
            ),
        ],
        vec![
            DdSpanEvent {
                time_unix_nano: 100,
                name: "boom".into(),
                attributes: HashMap::from_iter([
                    (
                        "key".into(),
                        Any::SingleValue(Scalar::String("Out of memory".into())),
                    ),
                    ("accuracy".into(), Any::SingleValue(Scalar::Double(2.4))),
                ]),
            },
            DdSpanEvent {
                time_unix_nano: 400,
                name: "exception".into(),
                attributes: HashMap::from_iter([
                    (
                        "exception.type".into(),
                        Any::SingleValue(Scalar::String("mem".into())),
                    ),
                    (
                        "exception.stacktrace".into(),
                        Any::SingleValue(Scalar::String("1/2/3".into())),
                    ),
                    (
                        "exception.message".into(),
                        Any::SingleValue(Scalar::String("Out of memory".into())),
                    ),
                ]),
            },
        ],
    )
}

fn make_test_span_links() -> (Vec<Link>, Vec<DdSpanLink<'static>>) {
    (
        vec![
            Link::new(
                SpanContext::new(
                    TraceId::from_hex("fedcba98765432100123456789abcdef").unwrap(),
                    SpanId::from_hex("abcdef0123456789").unwrap(),
                    TraceFlags::default(),
                    false,
                    TraceState::from_str("dd=asdf256,ee=jkl;128").unwrap(),
                ),
                vec![KeyValue::new("a1", "v1"), KeyValue::new("a2", "v2")],
                24,
            ),
            Link::new(
                SpanContext::new(
                    TraceId::from_hex("abcdef0123456789abcdef0123456789").unwrap(),
                    SpanId::from_hex("fedcba9876543210").unwrap(),
                    TraceFlags::default(),
                    false,
                    TraceState::default(),
                ),
                vec![
                    KeyValue::new(
                        "array",
                        opentelemetry::Value::Array(
                            vec![opentelemetry::StringValue::from("a"), "b".into()].into(),
                        ),
                    ),
                    KeyValue::new(
                        "bools",
                        opentelemetry::Value::Array(vec![true, false].into()),
                    ),
                    KeyValue::new("nested", opentelemetry::Value::Array(vec![1_i64, 2].into())),
                    KeyValue::new("floats", opentelemetry::Value::Array(vec![1.5].into())),
                ],
                2,
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
        ],
        vec![
            DdSpanLink {
                trace_id: 81985529216486895,
                trace_id_high: 18364758544493064720,
                span_id: 12379813738877118345,
                attributes: HashMap::from_iter([
                    ("a1".into(), "v1".into()),
                    ("a2".into(), "v2".into()),
                ]),
                tracestate: "dd=asdf256,ee=jkl;128".into(),
                flags: SPAN_LINK_FLAGS_SET,
            },
            DdSpanLink {
                trace_id: 12379813738877118345,
                trace_id_high: 12379813738877118345,
                span_id: 18364758544493064720,
                attributes: HashMap::from_iter([
                    ("array.0".into(), "a".into()),
                    ("array.1".into(), "b".into()),
                    ("bools.0".into(), "true".into()),
                    ("bools.1".into(), "false".into()),
                    ("nested.0".into(), "1".into()),
                    ("nested.1".into(), "2".into()),
                    ("floats.0".into(), "1.5".into()),
                ]),
                tracestate: "".into(),
                flags: SPAN_LINK_FLAGS_SET,
            },
            DdSpanLink {
                trace_id: 12379813738877118345,
                trace_id_high: 12379813738877118345,
                span_id: 18364758544493064720,
                attributes: HashMap::new(),
                tracestate: "".into(),
                flags: SPAN_LINK_FLAGS_SET,
            },
        ],
    )
}

pub struct TestSpan {
    span_context: opentelemetry::trace::SpanContext,
    parent_span_id: opentelemetry::trace::SpanId,
    span_kind: opentelemetry::trace::SpanKind,
    name: String,
    start_time: SystemTime,
    end_time: SystemTime,
    attributes: Vec<opentelemetry::KeyValue>,
    #[allow(dead_code)]
    dropped_attributes_count: u32,
    events: Vec<opentelemetry::trace::Event>,
    #[allow(dead_code)]
    dropped_event_count: u32,
    links: Vec<opentelemetry::trace::Link>,
    #[allow(dead_code)]
    dropped_links_count: u32,
    status: opentelemetry::trace::Status,
    instrumentation_scope: opentelemetry::InstrumentationScope,
}

pub fn test_span_to_sdk_span(test_span: &TestSpan) -> SdkSpan<'_> {
    SdkSpan {
        span_context: &test_span.span_context,
        parent_span_id: test_span.parent_span_id,
        span_kind: test_span.span_kind.clone(),
        name: &test_span.name,
        start_time: test_span.start_time,
        end_time: test_span.end_time,
        attributes: &test_span.attributes,
        dropped_attributes_count: test_span.dropped_attributes_count,
        events: &test_span.events,
        dropped_event_count: test_span.dropped_event_count,
        links: &test_span.links,
        dropped_links_count: test_span.dropped_links_count,
        status: &test_span.status,
        instrumentation_scope: &test_span.instrumentation_scope,
    }
}

pub struct Test<'a> {
    pub name: &'static str,
    pub input_resource: Vec<(&'static str, &'static str)>,
    pub input_span: TestSpan,
    pub expected_out: DdSpan<'a>,
}

pub fn test_cases() -> Vec<Test<'static>> {
    const TEST_TRACE_ID: opentelemetry::TraceId = TraceId::from_bytes([
        0x72, 0xdf, 0x52, 0xa, 0xf2, 0xbd, 0xe7, 0xa5, 0x24, 0x0, 0x31, 0xea, 0xd7, 0x50, 0xe5,
        0xf3,
    ]);
    const TEST_SPAN_ID: opentelemetry::SpanId =
        SpanId::from_bytes([0x24, 0x0, 0x31, 0xea, 0xd7, 0x50, 0xe5, 0xf3]);

    let start_time = SystemTime::now();
    let end_time = start_time + std::time::Duration::from_nanos(200000000);

    vec![
        Test {
            name: "basic",
            input_resource: vec![
                ("service.name", "pylons"),
                ("service.version", "v1.2.3"),
                ("env", "staging"),
            ],
            input_span: TestSpan {
                span_context: SpanContext::new(
                    TEST_TRACE_ID,
                    TEST_SPAN_ID,
                    TraceFlags::default(),
                    false,
                    TraceState::default(),
                ),
                parent_span_id: SpanId::INVALID,
                span_kind: SpanKind::Server,
                name: "/path".into(),
                start_time,
                end_time,
                attributes: vec![
                    KeyValue::new("name", "john"),
                    KeyValue::new("approx", 1.2),
                    KeyValue::new("count", 2),
                    KeyValue::new(
                        "names",
                        opentelemetry::Value::Array(
                            vec![opentelemetry::StringValue::from("a"), "b".into()].into(),
                        ),
                    ),
                    KeyValue::new(
                        "flags",
                        opentelemetry::Value::Array(vec![true, false].into()),
                    ),
                    KeyValue::new("counts", opentelemetry::Value::Array(vec![1_i64, 2].into())),
                    KeyValue::new("ratios", opentelemetry::Value::Array(vec![0.5, 1.5].into())),
                    KeyValue::new(
                        "http.request.header.accept",
                        opentelemetry::Value::Array(
                            vec![opentelemetry::StringValue::from("text/html")].into(),
                        ),
                    ),
                ],
                dropped_attributes_count: 0,
                events: make_test_span_events().0,
                dropped_event_count: 0,
                links: make_test_span_links().0,
                dropped_links_count: 0,
                status: Status::Error {
                    description: "Error".into(),
                },
                instrumentation_scope: InstrumentationScope::builder("ddtracer")
                    .with_version("v2")
                    .build(),
            },
            expected_out: DdSpan {
                name: "server.request".into(),
                resource: "/path".into(),
                service: "pylons".into(),
                trace_id: 2594128270069917171,
                span_id: 2594128270069917171,
                parent_id: 0,
                start: start_time
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as i64,
                duration: 200000000,
                error: 1,
                meta: VecMap::from_iter([
                    ("name".into(), "john".into()),
                    ("names.0".into(), "a".into()),
                    ("names.1".into(), "b".into()),
                    ("flags.0".into(), "true".into()),
                    ("flags.1".into(), "false".into()),
                    ("http.request.headers.accept.0".into(), "text/html".into()),
                    (
                        "otel.trace_id".into(),
                        "72df520af2bde7a5240031ead750e5f3".into(),
                    ),
                    ("env".into(), "staging".into()),
                    ("otel.status_code".into(), "Error".into()),
                    ("otel.status_description".into(), "Error".into()),
                    ("otel.scope.name".into(), "ddtracer".into()),
                    ("otel.scope.version".into(), "v2".into()),
                    ("service.version".into(), "v1.2.3".into()),
                    ("version".into(), "v1.2.3".into()),
                    ("error.message".into(), "Out of memory".into()),
                    ("error.type".into(), "mem".into()),
                    ("error.stack".into(), "1/2/3".into()),
                    ("span.kind".into(), "server".into()),
                    ("_dd.span_events.has_exception".into(), "true".into()),
                ]),
                metrics: VecMap::from_iter([
                    ("approx".into(), 1.2),
                    ("count".into(), 2.0),
                    ("counts.0".into(), 1.0),
                    ("counts.1".into(), 2.0),
                    ("ratios.0".into(), 0.5),
                    ("ratios.1".into(), 1.5),
                ]),
                r#type: "web".into(),
                span_events: make_test_span_events().1,
                span_links: make_test_span_links().1,
                meta_struct: VecMap::new(),
            },
        },
        Test {
            name: "complex",
            input_resource: vec![
                ("service.version", "v1.2.3"),
                ("service.name", "myservice"),
                ("peer.service", "mypeerservice"),
            ],
            input_span: TestSpan {
                span_context: SpanContext::new(
                    TEST_TRACE_ID,
                    TEST_SPAN_ID,
                    TraceFlags::default(),
                    false,
                    TraceState::from_str("state=1").unwrap(),
                ),
                parent_span_id: SpanId::INVALID,
                span_kind: SpanKind::Server,
                name: "/path".into(),
                start_time,
                end_time,
                attributes: vec![
                    KeyValue::new("name", "john"),
                    KeyValue::new("peer.service", "userbase"),
                    KeyValue::new("deployment.environment", "prod"),
                    KeyValue::new("http.request.method", "GET"),
                    KeyValue::new("http.route", "/path"),
                    KeyValue::new("approx", 1.2),
                    KeyValue::new("count", 2),
                    KeyValue::new("span.kind", "server"),
                ],
                dropped_attributes_count: 0,
                events: make_test_span_events().0,
                dropped_event_count: 0,
                links: make_test_span_links().0,
                dropped_links_count: 0,
                status: Status::Error {
                    description: "Error".into(),
                },
                instrumentation_scope: InstrumentationScope::builder("ddtracer")
                    .with_version("v2")
                    .build(),
            },
            expected_out: DdSpan {
                name: "http.server.request".into(),
                resource: "GET /path".into(),
                service: "myservice".into(),
                trace_id: 2594128270069917171,
                span_id: 2594128270069917171,
                parent_id: 0,
                start: start_time
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as i64,
                duration: 200000000,
                error: 1,
                meta: VecMap::from_iter([
                    ("name".into(), "john".into()),
                    ("deployment.environment".into(), "prod".into()),
                    (
                        "otel.trace_id".into(),
                        "72df520af2bde7a5240031ead750e5f3".into(),
                    ),
                    ("otel.status_code".into(), "Error".into()),
                    ("otel.status_description".into(), "Error".into()),
                    ("otel.scope.name".into(), "ddtracer".into()),
                    ("otel.scope.version".into(), "v2".into()),
                    ("service.version".into(), "v1.2.3".into()),
                    ("w3c.tracestate".into(), "state=1".into()),
                    ("version".into(), "v1.2.3".into()),
                    ("error.message".into(), "Out of memory".into()),
                    ("error.type".into(), "mem".into()),
                    ("error.stack".into(), "1/2/3".into()),
                    ("http.method".into(), "GET".into()),
                    ("http.route".into(), "/path".into()),
                    ("peer.service".into(), "userbase".into()),
                    ("span.kind".into(), "server".into()),
                    ("_dd.span_events.has_exception".into(), "true".into()),
                ]),
                metrics: VecMap::from_iter([("approx".into(), 1.2), ("count".into(), 2.0)]),
                r#type: "web".into(),
                span_events: make_test_span_events().1,
                span_links: make_test_span_links().1,
                meta_struct: VecMap::new(),
            },
        },
        Test {
            name: "http_attributes",
            input_resource: vec![
                ("service.name", "myservice"),
                ("service.version", "v1.2.3"),
                ("env", "staging"),
                ("client.address", "sample_client_address"),
                ("http.response.body.size", "sample_content_length"),
                ("http.response.status_code", "sample_status_code"),
                ("http.request.body.size", "sample_content_length"),
                ("http.request.header.referrer", "sample_referrer"),
                ("network.protocol.version", "sample_version"),
                ("server.address", "sample_server_name"),
                ("url.full", "sample_url"),
                ("user_agent.original", "sample_useragent"),
                ("http.request.header.example", "test"),
            ],
            input_span: TestSpan {
                span_context: SpanContext::new(
                    TEST_TRACE_ID,
                    TEST_SPAN_ID,
                    TraceFlags::default(),
                    false,
                    TraceState::from_str("state=1").unwrap(),
                ),
                parent_span_id: SpanId::INVALID,
                span_kind: SpanKind::Server,
                name: "/path".into(),
                start_time,
                end_time,
                attributes: vec![
                    KeyValue::new("name", "john"),
                    KeyValue::new("http.request.method", "GET"),
                    KeyValue::new("http.route", "/path"),
                    KeyValue::new("approx", 1.2),
                    KeyValue::new("count", 2),
                    KeyValue::new("analytics.event", "false"),
                    KeyValue::new("service.name", "pylons"),
                ],
                dropped_attributes_count: 0,
                events: make_test_span_events().0,
                dropped_event_count: 0,
                links: make_test_span_links().0,
                dropped_links_count: 0,
                status: Status::Error {
                    description: "Error".into(),
                },
                instrumentation_scope: InstrumentationScope::builder("ddtracer")
                    .with_version("v2")
                    .build(),
            },
            expected_out: DdSpan {
                name: "http.server.request".into(),
                resource: "GET /path".into(),
                service: "pylons".into(),
                trace_id: 2594128270069917171,
                span_id: 2594128270069917171,
                parent_id: 0,
                start: start_time
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as i64,
                duration: 200000000,
                error: 1,
                meta: VecMap::from_iter([
                    ("name".into(), "john".into()),
                    ("env".into(), "staging".into()),
                    (
                        "otel.trace_id".into(),
                        "72df520af2bde7a5240031ead750e5f3".into(),
                    ),
                    ("otel.status_code".into(), "Error".into()),
                    ("otel.status_description".into(), "Error".into()),
                    ("otel.scope.name".into(), "ddtracer".into()),
                    ("otel.scope.version".into(), "v2".into()),
                    ("service.version".into(), "v1.2.3".into()),
                    ("w3c.tracestate".into(), "state=1".into()),
                    ("version".into(), "v1.2.3".into()),
                    ("error.message".into(), "Out of memory".into()),
                    ("error.type".into(), "mem".into()),
                    ("error.stack".into(), "1/2/3".into()),
                    ("http.method".into(), "GET".into()),
                    ("http.route".into(), "/path".into()),
                    ("span.kind".into(), "server".into()),
                    ("_dd.span_events.has_exception".into(), "true".into()),
                    ("http.client_ip".into(), "sample_client_address".into()),
                    (
                        "http.response.content_length".into(),
                        "sample_content_length".into(),
                    ),
                    ("http.status_code".into(), "sample_status_code".into()),
                    (
                        "http.request.content_length".into(),
                        "sample_content_length".into(),
                    ),
                    ("http.referrer".into(), "sample_referrer".into()),
                    ("http.version".into(), "sample_version".into()),
                    ("http.server_name".into(), "sample_server_name".into()),
                    ("http.url".into(), "sample_url".into()),
                    ("http.useragent".into(), "sample_useragent".into()),
                    ("http.request.headers.example".into(), "test".into()),
                ]),
                metrics: VecMap::from_iter([
                    ("approx".into(), 1.2),
                    ("count".into(), 2.0),
                    (SAMPLING_RATE_EVENT_EXTRACTION_KEY.into(), 0.0),
                ]),
                r#type: "web".into(),
                span_events: make_test_span_events().1,
                span_links: make_test_span_links().1,
                meta_struct: VecMap::new(),
            },
        },
        Test {
            name: "db_attributes",
            input_resource: vec![("env", "staging"), ("service.name", "mongo")],
            input_span: TestSpan {
                span_context: SpanContext::new(
                    TEST_TRACE_ID,
                    TEST_SPAN_ID,
                    TraceFlags::default(),
                    false,
                    TraceState::default(),
                ),
                parent_span_id: SpanId::INVALID,
                span_kind: SpanKind::Internal,
                name: "/path".into(),
                start_time,
                end_time,
                attributes: vec![
                    KeyValue::new("operation.name", "READ"),
                    KeyValue::new("resource.name", "/path"),
                    KeyValue::new("span.type", "db"),
                    KeyValue::new("name", "john"),
                    KeyValue::new("container.id", "cid"),
                    KeyValue::new("k8s.container.name", "k8s-container"),
                    KeyValue::new("http.request.method", "GET"),
                    KeyValue::new("http.route", "/path"),
                    KeyValue::new("approx", 1.2),
                    KeyValue::new("count", 2),
                    KeyValue::new("analytics.event", true),
                ],
                dropped_attributes_count: 0,
                events: vec![],
                dropped_event_count: 0,
                links: vec![],
                dropped_links_count: 0,
                status: Status::Unset,
                instrumentation_scope: InstrumentationScope::builder("ddtracer")
                    .with_version("v2")
                    .build(),
            },
            expected_out: DdSpan {
                name: "READ".into(),
                resource: "/path".into(),
                service: "mongo".into(),
                trace_id: 2594128270069917171,
                span_id: 2594128270069917171,
                parent_id: 0,
                start: start_time
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as i64,
                duration: 200000000,
                error: 0,
                meta: VecMap::from_iter([
                    ("env".into(), "staging".into()),
                    ("container.id".into(), "cid".into()),
                    ("k8s.container.name".into(), "k8s-container".into()),
                    ("http.method".into(), "GET".into()),
                    ("http.route".into(), "/path".into()),
                    ("otel.status_code".into(), "Unset".into()),
                    ("otel.scope.name".into(), "ddtracer".into()),
                    ("otel.scope.version".into(), "v2".into()),
                    ("name".into(), "john".into()),
                    (
                        "otel.trace_id".into(),
                        "72df520af2bde7a5240031ead750e5f3".into(),
                    ),
                    ("span.kind".into(), "internal".into()),
                ]),
                metrics: VecMap::from_iter([
                    ("approx".into(), 1.2),
                    ("count".into(), 2.0),
                    (SAMPLING_RATE_EVENT_EXTRACTION_KEY.into(), 1.0),
                ]),
                r#type: "db".into(),
                span_events: vec![],
                span_links: vec![],
                meta_struct: VecMap::new(),
            },
        },
        Test {
            name: "http_naming_old_semconv",
            input_resource: vec![("env", "staging"), ("service.name", "document-uploader")],
            input_span: TestSpan {
                span_context: SpanContext::new(
                    TEST_TRACE_ID,
                    TEST_SPAN_ID,
                    TraceFlags::default(),
                    false,
                    TraceState::default(),
                ),
                parent_span_id: SpanId::INVALID,
                span_kind: SpanKind::Internal,
                name: "POST /uploads/:document_id".into(),
                start_time,
                end_time,
                attributes: vec![
                    KeyValue::new("operation.name", "ddtracer.server"),
                    KeyValue::new("http.request.method", "POST"),
                    KeyValue::new("url.path", "/uploads/4"),
                    KeyValue::new("url.scheme", "https"),
                    KeyValue::new("http.route", "/uploads/:document_id"),
                    KeyValue::new("http.response.status_code", "201"),
                    KeyValue::new("error.type", "WebSocketDisconnect"),
                ],
                dropped_attributes_count: 0,
                events: vec![],
                dropped_event_count: 0,
                links: vec![],
                dropped_links_count: 0,
                status: Status::Error {
                    description: "".into(),
                },
                instrumentation_scope: InstrumentationScope::builder("ddtracer")
                    .with_version("v2")
                    .build(),
            },
            expected_out: DdSpan {
                name: "ddtracer.server".into(),
                resource: "POST".into(),
                service: "document-uploader".into(),
                trace_id: 2594128270069917171,
                span_id: 2594128270069917171,
                parent_id: 0,
                start: start_time
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as i64,
                duration: 200000000,
                error: 1,
                meta: VecMap::from_iter([
                    ("env".into(), "staging".into()),
                    ("otel.scope.name".into(), "ddtracer".into()),
                    ("otel.scope.version".into(), "v2".into()),
                    ("otel.status_code".into(), "Error".into()),
                    ("error.message".into(), "201".into()),
                    ("http.method".into(), "POST".into()),
                    ("url.path".into(), "/uploads/4".into()),
                    ("url.scheme".into(), "https".into()),
                    ("http.route".into(), "/uploads/:document_id".into()),
                    ("http.status_code".into(), "201".into()),
                    ("error.type".into(), "WebSocketDisconnect".into()),
                    (
                        "otel.trace_id".into(),
                        "72df520af2bde7a5240031ead750e5f3".into(),
                    ),
                    ("span.kind".into(), "internal".into()),
                ]),
                metrics: VecMap::new(),
                r#type: "custom".into(),
                span_events: vec![],
                span_links: vec![],
                meta_struct: VecMap::new(),
            },
        },
        Test {
            name: "http_naming",
            input_resource: vec![("env", "staging"), ("service.name", "document-uploader")],
            input_span: TestSpan {
                span_context: SpanContext::new(
                    TEST_TRACE_ID,
                    TEST_SPAN_ID,
                    TraceFlags::default(),
                    false,
                    TraceState::default(),
                ),
                parent_span_id: SpanId::INVALID,
                span_kind: SpanKind::Internal,
                name: "POST /uploads/:document_id".into(),
                start_time,
                end_time,
                attributes: vec![
                    KeyValue::new("operation.name", "ddtracer.server"),
                    KeyValue::new("http.request.method", "POST"),
                    KeyValue::new("url.path", "/uploads/4"),
                    KeyValue::new("url.scheme", "https"),
                    KeyValue::new("http.route", "/uploads/:document_id"),
                    KeyValue::new("http.status_code", "201"),
                    KeyValue::new("error.type", "WebSocketDisconnect"),
                ],
                dropped_attributes_count: 0,
                events: vec![],
                dropped_event_count: 0,
                links: vec![],
                dropped_links_count: 0,
                status: Status::Error {
                    description: "".into(),
                },
                instrumentation_scope: InstrumentationScope::builder("ddtracer")
                    .with_version("v2")
                    .build(),
            },
            expected_out: DdSpan {
                name: "ddtracer.server".into(),
                resource: "POST".into(),
                service: "document-uploader".into(),
                trace_id: 2594128270069917171,
                span_id: 2594128270069917171,
                parent_id: 0,
                start: start_time
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as i64,
                duration: 200000000,
                error: 1,
                meta: VecMap::from_iter([
                    ("env".into(), "staging".into()),
                    ("otel.scope.name".into(), "ddtracer".into()),
                    ("otel.scope.version".into(), "v2".into()),
                    ("otel.status_code".into(), "Error".into()),
                    ("error.message".into(), "201".into()),
                    ("http.method".into(), "POST".into()),
                    ("url.path".into(), "/uploads/4".into()),
                    ("url.scheme".into(), "https".into()),
                    ("http.route".into(), "/uploads/:document_id".into()),
                    ("http.status_code".into(), "201".into()),
                    ("error.type".into(), "WebSocketDisconnect".into()),
                    (
                        "otel.trace_id".into(),
                        "72df520af2bde7a5240031ead750e5f3".into(),
                    ),
                    ("span.kind".into(), "internal".into()),
                ]),
                metrics: VecMap::new(),
                r#type: "custom".into(),
                span_events: vec![],
                span_links: vec![],
                meta_struct: VecMap::new(),
            },
        },
        Test {
            name: "datadog_overrides",
            input_resource: vec![
                ("service.name", "resource-service"),
                ("env", "staging"),
                ("service.version", "v1.2.3"),
            ],
            input_span: TestSpan {
                span_context: SpanContext::new(
                    TEST_TRACE_ID,
                    TEST_SPAN_ID,
                    TraceFlags::default(),
                    false,
                    TraceState::default(),
                ),
                parent_span_id: SpanId::INVALID,
                span_kind: SpanKind::Server,
                name: "GET /users/:id".into(),
                start_time,
                end_time,
                attributes: vec![
                    KeyValue::new("datadog.service", "datadog-service"),
                    KeyValue::new("datadog.name", "datadog.name"),
                    KeyValue::new("datadog.resource", "datadog-resource"),
                    KeyValue::new("datadog.type", "datadog-type"),
                    KeyValue::new("datadog.env", "datadog-env"),
                    KeyValue::new("datadog.version", "datadog-version"),
                    KeyValue::new("datadog.http_status_code", 503),
                    KeyValue::new("service.name", "span-service"),
                    KeyValue::new("operation.name", "span.operation"),
                    KeyValue::new("resource.name", "span-resource"),
                    KeyValue::new("span.type", "span-type"),
                    KeyValue::new("env", "span-env"),
                    KeyValue::new("http.request.method", "GET"),
                    KeyValue::new("http.response.status_code", 200),
                ],
                dropped_attributes_count: 0,
                events: vec![],
                dropped_event_count: 0,
                links: vec![],
                dropped_links_count: 0,
                status: Status::Unset,
                instrumentation_scope: InstrumentationScope::builder("ddtracer")
                    .with_version("v2")
                    .build(),
            },
            expected_out: DdSpan {
                name: "datadog.name".into(),
                resource: "datadog-resource".into(),
                service: "datadog-service".into(),
                trace_id: 2594128270069917171,
                span_id: 2594128270069917171,
                parent_id: 0,
                start: start_time
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as i64,
                duration: 200000000,
                error: 0,
                meta: VecMap::from_iter([
                    ("otel.scope.name".into(), "ddtracer".into()),
                    ("otel.scope.version".into(), "v2".into()),
                    (
                        "otel.trace_id".into(),
                        "72df520af2bde7a5240031ead750e5f3".into(),
                    ),
                    ("otel.status_code".into(), "Unset".into()),
                    ("env".into(), "datadog-env".into()),
                    ("version".into(), "datadog-version".into()),
                    ("http.status_code".into(), "503".into()),
                    ("http.status_code".into(), "503".into()),
                    ("http.method".into(), "GET".into()),
                    ("service.version".into(), "v1.2.3".into()),
                    ("span.kind".into(), "server".into()),
                ]),
                metrics: VecMap::from_iter([("http.status_code".into(), 200.0)]),
                r#type: "datadog-type".into(),
                span_events: vec![],
                span_links: vec![],
                meta_struct: VecMap::new(),
            },
        },
        Test {
            name: "numeric_env",
            input_resource: vec![
                ("service.name", "svc"),
                ("deployment.environment.name", "prod"),
            ],
            input_span: TestSpan {
                span_context: SpanContext::new(
                    TEST_TRACE_ID,
                    TEST_SPAN_ID,
                    TraceFlags::default(),
                    false,
                    TraceState::default(),
                ),
                parent_span_id: SpanId::INVALID,
                span_kind: SpanKind::Internal,
                name: "op".into(),
                start_time,
                end_time,
                attributes: vec![KeyValue::new("env", 123)],
                dropped_attributes_count: 0,
                events: vec![],
                dropped_event_count: 0,
                links: vec![],
                dropped_links_count: 0,
                status: Status::Unset,
                instrumentation_scope: InstrumentationScope::builder("ddtracer")
                    .with_version("v2")
                    .build(),
            },
            expected_out: DdSpan {
                name: "internal".into(),
                resource: "op".into(),
                service: "svc".into(),
                trace_id: 2594128270069917171,
                span_id: 2594128270069917171,
                parent_id: 0,
                start: start_time
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as i64,
                duration: 200000000,
                error: 0,
                meta: VecMap::from_iter([
                    ("otel.scope.name".into(), "ddtracer".into()),
                    ("otel.scope.version".into(), "v2".into()),
                    (
                        "otel.trace_id".into(),
                        "72df520af2bde7a5240031ead750e5f3".into(),
                    ),
                    ("otel.status_code".into(), "Unset".into()),
                    ("env".into(), "prod".into()),
                    ("deployment.environment.name".into(), "prod".into()),
                    ("span.kind".into(), "internal".into()),
                ]),
                metrics: VecMap::from_iter([("env".into(), 123.0)]),
                r#type: "custom".into(),
                span_events: vec![],
                span_links: vec![],
                meta_struct: VecMap::new(),
            },
        },
        Test {
            name: "empty_env",
            input_resource: vec![
                ("service.name", "svc"),
                ("deployment.environment.name", "prod"),
            ],
            input_span: TestSpan {
                span_context: SpanContext::new(
                    TEST_TRACE_ID,
                    TEST_SPAN_ID,
                    TraceFlags::default(),
                    false,
                    TraceState::default(),
                ),
                parent_span_id: SpanId::INVALID,
                span_kind: SpanKind::Internal,
                name: "op".into(),
                start_time,
                end_time,
                attributes: vec![KeyValue::new("env", "")],
                dropped_attributes_count: 0,
                events: vec![],
                dropped_event_count: 0,
                links: vec![],
                dropped_links_count: 0,
                status: Status::Unset,
                instrumentation_scope: InstrumentationScope::builder("ddtracer")
                    .with_version("v2")
                    .build(),
            },
            expected_out: DdSpan {
                name: "internal".into(),
                resource: "op".into(),
                service: "svc".into(),
                trace_id: 2594128270069917171,
                span_id: 2594128270069917171,
                parent_id: 0,
                start: start_time
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as i64,
                duration: 200000000,
                error: 0,
                meta: VecMap::from_iter([
                    ("otel.scope.name".into(), "ddtracer".into()),
                    ("otel.scope.version".into(), "v2".into()),
                    (
                        "otel.trace_id".into(),
                        "72df520af2bde7a5240031ead750e5f3".into(),
                    ),
                    ("otel.status_code".into(), "Unset".into()),
                    ("env".into(), "".into()),
                    ("deployment.environment.name".into(), "prod".into()),
                    ("span.kind".into(), "internal".into()),
                ]),
                metrics: VecMap::new(),
                r#type: "custom".into(),
                span_events: vec![],
                span_links: vec![],
                meta_struct: VecMap::new(),
            },
        },
        Test {
            name: "duplicate_env",
            input_resource: vec![("service.name", "svc")],
            input_span: TestSpan {
                span_context: SpanContext::new(
                    TEST_TRACE_ID,
                    TEST_SPAN_ID,
                    TraceFlags::default(),
                    false,
                    TraceState::default(),
                ),
                parent_span_id: SpanId::INVALID,
                span_kind: SpanKind::Internal,
                name: "op".into(),
                start_time,
                end_time,
                attributes: vec![KeyValue::new("env", "dev"), KeyValue::new("env", "qa")],
                dropped_attributes_count: 0,
                events: vec![],
                dropped_event_count: 0,
                links: vec![],
                dropped_links_count: 0,
                status: Status::Unset,
                instrumentation_scope: InstrumentationScope::builder("ddtracer")
                    .with_version("v2")
                    .build(),
            },
            expected_out: DdSpan {
                name: "internal".into(),
                resource: "op".into(),
                service: "svc".into(),
                trace_id: 2594128270069917171,
                span_id: 2594128270069917171,
                parent_id: 0,
                start: start_time
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as i64,
                duration: 200000000,
                error: 0,
                meta: VecMap::from_iter([
                    ("otel.scope.name".into(), "ddtracer".into()),
                    ("otel.scope.version".into(), "v2".into()),
                    (
                        "otel.trace_id".into(),
                        "72df520af2bde7a5240031ead750e5f3".into(),
                    ),
                    ("otel.status_code".into(), "Unset".into()),
                    ("env".into(), "dev".into()),
                    ("span.kind".into(), "internal".into()),
                ]),
                metrics: VecMap::new(),
                r#type: "custom".into(),
                span_events: vec![],
                span_links: vec![],
                meta_struct: VecMap::new(),
            },
        },
    ]
}

#[cfg(test)]
mod tests {
    use std::{
        borrow::Cow,
        fmt::{Debug, Write},
        str::FromStr,
        time::{Duration, SystemTime},
    };

    use bumpalo::Bump;
    use libdd_trace_utils::span::{
        v04::{AttributeAnyValue as Any, AttributeArrayValue as Scalar},
        vec_map::VecMap,
    };
    use opentelemetry::{
        trace::{Event, SpanContext, SpanKind, Status, TraceState},
        InstrumentationScope, KeyValue, SpanId, StringValue, TraceFlags, TraceId, Value,
    };
    use opentelemetry_sdk::{
        trace::{SpanData, SpanEvents, SpanLinks},
        Resource,
    };

    use crate::mappings::{
        sdk_span::SdkSpan,
        transform::{otel_span_to_dd_span, CowStr, SpanStr},
        DdSpan,
    };

    use super::{test_cases, test_span_to_sdk_span};

    fn downcast_lifetime<'a: 'b, 'b>(span: DdSpan<'a>) -> DdSpan<'b> {
        unsafe { std::mem::transmute(span) }
    }

    #[test]
    fn test_otel_span_to_dd_span() {
        let tests = test_cases();
        for test in tests {
            let input_resource = Resource::builder_empty()
                .with_attributes(
                    test.input_resource
                        .into_iter()
                        .map(|(k, v)| KeyValue::new(k, v)),
                )
                .build();
            let alloc = Bump::new();
            let mut output = DdSpan::default();
            otel_span_to_dd_span(
                &mut output,
                &test_span_to_sdk_span(&test.input_span),
                &input_resource,
                &alloc,
            );
            hashmap_diff(&output.meta, &test.expected_out.meta);
            hashmap_diff(&output.metrics, &test.expected_out.metrics);
            assert_eq!(
                output,
                downcast_lifetime(test.expected_out),
                "Test {} failed",
                test.name
            );
        }
    }

    #[track_caller]
    fn hashmap_diff<'a, V: PartialEq + Debug>(
        output: &VecMap<CowStr<'a>, V>,
        expected: &VecMap<CowStr<'a>, V>,
    ) {
        let mut a = Vec::from_iter(output);
        let mut b = Vec::from_iter(expected);
        a.sort_by_key(|(k, _)| k.as_str());
        b.sort_by_key(|(k, _)| k.as_str());
        let mut a = a.into_iter().peekable();
        let mut b = b.into_iter().peekable();
        let mut message = String::new();
        loop {
            match (a.peek(), b.peek()) {
                (Some(a_v), Some(b_v)) => match a_v.0.as_str().cmp(b_v.0.as_str()) {
                    std::cmp::Ordering::Less => {
                        writeln!(&mut message, "a  :+{a_v:?}").unwrap();
                        a.next();
                    }
                    std::cmp::Ordering::Equal => {
                        if a_v.1 != b_v.1 {
                            writeln!(&mut message, "a!b: {a_v:?} != {b_v:?}").unwrap();
                        } else {
                            writeln!(&mut message, "a b: {b_v:?}").unwrap();
                        }
                        a.next();
                        b.next();
                    }
                    std::cmp::Ordering::Greater => {
                        writeln!(&mut message, "  b:+{b_v:?}").unwrap();
                        b.next();
                    }
                },
                (None, None) => break,
                (Some(a_v), None) => {
                    writeln!(&mut message, "a  :+{a_v:?}").unwrap();
                    a.next();
                }
                (None, Some(b_v)) => {
                    writeln!(&mut message, "  b:+{b_v:?}").unwrap();
                    b.next();
                }
            }
        }
        if output != expected {
            eprintln!("Hashmaps are not equal :\n{message}");
        }
    }

    fn span_data() -> SpanData {
        SpanData {
            span_context: SpanContext::new(
                TraceId::from_hex("fedcba98765432100123456789abcdef").unwrap(),
                SpanId::from_hex("abcdef0123456789").unwrap(),
                TraceFlags::SAMPLED,
                false,
                TraceState::from_str("vendor=value,other=state").unwrap(),
            ),
            parent_span_id: SpanId::from_hex("0123456789abcdef").unwrap(),
            parent_span_is_remote: false,
            span_kind: SpanKind::Internal,
            name: Cow::Borrowed("fixed-span"),
            start_time: SystemTime::UNIX_EPOCH + Duration::from_nanos(1234),
            end_time: SystemTime::UNIX_EPOCH + Duration::from_nanos(5678),
            attributes: vec![],
            dropped_attributes_count: 0,
            events: SpanEvents::default(),
            links: SpanLinks::default(),
            status: Status::Unset,
            instrumentation_scope: InstrumentationScope::default(),
        }
    }

    fn convert<'a>(data: &'a SpanData, resource: &'a Resource, alloc: &'a Bump) -> DdSpan<'a> {
        let mut output = DdSpan::default();
        otel_span_to_dd_span(
            &mut output,
            &SdkSpan::from_sdk_span_data(data),
            resource,
            alloc,
        );
        output
    }

    fn tag<'a>(span: &'a DdSpan<'_>, key: &str) -> Option<&'a str> {
        span.meta.get(key).map(SpanStr::as_str)
    }

    #[test]
    fn sampling_priority_remap_before_processor_override() {
        let resource = Resource::builder_empty().build();
        let alloc = Bump::new();
        for value in [-1.0, 0.0, 0.5, 1.0, 2.0] {
            let mut data = span_data();
            data.attributes = vec![KeyValue::new("sampling.priority", value)];
            let output = convert(&data, &resource, &alloc);
            assert_eq!(
                output
                    .metrics
                    .get(&SpanStr::from_str("_sampling_priority_v1")),
                Some(&value)
            );
            assert!(!output
                .metrics
                .contains_key(&SpanStr::from_str("sampling.priority")));
        }
    }

    #[test]
    fn span_context_identity_tracestate_and_exact_time() {
        let resource = Resource::builder_empty().build();
        let alloc = Bump::new();
        let data = span_data();
        let output = convert(&data, &resource, &alloc);
        assert_eq!(output.trace_id, 0x0123456789abcdef_u64.into());
        assert_eq!(output.span_id, 0xabcdef0123456789);
        assert_eq!(output.parent_id, 0x0123456789abcdef);
        assert_eq!(
            tag(&output, "otel.trace_id"),
            Some("fedcba98765432100123456789abcdef")
        );
        assert_eq!(
            tag(&output, "w3c.tracestate"),
            Some("vendor=value,other=state")
        );
        assert_eq!(output.start, 1234);
        assert_eq!(output.duration, 4444);
    }

    #[test]
    fn duration_and_pre_epoch_timestamps_are_clamped() {
        let resource = Resource::builder_empty().build();
        let alloc = Bump::new();
        let mut data = span_data();
        for (start, end, expected_start, expected_duration) in [
            (10, 9, 10, 0),
            (10, 10, 10, 0),
            (-2, -1, 0, 0),
            (-1, 10, 0, 10),
        ] {
            let time = |n: i64| {
                if n < 0 {
                    SystemTime::UNIX_EPOCH - Duration::from_nanos(n.unsigned_abs())
                } else {
                    SystemTime::UNIX_EPOCH + Duration::from_nanos(n as u64)
                }
            };
            data.start_time = time(start);
            data.end_time = time(end);
            data.events.events = vec![Event::new("event", time(start), vec![], 0)];
            let output = convert(&data, &resource, &alloc);
            assert_eq!(
                (output.start, output.duration),
                (expected_start, expected_duration)
            );
            assert_eq!(output.span_events[0].time_unix_nano, expected_start as u64);
        }
    }

    /// The agent cannot downgrade these arrays, so assert their native v0.4 types
    /// directly instead of accepting a snapshot that never sees their values.
    #[test]
    fn event_arrays_preserve_every_element_and_type() {
        let resource = Resource::builder_empty().build();
        let alloc = Bump::new();
        let mut data = span_data();
        data.events.events = vec![Event::new(
            "arrays",
            SystemTime::UNIX_EPOCH + Duration::from_nanos(42),
            vec![
                KeyValue::new("bools", Value::Array(vec![true, false].into())),
                KeyValue::new("ints", Value::Array(vec![-7_i64, 8].into())),
                KeyValue::new("floats", Value::Array(vec![0.25, -1.5].into())),
                KeyValue::new(
                    "strings",
                    Value::Array(vec![StringValue::from("a"), "".into()].into()),
                ),
                KeyValue::new("empty-bools", Value::Array(Vec::<bool>::new().into())),
                KeyValue::new("empty-ints", Value::Array(Vec::<i64>::new().into())),
                KeyValue::new("empty-floats", Value::Array(Vec::<f64>::new().into())),
                KeyValue::new(
                    "empty-strings",
                    Value::Array(Vec::<StringValue>::new().into()),
                ),
            ],
            0,
        )];
        let output = convert(&data, &resource, &alloc);
        let event = &output.span_events[0];
        assert_eq!(event.time_unix_nano, 42);
        for (key, expected) in [
            ("bools", vec![Scalar::Boolean(true), Scalar::Boolean(false)]),
            ("ints", vec![Scalar::Integer(-7), Scalar::Integer(8)]),
            ("floats", vec![Scalar::Double(0.25), Scalar::Double(-1.5)]),
            (
                "strings",
                vec![
                    Scalar::String(SpanStr::from_str("a")),
                    Scalar::String(SpanStr::from_str("")),
                ],
            ),
            ("empty-bools", vec![]),
            ("empty-ints", vec![]),
            ("empty-floats", vec![]),
            ("empty-strings", vec![]),
        ] {
            assert_eq!(
                event.attributes.get(&SpanStr::from_str(key)),
                Some(&Any::Array(expected)),
                "{key}"
            );
        }
    }

    #[test]
    fn typed_exception_values_format_without_losing_false_or_empty_arrays() {
        let resource = Resource::builder_empty().build();
        let alloc = Bump::new();
        for (value, expected) in [
            (Value::Bool(false), "false"),
            (Value::I64(-42), "-42"),
            (Value::F64(1.5), "1.5"),
            (Value::Array(vec![true, false].into()), "[true,false]"),
            (Value::Array(vec![-1_i64, 2].into()), "[-1,2]"),
            (Value::Array(vec![1.5, 0.25].into()), "[1.5,0.25]"),
            (
                Value::Array(vec![StringValue::from("a"), "b".into()].into()),
                "[a,b]",
            ),
            (Value::Array(Vec::<i64>::new().into()), "[]"),
        ] {
            let mut data = span_data();
            data.status = Status::error("description must lose");
            data.events.events = vec![Event::new(
                "Exception",
                SystemTime::UNIX_EPOCH,
                vec![
                    KeyValue::new("exception.message", value.clone()),
                    KeyValue::new("exception.type", value.clone()),
                    KeyValue::new("exception.stacktrace", value),
                ],
                0,
            )];
            let output = convert(&data, &resource, &alloc);
            assert_eq!(output.error, 1);
            for key in ["error.message", "error.type", "error.stack"] {
                assert_eq!(tag(&output, key), Some(expected), "{key}");
            }
        }
    }

    /// SDK builders can overwrite duplicate keys. Feed the raw converter slice to
    /// distinguish last-index lookup from first-nonempty protected-tag insertion.
    #[test]
    fn duplicate_keys_and_indexed_arrays_keep_both_v04_namespaces() {
        let alloc = Bump::new();
        let resource = Resource::builder_empty()
            .with_attributes([KeyValue::new("shared", "resource")])
            .build();
        for reverse in [false, true] {
            let mut data = span_data();
            data.attributes = vec![
                KeyValue::new("datadog.name", "first-name"),
                KeyValue::new("datadog.name", "last-name"),
                KeyValue::new("ordinary", "first"),
                KeyValue::new("ordinary", "last"),
                KeyValue::new("shared", 42),
                KeyValue::new("shared", "span"),
                KeyValue::new("array", Value::Array(vec![7_i64].into())),
                KeyValue::new("array.0", "string"),
                KeyValue::new(
                    "indexed",
                    Value::Array(vec![StringValue::from("array")].into()),
                ),
                KeyValue::new("indexed.0", "scalar"),
                KeyValue::new("version", "first-version"),
                KeyValue::new("version", "last-version"),
            ];
            if reverse {
                data.attributes.reverse();
            }
            let output = convert(&data, &resource, &alloc);
            assert_eq!(
                output.name.as_str(),
                if reverse { "first-name" } else { "last-name" }
            );
            assert_eq!(
                tag(&output, "ordinary"),
                Some(if reverse { "first" } else { "last" })
            );
            assert_eq!(
                tag(&output, "version"),
                Some(if reverse {
                    "last-version"
                } else {
                    "first-version"
                })
            );
            assert_eq!(tag(&output, "shared"), Some("span"));
            assert_eq!(
                output.metrics.get(&SpanStr::from_str("shared")),
                Some(&42.0)
            );
            assert_eq!(tag(&output, "array.0"), Some("string"));
            assert_eq!(
                output.metrics.get(&SpanStr::from_str("array.0")),
                Some(&7.0)
            );
            assert_eq!(
                tag(&output, "indexed.0"),
                Some(if reverse { "array" } else { "scalar" })
            );
        }
    }
}
