// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    fmt::{Debug, Write},
    str::FromStr,
    time::{Duration, SystemTime},
    vec,
};

use datadog_trace_utils::span::{
    AttributeAnyValue as Any, AttributeArrayValue as Scalar, SpanBytes, SpanEvent, SpanEventBytes,
    SpanLink, SpanLinkBytes,
};

use dd_trace::constants::SAMPLING_RATE_EVENT_EXTRACTION_KEY;
use opentelemetry::{
    trace::{Event, Link, SpanContext, SpanKind, Status, TraceState},
    InstrumentationScope, KeyValue, SpanId, TraceFlags, TraceId,
};
use opentelemetry_sdk::Resource;
use tinybytes::BytesString;

use crate::{sdk_span::SdkSpan, transform::otel_span_to_dd_span};

fn timestamp_nano(nanos: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_nanos(nanos)
}

fn make_test_span_events() -> (Vec<Event>, Vec<SpanEventBytes>) {
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
            SpanEvent {
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
            SpanEvent {
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

fn make_test_span_links() -> (Vec<Link>, Vec<SpanLinkBytes>) {
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
                vec![],
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
            SpanLink {
                trace_id: 81985529216486895,
                trace_id_high: 18364758544493064720,
                span_id: 12379813738877118345,
                attributes: HashMap::from_iter([
                    ("a1".into(), "v1".into()),
                    ("a2".into(), "v2".into()),
                ]),
                tracestate: "dd=asdf256,ee=jkl;128".into(),
                flags: 0,
            },
            SpanLink {
                trace_id: 12379813738877118345,
                trace_id_high: 12379813738877118345,
                span_id: 18364758544493064720,
                attributes: HashMap::new(),
                tracestate: "".into(),
                flags: 0,
            },
            SpanLink {
                trace_id: 12379813738877118345,
                trace_id_high: 12379813738877118345,
                span_id: 18364758544493064720,
                attributes: HashMap::new(),
                tracestate: "".into(),
                flags: 0,
            },
        ],
    )
}

#[test]
fn test_otel_span_to_dd_span() {
    const TEST_TRACE_ID: opentelemetry::TraceId = TraceId::from_bytes([
        0x72, 0xdf, 0x52, 0xa, 0xf2, 0xbd, 0xe7, 0xa5, 0x24, 0x0, 0x31, 0xea, 0xd7, 0x50, 0xe5,
        0xf3,
    ]);
    const TEST_SPAN_ID: opentelemetry::SpanId =
        SpanId::from_bytes([0x24, 0x0, 0x31, 0xea, 0xd7, 0x50, 0xe5, 0xf3]);
    struct Test {
        name: &'static str,
        input_resource: Vec<(&'static str, &'static str)>,
        input_span: SdkSpan,
        expected_out: SpanBytes,
    }

    let start_time = SystemTime::now();
    let end_time = start_time + std::time::Duration::from_nanos(200000000);

    let tests: Vec<Test> = vec![
        Test {
            name: "basic",
            input_resource: vec![
                ("service.name", "pylons"),
                ("service.version", "v1.2.3"),
                ("env", "staging"),
            ],
            input_span: SdkSpan {
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
            expected_out: SpanBytes {
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
                meta: HashMap::from_iter([
                    ("name".into(), "john".into()),
                    (
                        "otel.trace_id".into(),
                        "72df520af2bde7a5240031ead750e5f3".into(),
                    ),
                    ("env".into(), "staging".into()),
                    ("otel.status_code".into(), "Error".into()),
                    ("otel.status_description".into(), "Error".into()),
                    ("otel.library.name".into(), "ddtracer".into()),
                    ("otel.library.version".into(), "v2".into()),
                    ("service.version".into(), "v1.2.3".into()),
                    ("version".into(), "v1.2.3".into()),
                    ("error.message".into(), "Out of memory".into()),
                    ("error.type".into(), "mem".into()),
                    ("error.stack".into(), "1/2/3".into()),
                    ("span.kind".into(), "server".into()),
                    ("_dd.span_events.has_exception".into(), "true".into()),
                ]),
                metrics: HashMap::from_iter([
                    ("_top_level".into(), 1.0),
                    ("approx".into(), 1.2),
                    ("count".into(), 2.0),
                ]),
                r#type: "web".into(),
                span_events: make_test_span_events().1,
                span_links: make_test_span_links().1,
                meta_struct: HashMap::new(),
            },
        },
        Test {
            name: "complex",
            input_resource: vec![
                ("service.version", "v1.2.3"),
                ("service.name", "myservice"),
                ("peer.service", "mypeerservice"),
            ],
            input_span: SdkSpan {
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
                    KeyValue::new("http.method", "GET"),
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
            expected_out: SpanBytes {
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
                meta: HashMap::from_iter([
                    ("name".into(), "john".into()),
                    ("deployment.environment".into(), "prod".into()),
                    (
                        "otel.trace_id".into(),
                        "72df520af2bde7a5240031ead750e5f3".into(),
                    ),
                    ("otel.status_code".into(), "Error".into()),
                    ("otel.status_description".into(), "Error".into()),
                    ("otel.library.name".into(), "ddtracer".into()),
                    ("otel.library.version".into(), "v2".into()),
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
                metrics: HashMap::from_iter([
                    ("_top_level".into(), 1.0),
                    ("approx".into(), 1.2),
                    ("count".into(), 2.0),
                ]),
                r#type: "web".into(),
                span_events: make_test_span_events().1,
                span_links: make_test_span_links().1,
                meta_struct: HashMap::new(),
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
            input_span: SdkSpan {
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
                    KeyValue::new("http.method", "GET"),
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
            expected_out: SpanBytes {
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
                meta: HashMap::from_iter([
                    ("name".into(), "john".into()),
                    ("env".into(), "staging".into()),
                    (
                        "otel.trace_id".into(),
                        "72df520af2bde7a5240031ead750e5f3".into(),
                    ),
                    ("otel.status_code".into(), "Error".into()),
                    ("otel.status_description".into(), "Error".into()),
                    ("otel.library.name".into(), "ddtracer".into()),
                    ("otel.library.version".into(), "v2".into()),
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
                metrics: HashMap::from_iter([
                    ("_top_level".into(), 1.0),
                    ("approx".into(), 1.2),
                    ("count".into(), 2.0),
                    (SAMPLING_RATE_EVENT_EXTRACTION_KEY.into(), 0.0),
                ]),
                r#type: "web".into(),
                span_events: make_test_span_events().1,
                span_links: make_test_span_links().1,
                meta_struct: HashMap::new(),
            },
        },
        Test {
            name: "db_attributes",
            input_resource: vec![("env", "staging"), ("service.name", "mongo")],
            input_span: SdkSpan {
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
                    KeyValue::new("http.method", "GET"),
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
            expected_out: SpanBytes {
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
                meta: HashMap::from_iter([
                    ("env".into(), "staging".into()),
                    ("container.id".into(), "cid".into()),
                    ("k8s.container.name".into(), "k8s-container".into()),
                    ("http.method".into(), "GET".into()),
                    ("http.route".into(), "/path".into()),
                    ("otel.status_code".into(), "Unset".into()),
                    ("otel.library.name".into(), "ddtracer".into()),
                    ("otel.library.version".into(), "v2".into()),
                    ("name".into(), "john".into()),
                    (
                        "otel.trace_id".into(),
                        "72df520af2bde7a5240031ead750e5f3".into(),
                    ),
                    ("span.kind".into(), "internal".into()),
                ]),
                metrics: HashMap::from_iter([
                    ("_top_level".into(), 1.0),
                    ("approx".into(), 1.2),
                    ("count".into(), 2.0),
                    (SAMPLING_RATE_EVENT_EXTRACTION_KEY.into(), 1.0),
                ]),
                r#type: "db".into(),
                span_events: vec![],
                span_links: vec![],
                meta_struct: HashMap::new(),
            },
        },
        Test {
            name: "http_naming_old_semconv",
            input_resource: vec![("env", "staging"), ("service.name", "document-uploader")],
            input_span: SdkSpan {
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
            expected_out: SpanBytes {
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
                meta: HashMap::from_iter([
                    ("env".into(), "staging".into()),
                    ("otel.library.name".into(), "ddtracer".into()),
                    ("otel.library.version".into(), "v2".into()),
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
                metrics: HashMap::from_iter([("_top_level".into(), 1.0)]),
                r#type: "custom".into(),
                span_events: vec![],
                span_links: vec![],
                meta_struct: HashMap::new(),
            },
        },
        Test {
            name: "http_naming",
            input_resource: vec![("env", "staging"), ("service.name", "document-uploader")],
            input_span: SdkSpan {
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
                    KeyValue::new("http.method", "POST"),
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
            expected_out: SpanBytes {
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
                meta: HashMap::from_iter([
                    ("env".into(), "staging".into()),
                    ("otel.library.name".into(), "ddtracer".into()),
                    ("otel.library.version".into(), "v2".into()),
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
                metrics: HashMap::from_iter([("_top_level".into(), 1.0)]),
                r#type: "custom".into(),
                span_events: vec![],
                span_links: vec![],
                meta_struct: HashMap::new(),
            },
        },
    ];

    for test in tests {
        let input_resource = Resource::builder_empty()
            .with_attributes(
                test.input_resource
                    .into_iter()
                    .map(|(k, v)| KeyValue::new(k, v)),
            )
            .build();
        let output = otel_span_to_dd_span(test.input_span, &input_resource);
        hashmap_diff(&output.meta, &test.expected_out.meta);
        hashmap_diff(&output.metrics, &test.expected_out.metrics);
        assert_eq!(output, test.expected_out, "Test {} failed", test.name);
    }
}

#[track_caller]
fn hashmap_diff<V: PartialEq + Debug>(
    output: &HashMap<BytesString, V>,
    expected: &HashMap<BytesString, V>,
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
