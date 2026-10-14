// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]

use std::{
    str::FromStr,
    time::{Duration, SystemTime},
    vec,
};

use libdd_trace_utils::span::v1::{AttributeValue, SpanKind as DdSpanKind, ThinVec};
use libdd_trace_utils::span::vec_map::VecMap;
use libdd_trace_utils::span::SpanText as _;

use crate::core::constants::SAMPLING_RATE_EVENT_EXTRACTION_KEY;
use opentelemetry::{
    trace::{Event, Link, SpanContext, SpanKind, Status, TraceState},
    InstrumentationScope, KeyValue, SpanId, TraceFlags, TraceId,
};

use super::{
    super::sdk_span::SdkSpan,
    super::transform::{CowStr, DdAttributeValue, DdSpanEvent, DdSpanLink},
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

fn string(s: &'static str) -> DdAttributeValue<'static> {
    AttributeValue::String(s.into())
}

/// Builds span attributes from string and numeric tags.
fn attributes<const N: usize, const M: usize>(
    strings: [(&'static str, &'static str); N],
    numbers: [(&'static str, f64); M],
) -> VecMap<CowStr<'static>, DdAttributeValue<'static>> {
    strings
        .into_iter()
        .map(|(k, v)| (k.into(), string(v)))
        .chain(
            numbers
                .into_iter()
                .map(|(k, v)| (k.into(), AttributeValue::Float(v))),
        )
        .collect()
}

fn make_test_span_events() -> (Vec<Event>, ThinVec<DdSpanEvent<'static>>) {
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
        ThinVec::from_iter([
            DdSpanEvent {
                time_unix_nano: 100,
                name: "boom".into(),
                attributes: VecMap::from_iter([
                    ("key".into(), string("Out of memory")),
                    ("accuracy".into(), AttributeValue::Float(2.4)),
                ]),
            },
            DdSpanEvent {
                time_unix_nano: 400,
                name: "exception".into(),
                attributes: VecMap::from_iter([
                    ("exception.message".into(), string("Out of memory")),
                    ("exception.type".into(), string("mem")),
                    ("exception.stacktrace".into(), string("1/2/3")),
                ]),
            },
        ]),
    )
}

fn make_test_span_links() -> (Vec<Link>, ThinVec<DdSpanLink<'static>>) {
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
        ThinVec::from_iter([
            DdSpanLink {
                trace_id: TraceId::from_hex("fedcba98765432100123456789abcdef")
                    .unwrap()
                    .to_bytes(),
                span_id: 12379813738877118345,
                attributes: VecMap::from_iter([
                    ("a1".into(), string("v1")),
                    ("a2".into(), string("v2")),
                ]),
                tracestate: "dd=asdf256,ee=jkl;128".into(),
                flags: 0,
            },
            DdSpanLink {
                trace_id: TraceId::from_hex("abcdef0123456789abcdef0123456789")
                    .unwrap()
                    .to_bytes(),
                span_id: 18364758544493064720,
                attributes: VecMap::new(),
                tracestate: "".into(),
                flags: 0,
            },
            DdSpanLink {
                trace_id: TraceId::from_hex("abcdef0123456789abcdef0123456789")
                    .unwrap()
                    .to_bytes(),
                span_id: 18364758544493064720,
                attributes: VecMap::new(),
                tracestate: "".into(),
                flags: 0,
            },
        ]),
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
                span_id: 2594128270069917171,
                parent_id: 0,
                start: start_time
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as i64,
                duration: 200000000,
                error: true,
                env: "staging".into(),
                version: "v1.2.3".into(),
                span_kind: DdSpanKind::Server,
                attributes: attributes(
                    [
                        ("name", "john"),
                        ("otel.trace_id", "72df520af2bde7a5240031ead750e5f3"),
                        ("otel.status_code", "Error"),
                        ("otel.status_description", "Error"),
                        ("otel.scope.name", "ddtracer"),
                        ("otel.scope.version", "v2"),
                        ("service.version", "v1.2.3"),
                        ("error.message", "Out of memory"),
                        ("error.type", "mem"),
                        ("error.stack", "1/2/3"),
                        ("_dd.span_events.has_exception", "true"),
                    ],
                    [("approx", 1.2), ("count", 2.0)],
                ),
                r#type: "web".into(),
                span_events: make_test_span_events().1,
                span_links: make_test_span_links().1,
                ..Default::default()
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
                span_id: 2594128270069917171,
                parent_id: 0,
                start: start_time
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as i64,
                duration: 200000000,
                error: true,
                version: "v1.2.3".into(),
                span_kind: DdSpanKind::Server,
                attributes: attributes(
                    [
                        ("name", "john"),
                        ("deployment.environment", "prod"),
                        ("otel.trace_id", "72df520af2bde7a5240031ead750e5f3"),
                        ("otel.status_code", "Error"),
                        ("otel.status_description", "Error"),
                        ("otel.scope.name", "ddtracer"),
                        ("otel.scope.version", "v2"),
                        ("service.version", "v1.2.3"),
                        ("w3c.tracestate", "state=1"),
                        ("error.message", "Out of memory"),
                        ("error.type", "mem"),
                        ("error.stack", "1/2/3"),
                        ("http.method", "GET"),
                        ("http.route", "/path"),
                        ("peer.service", "userbase"),
                        ("_dd.span_events.has_exception", "true"),
                    ],
                    [("approx", 1.2), ("count", 2.0)],
                ),
                r#type: "web".into(),
                span_events: make_test_span_events().1,
                span_links: make_test_span_links().1,
                ..Default::default()
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
                span_id: 2594128270069917171,
                parent_id: 0,
                start: start_time
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as i64,
                duration: 200000000,
                error: true,
                env: "staging".into(),
                version: "v1.2.3".into(),
                span_kind: DdSpanKind::Server,
                attributes: attributes(
                    [
                        ("name", "john"),
                        ("otel.trace_id", "72df520af2bde7a5240031ead750e5f3"),
                        ("otel.status_code", "Error"),
                        ("otel.status_description", "Error"),
                        ("otel.scope.name", "ddtracer"),
                        ("otel.scope.version", "v2"),
                        ("service.version", "v1.2.3"),
                        ("w3c.tracestate", "state=1"),
                        ("error.message", "Out of memory"),
                        ("error.type", "mem"),
                        ("error.stack", "1/2/3"),
                        ("http.method", "GET"),
                        ("http.route", "/path"),
                        ("_dd.span_events.has_exception", "true"),
                        ("http.client_ip", "sample_client_address"),
                        ("http.response.content_length", "sample_content_length"),
                        ("http.status_code", "sample_status_code"),
                        ("http.request.content_length", "sample_content_length"),
                        ("http.referrer", "sample_referrer"),
                        ("http.version", "sample_version"),
                        ("http.server_name", "sample_server_name"),
                        ("http.url", "sample_url"),
                        ("http.useragent", "sample_useragent"),
                        ("http.request.headers.example", "test"),
                    ],
                    [
                        ("approx", 1.2),
                        ("count", 2.0),
                        (SAMPLING_RATE_EVENT_EXTRACTION_KEY, 0.0),
                    ],
                ),
                r#type: "web".into(),
                span_events: make_test_span_events().1,
                span_links: make_test_span_links().1,
                ..Default::default()
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
                span_id: 2594128270069917171,
                parent_id: 0,
                start: start_time
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as i64,
                duration: 200000000,
                error: false,
                env: "staging".into(),
                span_kind: DdSpanKind::Internal,
                attributes: attributes(
                    [
                        ("container.id", "cid"),
                        ("k8s.container.name", "k8s-container"),
                        ("http.method", "GET"),
                        ("http.route", "/path"),
                        ("otel.status_code", "Unset"),
                        ("otel.scope.name", "ddtracer"),
                        ("otel.scope.version", "v2"),
                        ("name", "john"),
                        ("otel.trace_id", "72df520af2bde7a5240031ead750e5f3"),
                    ],
                    [
                        ("approx", 1.2),
                        ("count", 2.0),
                        (SAMPLING_RATE_EVENT_EXTRACTION_KEY, 1.0),
                    ],
                ),
                r#type: "db".into(),
                span_events: ThinVec::new(),
                span_links: ThinVec::new(),
                ..Default::default()
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
                span_id: 2594128270069917171,
                parent_id: 0,
                start: start_time
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as i64,
                duration: 200000000,
                error: true,
                env: "staging".into(),
                span_kind: DdSpanKind::Internal,
                attributes: attributes(
                    [
                        ("otel.scope.name", "ddtracer"),
                        ("otel.scope.version", "v2"),
                        ("otel.status_code", "Error"),
                        ("error.message", "201"),
                        ("http.method", "POST"),
                        ("url.path", "/uploads/4"),
                        ("url.scheme", "https"),
                        ("http.route", "/uploads/:document_id"),
                        ("http.status_code", "201"),
                        ("error.type", "WebSocketDisconnect"),
                        ("otel.trace_id", "72df520af2bde7a5240031ead750e5f3"),
                    ],
                    [],
                ),
                r#type: "custom".into(),
                span_events: ThinVec::new(),
                span_links: ThinVec::new(),
                ..Default::default()
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
                span_id: 2594128270069917171,
                parent_id: 0,
                start: start_time
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as i64,
                duration: 200000000,
                error: true,
                env: "staging".into(),
                span_kind: DdSpanKind::Internal,
                attributes: attributes(
                    [
                        ("otel.scope.name", "ddtracer"),
                        ("otel.scope.version", "v2"),
                        ("otel.status_code", "Error"),
                        ("error.message", "201"),
                        ("http.method", "POST"),
                        ("url.path", "/uploads/4"),
                        ("url.scheme", "https"),
                        ("http.route", "/uploads/:document_id"),
                        ("http.status_code", "201"),
                        ("error.type", "WebSocketDisconnect"),
                        ("otel.trace_id", "72df520af2bde7a5240031ead750e5f3"),
                    ],
                    [],
                ),
                r#type: "custom".into(),
                span_events: ThinVec::new(),
                span_links: ThinVec::new(),
                ..Default::default()
            },
        },
    ]
}

#[cfg(test)]
mod tests {
    use std::fmt::Write;

    use libdd_trace_utils::span::vec_map::VecMap;
    use opentelemetry::KeyValue;
    use opentelemetry_sdk::Resource;

    use crate::mappings::{
        transform::{otel_span_to_dd_span, CowStr, DdAttributeValue},
        DdSpan,
    };

    use crate::mappings::transform::transform_tests::{test_cases, test_span_to_sdk_span};

    /// `v1::Span` is invariant over its text lifetime: shortens the `'static` expected span to the
    /// lifetime of the output span.
    fn downcast_lifetime<'a: 'b, 'b>(span: DdSpan<'a>) -> DdSpan<'b> {
        unsafe { std::mem::transmute(span) }
    }

    /// `v1::Span` doesn't implement `PartialEq`, attribute maps are compared ignoring order.
    #[track_caller]
    fn assert_span_eq<'a>(output: &DdSpan<'a>, expected: &DdSpan<'a>, name: &str) {
        let scalars = |s: &DdSpan| {
            format!(
                "{:?} {:?}",
                (&s.service, &s.name, &s.resource, &s.r#type),
                (
                    s.span_id,
                    s.parent_id,
                    s.start,
                    s.duration,
                    s.error,
                    s.span_kind,
                    &s.env,
                    &s.version,
                    &s.component,
                )
            )
        };
        assert_eq!(scalars(output), scalars(expected), "Test {name} failed");

        hashmap_diff(&output.attributes, &expected.attributes);
        assert!(
            output.attributes.slow_compare(&expected.attributes),
            "Test {name} failed: attributes differ"
        );

        assert_eq!(
            output.span_events.len(),
            expected.span_events.len(),
            "Test {name} failed: span events differ"
        );
        for (o, e) in output.span_events.iter().zip(&expected.span_events) {
            assert_eq!(
                (o.time_unix_nano, &o.name),
                (e.time_unix_nano, &e.name),
                "Test {name} failed: span event differs"
            );
            assert!(
                o.attributes.slow_compare(&e.attributes),
                "Test {name} failed: span event attributes differ: {:?} != {:?}",
                o.attributes,
                e.attributes
            );
        }

        assert_eq!(
            output.span_links.len(),
            expected.span_links.len(),
            "Test {name} failed: span links differ"
        );
        for (o, e) in output.span_links.iter().zip(&expected.span_links) {
            assert_eq!(
                (o.trace_id, o.span_id, &o.tracestate, o.flags),
                (e.trace_id, e.span_id, &e.tracestate, e.flags),
                "Test {name} failed: span link differs"
            );
            assert!(
                o.attributes.slow_compare(&e.attributes),
                "Test {name} failed: span link attributes differ: {:?} != {:?}",
                o.attributes,
                e.attributes
            );
        }
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
            let output =
                otel_span_to_dd_span(&test_span_to_sdk_span(&test.input_span), &input_resource);
            assert_span_eq(&output, &downcast_lifetime(test.expected_out), test.name);
        }
    }

    #[track_caller]
    fn hashmap_diff<'a>(
        output: &VecMap<CowStr<'a>, DdAttributeValue<'a>>,
        expected: &VecMap<CowStr<'a>, DdAttributeValue<'a>>,
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
        if !output.slow_compare(expected) {
            eprintln!("Hashmaps are not equal :\n{message}");
        }
    }
}
