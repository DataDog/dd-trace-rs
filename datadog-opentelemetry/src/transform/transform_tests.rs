// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    fmt::{Debug, Write},
    time::{Duration, SystemTime},
    vec,
};

use datadog_trace_utils::span::SpanBytes;
use opentelemetry::{
    trace::{SpanContext, SpanKind, Status, TraceState},
    InstrumentationScope, KeyValue, SpanId, TraceFlags, TraceId,
};
use opentelemetry_sdk::{
    trace::{SpanData, SpanEvents, SpanLinks},
    Resource,
};
use tinybytes::BytesString;

use crate::transform::otel_span_to_dd_span;

#[test]
fn test_otel_span_to_dd_span() {
    struct Test {
        name: &'static str,
        input_ressource: Vec<(&'static str, &'static str)>,
        input_span: SpanData,
        expected_out: SpanBytes,
    }

    let start_time = SystemTime::now();
    let end_time = start_time + std::time::Duration::from_nanos(200000000);

    let tests: Vec<Test> = vec![Test {
        name: "basic",
        input_ressource: vec![
            ("service.name", "pylons"),
            ("service.version", "v1.2.3"),
            ("env", "staging"),
        ],
        input_span: SpanData {
            span_context: SpanContext::new(
                TraceId::from_bytes([
                    0x72, 0xdf, 0x52, 0xa, 0xf2, 0xbd, 0xe7, 0xa5, 0x24, 0x0, 0x31, 0xea, 0xd7,
                    0x50, 0xe5, 0xf3,
                ]),
                SpanId::from_bytes([0x24, 0x0, 0x31, 0xea, 0xd7, 0x50, 0xe5, 0xf3]),
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
            events: SpanEvents::default(),
            links: SpanLinks::default(),
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
                ("error.msg".into(), "Error".into()),
                // ("error.type".into(), "Error".into()),
                // ("error.stack".into(), "Error".into()),
                ("span.kind".into(), "server".into()),
                // ("_dd.span_events.has_exception".into(), "true".into()),
            ]),
            metrics: HashMap::from_iter([
                ("_top_level".into(), 1.0),
                ("approx".into(), 1.2),
                ("count".into(), 2.0),
            ]),
            r#type: "web".into(),
            ..Default::default()
        },
    }];

    for test in tests {
        let input_ressource = Resource::builder_empty()
            .with_attributes(
                test.input_ressource
                    .into_iter()
                    .map(|(k, v)| KeyValue::new(k, v)),
            )
            .build();
        let output = otel_span_to_dd_span(test.input_span, &input_ressource);
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
    let mut a = output.into_iter().collect::<Vec<_>>();
    let mut b = expected.into_iter().collect::<Vec<_>>();
    a.sort_by_key(|(k, _)| k.as_str());
    b.sort_by_key(|(k, _)| k.as_str());
    let mut a = a.into_iter().peekable();
    let mut b = b.into_iter().peekable();
    let mut message = String::new();
    loop {
        match (a.peek(), b.peek()) {
            (Some(a_v), Some(b_v)) => match a_v.0.as_str().cmp(b_v.0.as_str()) {
                std::cmp::Ordering::Less => {
                    write!(&mut message, "a  :+{:?}\n", a_v).unwrap();
                    a.next();
                }
                std::cmp::Ordering::Equal => {
                    if a_v.1 != b_v.1 {
                        write!(&mut message, "a!b: {:?} != {:?}\n", a_v, b_v).unwrap();
                    } else {
                        write!(&mut message, "a b: {:?}\n", b_v).unwrap();
                    }
                    a.next();
                    b.next();
                }
                std::cmp::Ordering::Greater => {
                    write!(&mut message, "  b:+{:?}\n", b_v).unwrap();
                    b.next();
                }
            },
            (None, None) => break,
            (Some(a_v), None) => {
                write!(&mut message, "a  :+{:?}\n", a_v).unwrap();
                a.next();
            }
            (None, Some(b_v)) => {
                write!(&mut message, "  b:+{:?}\n", b_v).unwrap();
                b.next();
            }
        }
    }
    if output != expected {
        eprintln!("Hashmaps are not equal :\n{}", message);
    }
}
