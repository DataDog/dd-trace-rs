// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for EventBridgeInterceptor.
//!
//! Tests are serialized with `#[serial]` because `init_test_tracer` sets the
//! global OTel tracer provider and propagator. Concurrent tests would race on
//! that global state, causing spans to land in the wrong exporter.

use aws_sdk_eventbridge::types::PutEventsRequestEntry;
use aws_types::SdkConfig;
use datadog_aws_core::integration_test_helpers::{
    init_test_tracer, mock_aws, sdk_config, span_attrs, split_traceparent,
};
use serial_test::serial;

use datadog_aws_eventbridge::EventBridgeInterceptor;

fn eventbridge_client(cfg: &SdkConfig) -> aws_sdk_eventbridge::Client {
    let config = aws_sdk_eventbridge::config::Builder::from(cfg)
        .interceptor(EventBridgeInterceptor::new())
        .build();
    aws_sdk_eventbridge::Client::from_conf(config)
}

#[tokio::test]
#[serial]
async fn eventbridge_put_events_creates_span_and_injects_detail() {
    let exporter = init_test_tracer();
    let (url, _srv, captured) = mock_aws(200).await;
    let client = eventbridge_client(&sdk_config(&url));

    let entry = PutEventsRequestEntry::builder()
        .source("my.source")
        .detail_type("MyType")
        .detail(r#"{"key":"value"}"#)
        .build();

    let _ = client.put_events().entries(entry).send().await;

    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 1);
    let attrs = span_attrs(&spans[0]);
    assert_eq!(spans[0].name, "eventbridge.request");
    assert_eq!(attrs["aws.service"], "EventBridge");
    assert_eq!(attrs["aws.operation"], "PutEvents");
    assert_eq!(attrs["operation.name"], "aws.eventbridge.request");
    assert_eq!(attrs["resource.name"], "EventBridge.PutEvents");

    let bodies = captured.lock().unwrap();
    assert_eq!(bodies.len(), 1);
    let body: serde_json::Value = serde_json::from_str(&bodies[0]).unwrap();
    let entries = body["Entries"].as_array().unwrap();
    let detail: serde_json::Value =
        serde_json::from_str(entries[0]["Detail"].as_str().unwrap()).unwrap();
    let tp = detail["_datadog"]["traceparent"]
        .as_str()
        .expect("_datadog.traceparent should be a string");
    let (injected_trace_id, injected_parent_id) = split_traceparent(tp);
    assert_eq!(
        injected_trace_id,
        format!("{}", spans[0].span_context.trace_id())
    );
    assert_eq!(
        injected_parent_id,
        format!("{}", spans[0].span_context.span_id())
    );
}

#[tokio::test]
#[serial]
async fn eventbridge_put_events_with_bus_name_creates_span() {
    let exporter = init_test_tracer();
    let (url, _srv, _bodies) = mock_aws(200).await;
    let client = eventbridge_client(&sdk_config(&url));

    let entry = PutEventsRequestEntry::builder()
        .source("my.source")
        .detail_type("MyType")
        .detail(r#"{"key":"value"}"#)
        .event_bus_name("my-bus")
        .build();

    let _ = client.put_events().entries(entry).send().await;

    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 1);
    assert_eq!(span_attrs(&spans[0])["aws.operation"], "PutEvents");
}

#[tokio::test]
#[serial]
async fn eventbridge_put_events_multi_entry_creates_single_span() {
    let exporter = init_test_tracer();
    let (url, _srv, _bodies) = mock_aws(200).await;
    let client = eventbridge_client(&sdk_config(&url));

    let entry1 = PutEventsRequestEntry::builder()
        .source("src1")
        .detail_type("T1")
        .detail(r#"{"a":1}"#)
        .event_bus_name("bus-1")
        .build();
    let entry2 = PutEventsRequestEntry::builder()
        .source("src2")
        .detail_type("T2")
        .detail(r#"{"b":2}"#)
        .build();

    let _ = client
        .put_events()
        .entries(entry1)
        .entries(entry2)
        .send()
        .await;

    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 1);
    assert_eq!(span_attrs(&spans[0])["aws.operation"], "PutEvents");
}

#[tokio::test]
#[serial]
async fn eventbridge_put_rule_creates_span_with_rulename() {
    let exporter = init_test_tracer();
    let (url, _srv, _bodies) = mock_aws(200).await;
    let client = eventbridge_client(&sdk_config(&url));

    let _ = client.put_rule().name("my-rule").send().await;

    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 1);
    let attrs = span_attrs(&spans[0]);
    assert_eq!(attrs["aws.operation"], "PutRule");
    assert_eq!(attrs["rulename"], "my-rule");
}

#[tokio::test]
#[serial]
async fn eventbridge_put_targets_creates_span_with_rulename() {
    let exporter = init_test_tracer();
    let (url, _srv, _bodies) = mock_aws(200).await;
    let client = eventbridge_client(&sdk_config(&url));

    let _ = client.put_targets().rule("my-rule").send().await;

    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 1);
    let attrs = span_attrs(&spans[0]);
    assert_eq!(attrs["aws.operation"], "PutTargets");
    assert_eq!(attrs["rulename"], "my-rule");
}
