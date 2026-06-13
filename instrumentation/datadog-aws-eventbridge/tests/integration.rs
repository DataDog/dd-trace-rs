// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for EventBridgeInterceptor.

use aws_sdk_eventbridge::types::PutEventsRequestEntry;
use aws_types::SdkConfig;
use datadog_aws_core_test_utils::integration_test_helpers::{
    span_attrs, split_traceparent, TestHarness,
};

use datadog_aws_eventbridge::ConfigExt as _;

fn eventbridge_client(cfg: &SdkConfig) -> aws_sdk_eventbridge::Client {
    let config = aws_sdk_eventbridge::config::Builder::from(cfg)
        .datadog_tracing()
        .build();
    aws_sdk_eventbridge::Client::from_conf(config)
}

#[tokio::test]
async fn eventbridge_put_events_creates_span_and_injects_detail() {
    let harness = TestHarness::ok().await;
    let client = eventbridge_client(&harness.sdk_config());

    let entry = PutEventsRequestEntry::builder()
        .source("my.source")
        .detail_type("MyType")
        .detail(r#"{"key":"value"}"#)
        .build();

    let _ = client.put_events().entries(entry).send().await;

    let spans = harness.finished_spans();
    assert_eq!(spans.len(), 1);
    let attrs = span_attrs(&spans[0]);
    assert_eq!(spans[0].name, "eventbridge.request");
    assert_eq!(attrs["aws.service"], "EventBridge");
    assert_eq!(attrs["aws.operation"], "PutEvents");
    assert_eq!(attrs["operation.name"], "aws.eventbridge.request");
    assert_eq!(attrs["resource.name"], "EventBridge.PutEvents");
    assert!(!attrs.contains_key("rulename"));

    let bodies = harness.server.bodies();
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
async fn eventbridge_put_events_with_bus_name_creates_span() {
    let harness = TestHarness::ok().await;
    let client = eventbridge_client(&harness.sdk_config());

    let entry = PutEventsRequestEntry::builder()
        .source("my.source")
        .detail_type("MyType")
        .detail(r#"{"key":"value"}"#)
        .event_bus_name("my-bus")
        .build();

    let _ = client.put_events().entries(entry).send().await;

    let spans = harness.finished_spans();
    assert_eq!(spans.len(), 1);
    assert_eq!(span_attrs(&spans[0])["aws.operation"], "PutEvents");
}

#[tokio::test]
async fn eventbridge_put_events_multi_entry_creates_single_span() {
    let harness = TestHarness::ok().await;
    let client = eventbridge_client(&harness.sdk_config());

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

    let spans = harness.finished_spans();
    assert_eq!(spans.len(), 1);
    assert_eq!(span_attrs(&spans[0])["aws.operation"], "PutEvents");
}

#[tokio::test]
async fn eventbridge_put_rule_creates_span_with_rulename() {
    let harness = TestHarness::ok().await;
    let client = eventbridge_client(&harness.sdk_config());

    let _ = client.put_rule().name("my-rule").send().await;

    let spans = harness.finished_spans();
    assert_eq!(spans.len(), 1);
    let attrs = span_attrs(&spans[0]);
    assert_eq!(attrs["aws.operation"], "PutRule");
    assert_eq!(attrs["rulename"], "my-rule");
}

#[tokio::test]
async fn eventbridge_put_targets_creates_span_with_rulename() {
    let harness = TestHarness::ok().await;
    let client = eventbridge_client(&harness.sdk_config());

    let _ = client.put_targets().rule("my-rule").send().await;

    let spans = harness.finished_spans();
    assert_eq!(spans.len(), 1);
    let attrs = span_attrs(&spans[0]);
    assert_eq!(attrs["aws.operation"], "PutTargets");
    assert_eq!(attrs["rulename"], "my-rule");
}
