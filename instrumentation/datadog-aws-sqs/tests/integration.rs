// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for SqsInterceptor.
//!
//! Tests are serialized with `#[serial]` because `init_test_tracer` sets the
//! global OTel tracer provider and propagator. Concurrent tests would race on
//! that global state, causing spans to land in the wrong exporter.

use aws_sdk_sqs::types::SendMessageBatchRequestEntry;
use aws_types::SdkConfig;
use datadog_aws_core_test_utils::integration_test_helpers::{
    extract_traceparent, span_attrs, split_traceparent, TestHarness,
};
use opentelemetry::trace::{SpanKind, TraceContextExt, Tracer};
use opentelemetry::{global, Context};
use serial_test::serial;

use datadog_aws_sqs::ConfigExt as _;

fn sqs_client(cfg: &SdkConfig) -> aws_sdk_sqs::Client {
    let config = aws_sdk_sqs::config::Builder::from(cfg)
        .datadog_tracing()
        .build();
    aws_sdk_sqs::Client::from_conf(config)
}

const QUEUE_URL: &str = "https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue";
const QUEUE_URL_TRAILING: &str = "https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue/";
const HTTP_200: &str = "200";
const HTTP_400: &str = "400";

#[tokio::test]
#[serial]
async fn sqs_send_message_creates_span_with_tags_and_injects_context() {
    let harness = TestHarness::ok().await;
    let client = sqs_client(&harness.sdk_config());

    let _ = client
        .send_message()
        .queue_url(QUEUE_URL)
        .message_body("hello")
        .send()
        .await;

    let spans = harness.finished_spans();
    assert_eq!(spans.len(), 1);
    let attrs = span_attrs(&spans[0]);

    assert_eq!(spans[0].name, "sqs.request");
    assert_eq!(attrs["aws.service"], "SQS");
    assert_eq!(attrs["aws.operation"], "SendMessage");
    assert_eq!(attrs["aws.region"], "us-east-1");
    assert_eq!(attrs["aws.partition"], "aws");
    assert_eq!(attrs["operation.name"], "aws.sqs.request");
    assert_eq!(attrs["resource.name"], "SQS.SendMessage");
    assert_eq!(attrs["span.kind"], "client");
    assert_eq!(attrs["queuename"], "MyQueue");
    assert_eq!(
        attrs["cloud.resource_id"],
        "arn:aws:sqs:us-east-1:123456789012:MyQueue"
    );
    assert_eq!(attrs["messaging.system"], "amazonsqs");
    assert_eq!(attrs["http.status_code"], HTTP_200);
    assert_eq!(attrs["aws.request_id"], "test_req");
    assert_eq!(spans[0].span_kind, SpanKind::Client);

    let bodies = harness.server.bodies();
    assert_eq!(bodies.len(), 1);
    assert!(
        bodies[0].contains("_datadog"),
        "body should contain _datadog attribute name"
    );
    let tp = extract_traceparent(&bodies[0]).expect("traceparent should be in body");
    let (injected_trace_id, injected_parent_id) = split_traceparent(&tp);
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
async fn sqs_send_message_batch_creates_span_and_injects_into_all_entries() {
    let harness = TestHarness::ok().await;
    let client = sqs_client(&harness.sdk_config());

    let entry1 = SendMessageBatchRequestEntry::builder()
        .id("1")
        .message_body("body1")
        .build()
        .unwrap();
    let entry2 = SendMessageBatchRequestEntry::builder()
        .id("2")
        .message_body("body2")
        .build()
        .unwrap();

    let _ = client
        .send_message_batch()
        .queue_url(QUEUE_URL)
        .entries(entry1)
        .entries(entry2)
        .send()
        .await;

    let spans = harness.finished_spans();
    assert_eq!(spans.len(), 1);
    let attrs = span_attrs(&spans[0]);
    assert_eq!(spans[0].name, "sqs.request");
    assert_eq!(attrs["aws.operation"], "SendMessageBatch");
    assert_eq!(attrs["queuename"], "MyQueue");

    let bodies = harness.server.bodies();
    assert_eq!(bodies.len(), 1);
    assert!(
        bodies[0].contains("_datadog"),
        "body should contain _datadog attribute"
    );
    assert!(
        bodies[0].contains("traceparent"),
        "body should contain traceparent"
    );
}

#[tokio::test]
#[serial]
async fn sqs_receive_message_creates_span_with_queue_tags() {
    let harness = TestHarness::ok().await;
    let client = sqs_client(&harness.sdk_config());

    let _ = client.receive_message().queue_url(QUEUE_URL).send().await;

    let spans = harness.finished_spans();
    assert_eq!(spans.len(), 1);
    let attrs = span_attrs(&spans[0]);
    assert_eq!(attrs["aws.operation"], "ReceiveMessage");
    assert_eq!(attrs["queuename"], "MyQueue");
    assert_eq!(
        attrs["cloud.resource_id"],
        "arn:aws:sqs:us-east-1:123456789012:MyQueue"
    );

    let bodies = harness.server.bodies();
    assert_eq!(bodies.len(), 1);
    assert!(
        bodies[0].contains("_datadog"),
        "body should request _datadog message attribute"
    );
}

#[tokio::test]
#[serial]
async fn sqs_delete_message_creates_span_with_queue_tags() {
    let harness = TestHarness::ok().await;
    let client = sqs_client(&harness.sdk_config());

    let _ = client
        .delete_message()
        .queue_url(QUEUE_URL)
        .receipt_handle("handle")
        .send()
        .await;

    let spans = harness.finished_spans();
    assert_eq!(spans.len(), 1);
    let attrs = span_attrs(&spans[0]);
    assert_eq!(attrs["aws.operation"], "DeleteMessage");
    assert_eq!(attrs["queuename"], "MyQueue");
}

#[tokio::test]
#[serial]
async fn sqs_delete_message_batch_creates_span_with_queue_tags() {
    let harness = TestHarness::ok().await;
    let client = sqs_client(&harness.sdk_config());

    let _ = client
        .delete_message_batch()
        .queue_url(QUEUE_URL)
        .send()
        .await;

    let spans = harness.finished_spans();
    assert_eq!(spans.len(), 1);
    let attrs = span_attrs(&spans[0]);
    assert_eq!(attrs["aws.operation"], "DeleteMessageBatch");
    assert_eq!(attrs["queuename"], "MyQueue");
}

#[tokio::test]
#[serial]
async fn sqs_queue_url_trailing_slash_parsed_correctly() {
    let harness = TestHarness::ok().await;
    let client = sqs_client(&harness.sdk_config());

    let _ = client
        .send_message()
        .queue_url(QUEUE_URL_TRAILING)
        .message_body("hello")
        .send()
        .await;

    let spans = harness.finished_spans();
    let attrs = span_attrs(&spans[0]);
    assert_eq!(attrs["queuename"], "MyQueue");
    assert_eq!(
        attrs["cloud.resource_id"],
        "arn:aws:sqs:us-east-1:123456789012:MyQueue"
    );
}

#[tokio::test]
#[serial]
async fn sqs_error_response_sets_span_error_status_and_http_code() {
    let harness = TestHarness::bad_request().await;
    let client = sqs_client(&harness.sdk_config());

    let _ = client
        .send_message()
        .queue_url(QUEUE_URL)
        .message_body("hello")
        .send()
        .await;

    let spans = harness.finished_spans();
    assert_eq!(spans.len(), 1);
    let attrs = span_attrs(&spans[0]);
    assert_eq!(attrs["http.status_code"], HTTP_400);
    assert!(matches!(
        spans[0].status,
        opentelemetry::trace::Status::Error { .. }
    ));
}

#[tokio::test]
#[serial]
async fn sqs_send_message_propagates_parent_context() {
    let harness = TestHarness::ok().await;
    let client = sqs_client(&harness.sdk_config());

    let tracer = global::tracer("test");
    let parent_span = tracer.start("parent");
    let parent_cx = Context::current().with_span(parent_span);

    let _guard = parent_cx.clone().attach();
    let _ = client
        .send_message()
        .queue_url(QUEUE_URL)
        .message_body("hello")
        .send()
        .await;

    let spans = harness.finished_spans();
    let sqs_span = spans
        .iter()
        .find(|s| s.name == "sqs.request")
        .expect("sqs.request span not found");

    assert_eq!(
        sqs_span.parent_span_id,
        parent_cx.span().span_context().span_id()
    );

    let bodies = harness.server.bodies();
    let tp = extract_traceparent(&bodies[0]).expect("traceparent should be in body");
    let (_, injected_parent_id) = split_traceparent(&tp);
    assert_eq!(
        injected_parent_id,
        format!("{}", sqs_span.span_context.span_id())
    );
}
