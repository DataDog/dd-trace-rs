// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for SqsInterceptor.

use aws_sdk_sqs::types::{DeleteMessageBatchRequestEntry, SendMessageBatchRequestEntry};
use aws_types::SdkConfig;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use datadog_aws_core::attribute_keys::MESSAGING_BATCH_MESSAGE_COUNT;
use datadog_aws_core_test_utils::integration_test_helpers::{
    extract_traceparent, span_attrs, split_traceparent, TestHarness,
};
use opentelemetry::trace::{
    SpanContext, SpanId, SpanKind, TraceContextExt, TraceFlags, TraceId, TraceState,
};
use opentelemetry::KeyValue;

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
const MESSAGING_MESSAGE_ID: &str = "messaging.message.id";

fn sns_envelope_body(data_type: &str, value: impl Into<serde_json::Value>) -> String {
    serde_json::json!({
        "Type": "Notification",
        "MessageId": "sns-message-id",
        "TopicArn": "arn:aws:sns:us-east-1:123456789012:MyTopic",
        "Message": "hello",
        "MessageAttributes": {
            "_datadog": {
                "Type": data_type,
                "Value": value.into()
            }
        }
    })
    .to_string()
}

#[tokio::test]
async fn sqs_send_message_creates_span_with_tags_and_injects_context() {
    let response_body = serde_json::json!({
        "MessageId": "producer-message-id"
    })
    .to_string();
    let harness = TestHarness::ok_with_body(response_body).await;
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
    assert_eq!(attrs[MESSAGING_MESSAGE_ID], "producer-message-id");
    assert_eq!(attrs["http.status_code"], HTTP_200);
    assert_eq!(attrs["aws.request_id"], harness.server.request_id());
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
    assert_eq!(attrs[MESSAGING_BATCH_MESSAGE_COUNT], "2");

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
    assert_eq!(attrs[MESSAGING_BATCH_MESSAGE_COUNT], "0");
    assert_eq!(spans[0].events.events.len(), 1);
    assert_eq!(spans[0].events.events[0].name, "sqs.receive.messages");
    assert!(spans[0].events.events[0].attributes.is_empty());

    let bodies = harness.server.bodies();
    assert_eq!(bodies.len(), 1);
    assert!(
        bodies[0].contains("_datadog"),
        "body should request _datadog message attribute"
    );
}

#[tokio::test]
async fn sqs_receive_message_links_span_to_message_context() {
    let message_span_context = SpanContext::new(
        TraceId::from_hex("11111111111111111111111111111111").unwrap(),
        SpanId::from_hex("2222222222222222").unwrap(),
        TraceFlags::SAMPLED,
        true,
        TraceState::NONE,
    );
    let datadog_attr = serde_json::json!({
        "traceparent": "00-11111111111111111111111111111111-2222222222222222-01"
    })
    .to_string();
    let response_body = serde_json::json!({
        "Messages": [
            {
                "MessageId": "message-id",
                "ReceiptHandle": "receipt-handle",
                "Body": "hello",
                "MessageAttributes": {
                    "_datadog": {
                        "DataType": "String",
                        "StringValue": datadog_attr
                    }
                }
            }
        ]
    })
    .to_string();

    let harness = TestHarness::ok_with_body(response_body).await;
    let client = sqs_client(&harness.sdk_config());

    let output = client
        .receive_message()
        .queue_url(QUEUE_URL)
        .send()
        .await
        .unwrap();
    assert_eq!(output.messages().len(), 1);
    let extracted_context = datadog_aws_sqs::extract_context(&output.messages()[0]).unwrap();
    assert_eq!(
        extracted_context.span().span_context(),
        &message_span_context
    );

    let spans = harness.finished_spans();
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].links.links.len(), 1);
    assert_eq!(spans[0].links.links[0].span_context, message_span_context);
    assert_eq!(
        spans[0].links.links[0].attributes,
        vec![KeyValue::new(MESSAGING_MESSAGE_ID, "message-id")]
    );
    let attrs = span_attrs(&spans[0]);
    assert_eq!(attrs[MESSAGING_BATCH_MESSAGE_COUNT], "1");
    assert_eq!(spans[0].events.events.len(), 1);
    assert_eq!(spans[0].events.events[0].name, "sqs.receive.messages");
    assert!(spans[0].events.events[0].attributes.is_empty());
}

#[tokio::test]
async fn sqs_receive_message_links_span_to_sns_envelope_string_context() {
    let message_span_context = SpanContext::new(
        TraceId::from_hex("11111111111111111111111111111111").unwrap(),
        SpanId::from_hex("2222222222222222").unwrap(),
        TraceFlags::SAMPLED,
        true,
        TraceState::NONE,
    );
    let datadog_attr = serde_json::json!({
        "traceparent": "00-11111111111111111111111111111111-2222222222222222-01"
    })
    .to_string();
    let sns_body = sns_envelope_body("String", datadog_attr);
    let response_body = serde_json::json!({
        "Messages": [
            {
                "MessageId": "sqs-message-id",
                "ReceiptHandle": "receipt-handle",
                "Body": sns_body
            }
        ]
    })
    .to_string();

    let harness = TestHarness::ok_with_body(response_body).await;
    let client = sqs_client(&harness.sdk_config());

    let output = client
        .receive_message()
        .queue_url(QUEUE_URL)
        .send()
        .await
        .unwrap();
    assert_eq!(output.messages().len(), 1);
    let extracted_context = datadog_aws_sqs::extract_context(&output.messages()[0]).unwrap();
    assert_eq!(
        extracted_context.span().span_context(),
        &message_span_context
    );

    let spans = harness.finished_spans();
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].links.links.len(), 1);
    assert_eq!(spans[0].links.links[0].span_context, message_span_context);
    assert_eq!(
        spans[0].links.links[0].attributes,
        vec![KeyValue::new(MESSAGING_MESSAGE_ID, "sqs-message-id")]
    );
}

#[tokio::test]
async fn sqs_receive_message_links_span_to_sns_envelope_context() {
    let message_span_context = SpanContext::new(
        TraceId::from_hex("11111111111111111111111111111111").unwrap(),
        SpanId::from_hex("2222222222222222").unwrap(),
        TraceFlags::SAMPLED,
        true,
        TraceState::NONE,
    );
    let datadog_attr = BASE64_STANDARD.encode(
        serde_json::to_vec(&serde_json::json!({
            "traceparent": "00-11111111111111111111111111111111-2222222222222222-01"
        }))
        .unwrap(),
    );
    let sns_body = sns_envelope_body("Binary", datadog_attr);
    let response_body = serde_json::json!({
        "Messages": [
            {
                "MessageId": "sqs-message-id",
                "ReceiptHandle": "receipt-handle",
                "Body": sns_body
            }
        ]
    })
    .to_string();

    let harness = TestHarness::ok_with_body(response_body).await;
    let client = sqs_client(&harness.sdk_config());

    let output = client
        .receive_message()
        .queue_url(QUEUE_URL)
        .send()
        .await
        .unwrap();
    assert_eq!(output.messages().len(), 1);
    let extracted_context = datadog_aws_sqs::extract_context(&output.messages()[0]).unwrap();
    assert_eq!(
        extracted_context.span().span_context(),
        &message_span_context
    );

    let spans = harness.finished_spans();
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].links.links.len(), 1);
    assert_eq!(spans[0].links.links[0].span_context, message_span_context);
    assert_eq!(
        spans[0].links.links[0].attributes,
        vec![KeyValue::new(MESSAGING_MESSAGE_ID, "sqs-message-id")]
    );
}

#[tokio::test]
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
async fn sqs_delete_message_batch_creates_span_with_queue_tags() {
    let harness = TestHarness::ok().await;
    let client = sqs_client(&harness.sdk_config());

    let entry1 = DeleteMessageBatchRequestEntry::builder()
        .id("1")
        .receipt_handle("handle1")
        .build()
        .unwrap();
    let entry2 = DeleteMessageBatchRequestEntry::builder()
        .id("2")
        .receipt_handle("handle2")
        .build()
        .unwrap();

    let _ = client
        .delete_message_batch()
        .queue_url(QUEUE_URL)
        .entries(entry1)
        .entries(entry2)
        .send()
        .await;

    let spans = harness.finished_spans();
    assert_eq!(spans.len(), 1);
    let attrs = span_attrs(&spans[0]);
    assert_eq!(attrs["aws.operation"], "DeleteMessageBatch");
    assert_eq!(attrs["queuename"], "MyQueue");
    assert_eq!(attrs[MESSAGING_BATCH_MESSAGE_COUNT], "2");
}

#[tokio::test]
async fn sqs_queue_scoped_operations_create_spans_with_queue_tags() {
    let harness = TestHarness::ok().await;
    let client = sqs_client(&harness.sdk_config());

    let _ = client.purge_queue().queue_url(QUEUE_URL).send().await;
    let _ = client.delete_queue().queue_url(QUEUE_URL).send().await;
    let _ = client
        .get_queue_attributes()
        .queue_url(QUEUE_URL)
        .send()
        .await;
    let _ = client
        .change_message_visibility()
        .queue_url(QUEUE_URL)
        .receipt_handle("handle")
        .visibility_timeout(30)
        .send()
        .await;

    let spans = harness.finished_spans();
    assert_eq!(spans.len(), 4);
    let mut operations = Vec::new();
    for span in spans {
        let attrs = span_attrs(&span);
        operations.push(attrs["aws.operation"].clone());
        assert_eq!(attrs["queuename"], "MyQueue");
        assert_eq!(
            attrs["cloud.resource_id"],
            "arn:aws:sqs:us-east-1:123456789012:MyQueue"
        );
    }
    operations.sort();
    assert_eq!(
        operations,
        [
            "ChangeMessageVisibility",
            "DeleteQueue",
            "GetQueueAttributes",
            "PurgeQueue",
        ]
    );
}

#[tokio::test]
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
