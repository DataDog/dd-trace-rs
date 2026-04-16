// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for SnsInterceptor.
//!
//! Tests are serialized with `#[serial]` because `init_test_tracer` sets the
//! global OTel tracer provider and propagator. Concurrent tests would race on
//! that global state, causing spans to land in the wrong exporter.

use aws_types::SdkConfig;
use datadog_aws_core::integration_test_helpers::{
    init_test_tracer, mock_aws, sdk_config, span_attrs,
};
use serial_test::serial;

use datadog_aws_sns::SnsInterceptor;

fn sns_client(cfg: &SdkConfig) -> aws_sdk_sns::Client {
    let config = aws_sdk_sns::config::Builder::from(cfg)
        .interceptor(SnsInterceptor::new())
        .build();
    aws_sdk_sns::Client::from_conf(config)
}

const TOPIC_ARN: &str = "arn:aws:sns:us-east-1:111111111111:MyTopic";
const TARGET_ARN: &str = "arn:aws:sns:us-east-1:111111111111:MyTarget";

#[tokio::test]
#[serial]
async fn sns_publish_with_topic_creates_span_and_injects_binary_context() {
    let exporter = init_test_tracer();
    let (url, _srv, captured) = mock_aws(200).await;
    let client = sns_client(&sdk_config(&url));

    let _ = client
        .publish()
        .topic_arn(TOPIC_ARN)
        .message("hello")
        .send()
        .await;

    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 1);
    let attrs = span_attrs(&spans[0]);
    assert_eq!(spans[0].name, "sns.request");
    assert_eq!(attrs["aws.service"], "SNS");
    assert_eq!(attrs["aws.operation"], "Publish");
    assert_eq!(attrs["topicname"], "MyTopic");
    assert_eq!(attrs["operation.name"], "aws.sns.request");
    assert_eq!(attrs["resource.name"], "SNS.Publish");

    let bodies = captured.lock().unwrap();
    assert_eq!(bodies.len(), 1);
    assert!(
        bodies[0].contains("_datadog"),
        "body should contain _datadog attribute name"
    );
    assert!(
        bodies[0].contains("Binary"),
        "body should indicate Binary data type"
    );
}

#[tokio::test]
#[serial]
async fn sns_publish_with_target_sets_targetname_tag() {
    let exporter = init_test_tracer();
    let (url, _srv, _bodies) = mock_aws(200).await;
    let client = sns_client(&sdk_config(&url));

    let _ = client
        .publish()
        .target_arn(TARGET_ARN)
        .message("hello")
        .send()
        .await;

    let spans = exporter.get_finished_spans().unwrap();
    let attrs = span_attrs(&spans[0]);
    assert_eq!(attrs["targetname"], "MyTarget");
    assert!(!attrs.contains_key("topicname"));
}

#[tokio::test]
#[serial]
async fn sns_publish_batch_creates_span_with_topicname() {
    let exporter = init_test_tracer();
    let (url, _srv, captured) = mock_aws(200).await;
    let client = sns_client(&sdk_config(&url));

    let entry = aws_sdk_sns::types::PublishBatchRequestEntry::builder()
        .id("1")
        .message("body")
        .build()
        .unwrap();

    let _ = client
        .publish_batch()
        .topic_arn(TOPIC_ARN)
        .publish_batch_request_entries(entry)
        .send()
        .await;

    let spans = exporter.get_finished_spans().unwrap();
    let attrs = span_attrs(&spans[0]);
    assert_eq!(spans[0].name, "sns.request");
    assert_eq!(attrs["aws.operation"], "PublishBatch");
    assert_eq!(attrs["topicname"], "MyTopic");

    let bodies = captured.lock().unwrap();
    assert_eq!(bodies.len(), 1);
    assert!(
        bodies[0].contains("_datadog"),
        "batch body should contain _datadog attribute"
    );
    assert!(
        bodies[0].contains("Binary"),
        "batch body should indicate Binary data type"
    );
}

#[tokio::test]
#[serial]
async fn sns_subscribe_creates_span_with_topicname() {
    let exporter = init_test_tracer();
    let (url, _srv, _bodies) = mock_aws(200).await;
    let client = sns_client(&sdk_config(&url));

    let _ = client
        .subscribe()
        .topic_arn(TOPIC_ARN)
        .protocol("sqs")
        .send()
        .await;

    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 1);
    let attrs = span_attrs(&spans[0]);
    assert_eq!(attrs["aws.operation"], "Subscribe");
    assert_eq!(attrs["topicname"], "MyTopic");
}

#[tokio::test]
#[serial]
async fn sns_create_topic_uses_name_field_not_arn() {
    let exporter = init_test_tracer();
    let (url, _srv, _bodies) = mock_aws(200).await;
    let client = sns_client(&sdk_config(&url));

    let _ = client.create_topic().name("MyNewTopic").send().await;

    let spans = exporter.get_finished_spans().unwrap();
    let attrs = span_attrs(&spans[0]);
    assert_eq!(attrs["aws.operation"], "CreateTopic");
    assert_eq!(attrs["topicname"], "MyNewTopic");
}

#[tokio::test]
#[serial]
async fn sns_get_topic_attributes_creates_span_with_topicname() {
    let exporter = init_test_tracer();
    let (url, _srv, _bodies) = mock_aws(200).await;
    let client = sns_client(&sdk_config(&url));

    let _ = client
        .get_topic_attributes()
        .topic_arn(TOPIC_ARN)
        .send()
        .await;

    let spans = exporter.get_finished_spans().unwrap();
    let attrs = span_attrs(&spans[0]);
    assert_eq!(attrs["aws.operation"], "GetTopicAttributes");
    assert_eq!(attrs["topicname"], "MyTopic");
}

#[tokio::test]
#[serial]
async fn sns_error_response_sets_span_error_status() {
    let exporter = init_test_tracer();
    let (url, _srv, _bodies) = mock_aws(400).await;
    let client = sns_client(&sdk_config(&url));

    let _ = client
        .publish()
        .topic_arn(TOPIC_ARN)
        .message("hello")
        .send()
        .await;

    let spans = exporter.get_finished_spans().unwrap();
    let attrs = span_attrs(&spans[0]);
    assert_eq!(attrs["http.status_code"], "400");
    assert!(matches!(
        spans[0].status,
        opentelemetry::trace::Status::Error { .. }
    ));
}
