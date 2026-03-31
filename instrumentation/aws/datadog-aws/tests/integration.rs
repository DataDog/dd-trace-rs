// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! End-to-end integration tests for DatadogAwsInterceptor.
//!
//! Each test starts a minimal mock HTTP server, makes a real AWS SDK call with
//! the interceptor attached, and asserts on the finished OTel span and any
//! trace context injected into the request payload.
//!
//! Tests are serialized with `#[serial]` because they share OTel global state
//! (tracer provider + propagator).

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use aws_credential_types::provider::SharedCredentialsProvider;
use aws_credential_types::Credentials;
use aws_sdk_eventbridge::types::PutEventsRequestEntry;
use aws_sdk_sqs::types::SendMessageBatchRequestEntry;
use aws_smithy_runtime_api::client::behavior_version::BehaviorVersion;
use aws_types::region::Region;
use aws_types::SdkConfig;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use opentelemetry::trace::{SpanKind, TraceContextExt, Tracer};
use opentelemetry::{global, Context};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SimpleSpanProcessor, SpanData};
use serial_test::serial;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use datadog_aws_sdk::DatadogAwsInterceptor;


/// Starts a minimal mock HTTP server: every request gets `x-amzn-requestid: test_req`,
/// the given status code, and body `{}`.
/// Returns `(base_url, server_handle, captured_bodies)` where `captured_bodies`
/// accumulates each request body as a UTF-8 string for injection assertions.
async fn mock_aws(status: u16) -> (String, JoinHandle<()>, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let bodies: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let bodies_server = bodies.clone();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let bodies_conn = bodies_server.clone();
            tokio::spawn(async move {
                let _ = Builder::new(TokioExecutor::new())
                    .serve_connection(
                        TokioIo::new(stream),
                        hyper::service::service_fn(move |req: Request<Incoming>| {
                            let bodies_req = bodies_conn.clone();
                            async move {
                                let raw = req.into_body().collect().await.unwrap_or_default();
                                let text = String::from_utf8_lossy(&raw.to_bytes()).into_owned();
                                bodies_req.lock().unwrap().push(text);
                                let body: BoxBody<Bytes, hyper::Error> =
                                    Full::new(Bytes::from_static(b"{}"))
                                        .map_err(|e| match e {})
                                        .boxed();
                                let resp = Response::builder()
                                    .status(status)
                                    .header("x-amzn-requestid", "test_req")
                                    .header("Content-Type", "application/json")
                                    .body(body)
                                    .unwrap();
                                Ok::<_, Infallible>(resp)
                            }
                        }),
                    )
                    .await;
            });
        }
    });
    (format!("http://{addr}"), handle, bodies)
}

/// Registers an `InMemorySpanExporter` as the global tracer provider and
/// a `TraceContextPropagator` as the global propagator, then returns the
/// exporter so tests can retrieve finished spans.
///
/// The inject functions in all three services treat trace headers as an opaque
/// `HashMap<String, String>`, so the W3C propagator's header format is fine for
/// testing that injection wiring works end-to-end.
fn init_test_tracer() -> InMemorySpanExporter {
    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_span_processor(SimpleSpanProcessor::new(exporter.clone()))
        .build();
    global::set_tracer_provider(provider);
    global::set_text_map_propagator(TraceContextPropagator::new());
    exporter
}

fn sdk_config(endpoint: &str) -> SdkConfig {
    SdkConfig::builder()
        .behavior_version(BehaviorVersion::latest())
        .endpoint_url(endpoint)
        .region(Region::new("us-east-1"))
        .credentials_provider(SharedCredentialsProvider::new(Credentials::for_tests()))
        .build()
}

fn sqs_client(cfg: &SdkConfig) -> aws_sdk_sqs::Client {
    let config = aws_sdk_sqs::config::Builder::from(cfg)
        .interceptor(DatadogAwsInterceptor::new())
        .build();
    aws_sdk_sqs::Client::from_conf(config)
}

fn sns_client(cfg: &SdkConfig) -> aws_sdk_sns::Client {
    let config = aws_sdk_sns::config::Builder::from(cfg)
        .interceptor(DatadogAwsInterceptor::new())
        .build();
    aws_sdk_sns::Client::from_conf(config)
}

fn eventbridge_client(cfg: &SdkConfig) -> aws_sdk_eventbridge::Client {
    let config = aws_sdk_eventbridge::config::Builder::from(cfg)
        .interceptor(DatadogAwsInterceptor::new())
        .build();
    aws_sdk_eventbridge::Client::from_conf(config)
}

/// Flattens OTel span attributes into a `HashMap<key, value_as_string>`.
fn span_attrs(span: &SpanData) -> HashMap<String, String> {
    span.attributes
        .iter()
        .map(|kv| (kv.key.to_string(), kv.value.to_string()))
        .collect()
}

/// Extracts the W3C `traceparent` value (`00-{trace_id}-{span_id}-{flags}`) from
/// a request body string, whether form-encoded (SQS/SNS) or JSON (EventBridge).
/// `traceparent` and hex characters never require URL-encoding, so this works on
/// the raw body without a decode step.
fn extract_traceparent(body: &str) -> Option<String> {
    // Find "traceparent" key, then find the value starting with "00-".
    let after_key = &body[body.find("traceparent")? + "traceparent".len()..];
    let val_start = after_key.find("00-")?;
    let val = &after_key[val_start..];
    // W3C format: 00-{32 hex}-{16 hex}-{2 hex} = 55 chars total.
    (val.len() >= 55).then(|| val[..55].to_string())
}

/// Returns `(trace_id_hex, span_id_hex)` from a W3C traceparent string.
fn split_traceparent(tp: &str) -> (String, String) {
    let parts: Vec<&str> = tp.splitn(4, '-').collect();
    (parts[1].to_string(), parts[2].to_string())
}

const QUEUE_URL: &str = "https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue";
const QUEUE_URL_TRAILING: &str = "https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue/";
const TOPIC_ARN: &str = "arn:aws:sns:us-east-1:111111111111:MyTopic";
const TARGET_ARN: &str = "arn:aws:sns:us-east-1:111111111111:MyTarget";

// ---------------------------------------------------------------------------
// SQS tests
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn sqs_send_message_creates_span_with_tags_and_injects_context() {
    let exporter = init_test_tracer();
    let (url, _srv, captured) = mock_aws(200).await;
    let client = sqs_client(&sdk_config(&url));

    // SQS uses query/XML protocol; the mock returns JSON which causes a parse
    // error, but read_after_execution still runs and ends the span.
    let _ = client
        .send_message()
        .queue_url(QUEUE_URL)
        .message_body("hello")
        .send()
        .await;

    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 1);
    let attrs = span_attrs(&spans[0]);

    assert_eq!(spans[0].name, "sqs.request");
    assert_eq!(attrs["aws.service"], "SQS");
    assert_eq!(attrs["aws.operation"], "SendMessage");
    assert_eq!(attrs["aws.region"], "us-east-1");
    assert_eq!(attrs["aws.partition"], "aws");
    assert_eq!(attrs["service.name"], "aws.sqs");
    assert_eq!(attrs["resource.name"], "sqs.SendMessage");
    assert_eq!(attrs["component"], "datadog-aws-sdk");
    assert_eq!(attrs["span.kind"], "client");
    assert_eq!(attrs["queuename"], "MyQueue");
    assert_eq!(
        attrs["cloud.resource_id"],
        "arn:aws:sqs:us-east-1:123456789012:MyQueue"
    );
    assert_eq!(attrs["messaging.system"], "amazonsqs");
    assert_eq!(attrs["http.status_code"], "200");
    assert_eq!(attrs["aws.request_id"], "test_req");
    assert_eq!(spans[0].span_kind, SpanKind::Client);

    // Verify _datadog trace context was injected and points to the span we created,
    // not the caller's context, proving the injected downstream parent is correct.
    let bodies = captured.lock().unwrap();
    assert_eq!(bodies.len(), 1);
    assert!(bodies[0].contains("_datadog"), "body should contain _datadog attribute name");
    let tp = extract_traceparent(&bodies[0]).expect("traceparent should be in body");
    let (injected_trace_id, injected_parent_id) = split_traceparent(&tp);
    assert_eq!(injected_trace_id, format!("{}", spans[0].span_context.trace_id()));
    assert_eq!(injected_parent_id, format!("{}", spans[0].span_context.span_id()));
}

#[tokio::test]
#[serial]
async fn sqs_send_message_batch_creates_span_and_injects_into_all_entries() {
    let exporter = init_test_tracer();
    let (url, _srv, captured) = mock_aws(200).await;
    let client = sqs_client(&sdk_config(&url));

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

    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 1);
    let attrs = span_attrs(&spans[0]);
    assert_eq!(spans[0].name, "sqs.request");
    assert_eq!(attrs["aws.operation"], "SendMessageBatch");
    assert_eq!(attrs["queuename"], "MyQueue");

    // Verify _datadog was injected into the batch entries.
    let bodies = captured.lock().unwrap();
    assert_eq!(bodies.len(), 1);
    assert!(bodies[0].contains("_datadog"), "body should contain _datadog attribute");
    assert!(bodies[0].contains("traceparent"), "body should contain traceparent");
}

#[tokio::test]
#[serial]
async fn sqs_receive_message_creates_span_with_queue_tags() {
    let exporter = init_test_tracer();
    let (url, _srv, _bodies) = mock_aws(200).await;
    let client = sqs_client(&sdk_config(&url));

    let _ = client
        .receive_message()
        .queue_url(QUEUE_URL)
        .send()
        .await;

    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 1);
    let attrs = span_attrs(&spans[0]);
    assert_eq!(attrs["aws.operation"], "ReceiveMessage");
    assert_eq!(attrs["queuename"], "MyQueue");
    assert_eq!(
        attrs["cloud.resource_id"],
        "arn:aws:sqs:us-east-1:123456789012:MyQueue"
    );
}

#[tokio::test]
#[serial]
async fn sqs_delete_message_creates_span_with_queue_tags() {
    let exporter = init_test_tracer();
    let (url, _srv, _bodies) = mock_aws(200).await;
    let client = sqs_client(&sdk_config(&url));

    let _ = client
        .delete_message()
        .queue_url(QUEUE_URL)
        .receipt_handle("handle")
        .send()
        .await;

    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 1);
    let attrs = span_attrs(&spans[0]);
    assert_eq!(attrs["aws.operation"], "DeleteMessage");
    assert_eq!(attrs["queuename"], "MyQueue");
}

#[tokio::test]
#[serial]
async fn sqs_delete_message_batch_creates_span_with_queue_tags() {
    let exporter = init_test_tracer();
    let (url, _srv, _bodies) = mock_aws(200).await;
    let client = sqs_client(&sdk_config(&url));

    let _ = client
        .delete_message_batch()
        .queue_url(QUEUE_URL)
        .send()
        .await;

    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 1);
    let attrs = span_attrs(&spans[0]);
    assert_eq!(attrs["aws.operation"], "DeleteMessageBatch");
    assert_eq!(attrs["queuename"], "MyQueue");
}

#[tokio::test]
#[serial]
async fn sqs_queue_url_trailing_slash_parsed_correctly() {
    let exporter = init_test_tracer();
    let (url, _srv, _bodies) = mock_aws(200).await;
    let client = sqs_client(&sdk_config(&url));

    let _ = client
        .send_message()
        .queue_url(QUEUE_URL_TRAILING)
        .message_body("hello")
        .send()
        .await;

    let spans = exporter.get_finished_spans().unwrap();
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
    let exporter = init_test_tracer();
    let (url, _srv, _bodies) = mock_aws(400).await;
    let client = sqs_client(&sdk_config(&url));

    let _ = client
        .send_message()
        .queue_url(QUEUE_URL)
        .message_body("hello")
        .send()
        .await;

    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 1);
    let attrs = span_attrs(&spans[0]);
    assert_eq!(attrs["http.status_code"], "400");
    assert!(matches!(
        spans[0].status,
        opentelemetry::trace::Status::Error { .. }
    ));
}

// ---------------------------------------------------------------------------
// SNS tests
// ---------------------------------------------------------------------------

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
    assert_eq!(attrs["service.name"], "aws.sns");
    assert_eq!(attrs["resource.name"], "sns.Publish");

    // SNS injects _datadog as a Binary attribute; the value is base64-encoded
    // so traceparent won't appear in plaintext. Assert the attribute name and type.
    let bodies = captured.lock().unwrap();
    assert_eq!(bodies.len(), 1);
    assert!(bodies[0].contains("_datadog"), "body should contain _datadog attribute name");
    assert!(bodies[0].contains("Binary"), "body should indicate Binary data type");
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

    // SNS batch injects _datadog Binary attribute into each entry.
    let bodies = captured.lock().unwrap();
    assert_eq!(bodies.len(), 1);
    assert!(bodies[0].contains("_datadog"), "batch body should contain _datadog attribute");
    assert!(bodies[0].contains("Binary"), "batch body should indicate Binary data type");
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

// ---------------------------------------------------------------------------
// EventBridge tests
// ---------------------------------------------------------------------------

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
    assert_eq!(attrs["service.name"], "aws.eventbridge");
    assert_eq!(attrs["resource.name"], "eventbridge.PutEvents");

    // EventBridge uses JSON protocol, so we can fully parse the body and verify
    // the injected traceparent points to the span that was created.
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
    assert_eq!(injected_trace_id, format!("{}", spans[0].span_context.trace_id()));
    assert_eq!(injected_parent_id, format!("{}", spans[0].span_context.span_id()));
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

// ---------------------------------------------------------------------------
// Cross-cutting: HTTP tags
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn http_tags_set_on_span() {
    let exporter = init_test_tracer();
    let (url, _srv, _bodies) = mock_aws(200).await;
    let client = sqs_client(&sdk_config(&url));

    let _ = client
        .send_message()
        .queue_url(QUEUE_URL)
        .message_body("hello")
        .send()
        .await;

    let spans = exporter.get_finished_spans().unwrap();
    let attrs = span_attrs(&spans[0]);
    assert_eq!(spans[0].name, "sqs.request");
    assert_eq!(attrs["http.method"], "POST");
    assert!(attrs["http.url"].starts_with(&url));
    assert_eq!(attrs["http.status_code"], "200");
    assert_eq!(attrs["aws.request_id"], "test_req");
    assert!(attrs.contains_key("aws.agent"), "aws.agent should be set from user-agent header");
}

#[tokio::test]
#[serial]
async fn interceptor_span_is_child_of_active_parent() {
    let exporter = init_test_tracer();
    let (url, _srv, _bodies) = mock_aws(200).await;
    let client = sqs_client(&sdk_config(&url));

    // Create a parent span and make the AWS call within its context.
    let tracer = global::tracer("test");
    let parent_span = tracer.start("parent-operation");
    let parent_cx = Context::current().with_span(parent_span);
    let _guard = parent_cx.clone().attach();

    let parent_span_id = parent_cx.span().span_context().span_id();
    let parent_trace_id = parent_cx.span().span_context().trace_id();

    let _ = client
        .send_message()
        .queue_url(QUEUE_URL)
        .message_body("hello")
        .send()
        .await;

    // Drop the guard so the parent span can be exported.
    drop(_guard);
    parent_cx.span().end();

    let spans = exporter.get_finished_spans().unwrap();
    // Find the interceptor span (not the parent).
    let interceptor_span = spans
        .iter()
        .find(|s| s.name == "sqs.request")
        .expect("should have an sqs.request span");

    // The interceptor span must be a child of the parent, in the same trace.
    assert_eq!(interceptor_span.span_context.trace_id(), parent_trace_id);
    assert_eq!(interceptor_span.parent_span_id, parent_span_id);
}
