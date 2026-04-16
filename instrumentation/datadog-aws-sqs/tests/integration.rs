// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use aws_credential_types::provider::SharedCredentialsProvider;
use aws_credential_types::Credentials;
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

use datadog_aws_sqs::SqsInterceptor;

async fn mock_aws(status: u16) -> (String, JoinHandle<()>, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let bodies: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let bodies_server = bodies.clone();
    let handle = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
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
        .interceptor(SqsInterceptor::new())
        .build();
    aws_sdk_sqs::Client::from_conf(config)
}

fn span_attrs(span: &SpanData) -> HashMap<String, String> {
    span.attributes
        .iter()
        .map(|kv| (kv.key.to_string(), kv.value.to_string()))
        .collect()
}

fn extract_traceparent(body: &str) -> Option<String> {
    let after_key = &body[body.find("traceparent")? + "traceparent".len()..];
    let val_start = after_key.find("00-")?;
    let val = &after_key[val_start..];
    (val.len() >= 55).then(|| val[..55].to_string())
}

fn split_traceparent(tp: &str) -> (String, String) {
    let parts: Vec<&str> = tp.splitn(4, '-').collect();
    (parts[1].to_string(), parts[2].to_string())
}

const QUEUE_URL: &str = "https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue";
const QUEUE_URL_TRAILING: &str = "https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue/";

#[tokio::test]
#[serial]
async fn sqs_send_message_creates_span_with_tags_and_injects_context() {
    let exporter = init_test_tracer();
    let (url, _srv, captured) = mock_aws(200).await;
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

    assert_eq!(spans[0].name, "sqs.request");
    assert_eq!(attrs["aws.service"], "SQS");
    assert_eq!(attrs["aws.operation"], "SendMessage");
    assert_eq!(attrs["aws.region"], "us-east-1");
    assert_eq!(attrs["aws.partition"], "aws");
    assert_eq!(attrs["operation.name"], "aws.sqs.request");
    assert_eq!(attrs["resource.name"], "SQS.SendMessage");
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

    let bodies = captured.lock().unwrap();
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

    let bodies = captured.lock().unwrap();
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
    let exporter = init_test_tracer();
    let (url, _srv, _bodies) = mock_aws(200).await;
    let client = sqs_client(&sdk_config(&url));

    let _ = client.receive_message().queue_url(QUEUE_URL).send().await;

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

#[tokio::test]
#[serial]
async fn sqs_send_message_propagates_parent_context() {
    let exporter = init_test_tracer();
    let (url, _srv, captured) = mock_aws(200).await;
    let client = sqs_client(&sdk_config(&url));

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

    let spans = exporter.get_finished_spans().unwrap();
    let sqs_span = spans
        .iter()
        .find(|s| s.name == "sqs.request")
        .expect("sqs.request span not found");

    assert_eq!(
        sqs_span.parent_span_id,
        parent_cx.span().span_context().span_id()
    );

    let bodies = captured.lock().unwrap();
    let tp = extract_traceparent(&bodies[0]).expect("traceparent should be in body");
    let (_, injected_parent_id) = split_traceparent(&tp);
    assert_eq!(
        injected_parent_id,
        format!("{}", sqs_span.span_context.span_id())
    );
}
