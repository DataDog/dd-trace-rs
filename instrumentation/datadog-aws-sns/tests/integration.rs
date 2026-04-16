// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use aws_credential_types::provider::SharedCredentialsProvider;
use aws_credential_types::Credentials;
use aws_smithy_runtime_api::client::behavior_version::BehaviorVersion;
use aws_types::region::Region;
use aws_types::SdkConfig;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use opentelemetry::global;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SimpleSpanProcessor, SpanData};
use serial_test::serial;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use datadog_aws_sns::SnsInterceptor;

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

fn sns_client(cfg: &SdkConfig) -> aws_sdk_sns::Client {
    let config = aws_sdk_sns::config::Builder::from(cfg)
        .interceptor(SnsInterceptor::new())
        .build();
    aws_sdk_sns::Client::from_conf(config)
}

fn span_attrs(span: &SpanData) -> HashMap<String, String> {
    span.attributes
        .iter()
        .map(|kv| (kv.key.to_string(), kv.value.to_string()))
        .collect()
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
