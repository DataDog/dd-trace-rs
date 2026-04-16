// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use aws_credential_types::provider::SharedCredentialsProvider;
use aws_credential_types::Credentials;
use aws_sdk_eventbridge::types::PutEventsRequestEntry;
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

use datadog_aws_eventbridge::EventBridgeInterceptor;

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

fn eventbridge_client(cfg: &SdkConfig) -> aws_sdk_eventbridge::Client {
    let config = aws_sdk_eventbridge::config::Builder::from(cfg)
        .interceptor(EventBridgeInterceptor::new())
        .build();
    aws_sdk_eventbridge::Client::from_conf(config)
}

fn span_attrs(span: &SpanData) -> HashMap<String, String> {
    span.attributes
        .iter()
        .map(|kv| (kv.key.to_string(), kv.value.to_string()))
        .collect()
}

fn split_traceparent(tp: &str) -> (String, String) {
    let parts: Vec<&str> = tp.splitn(4, '-').collect();
    (parts[1].to_string(), parts[2].to_string())
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
