// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aws_credential_types::provider::SharedCredentialsProvider;
use aws_credential_types::Credentials;
use aws_smithy_runtime_api::client::behavior_version::BehaviorVersion;
use aws_types::region::Region;
use aws_types::SdkConfig;
use opentelemetry::global;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{
    InMemorySpanExporter, SdkTracerProvider, SimpleSpanProcessor, SpanData,
};
use wiremock::matchers::any;
use wiremock::{Mock, MockServer as WireMockServer, Request, Respond, ResponseTemplate};

#[derive(Clone)]
struct CaptureBodyResponder {
    status: u16,
    bodies: Arc<Mutex<Vec<String>>>,
    response_body: String,
}

impl Respond for CaptureBodyResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body = String::from_utf8_lossy(&request.body).into_owned();
        self.bodies.lock().unwrap().push(body);

        ResponseTemplate::new(self.status)
            .insert_header("x-amzn-requestid", "test_req")
            .set_body_raw(self.response_body.clone(), "application/json")
    }
}

/// Handle to the shared mock AWS endpoint used by integration tests.
pub struct MockAwsServer {
    pub url: String,
    bodies: Arc<Mutex<Vec<String>>>,
    _server: WireMockServer,
}

impl MockAwsServer {
    /// Returns a snapshot of all request bodies received so far.
    pub fn bodies(&self) -> Vec<String> {
        self.bodies.lock().unwrap().clone()
    }
}

/// Shared setup used in integration tests.
///
/// Typical usage is one harness per test:
/// 1. `let harness = TestHarness::ok().await;`
/// 2. Build the AWS client with `harness.sdk_config()`.
/// 3. Execute SDK calls, then assert on `harness.finished_spans()` and `harness.server.bodies()`.
///
/// Tests should remain serialized (`#[serial]`) because harness creation sets global
/// OpenTelemetry tracer/propagator state via `init_test_tracer`.
pub struct TestHarness {
    pub exporter: InMemorySpanExporter,
    pub server: MockAwsServer,
}

impl TestHarness {
    /// Initializes tracing and starts a mock AWS endpoint returning `200 OK`
    /// for every request.
    pub async fn ok() -> Self {
        Self::from_status(200).await
    }

    /// Initializes tracing and starts a mock AWS endpoint returning `200 OK`
    /// with the supplied response body.
    pub async fn ok_with_body(response_body: impl Into<String>) -> Self {
        Self::from_status_and_body(200, response_body).await
    }

    /// Initializes tracing and starts a mock AWS endpoint returning
    /// `400 Bad Request` for every request.
    pub async fn bad_request() -> Self {
        Self::from_status(400).await
    }

    /// Builds an SDK config targeting this harness's mock AWS endpoint.
    pub fn sdk_config(&self) -> SdkConfig {
        sdk_config(&self.server.url)
    }

    /// Returns all finished spans currently exported by this harness.
    pub fn finished_spans(&self) -> Vec<SpanData> {
        self.exporter.get_finished_spans().unwrap()
    }

    async fn from_status(status: u16) -> Self {
        Self::from_status_and_body(status, "{}").await
    }

    async fn from_status_and_body(status: u16, response_body: impl Into<String>) -> Self {
        Self {
            exporter: init_test_tracer(),
            server: mock_aws_with_body(status, response_body).await,
        }
    }
}

/// Starts a minimal mock HTTP server. Every request gets status `status`,
/// body `{}`, and header `x-amzn-requestid: test_req`.
pub async fn mock_aws(status: u16) -> MockAwsServer {
    mock_aws_with_body(status, "{}").await
}

/// Starts a minimal mock HTTP server. Every request gets status `status`,
/// body `response_body`, and header `x-amzn-requestid: test_req`.
pub async fn mock_aws_with_body(status: u16, response_body: impl Into<String>) -> MockAwsServer {
    let server = WireMockServer::start().await;
    let bodies: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    let responder = CaptureBodyResponder {
        status,
        bodies: Arc::clone(&bodies),
        response_body: response_body.into(),
    };

    Mock::given(any())
        .respond_with(responder)
        .mount(&server)
        .await;

    MockAwsServer {
        url: server.uri(),
        bodies,
        _server: server,
    }
}

/// Registers an `InMemorySpanExporter` as the global tracer provider and
/// a `TraceContextPropagator` as the global propagator.
pub fn init_test_tracer() -> InMemorySpanExporter {
    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_span_processor(SimpleSpanProcessor::new(exporter.clone()))
        .build();
    global::set_tracer_provider(provider);
    global::set_text_map_propagator(TraceContextPropagator::new());
    exporter
}

/// Builds an `SdkConfig` pointing at `endpoint` with test credentials.
pub fn sdk_config(endpoint: &str) -> SdkConfig {
    SdkConfig::builder()
        .behavior_version(BehaviorVersion::latest())
        .endpoint_url(endpoint)
        .region(Region::new("us-east-1"))
        .credentials_provider(SharedCredentialsProvider::new(Credentials::for_tests()))
        .build()
}

/// Flattens OTel span attributes into a `HashMap<key, value_as_string>`.
pub fn span_attrs(span: &SpanData) -> HashMap<String, String> {
    span.attributes
        .iter()
        .map(|kv| (kv.key.to_string(), kv.value.to_string()))
        .collect()
}

/// Extracts the W3C `traceparent` value from a request body string.
/// Works on both form-encoded (SQS/SNS) and JSON (EventBridge) bodies.
pub fn extract_traceparent(body: &str) -> Option<String> {
    let after_key = &body[body.find("traceparent")? + "traceparent".len()..];
    let val_start = after_key.find("00-")?;
    let val = &after_key[val_start..];
    // W3C format: 00-{32 hex}-{16 hex}-{2 hex} = 55 chars total.
    (val.len() >= 55).then(|| val[..55].to_string())
}

/// Returns `(trace_id_hex, span_id_hex)` from a W3C traceparent string.
pub fn split_traceparent(tp: &str) -> (String, String) {
    let parts: Vec<&str> = tp.splitn(4, '-').collect();
    (parts[1].to_string(), parts[2].to_string())
}
