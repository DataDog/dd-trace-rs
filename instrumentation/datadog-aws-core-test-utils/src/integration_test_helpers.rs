// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

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

const AWS_REQUEST_ID: &str = "aws.request_id";
const REQUEST_ID_PREFIX: &str = "test_req";

#[derive(Clone)]
struct CaptureBodyResponder {
    status: u16,
    bodies: Arc<Mutex<Vec<String>>>,
    response_body: String,
    request_id: String,
}

impl Respond for CaptureBodyResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body = String::from_utf8_lossy(&request.body).into_owned();
        self.bodies.lock().unwrap().push(body);

        ResponseTemplate::new(self.status)
            .insert_header("x-amzn-requestid", self.request_id.clone())
            .set_body_raw(self.response_body.clone(), "application/json")
    }
}

/// Handle to the shared mock AWS endpoint used by integration tests.
pub struct MockAwsServer {
    pub url: String,
    request_id: String,
    bodies: Arc<Mutex<Vec<String>>>,
    _server: WireMockServer,
}

impl MockAwsServer {
    /// Returns the request ID emitted in every mock AWS response.
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

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
/// The global OpenTelemetry tracer and propagator are initialized once per test
/// binary. Each harness filters exported spans by its mock AWS request ID, so
/// tests can run concurrently.
pub struct TestHarness {
    exporter: InMemorySpanExporter,
    pub server: MockAwsServer,
}

impl TestHarness {
    /// Ensures tracing is initialized and starts a mock AWS endpoint returning `200 OK`
    /// for every request.
    pub async fn ok() -> Self {
        Self::from_status(200).await
    }

    /// Ensures tracing is initialized and starts a mock AWS endpoint returning `200 OK`
    /// with the supplied response body.
    pub async fn ok_with_body(response_body: impl Into<String>) -> Self {
        Self::from_status_and_body(200, response_body).await
    }

    /// Ensures tracing is initialized and starts a mock AWS endpoint returning
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
        self.exporter
            .get_finished_spans()
            .unwrap()
            .into_iter()
            .filter(|span| span_has_request_id(span, self.server.request_id()))
            .collect()
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
/// body `{}`, and a unique `x-amzn-requestid` header.
pub async fn mock_aws(status: u16) -> MockAwsServer {
    mock_aws_with_body(status, "{}").await
}

/// Starts a minimal mock HTTP server. Every request gets status `status`,
/// body `response_body`, and a unique `x-amzn-requestid` header.
pub async fn mock_aws_with_body(status: u16, response_body: impl Into<String>) -> MockAwsServer {
    let server = WireMockServer::start().await;
    let bodies: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let request_id = next_request_id();

    let responder = CaptureBodyResponder {
        status,
        bodies: Arc::clone(&bodies),
        response_body: response_body.into(),
        request_id: request_id.clone(),
    };

    Mock::given(any())
        .respond_with(responder)
        .mount(&server)
        .await;

    MockAwsServer {
        url: server.uri(),
        request_id,
        bodies,
        _server: server,
    }
}

/// Registers an `InMemorySpanExporter` as the global tracer provider and
/// a `TraceContextPropagator` as the global propagator once per test binary.
pub fn init_test_tracer() -> InMemorySpanExporter {
    static EXPORTER: OnceLock<InMemorySpanExporter> = OnceLock::new();

    EXPORTER
        .get_or_init(|| {
            let exporter = InMemorySpanExporter::default();
            let provider = SdkTracerProvider::builder()
                .with_span_processor(SimpleSpanProcessor::new(exporter.clone()))
                .build();
            global::set_tracer_provider(provider);
            global::set_text_map_propagator(TraceContextPropagator::new());
            exporter
        })
        .clone()
}

fn next_request_id() -> String {
    static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

    let id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    format!("{REQUEST_ID_PREFIX}_{id}")
}

fn span_has_request_id(span: &SpanData, request_id: &str) -> bool {
    span.attributes
        .iter()
        .any(|kv| kv.key.as_str() == AWS_REQUEST_ID && kv.value.to_string() == request_id)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_request_ids_are_unique() {
        let first = next_request_id();
        let second = next_request_id();

        assert_ne!(first, second);
        assert!(first.starts_with(REQUEST_ID_PREFIX));
        assert!(second.starts_with(REQUEST_ID_PREFIX));
    }
}
