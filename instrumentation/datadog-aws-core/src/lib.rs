// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

pub mod attribute_keys;
mod interceptor;
pub mod limits;

pub use interceptor::{AwsInterceptor, ServiceHandler};

/// Lightweight test helpers for unit tests within service crates.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_helpers {
    use std::collections::HashMap;

    use opentelemetry::{KeyValue, Value};

    pub const DATADOG_TRACE_ID_KEY: &str = "x-datadog-trace-id";
    pub const DATADOG_PARENT_ID_KEY: &str = "x-datadog-parent-id";
    pub const DATADOG_SAMPLING_PRIORITY_KEY: &str = "x-datadog-sampling-priority";

    pub fn sample_trace_headers() -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert(DATADOG_TRACE_ID_KEY.to_string(), "123456789".to_string());
        headers.insert(DATADOG_PARENT_ID_KEY.to_string(), "987654321".to_string());
        headers.insert(DATADOG_SAMPLING_PRIORITY_KEY.to_string(), "1".to_string());
        headers
    }

    pub fn collect_string_tags(tags: Vec<KeyValue>) -> HashMap<String, String> {
        tags.into_iter()
            .map(|KeyValue { key, value, .. }| {
                let Value::String(value) = value else {
                    panic!("expected string tag value for {}", key.as_str());
                };
                (key.as_str().to_string(), value.to_string())
            })
            .collect()
    }
}

/// Shared infrastructure for integration tests across service crates.
///
/// Provides a mock AWS HTTP server, OTel tracer setup, SDK config helpers,
/// and span/body inspection utilities. Enable via `features = ["test-utils"]`
/// in dev-dependencies.
#[cfg(feature = "test-utils")]
pub mod integration_test_helpers {
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
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};
    use wiremock::matchers::any;

    #[derive(Clone)]
    struct CaptureBodyResponder {
        status: u16,
        bodies: Arc<Mutex<Vec<String>>>,
    }

    impl Respond for CaptureBodyResponder {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let body = String::from_utf8_lossy(&request.body).into_owned();
            self.bodies.lock().unwrap().push(body);

            ResponseTemplate::new(self.status)
                .insert_header("x-amzn-requestid", "test_req")
                .set_body_raw("{}", "application/json")
        }
    }

    /// Starts a minimal mock HTTP server. Every request gets status `status`,
    /// body `{}`, and header `x-amzn-requestid: test_req`.
    ///
    /// Returns `(base_url, mock_server, captured_bodies)` where
    /// `captured_bodies` accumulates each request body as a UTF-8 string.
    pub async fn mock_aws(status: u16) -> (String, MockServer, Arc<Mutex<Vec<String>>>) {
        let server = MockServer::start().await;
        let bodies: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

        let responder = CaptureBodyResponder {
            status,
            bodies: Arc::clone(&bodies),
        };

        Mock::given(any())
            .respond_with(responder)
            .mount(&server)
            .await;

        (server.uri(), server, bodies)
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
}
