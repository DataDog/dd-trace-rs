// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! In-repo integration test for OTLP trace export.
//!
//! These tests start an application that uses only the Datadog tracer's own OpenTelemetry-shim API
//! (no external OpenTelemetry SDK setup) and verify that, when `OTEL_TRACES_EXPORTER=otlp` is set,
//! sampled spans are emitted as OTLP HTTP (JSON or protobuf, per
//! `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL`) to a local HTTP endpoint instead of to the Datadog agent
//! in MessagePack.
//!
//! A minimal local HTTP server doubles as both the Datadog agent (`/info`, so the trace exporter
//! worker can start) and the OTLP collector (`/v1/traces`, which captures the exported payload).

use std::sync::Arc;
use std::time::Duration;

use datadog_opentelemetry::configuration::{Config, ConfigBuilder};
use datadog_opentelemetry::make_test_tracer;
use opentelemetry::trace::{SpanBuilder, TracerProvider};
use opentelemetry::Context;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// A captured HTTP request received by the mock collector.
#[derive(Debug, Clone)]
struct CapturedRequest {
    path: String,
    content_type: Option<String>,
    headers: Vec<(String, String)>,
    body: String,
}

/// A mock server that serves the agent `/info` endpoint and captures OTLP `/v1/traces` POSTs.
struct MockCollector {
    base_url: String,
    rx: mpsc::UnboundedReceiver<CapturedRequest>,
}

impl MockCollector {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind mock collector");
        let addr = listener.local_addr().expect("failed to read local addr");
        let base_url = format!("http://{addr}");
        let (tx, rx) = mpsc::unbounded_channel();

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let tx = tx.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, tx).await;
                });
            }
        });

        MockCollector { base_url, rx }
    }

    /// Waits for the next OTLP `/v1/traces` request, ignoring `/info` polls, with a timeout.
    async fn next_trace_request(&mut self) -> Option<CapturedRequest> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return None;
            }
            match tokio::time::timeout(remaining, self.rx.recv()).await {
                Ok(Some(req)) if req.path.contains("/v1/traces") => return Some(req),
                Ok(Some(_)) => continue, // ignore /info and other polls
                Ok(None) => return None,
                Err(_) => return None,
            }
        }
    }
}

/// Reads a single HTTP/1.1 request from the stream, records it, and responds with a minimal 200.
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    tx: mpsc::UnboundedSender<CapturedRequest>,
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];

    // Read until we have the full headers section.
    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    let header_text = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .to_string();

    let mut content_length = 0usize;
    let mut content_type = None;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_string();
            let value = value.trim().to_string();
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse().unwrap_or(0);
            } else if name.eq_ignore_ascii_case("content-type") {
                content_type = Some(value.clone());
            }
            headers.push((name.to_lowercase(), value));
        }
    }

    // Read the remaining body bytes.
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }

    // Respond to `/info` with a minimal agent info payload; everything else gets an empty 200.
    let response_body = if path.contains("/info") {
        br#"{"endpoints":["/v0.4/traces"],"client_drop_p0s":true}"#.to_vec()
    } else {
        b"{}".to_vec()
    };
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response_body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.write_all(&response_body).await?;
    stream.flush().await?;

    let _ = tx.send(CapturedRequest {
        path,
        content_type,
        headers,
        body: String::from_utf8_lossy(&body).to_string(),
    });
    Ok(())
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Builds a tracer wired for OTLP export against the mock collector and emits one sampled span.
///
/// The default Datadog sampler keeps all root spans (rate 1.0), so a normally-started span is
/// sampled — and therefore exported — without forcing a sampling decision on the span builder.
fn emit_one_sampled_span(cfg: ConfigBuilder) {
    let cfg = Arc::new(cfg.build());
    let (tracer_provider, _propagator) = make_test_tracer(cfg);
    let tracer = tracer_provider.tracer("otlp-trace-export-test");
    let span = SpanBuilder::from_name("otlp.test.span")
        .with_kind(opentelemetry::trace::SpanKind::Server)
        .start_with_context(&tracer, &Context::new());
    drop(span);
    tracer_provider.force_flush().expect("force_flush failed");
    tracer_provider.shutdown().expect("shutdown failed");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_otlp_traces_exported_to_local_endpoint() {
    let mut collector = MockCollector::start().await;

    // No OpenTelemetry SDK is configured by the app — only the Datadog tracer config selects OTLP.
    let mut cfg = Config::builder();
    cfg.set_service("otlp-export-svc".to_string())
        .set_env("test".to_string())
        .set_version("9.9.9".to_string())
        // Agent URL serves `/info` so the exporter worker can start; OTLP endpoint is separate.
        .set_trace_agent_url(collector.base_url.clone())
        .set_otel_traces_exporter("otlp".to_string())
        .set_otlp_traces_endpoint(format!("{}/v1/traces", collector.base_url))
        .set_otlp_traces_headers("dd-protocol=otlp,team=intake".to_string());

    assert!(cfg.build().otlp_traces_enabled());

    std::thread::spawn(move || emit_one_sampled_span(cfg));

    let request = collector
        .next_trace_request()
        .await
        .expect("did not receive an OTLP /v1/traces request");

    // OTLP HTTP/JSON: posted to /v1/traces with JSON content type.
    assert!(
        request.path.ends_with("/v1/traces"),
        "path was {}",
        request.path
    );
    assert_eq!(request.content_type.as_deref(), Some("application/json"));

    // Custom OTLP headers were forwarded.
    assert!(
        request
            .headers
            .iter()
            .any(|(k, v)| k == "dd-protocol" && v == "otlp"),
        "missing dd-protocol header, got {:?}",
        request.headers
    );

    // Canonical OTLP JSON shape produced by libdatadog's otlp_encoder.
    let json: serde_json::Value =
        serde_json::from_str(&request.body).expect("OTLP body was not valid JSON");
    let resource_spans = json
        .get("resourceSpans")
        .and_then(|v| v.as_array())
        .expect("missing resourceSpans");
    assert!(!resource_spans.is_empty(), "resourceSpans was empty");

    // The exported payload contains our span name and lowerCamelCase OTLP keys, confirming the
    // OTLP encoding path (rather than Datadog MessagePack).
    let body_str = request.body;
    assert!(
        body_str.contains("otlp.test.span"),
        "exported payload did not contain the span name: {body_str}"
    );
    assert!(
        body_str.contains("traceId") && body_str.contains("spanId"),
        "exported payload was not lowerCamelCase OTLP JSON: {body_str}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_otlp_traces_exported_as_protobuf() {
    let mut collector = MockCollector::start().await;

    // Same wiring as the JSON test, but selecting the OTel-standard http/protobuf encoding.
    let mut cfg = Config::builder();
    cfg.set_service("otlp-protobuf-svc".to_string())
        .set_env("test".to_string())
        .set_version("9.9.9".to_string())
        .set_trace_agent_url(collector.base_url.clone())
        .set_otel_traces_exporter("otlp".to_string())
        .set_otlp_traces_endpoint(format!("{}/v1/traces", collector.base_url))
        .set_otlp_traces_protocol("http/protobuf".to_string());

    assert!(cfg.build().otlp_traces_enabled());

    std::thread::spawn(move || emit_one_sampled_span(cfg));

    let request = collector
        .next_trace_request()
        .await
        .expect("did not receive an OTLP /v1/traces request");

    // OTLP HTTP/protobuf: posted to /v1/traces with the protobuf content type.
    assert!(
        request.path.ends_with("/v1/traces"),
        "path was {}",
        request.path
    );
    assert_eq!(
        request.content_type.as_deref(),
        Some("application/x-protobuf")
    );

    // The payload is binary protobuf, not JSON. Proto string fields are UTF-8, so the span name
    // still appears verbatim in the bytes, while the lowerCamelCase JSON keys do not.
    assert!(
        request.body.contains("otlp.test.span"),
        "protobuf payload did not contain the span name"
    );
    assert!(
        !request.body.contains("resourceSpans"),
        "protobuf payload unexpectedly looked like OTLP JSON: {}",
        request.body
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_unsampled_spans_not_exported() {
    let mut collector = MockCollector::start().await;

    let mut cfg = Config::builder();
    cfg.set_service("otlp-drop-svc".to_string())
        .set_trace_agent_url(collector.base_url.clone())
        .set_otel_traces_exporter("otlp".to_string())
        .set_otlp_traces_endpoint(format!("{}/v1/traces", collector.base_url))
        // Force every root trace to a drop decision.
        .set_otel_traces_sampler("parentbased_always_off".to_string());

    let cfg_for_thread = cfg;
    std::thread::spawn(move || {
        let cfg = Arc::new(cfg_for_thread.build());
        let (tracer_provider, _propagator) = make_test_tracer(cfg);
        let tracer = tracer_provider.tracer("otlp-drop-test");
        // Let the sampler decide (it will drop because the rate is 0.0).
        let span = SpanBuilder::from_name("dropped.span").start(&tracer);
        drop(span);
        // force_flush / shutdown results are intentionally ignored here: this test asserts that
        // no OTLP request is produced for a dropped span, not the shutdown outcome.
        let _ = tracer_provider.force_flush();
        let _ = tracer_provider.shutdown();
    });

    // No /v1/traces request should arrive within a short window because the only span was dropped.
    let got = tokio::time::timeout(Duration::from_secs(3), collector.next_trace_request()).await;
    assert!(
        matches!(got, Ok(None) | Err(_)),
        "unsampled spans should not be exported, but received: {got:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_grpc_protocol_disables_otlp_export() {
    let mut collector = MockCollector::start().await;

    // grpc is not supported for OTLP trace export. Rather than coercing to http/json (which would
    // fail against a grpc-only endpoint and drop traces), OTLP export is disabled and traces are
    // sent to the Datadog agent — so no OTLP /v1/traces request is produced for a sampled span.
    let mut cfg = Config::builder();
    cfg.set_service("otlp-grpc-svc".to_string())
        .set_trace_agent_url(collector.base_url.clone())
        .set_otel_traces_exporter("otlp".to_string())
        .set_otlp_traces_endpoint(format!("{}/v1/traces", collector.base_url))
        .set_otlp_traces_protocol("grpc".to_string());

    std::thread::spawn(move || emit_one_sampled_span(cfg));

    let got = tokio::time::timeout(Duration::from_secs(3), collector.next_trace_request()).await;
    assert!(
        matches!(got, Ok(None) | Err(_)),
        "grpc should disable OTLP export (no /v1/traces expected), but received: {got:?}"
    );
}
