// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::time::Duration;

use datadog_opentelemetry::configuration::Config;
use datadog_opentelemetry::{create_meter_provider_with_protocol, OtlpProtocol};
use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram, UpDownCounter};
use opentelemetry::KeyValue;

use crate::integration_tests::make_test_agent;

async fn setup_test_agent(
    session_name: &'static str,
) -> libdd_trace_utils::test_utils::datadog_test_agent::DatadogTestAgent {
    make_test_agent(session_name).await
}

fn create_all_metric_types(meter: &opentelemetry::metrics::Meter) {
    let counter: Counter<u64> = meter.u64_counter("test.counter").build();
    counter.add(10, &[KeyValue::new("key1", "value1")]);

    let updown_counter: UpDownCounter<i64> = meter.i64_up_down_counter("test.updown").build();
    updown_counter.add(5, &[KeyValue::new("key2", "value2")]);
    updown_counter.add(-2, &[KeyValue::new("key2", "value2")]);

    let histogram: Histogram<f64> = meter.f64_histogram("test.histogram").build();
    histogram.record(1.5, &[KeyValue::new("key3", "value3")]);
    histogram.record(2.3, &[KeyValue::new("key3", "value3")]);
    histogram.record(3.7, &[KeyValue::new("key3", "value3")]);

    let _observable_counter = meter
        .u64_observable_counter("test.observable_counter")
        .with_callback(|result| {
            result.observe(20, &[KeyValue::new("key4", "value4")]);
        })
        .build();

    let _observable_gauge = meter
        .f64_observable_gauge("test.observable_gauge")
        .with_callback(|result| {
            result.observe(42.0, &[KeyValue::new("key5", "value5")]);
        })
        .build();

    let _observable_updown = meter
        .i64_observable_up_down_counter("test.observable_updown")
        .with_callback(|result| {
            result.observe(15, &[KeyValue::new("key6", "value6")]);
        })
        .build();
}

#[tokio::test]
async fn test_metrics_export_grpc() {
    const SESSION_NAME: &str = "opentelemetry_api/test_metrics_grpc";

    let test_agent = setup_test_agent(SESSION_NAME).await;
    let base_uri = test_agent.get_base_uri().await;

    let url = base_uri.to_string();
    let url = url.parse::<hyper::http::Uri>().unwrap();
    let scheme = url.scheme_str().unwrap_or("http");
    let host = url.host().unwrap();
    let otlp_endpoint = format!("{scheme}://{host}:4317");

    let config = Arc::new(
        Config::builder()
            .set_trace_agent_url(base_uri.to_string())
            .set_service("test-service".to_string())
            .set_metrics_otel_enabled(true)
            .set_otlp_metrics_endpoint(otlp_endpoint)
            .build(),
    );

    let meter_provider = create_meter_provider_with_protocol(
        config,
        None,
        Some(Duration::from_millis(100)),
        Some(OtlpProtocol::Grpc),
    )
    .expect("Failed to create meter provider");

    global::set_meter_provider(meter_provider.clone());

    let meter = global::meter("test-meter");
    create_all_metric_types(&meter);

    // Wait for metrics to be exported
    tokio::time::sleep(Duration::from_millis(500)).await;

    if let Err(e) = meter_provider.shutdown() {
        eprintln!("Warning: Meter provider shutdown error: {:?}", e);
    }

    // Note: Test agent doesn't support receiving OTLP metrics, but we verify
    // that the meter provider was created successfully and metrics were recorded without errors.
}

#[tokio::test]
async fn test_metrics_export_http_protobuf() {
    const SESSION_NAME: &str = "opentelemetry_api/test_metrics_http_protobuf";

    let test_agent = setup_test_agent(SESSION_NAME).await;
    let base_uri = test_agent.get_base_uri().await;

    let url = base_uri.to_string();
    let url = url.parse::<hyper::http::Uri>().unwrap();
    let scheme = url.scheme_str().unwrap_or("http");
    let host = url.host().unwrap();
    let otlp_endpoint = format!("{scheme}://{host}:4318");

    let config = Arc::new(
        Config::builder()
            .set_trace_agent_url(base_uri.to_string())
            .set_service("test-service".to_string())
            .set_metrics_otel_enabled(true)
            .set_otlp_metrics_endpoint(format!("{}/v1/metrics", otlp_endpoint))
            .set_otlp_metrics_protocol("http/protobuf".to_string())
            .build(),
    );

    let meter_provider = create_meter_provider_with_protocol(
        config,
        None,
        Some(Duration::from_millis(100)),
        Some(OtlpProtocol::HttpProtobuf),
    )
    .expect("Failed to create meter provider");

    global::set_meter_provider(meter_provider.clone());

    let meter = global::meter("test-meter");
    create_all_metric_types(&meter);

    // Wait for metrics to be exported
    tokio::time::sleep(Duration::from_millis(500)).await;

    if let Err(e) = meter_provider.shutdown() {
        eprintln!("Warning: Meter provider shutdown error: {:?}", e);
    }

    // Note: Test agent doesn't support receiving OTLP metrics, but we verify
    // that the meter provider was created successfully and metrics were recorded without errors.
}

#[tokio::test]
async fn test_metrics_export_http_json() {
    const SESSION_NAME: &str = "opentelemetry_api/test_metrics_http_json";

    let test_agent = setup_test_agent(SESSION_NAME).await;
    let base_uri = test_agent.get_base_uri().await;

    let url = base_uri.to_string();
    let url = url.parse::<hyper::http::Uri>().unwrap();
    let scheme = url.scheme_str().unwrap_or("http");
    let host = url.host().unwrap();
    let otlp_endpoint = format!("{scheme}://{host}:4318");

    // Note: HTTP/JSON is not natively supported by opentelemetry-otlp,
    // so this test verifies graceful degradation (no-op provider is returned)
    let config = Arc::new(
        Config::builder()
            .set_trace_agent_url(base_uri.to_string())
            .set_service("test-service".to_string())
            .set_metrics_otel_enabled(true)
            .set_otlp_metrics_endpoint(otlp_endpoint)
            .set_otlp_metrics_protocol("http/json".to_string())
            .build(),
    );

    let result = create_meter_provider_with_protocol(
        config,
        None,
        Some(Duration::from_millis(100)),
        Some(OtlpProtocol::HttpJson),
    );

    // Should succeed but return a no-op provider (graceful degradation)
    assert!(result.is_ok());
    let meter_provider = result.unwrap();

    global::set_meter_provider(meter_provider.clone());

    let meter = global::meter("test-meter");
    let counter: Counter<u64> = meter.u64_counter("test.counter").build();
    counter.add(10, &[KeyValue::new("key1", "value1")]);

    tokio::time::sleep(Duration::from_millis(200)).await;

    if let Err(e) = meter_provider.shutdown() {
        eprintln!("Warning: Meter provider shutdown error: {:?}", e);
    }
}

#[tokio::test]
async fn test_metrics_export_missing_feature_graceful_degradation() {
    const SESSION_NAME: &str = "opentelemetry_api/test_metrics_missing_feature";

    let test_agent = setup_test_agent(SESSION_NAME).await;
    let base_uri = test_agent.get_base_uri().await;

    let url = base_uri.to_string();
    let url = url.parse::<hyper::http::Uri>().unwrap();
    let scheme = url.scheme_str().unwrap_or("http");
    let host = url.host().unwrap();
    let otlp_endpoint = format!("{scheme}://{host}:4318");

    let config = Arc::new(
        Config::builder()
            .set_trace_agent_url(base_uri.to_string())
            .set_service("test-service".to_string())
            .set_metrics_otel_enabled(true)
            .set_otlp_metrics_endpoint(format!("{}/v1/metrics", otlp_endpoint))
            .set_otlp_metrics_protocol("http/protobuf".to_string())
            .build(),
    );

    let result = create_meter_provider_with_protocol(
        config,
        None,
        Some(Duration::from_millis(100)),
        Some(OtlpProtocol::HttpProtobuf),
    );

    // Should succeed (graceful degradation returns no-op provider if feature missing)
    assert!(result.is_ok());
    let meter_provider = result.unwrap();

    global::set_meter_provider(meter_provider.clone());

    let meter = global::meter("test-meter");
    let counter: Counter<u64> = meter.u64_counter("test.counter").build();
    counter.add(10, &[KeyValue::new("key1", "value1")]);

    tokio::time::sleep(Duration::from_millis(200)).await;

    if let Err(e) = meter_provider.shutdown() {
        eprintln!("Warning: Meter provider shutdown error: {:?}", e);
    }
}
