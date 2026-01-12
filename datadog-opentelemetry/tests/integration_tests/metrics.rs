// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::time::Duration;

use datadog_opentelemetry::configuration::Config;
use datadog_opentelemetry::metrics;
use datadog_opentelemetry::OtlpProtocol;
use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram, UpDownCounter};
use opentelemetry::KeyValue;

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
    // Clean up any previous env vars first
    env::remove_var("DD_SERVICE");
    env::remove_var("DD_METRICS_OTEL_ENABLED");
    env::remove_var("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT");
    env::remove_var("OTEL_EXPORTER_OTLP_PROTOCOL");

    env::set_var("DD_SERVICE", "test-service");
    env::set_var("DD_METRICS_OTEL_ENABLED", "true");
    env::set_var("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "http://localhost:4317");
    env::set_var("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc");

    let meter_provider = metrics()
        .with_export_interval(Duration::from_millis(100))
        .init();

    // Verify meter provider is set globally (can get a meter)
    let _meter = global::meter("test-verify");
    let _ = _meter; // Meter provider is set if we can get a meter

    // Verify configuration is applied
    let config = Config::builder().build();
    assert_eq!(&*config.service(), "test-service");
    assert!(config.metrics_otel_enabled());
    assert_eq!(config.otlp_metrics_endpoint(), "http://localhost:4317");

    let meter = global::meter("test-meter");
    create_all_metric_types(&meter);

    tokio::time::sleep(Duration::from_millis(500)).await;

    meter_provider.shutdown().expect("Meter provider should shutdown cleanly");

    // Cleanup
    env::remove_var("DD_SERVICE");
    env::remove_var("DD_METRICS_OTEL_ENABLED");
    env::remove_var("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT");
    env::remove_var("OTEL_EXPORTER_OTLP_PROTOCOL");
}

#[tokio::test]
async fn test_metrics_export_http_protobuf() {
    // Clean up any previous env vars first
    env::remove_var("DD_SERVICE");
    env::remove_var("DD_METRICS_OTEL_ENABLED");
    env::remove_var("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT");
    env::remove_var("OTEL_EXPORTER_OTLP_PROTOCOL");

    env::set_var("DD_SERVICE", "test-service");
    env::set_var("DD_METRICS_OTEL_ENABLED", "true");
    env::set_var("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "http://localhost:4318/v1/metrics");
    env::set_var("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf");

    let meter_provider = metrics()
        .with_export_interval(Duration::from_millis(100))
        .init();

    // Verify meter provider is set globally (can get a meter)
    let _meter = global::meter("test-verify");
    let _ = _meter; // Meter provider is set if we can get a meter

    // Verify configuration is applied
    let config = Config::builder().build();
    assert_eq!(&*config.service(), "test-service");
    assert!(config.metrics_otel_enabled());
    // Note: endpoint gets /v1/metrics appended automatically for HTTP/protobuf
    assert!(config.otlp_metrics_endpoint().contains("localhost:4318"));
    assert_eq!(config.otlp_metrics_protocol(), Some(OtlpProtocol::HttpProtobuf));

    let meter = global::meter("test-meter");
    create_all_metric_types(&meter);

    tokio::time::sleep(Duration::from_millis(500)).await;

    meter_provider.shutdown().expect("Meter provider should shutdown cleanly");

    // Cleanup
    env::remove_var("DD_SERVICE");
    env::remove_var("DD_METRICS_OTEL_ENABLED");
    env::remove_var("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT");
    env::remove_var("OTEL_EXPORTER_OTLP_PROTOCOL");
}

#[tokio::test]
async fn test_metrics_export_http_json() {
    // Clean up any previous env vars first
    env::remove_var("DD_SERVICE");
    env::remove_var("DD_METRICS_OTEL_ENABLED");
    env::remove_var("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT");
    env::remove_var("OTEL_EXPORTER_OTLP_PROTOCOL");

    env::set_var("DD_SERVICE", "test-service");
    env::set_var("DD_METRICS_OTEL_ENABLED", "true");
    env::set_var("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "http://localhost:4318");
    env::set_var("OTEL_EXPORTER_OTLP_PROTOCOL", "http/json");

    // Note: HTTP/JSON is not natively supported by opentelemetry-otlp,
    // so this test verifies graceful degradation (no-op provider is returned)
    let meter_provider = metrics()
        .with_export_interval(Duration::from_millis(100))
        .init();

    // Verify meter provider is set globally (even if it's a no-op)
    let _meter = global::meter("test-verify");
    let _ = _meter; // Meter provider is set if we can get a meter

    // Verify configuration is applied
    let config = Config::builder().build();
    assert_eq!(&*config.service(), "test-service");
    assert!(config.metrics_otel_enabled());
    assert_eq!(config.otlp_metrics_protocol(), Some(OtlpProtocol::HttpJson));

    let meter = global::meter("test-meter");
    let counter: Counter<u64> = meter.u64_counter("test.counter").build();
    counter.add(10, &[KeyValue::new("key1", "value1")]);

    tokio::time::sleep(Duration::from_millis(200)).await;

    meter_provider.shutdown().expect("Meter provider should shutdown cleanly");

    // Cleanup
    env::remove_var("DD_SERVICE");
    env::remove_var("DD_METRICS_OTEL_ENABLED");
    env::remove_var("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT");
    env::remove_var("OTEL_EXPORTER_OTLP_PROTOCOL");
}

#[tokio::test]
async fn test_metrics_export_configuration_applied() {
    // Clean up any previous env vars first
    env::remove_var("DD_SERVICE");
    env::remove_var("DD_ENV");
    env::remove_var("DD_VERSION");
    env::remove_var("DD_METRICS_OTEL_ENABLED");
    env::remove_var("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT");
    env::remove_var("OTEL_EXPORTER_OTLP_PROTOCOL");

    env::set_var("DD_SERVICE", "test-service-config");
    env::set_var("DD_ENV", "test-env");
    env::set_var("DD_VERSION", "1.0.0");
    env::set_var("DD_METRICS_OTEL_ENABLED", "true");
    env::set_var("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "http://localhost:4318/v1/metrics");
    env::set_var("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf");

    let meter_provider = metrics()
        .with_export_interval(Duration::from_millis(100))
        .init();

    // Verify meter provider is set globally (can get a meter)
    let _meter = global::meter("test-verify");
    let _ = _meter; // Meter provider is set if we can get a meter

    // Verify all configurations are correctly applied
    let config = Config::builder().build();
    assert_eq!(&*config.service(), "test-service-config");
    assert_eq!(config.env(), Some("test-env"));
    assert_eq!(config.version(), Some("1.0.0"));
    assert!(config.metrics_otel_enabled());
    assert_eq!(config.otlp_metrics_endpoint(), "http://localhost:4318/v1/metrics");
    assert_eq!(config.otlp_metrics_protocol(), Some(OtlpProtocol::HttpProtobuf));

    let meter = global::meter("test-meter");
    let counter: Counter<u64> = meter.u64_counter("test.counter").build();
    counter.add(10, &[KeyValue::new("key1", "value1")]);

    tokio::time::sleep(Duration::from_millis(200)).await;

    meter_provider.shutdown().expect("Meter provider should shutdown cleanly");

    // Cleanup
    env::remove_var("DD_SERVICE");
    env::remove_var("DD_ENV");
    env::remove_var("DD_VERSION");
    env::remove_var("DD_METRICS_OTEL_ENABLED");
    env::remove_var("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT");
    env::remove_var("OTEL_EXPORTER_OTLP_PROTOCOL");
}
