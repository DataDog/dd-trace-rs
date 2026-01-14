// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use datadog_opentelemetry::configuration::Config;
use datadog_opentelemetry::metrics;
use datadog_opentelemetry::OtlpProtocol;
use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram, UpDownCounter};

const TEST_EXPORT_INTERVAL: Duration = Duration::from_millis(100);
const TEST_METER_NAME: &str = "test-meter";

#[track_caller]
fn assert_meter_can_create_instruments(meter: &opentelemetry::metrics::Meter) {
    let _counter: Counter<u64> = meter.u64_counter("test.counter").build();
    let _updown_counter: UpDownCounter<i64> = meter.i64_up_down_counter("test.updown").build();
    let _histogram: Histogram<f64> = meter.f64_histogram("test.histogram").build();

    let _observable_counter = meter
        .u64_observable_counter("test.observable_counter")
        .with_callback(|_result| {})
        .build();

    let _observable_gauge = meter
        .f64_observable_gauge("test.observable_gauge")
        .with_callback(|_result| {})
        .build();

    let _observable_updown = meter
        .i64_observable_up_down_counter("test.observable_updown")
        .with_callback(|_result| {})
        .build();
}

fn create_meter_provider_with_config(
    config: Config,
) -> opentelemetry_sdk::metrics::SdkMeterProvider {
    metrics()
        .with_config(config)
        .with_export_interval(TEST_EXPORT_INTERVAL)
        .init()
}

fn create_meter_provider_with_config_no_interval(
    config: Config,
) -> opentelemetry_sdk::metrics::SdkMeterProvider {
    metrics().with_config(config).init()
}

#[tokio::test]
async fn test_metrics_default_configuration() {
    let config = Config::builder().build();

    assert!(config.metrics_otel_enabled());
    assert_eq!(config.otlp_metrics_endpoint(), "");
    assert_eq!(config.otlp_metrics_protocol(), None);
    assert_eq!(config.otlp_metrics_timeout(), 10000);
    assert_eq!(
        config.otel_metrics_temporality_preference(),
        Some(opentelemetry_sdk::metrics::Temporality::Delta)
    );
    assert_eq!(config.metric_export_interval(), 10000);
    assert_eq!(config.metric_export_timeout(), 7500);
    assert_eq!(config.otel_resource_attributes().count(), 0);
}

#[tokio::test]
async fn test_metrics_configuration() {
    let config = Config::builder()
        .set_service("test-service-config".to_string())
        .set_env("test-env".to_string())
        .set_version("1.0.0".to_string())
        .set_metrics_otel_enabled(false)
        .set_otlp_metrics_endpoint("http://localhost:4318/v1/metrics".to_string())
        .set_otlp_metrics_protocol("http/protobuf".to_string())
        .set_otlp_metrics_timeout(5000)
        .set_otel_metrics_temporality_preference(
            opentelemetry_sdk::metrics::Temporality::Cumulative,
        )
        .set_metric_export_interval(2000)
        .set_metric_export_timeout(3000)
        .build();

    assert_eq!(&*config.service(), "test-service-config");
    assert_eq!(config.env(), Some("test-env"));
    assert_eq!(config.version(), Some("1.0.0"));
    assert!(!config.metrics_otel_enabled());
    assert_eq!(
        config.otlp_metrics_endpoint(),
        "http://localhost:4318/v1/metrics"
    );
    assert_eq!(
        config.otlp_metrics_protocol(),
        Some(OtlpProtocol::HttpProtobuf)
    );
    assert_eq!(config.otlp_metrics_timeout(), 5000);
    assert_eq!(
        config.otel_metrics_temporality_preference(),
        Some(opentelemetry_sdk::metrics::Temporality::Cumulative)
    );
    assert_eq!(config.metric_export_interval(), 2000);
    assert_eq!(config.metric_export_timeout(), 3000);
    assert_eq!(config.otel_resource_attributes().count(), 0);

    let meter_provider = create_meter_provider_with_config(config);
    let meter = global::meter(TEST_METER_NAME);
    assert_meter_can_create_instruments(&meter);
    
    // Shutdown needs to be called from a blocking context to avoid deadlock
    // with periodic_reader_with_async_runtime's internal block_on
    tokio::task::spawn_blocking(move || {
        let _ = meter_provider.shutdown();
    })
    .await
    .ok();
}

#[tokio::test]
async fn test_metrics_resource_attributes() {
    let config = Config::builder()
        .set_metrics_otel_enabled(true)
        .set_otlp_metrics_protocol("http/protobuf".to_string())
        .set_otel_resource_attributes(vec![
            ("custom.attribute".to_string(), "custom.value".to_string()),
            ("another.attr".to_string(), "another.value".to_string()),
        ])
        .build();

    let attributes: Vec<(&str, &str)> = config.otel_resource_attributes().collect();
    assert_eq!(attributes.len(), 2);
    assert!(attributes.contains(&("custom.attribute", "custom.value")));
    assert!(attributes.contains(&("another.attr", "another.value")));

    let meter_provider = create_meter_provider_with_config(config);
    let meter = global::meter(TEST_METER_NAME);
    assert_meter_can_create_instruments(&meter);
    
    // Shutdown needs to be called from a blocking context to avoid deadlock
    // with periodic_reader_with_async_runtime's internal block_on
    tokio::task::spawn_blocking(move || {
        let _ = meter_provider.shutdown();
    })
    .await
    .ok();
}

#[tokio::test]
async fn test_metrics_temporality_preference_delta() {
    let config = Config::builder()
        .set_metrics_otel_enabled(true)
        .set_otlp_metrics_protocol("http/protobuf".to_string())
        .set_otel_metrics_temporality_preference(opentelemetry_sdk::metrics::Temporality::Delta)
        .build();

    assert_eq!(
        config.otel_metrics_temporality_preference(),
        Some(opentelemetry_sdk::metrics::Temporality::Delta)
    );

    let meter_provider = create_meter_provider_with_config(config);
    let meter = global::meter(TEST_METER_NAME);
    assert_meter_can_create_instruments(&meter);
    
    // Shutdown needs to be called from a blocking context to avoid deadlock
    // with periodic_reader_with_async_runtime's internal block_on
    tokio::task::spawn_blocking(move || {
        let _ = meter_provider.shutdown();
    })
    .await
    .ok();
}

#[tokio::test]
async fn test_metrics_temporality_preference_cumulative() {
    let config = Config::builder()
        .set_metrics_otel_enabled(true)
        .set_otlp_metrics_protocol("http/protobuf".to_string())
        .set_otel_metrics_temporality_preference(
            opentelemetry_sdk::metrics::Temporality::Cumulative,
        )
        .build();

    assert_eq!(
        config.otel_metrics_temporality_preference(),
        Some(opentelemetry_sdk::metrics::Temporality::Cumulative)
    );

    let meter_provider = create_meter_provider_with_config(config);
    let meter = global::meter(TEST_METER_NAME);
    assert_meter_can_create_instruments(&meter);
    
    // Shutdown needs to be called from a blocking context to avoid deadlock
    // with periodic_reader_with_async_runtime's internal block_on
    tokio::task::spawn_blocking(move || {
        let _ = meter_provider.shutdown();
    })
    .await
    .ok();
}

#[tokio::test]
async fn test_metrics_export_grpc() {
    let config = Config::builder()
        .set_metrics_otel_enabled(true)
        .set_otlp_metrics_protocol("grpc".to_string())
        .build();

    assert_eq!(config.otlp_metrics_protocol(), Some(OtlpProtocol::Grpc));

    let meter_provider = create_meter_provider_with_config(config);
    let meter = global::meter(TEST_METER_NAME);
    assert_meter_can_create_instruments(&meter);
    
    // Shutdown needs to be called from a blocking context to avoid deadlock
    // with periodic_reader_with_async_runtime's internal block_on
    tokio::task::spawn_blocking(move || {
        let _ = meter_provider.shutdown();
    })
    .await
    .ok();
}

#[tokio::test]
async fn test_metrics_export_http_protobuf() {
    let config = Config::builder()
        .set_metrics_otel_enabled(true)
        .set_otlp_metrics_protocol("http/protobuf".to_string())
        .build();

    assert_eq!(
        config.otlp_metrics_protocol(),
        Some(OtlpProtocol::HttpProtobuf)
    );

    let meter_provider = create_meter_provider_with_config(config);
    let meter = global::meter(TEST_METER_NAME);
    assert_meter_can_create_instruments(&meter);
    
    // Shutdown needs to be called from a blocking context to avoid deadlock
    // with periodic_reader_with_async_runtime's internal block_on
    tokio::task::spawn_blocking(move || {
        let _ = meter_provider.shutdown();
    })
    .await
    .ok();
}

#[tokio::test]
async fn test_metrics_disabled_returns_noop() {
    let config = Config::builder().set_metrics_otel_enabled(false).build();

    assert!(!config.metrics_otel_enabled());

    let _meter_provider = create_meter_provider_with_config_no_interval(config);
    let meter = global::meter(TEST_METER_NAME);
    assert_meter_can_create_instruments(&meter);
}

#[tokio::test]
async fn test_metrics_export_http_json() {
    let config = Config::builder()
        .set_metrics_otel_enabled(true)
        .set_otlp_metrics_protocol("http/json".to_string())
        .build();

    assert_eq!(config.otlp_metrics_protocol(), Some(OtlpProtocol::HttpJson));

    let meter_provider = create_meter_provider_with_config(config);
    let meter = global::meter(TEST_METER_NAME);
    assert_meter_can_create_instruments(&meter);
    
    // Shutdown needs to be called from a blocking context to avoid deadlock
    // with periodic_reader_with_async_runtime's internal block_on
    tokio::task::spawn_blocking(move || {
        let _ = meter_provider.shutdown();
    })
    .await
    .ok();
}
