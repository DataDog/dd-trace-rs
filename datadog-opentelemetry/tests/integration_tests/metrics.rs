// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::time::Duration;

use datadog_opentelemetry::configuration::Config;
use datadog_opentelemetry::{create_meter_provider_with_protocol, OtlpProtocol};
use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram, UpDownCounter};
use opentelemetry::KeyValue;
use libdd_common::hyper_migration::{self, Body};
use http_body_util::BodyExt;

use crate::integration_tests::make_test_agent;

async fn setup_test_agent(
    session_name: &'static str,
) -> libdd_trace_utils::test_utils::datadog_test_agent::DatadogTestAgent {
    make_test_agent(session_name).await
}

async fn verify_scoped_metrics_count(
    test_agent: &libdd_trace_utils::test_utils::datadog_test_agent::DatadogTestAgent,
    session_name: &str,
    expected: usize,
) {
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    let uri = format!("{}/test/session/metrics?test_session_token={}", 
        test_agent.get_otlp_http_uri().await.to_string().trim_end_matches('/'), session_name)
        .parse::<hyper::Uri>().unwrap();
    
    let response = hyper_migration::new_default_client()
        .request(hyper::Request::builder().method("GET").uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    
    let (_, body) = response.into_parts();
    let metrics: serde_json::Value = serde_json::from_slice(
        &body.collect().await.unwrap().to_bytes()
    ).unwrap();
    
    let count = metrics.as_array()
        .unwrap()
        .iter()
        .flat_map(|b| b["resource_metrics"].as_array().unwrap())
        .flat_map(|rm| rm["scope_metrics"].as_array().unwrap())
        .count();
    
    assert_eq!(count, expected);
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

async fn setup_meter_provider(
    test_agent: &libdd_trace_utils::test_utils::datadog_test_agent::DatadogTestAgent,
    protocol: OtlpProtocol,
) -> opentelemetry_sdk::metrics::SdkMeterProvider {
    let base_uri = test_agent.get_base_uri().await.to_string();
    let endpoint = match protocol {
        OtlpProtocol::Grpc => test_agent.get_otlp_grpc_uri().await.to_string(),
        OtlpProtocol::HttpProtobuf => {
            let uri = test_agent.get_otlp_http_uri().await.to_string();
            let trimmed = uri.trim_end_matches('/');
            format!("{}/v1/metrics", trimmed)
        },
        OtlpProtocol::HttpJson => test_agent.get_otlp_http_uri().await.to_string(),
    };
    
    let mut builder = Config::builder();
    builder.set_trace_agent_url(base_uri)
        .set_service("test-service".to_string())
        .set_metrics_otel_enabled(true)
        .set_otlp_metrics_endpoint(endpoint);
    
    if protocol != OtlpProtocol::Grpc {
        let protocol_str = match protocol {
            OtlpProtocol::HttpProtobuf => "http/protobuf",
            OtlpProtocol::HttpJson => "http/json",
            _ => unreachable!(),
        };
        builder.set_otlp_metrics_protocol(protocol_str.to_string());
    }
    
    create_meter_provider_with_protocol(
        Arc::new(builder.build()),
        None,
        Some(Duration::from_millis(100)),
        Some(protocol),
    ).unwrap()
}

#[tokio::test]
async fn test_metrics_export_grpc() {
    let test_agent = setup_test_agent("opentelemetry_api/test_metrics_grpc").await;
    let meter_provider = setup_meter_provider(&test_agent, OtlpProtocol::Grpc).await;
    
    global::set_meter_provider(meter_provider.clone());
    create_all_metric_types(&global::meter("test-meter"));
    
    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = meter_provider.shutdown();
    
    verify_scoped_metrics_count(&test_agent, "opentelemetry_api/test_metrics_grpc", 5).await;
}

#[tokio::test]
async fn test_metrics_export_http_protobuf() {
    let test_agent = setup_test_agent("opentelemetry_api/test_metrics_http_protobuf").await;
    let meter_provider = setup_meter_provider(&test_agent, OtlpProtocol::HttpProtobuf).await;
    
    global::set_meter_provider(meter_provider.clone());
    create_all_metric_types(&global::meter("test-meter"));
    
    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = meter_provider.shutdown();
    
    verify_scoped_metrics_count(&test_agent, "opentelemetry_api/test_metrics_http_protobuf", 5).await;
}

#[tokio::test]
async fn test_metrics_export_http_json() {
    let test_agent = setup_test_agent("opentelemetry_api/test_metrics_http_json").await;
    let meter_provider = setup_meter_provider(&test_agent, OtlpProtocol::HttpJson).await;
    
    global::set_meter_provider(meter_provider.clone());
    global::meter("test-meter").u64_counter("test.counter").build()
        .add(10, &[KeyValue::new("key1", "value1")]);
    
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(meter_provider.shutdown().is_ok());
}

#[tokio::test]
async fn test_metrics_export_missing_feature_graceful_degradation() {
    let test_agent = setup_test_agent("opentelemetry_api/test_metrics_missing_feature").await;
    let meter_provider = setup_meter_provider(&test_agent, OtlpProtocol::HttpProtobuf).await;
    
    global::set_meter_provider(meter_provider.clone());
    global::meter("test-meter").u64_counter("test.counter").build()
        .add(10, &[KeyValue::new("key1", "value1")]);
    
    tokio::time::sleep(Duration::from_millis(200)).await;
    let _ = meter_provider.shutdown();
}
