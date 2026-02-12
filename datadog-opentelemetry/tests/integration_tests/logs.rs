// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use datadog_opentelemetry::configuration::Config;
use datadog_opentelemetry::configuration::OtlpProtocol;
use datadog_opentelemetry::logs;
use opentelemetry::logs::LoggerProvider;

const TEST_LOGGER_NAME: &str = "test-logger";

#[track_caller]
fn assert_logger_provider_can_create_logger(
    logger_provider: &opentelemetry_sdk::logs::SdkLoggerProvider,
) {
    let _logger = logger_provider.logger(TEST_LOGGER_NAME);
}

fn create_logger_provider_with_config(
    config: Config,
) -> opentelemetry_sdk::logs::SdkLoggerProvider {
    logs().with_config(config).init()
}

#[tokio::test]
async fn test_logs_default_configuration() {
    let config = Config::builder().build();

    assert!(config.logs_otel_enabled());
    assert_eq!(config.otlp_logs_endpoint(), "");
    assert_eq!(config.otlp_logs_protocol(), None);
    assert_eq!(config.otlp_logs_timeout(), 10000);
    assert_eq!(config.otel_resource_attributes().count(), 0);
}

#[tokio::test]
async fn test_logs_configuration() {
    let config = Config::builder()
        .set_service("test-service-config".to_string())
        .set_env("test-env".to_string())
        .set_version("1.0.0".to_string())
        .set_logs_otel_enabled(false)
        .set_otlp_logs_endpoint("http://localhost:4318/v1/logs".to_string())
        .set_otlp_logs_protocol("http/protobuf".to_string())
        .set_otlp_logs_timeout(5000)
        .build();

    assert_eq!(&*config.service(), "test-service-config");
    assert_eq!(config.env(), Some("test-env"));
    assert_eq!(config.version(), Some("1.0.0"));
    assert!(!config.logs_otel_enabled());
    assert_eq!(config.otlp_logs_endpoint(), "http://localhost:4318/v1/logs");
    assert_eq!(
        config.otlp_logs_protocol(),
        Some(OtlpProtocol::HttpProtobuf)
    );
    assert_eq!(config.otlp_logs_timeout(), 5000);
    assert_eq!(config.otel_resource_attributes().count(), 0);

    let logger_provider = create_logger_provider_with_config(config);
    assert_logger_provider_can_create_logger(&logger_provider);
}

#[tokio::test]
async fn test_logs_resource_attributes() {
    let config = Config::builder()
        .set_logs_otel_enabled(true)
        .set_otlp_logs_protocol("http/protobuf".to_string())
        .set_otel_resource_attributes(vec![
            ("custom.attribute".to_string(), "custom.value".to_string()),
            ("another.attr".to_string(), "another.value".to_string()),
        ])
        .build();

    let attributes: Vec<(&str, &str)> = config.otel_resource_attributes().collect();
    assert_eq!(attributes.len(), 2);
    assert!(attributes.contains(&("custom.attribute", "custom.value")));
    assert!(attributes.contains(&("another.attr", "another.value")));

    let logger_provider = create_logger_provider_with_config(config);
    assert_logger_provider_can_create_logger(&logger_provider);
}

#[tokio::test]
async fn test_logs_export_grpc() {
    let config = Config::builder()
        .set_logs_otel_enabled(true)
        .set_otlp_logs_protocol("grpc".to_string())
        .build();

    assert_eq!(config.otlp_logs_protocol(), Some(OtlpProtocol::Grpc));

    let logger_provider = create_logger_provider_with_config(config);
    assert_logger_provider_can_create_logger(&logger_provider);
}

#[tokio::test]
async fn test_logs_export_http_protobuf() {
    let config = Config::builder()
        .set_logs_otel_enabled(true)
        .set_otlp_logs_protocol("http/protobuf".to_string())
        .build();

    assert_eq!(
        config.otlp_logs_protocol(),
        Some(OtlpProtocol::HttpProtobuf)
    );

    let logger_provider = create_logger_provider_with_config(config);
    assert_logger_provider_can_create_logger(&logger_provider);
}

#[tokio::test]
async fn test_logs_disabled_returns_noop() {
    let config = Config::builder().set_logs_otel_enabled(false).build();

    assert!(!config.logs_otel_enabled());

    let logger_provider = create_logger_provider_with_config(config);
    assert_logger_provider_can_create_logger(&logger_provider);
}

#[tokio::test]
async fn test_logs_export_http_json() {
    let config = Config::builder()
        .set_logs_otel_enabled(true)
        .set_otlp_logs_protocol("http/json".to_string())
        .build();

    assert_eq!(config.otlp_logs_protocol(), Some(OtlpProtocol::HttpJson));

    let logger_provider = create_logger_provider_with_config(config);
    assert_logger_provider_can_create_logger(&logger_provider);
}
