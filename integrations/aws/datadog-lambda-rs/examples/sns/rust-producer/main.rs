// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Rust → SNS → Python (direct subscription)
//!
//! Rust Lambda publishes to an SNS topic with Datadog trace context injected
//! via `DatadogInterceptor`. A downstream Python Lambda is subscribed directly
//! to the topic.

use aws_config::BehaviorVersion;
use aws_sdk_sns::Client as SnsClient;
use datadog_aws_sdk::DatadogInterceptor;
use datadog_lambda_rs::{set_tracer_provider, wrap_handler};
use lambda_runtime::{service_fn, Error, LambdaEvent};
use serde_json::{json, Value};

async fn handler(event: LambdaEvent<Value>) -> Result<Value, Error> {
    #[allow(clippy::disallowed_methods)]
    let topic_arn = std::env::var("TOPIC_ARN").expect("TOPIC_ARN must be set");

    let message = event
        .payload
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("hello from Rust SNS producer");

    eprintln!("[sns-producer] publishing to {topic_arn}: {message}");

    let sdk_config = aws_config::defaults(BehaviorVersion::latest()).load().await;
    let sns_config = aws_sdk_sns::config::Builder::from(&sdk_config)
        .interceptor(DatadogInterceptor::new())
        .build();
    let client = SnsClient::from_conf(sns_config);

    let result = client
        .publish()
        .topic_arn(&topic_arn)
        .message(message)
        .send()
        .await?;

    eprintln!(
        "[sns-producer] published messageId={}",
        result.message_id().unwrap_or("unknown")
    );

    Ok(json!({ "statusCode": 200 }))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let provider = datadog_opentelemetry::tracing()
        .with_config(
            datadog_opentelemetry::configuration::Config::builder()
                .set_service("sns-producer".to_string())
                .set_env("dev".to_string())
                .set_version("1.0.0".to_string())
                .build(),
        )
        .init();
    set_tracer_provider(provider);
    lambda_runtime::run(service_fn(wrap_handler(handler))).await
}
