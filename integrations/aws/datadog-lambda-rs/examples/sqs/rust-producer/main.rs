// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Rust → SQS → Python
//!
//! Rust Lambda sends a message to SQS with Datadog trace context injected
//! via `DatadogInterceptor`. A downstream Python Lambda (auto-instrumented
//! by ddtrace) consumes the queue, producing a connected trace.

use aws_config::BehaviorVersion;
use aws_sdk_sqs::Client as SqsClient;
use datadog_aws_sdk::DatadogInterceptor;
use datadog_lambda_rs::wrap_handler;
use lambda_runtime::{service_fn, Error, LambdaEvent};
use serde_json::{json, Value};

async fn handler(event: LambdaEvent<Value>) -> Result<Value, Error> {
    #[allow(clippy::disallowed_methods)]
    let queue_url = std::env::var("QUEUE_URL").expect("QUEUE_URL must be set");

    let body = event
        .payload
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or("hello from Rust SQS producer");

    eprintln!("[sqs-producer] sending message to {queue_url}: {body}");

    let sdk_config = aws_config::defaults(BehaviorVersion::latest()).load().await;
    let sqs_config = aws_sdk_sqs::config::Builder::from(&sdk_config)
        .interceptor(DatadogInterceptor::new())
        .build();
    let client = SqsClient::from_conf(sqs_config);

    let result = client
        .send_message()
        .queue_url(&queue_url)
        .message_body(body)
        .send()
        .await?;

    eprintln!(
        "[sqs-producer] sent messageId={}",
        result.message_id().unwrap_or("unknown")
    );

    Ok(json!({ "statusCode": 200 }))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let provider = datadog_opentelemetry::tracing()
        .with_config(
            datadog_opentelemetry::configuration::Config::builder()
                .set_service("sqs-producer".to_string())
                .set_env("dev".to_string())
                .set_version("1.0.0".to_string())
                .build(),
        )
        .init();
    lambda_runtime::run(service_fn(wrap_handler(handler, provider))).await
}
