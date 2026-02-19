// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Rust SQS Producer example
//!
//! Demonstrates a Rust Lambda that sends messages to SQS with Datadog trace
//! context injected via `datadog_aws_sdk::DatadogInterceptor`. A downstream
//! Python Lambda (auto-instrumented by ddtrace) consumes the queue, producing
//! a connected trace: Rust → SQS → Python.

use aws_config::BehaviorVersion;
use aws_sdk_sqs::Client as SqsClient;
use datadog_aws_sdk::DatadogInterceptor;
use datadog_lambda_rs::{set_tracer_provider, wrap_handler};
use lambda_runtime::{service_fn, Error, LambdaEvent};
use opentelemetry::trace::TracerProvider;
use serde_json::{json, Value};
use tracing::{info, instrument};
use tracing_subscriber::prelude::*;

#[instrument(name = "send_to_sqs", skip(client))]
async fn send_to_sqs(client: &SqsClient, queue_url: &str, body: &str) -> Result<(), Error> {
    let result = client
        .send_message()
        .queue_url(queue_url)
        .message_body(body)
        .customize()
        .interceptor(DatadogInterceptor::new())
        .send()
        .await?;

    info!(
        message_id = ?result.message_id(),
        "sent message to SQS"
    );
    Ok(())
}

async fn handler(event: LambdaEvent<Value>) -> Result<Value, Error> {
    let request_id = event.context.request_id.clone();
    #[allow(clippy::disallowed_methods)] // Example reads user-configured env var
    let queue_url = std::env::var("QUEUE_URL").expect("QUEUE_URL must be set");

    let body = event
        .payload
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or("hello from Rust SQS producer");

    info!(request_id = %request_id, body = %body, "producing SQS message");

    let sdk_config = aws_config::defaults(BehaviorVersion::latest()).load().await;
    let sqs_client = SqsClient::new(&sdk_config);

    send_to_sqs(&sqs_client, &queue_url, body).await?;

    Ok(json!({
        "statusCode": 200,
        "body": json!({
            "message": "Message sent to SQS",
            "request_id": request_id
        }).to_string()
    }))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let provider = datadog_opentelemetry::tracing()
        .with_config(
            datadog_opentelemetry::configuration::Config::builder()
                .set_service("rust-sqs-producer".to_string())
                .set_env("dev".to_string())
                .set_version("1.0.0".to_string())
                .build(),
        )
        .init();

    set_tracer_provider(provider.clone());

    let telemetry_layer =
        tracing_opentelemetry::layer().with_tracer(provider.tracer("rust-sqs-producer"));

    tracing_subscriber::registry()
        .with(telemetry_layer)
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    lambda_runtime::run(service_fn(wrap_handler(handler))).await
}
