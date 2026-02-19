// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! SQS -> Lambda example
//!
//! Demonstrates `wrap_handler` + `set_tracer_provider` from `datadog_lambda_rs`
//! with SQS as the event source. Each message is processed in a child span
//! that simulates 30 ms of work.

use datadog_lambda_rs::{set_tracer_provider, wrap_handler};
use lambda_runtime::{service_fn, Error, LambdaEvent};
use opentelemetry::trace::TracerProvider;
use serde_json::{json, Value};
use std::time::Duration;
use tracing::{info, instrument};
use tracing_subscriber::prelude::*;

async fn handler(event: LambdaEvent<Value>) -> Result<Value, Error> {
    let request_id = event.context.request_id.clone();

    // SQS batches messages in event.payload.Records
    let records = event
        .payload
        .get("Records")
        .and_then(|r| r.as_array())
        .cloned()
        .unwrap_or_default();

    info!(request_id = %request_id, record_count = records.len(), "processing SQS batch");

    for (i, record) in records.iter().enumerate() {
        let message_id = record
            .get("messageId")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let body = record.get("body").and_then(|v| v.as_str()).unwrap_or("");

        process_message(&request_id, i, message_id, body).await;
    }

    Ok(json!({
        "statusCode": 200,
        "body": json!({
            "message": "Processed SQS batch",
            "request_id": request_id,
            "records_processed": records.len()
        }).to_string()
    }))
}

#[instrument(
    name = "process_message",
    fields(request.id = %request_id, message.index = index, message.id = %message_id)
)]
async fn process_message(request_id: &str, index: usize, message_id: &str, body: &str) {
    info!(body = %body, "processing message");
    // Simulate 30 ms of work per message
    tokio::time::sleep(Duration::from_millis(30)).await;
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let provider = datadog_opentelemetry::tracing()
        .with_config(
            datadog_opentelemetry::configuration::Config::builder()
                .set_service("rust-lambda-sqs".to_string())
                .set_env("dev".to_string())
                .set_version("1.0.0".to_string())
                .build(),
        )
        .init();

    set_tracer_provider(provider.clone());

    let telemetry_layer =
        tracing_opentelemetry::layer().with_tracer(provider.tracer("rust-lambda-sqs"));

    tracing_subscriber::registry()
        .with(telemetry_layer)
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    lambda_runtime::run(service_fn(wrap_handler(handler))).await
}
