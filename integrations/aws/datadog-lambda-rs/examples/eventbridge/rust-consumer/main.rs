// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Python → EventBridge → Rust
//!
//! Rust Lambda triggered by an EventBridge rule. A co-located Python Lambda
//! puts events on the bus, and the Datadog Lambda Extension extracts trace
//! context from the `_datadog` key in the event detail.

use datadog_lambda_rs::wrap_handler;
use lambda_runtime::{service_fn, Error, LambdaEvent};
use serde_json::{json, Value};

async fn handler(event: LambdaEvent<Value>) -> Result<Value, Error> {
    let source = event
        .payload
        .get("source")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let detail_type = event
        .payload
        .get("detail-type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    eprintln!("[eventbridge-consumer] received event: source={source} detail-type={detail_type}");
    eprintln!("[eventbridge-consumer] event: {}", event.payload);

    Ok(json!({ "statusCode": 200, "source": source, "detail_type": detail_type }))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let provider = datadog_opentelemetry::tracing()
        .with_config(
            datadog_opentelemetry::configuration::Config::builder()
                .set_service("eventbridge-consumer".to_string())
                .set_env("dev".to_string())
                .set_version("1.0.0".to_string())
                .build(),
        )
        .init();
    lambda_runtime::run(service_fn(wrap_handler(handler, provider))).await
}
