// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Python → SNS → Rust (direct subscription)
//!
//! Rust Lambda subscribed directly to an SNS topic. A co-located Python Lambda
//! publishes to the topic, and the Datadog Lambda Extension extracts trace
//! context from the `_datadog` MessageAttribute.

use datadog_lambda_rs::{set_tracer_provider, wrap_handler};
use lambda_runtime::{service_fn, Error, LambdaEvent};
use serde_json::{json, Value};

async fn handler(event: LambdaEvent<Value>) -> Result<Value, Error> {
    let records = event
        .payload
        .get("Records")
        .and_then(|r| r.as_array())
        .map(|r| r.len())
        .unwrap_or(0);

    eprintln!("[sns-consumer] received {records} record(s)");
    eprintln!("[sns-consumer] event: {}", event.payload);

    Ok(json!({ "statusCode": 200, "records_processed": records }))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let provider = datadog_opentelemetry::tracing()
        .with_config(
            datadog_opentelemetry::configuration::Config::builder()
                .set_service("sns-consumer".to_string())
                .set_env("dev".to_string())
                .set_version("1.0.0".to_string())
                .build(),
        )
        .init();
    set_tracer_provider(provider);
    lambda_runtime::run(service_fn(wrap_handler(handler))).await
}
