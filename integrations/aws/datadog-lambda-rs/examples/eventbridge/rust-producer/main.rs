// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Rust → EventBridge → Python
//!
//! Rust Lambda puts an event on an EventBridge bus with Datadog trace context
//! injected via `DatadogInterceptor`. A rule routes the event to a downstream
//! Python Lambda.

use aws_config::BehaviorVersion;
use aws_sdk_eventbridge::types::PutEventsRequestEntry;
use aws_sdk_eventbridge::Client as EventBridgeClient;
use datadog_aws_sdk::DatadogInterceptor;
use datadog_lambda_rs::wrap_handler;
use lambda_runtime::{service_fn, Error, LambdaEvent};
use serde_json::{json, Value};

async fn handler(event: LambdaEvent<Value>) -> Result<Value, Error> {
    #[allow(clippy::disallowed_methods)]
    let bus_name = std::env::var("EVENT_BUS_NAME").expect("EVENT_BUS_NAME must be set");

    let detail = event
        .payload
        .get("detail")
        .cloned()
        .unwrap_or_else(|| json!({ "message": "hello from Rust EventBridge producer" }));

    eprintln!("[eventbridge-producer] putting event on bus {bus_name}: {detail}");

    let sdk_config = aws_config::defaults(BehaviorVersion::latest()).load().await;
    let eb_config = aws_sdk_eventbridge::config::Builder::from(&sdk_config)
        .interceptor(DatadogInterceptor::new())
        .build();
    let client = EventBridgeClient::from_conf(eb_config);

    let entry = PutEventsRequestEntry::builder()
        .event_bus_name(&bus_name)
        .source("datadog-lambda-rs.example")
        .detail_type("ExampleEvent")
        .detail(detail.to_string())
        .build();

    let result = client.put_events().entries(entry).send().await?;

    eprintln!(
        "[eventbridge-producer] put_events failed_count={}",
        result.failed_entry_count()
    );

    Ok(json!({ "statusCode": 200 }))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let provider = datadog_opentelemetry::tracing()
        .with_config(
            datadog_opentelemetry::configuration::Config::builder()
                .set_service("eventbridge-producer".to_string())
                .set_env("dev".to_string())
                .set_version("1.0.0".to_string())
                .build(),
        )
        .init();
    lambda_runtime::run(service_fn(wrap_handler(handler, provider))).await
}
