// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! EventBridge-specific trace context enrichment.
//!
//! Injects trace context into the `Detail` JSON field of PutEvents entries as a `_datadog` key,
//! matching dd-trace-go's format. Includes `x-datadog-start-time` and per-entry
//! `x-datadog-resource-name` (set to EventBusName when present).

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_sdk_eventbridge::operation::put_events::PutEventsInput;
use aws_smithy_runtime_api::box_error::BoxError;
use aws_smithy_runtime_api::client::interceptors::context::Input;

use super::{AwsService, ServiceInjector, DATADOG_ATTRIBUTE_KEY, ONE_MB};
const START_TIME_KEY: &str = "x-datadog-start-time";
const RESOURCE_NAME_KEY: &str = "x-datadog-resource-name";

fn inject_into_put_events(
    input: &mut PutEventsInput,
    trace_headers: &HashMap<String, String>,
) -> Result<(), BoxError> {
    let entries = match input.entries.as_mut() {
        Some(entries) => entries,
        None => return Ok(()),
    };

    let start_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .to_string();

    let mut ctx = serde_json::Map::with_capacity(trace_headers.len() + 2);
    for (k, v) in trace_headers {
        ctx.insert(k.clone(), serde_json::Value::String(v.clone()));
    }
    ctx.insert(START_TIME_KEY.into(), serde_json::Value::String(start_time));

    for entry in entries.iter_mut() {
        if let Some(name) = entry.event_bus_name.as_deref() {
            ctx.insert(
                RESOURCE_NAME_KEY.into(),
                serde_json::Value::String(name.into()),
            );
        }

        let trace_ctx = serde_json::to_string(&ctx)?;
        ctx.remove(RESOURCE_NAME_KEY);

        let detail = entry.detail.as_deref().unwrap_or("{}");

        if detail.len() < 2 || !detail.ends_with('}') {
            continue;
        }

        let new_detail = if detail.len() > 2 {
            format!(
                "{},\"{DATADOG_ATTRIBUTE_KEY}\":{trace_ctx}}}",
                &detail[..detail.len() - 1]
            )
        } else {
            format!("{{\"{DATADOG_ATTRIBUTE_KEY}\":{trace_ctx}}}")
        };

        if new_detail.len() > ONE_MB {
            continue;
        }

        entry.detail = Some(new_detail);
    }
    Ok(())
}

pub(crate) struct EventBridgeInjector;

impl ServiceInjector for EventBridgeInjector {
    fn service(&self) -> AwsService {
        AwsService::EventBridge
    }

    fn inject(
        &self,
        operation: &str,
        trace_headers: &HashMap<String, String>,
        input: &mut Input,
    ) -> Result<(), BoxError> {
        if operation == "PutEvents" {
            if let Some(put_input) = input.downcast_mut::<PutEventsInput>() {
                inject_into_put_events(put_input, trace_headers)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::test_helpers::{
        sample_trace_headers, DATADOG_PARENT_ID_KEY, DATADOG_SAMPLING_PRIORITY_KEY,
        DATADOG_TRACE_ID_KEY,
    };
    use aws_sdk_eventbridge::types::PutEventsRequestEntry;

    fn parse_detail_datadog(detail: &str) -> HashMap<String, String> {
        let parsed: serde_json::Value = serde_json::from_str(detail).unwrap();
        let dd = parsed
            .get(DATADOG_ATTRIBUTE_KEY)
            .unwrap()
            .as_object()
            .unwrap();
        dd.iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
            .collect()
    }

    #[test]
    fn test_put_events_injection() {
        let trace_headers = sample_trace_headers();
        let entry = PutEventsRequestEntry::builder()
            .source("my.source")
            .detail_type("MyDetailType")
            .detail(r#"{"key":"value"}"#)
            .build();
        let mut input = PutEventsInput::builder().entries(entry).build().unwrap();

        inject_into_put_events(&mut input, &trace_headers).unwrap();

        let entries = input.entries.as_ref().unwrap();
        let detail = entries[0].detail.as_ref().unwrap();
        let dd = parse_detail_datadog(detail);
        assert_eq!(dd[DATADOG_TRACE_ID_KEY], "123456789");
        assert_eq!(dd[DATADOG_PARENT_ID_KEY], "987654321");
        assert_eq!(dd[DATADOG_SAMPLING_PRIORITY_KEY], "1");
        assert!(dd.contains_key(START_TIME_KEY));

        let parsed: serde_json::Value = serde_json::from_str(detail).unwrap();
        assert_eq!(parsed["key"], "value");
    }

    #[test]
    fn test_put_events_empty_detail() {
        let trace_headers = sample_trace_headers();
        let entry = PutEventsRequestEntry::builder()
            .source("my.source")
            .detail_type("MyDetailType")
            .build();
        let mut input = PutEventsInput::builder().entries(entry).build().unwrap();

        inject_into_put_events(&mut input, &trace_headers).unwrap();

        let entries = input.entries.as_ref().unwrap();
        let detail = entries[0].detail.as_ref().unwrap();
        let dd = parse_detail_datadog(detail);
        assert_eq!(dd[DATADOG_TRACE_ID_KEY], "123456789");
        assert!(!dd.contains_key(RESOURCE_NAME_KEY));
    }

    #[test]
    fn test_put_events_with_event_bus_name() {
        let trace_headers = sample_trace_headers();
        let entry = PutEventsRequestEntry::builder()
            .source("my.source")
            .detail_type("MyDetailType")
            .detail(r#"{"key":"value"}"#)
            .event_bus_name("my-bus")
            .build();
        let mut input = PutEventsInput::builder().entries(entry).build().unwrap();

        inject_into_put_events(&mut input, &trace_headers).unwrap();

        let entries = input.entries.as_ref().unwrap();
        let detail = entries[0].detail.as_ref().unwrap();
        let dd = parse_detail_datadog(detail);
        assert_eq!(dd[RESOURCE_NAME_KEY], "my-bus");
    }

    #[test]
    fn test_put_events_multiple_entries() {
        let trace_headers = sample_trace_headers();
        let entry1 = PutEventsRequestEntry::builder()
            .source("src1")
            .detail_type("Type1")
            .detail(r#"{"a":1}"#)
            .event_bus_name("bus-1")
            .build();
        let entry2 = PutEventsRequestEntry::builder()
            .source("src2")
            .detail_type("Type2")
            .detail(r#"{"b":2}"#)
            .build();
        let mut input = PutEventsInput::builder()
            .entries(entry1)
            .entries(entry2)
            .build()
            .unwrap();

        inject_into_put_events(&mut input, &trace_headers).unwrap();

        let entries = input.entries.as_ref().unwrap();
        for entry in entries {
            let detail = entry.detail.as_ref().unwrap();
            let dd = parse_detail_datadog(detail);
            assert_eq!(dd[DATADOG_TRACE_ID_KEY], "123456789");
            assert!(dd.contains_key(START_TIME_KEY));
        }
        let dd0 = parse_detail_datadog(entries[0].detail.as_ref().unwrap());
        assert_eq!(dd0[RESOURCE_NAME_KEY], "bus-1");
        let dd1 = parse_detail_datadog(entries[1].detail.as_ref().unwrap());
        assert!(!dd1.contains_key(RESOURCE_NAME_KEY));
    }

    #[test]
    fn test_put_events_invalid_detail_skipped() {
        let trace_headers = sample_trace_headers();
        let entry = PutEventsRequestEntry::builder()
            .source("my.source")
            .detail_type("MyDetailType")
            .detail("not json")
            .build();
        let mut input = PutEventsInput::builder().entries(entry).build().unwrap();

        inject_into_put_events(&mut input, &trace_headers).unwrap();

        let entries = input.entries.as_ref().unwrap();
        assert_eq!(entries[0].detail.as_deref(), Some("not json"));
    }

    #[test]
    fn test_put_events_oversized_detail_skipped() {
        let trace_headers = sample_trace_headers();
        let large_value = "x".repeat(ONE_MB);
        let detail = format!("{{\"big\":\"{large_value}\"}}");
        let entry = PutEventsRequestEntry::builder()
            .source("my.source")
            .detail_type("MyDetailType")
            .detail(&detail)
            .build();
        let mut input = PutEventsInput::builder().entries(entry).build().unwrap();

        inject_into_put_events(&mut input, &trace_headers).unwrap();

        let entries = input.entries.as_ref().unwrap();
        assert_eq!(entries[0].detail.as_deref(), Some(detail.as_str()));
    }

    #[test]
    fn test_unknown_operation_noop() {
        let trace_headers = sample_trace_headers();
        let injector = EventBridgeInjector;
        let entry = PutEventsRequestEntry::builder()
            .source("my.source")
            .detail_type("MyDetailType")
            .detail(r#"{"key":"value"}"#)
            .build();
        let put_input = PutEventsInput::builder().entries(entry).build().unwrap();
        let mut input = Input::erase(put_input);

        injector
            .inject("DescribeRule", &trace_headers, &mut input)
            .unwrap();

        let put_input = input.downcast_ref::<PutEventsInput>().unwrap();
        let detail = put_input.entries.as_ref().unwrap()[0]
            .detail
            .as_deref()
            .unwrap();
        assert!(!detail.contains(DATADOG_ATTRIBUTE_KEY));
    }
}
