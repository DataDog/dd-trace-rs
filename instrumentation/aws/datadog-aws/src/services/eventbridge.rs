// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_sdk_eventbridge::operation::delete_rule::DeleteRuleInput;
use aws_sdk_eventbridge::operation::describe_rule::DescribeRuleInput;
use aws_sdk_eventbridge::operation::disable_rule::DisableRuleInput;
use aws_sdk_eventbridge::operation::enable_rule::EnableRuleInput;
use aws_sdk_eventbridge::operation::put_events::PutEventsInput;
use aws_sdk_eventbridge::operation::put_rule::PutRuleInput;
use aws_sdk_eventbridge::operation::put_targets::PutTargetsInput;
use aws_sdk_eventbridge::operation::remove_targets::RemoveTargetsInput;
use aws_smithy_runtime_api::box_error::BoxError;
use aws_smithy_runtime_api::client::interceptors::context::Input;
use opentelemetry::KeyValue;

use crate::attribute_keys::{
    DATADOG_ATTRIBUTE_KEY, DATADOG_RESOURCE_NAME_KEY, RULE_NAME, START_TIME_KEY,
};

use super::ONE_MB;

#[derive(Debug, Clone, Copy)]
pub(super) enum EventBridgeOperation {
    PutEvents,
    PutRule,
    DescribeRule,
    DeleteRule,
    EnableRule,
    DisableRule,
    PutTargets,
    RemoveTargets,
}

impl EventBridgeOperation {
    pub(super) fn from_name(operation: &str) -> Option<Self> {
        match operation {
            "PutEvents" => Some(Self::PutEvents),
            "PutRule" => Some(Self::PutRule),
            "DescribeRule" => Some(Self::DescribeRule),
            "DeleteRule" => Some(Self::DeleteRule),
            "EnableRule" => Some(Self::EnableRule),
            "DisableRule" => Some(Self::DisableRule),
            "PutTargets" => Some(Self::PutTargets),
            "RemoveTargets" => Some(Self::RemoveTargets),
            _ => None,
        }
    }
}

// Only PutEvents carries a detail payload that supports trace context injection.
pub(super) fn inject(
    operation: EventBridgeOperation,
    trace_headers: &HashMap<String, String>,
    input: &mut Input,
) -> Result<(), BoxError> {
    if !matches!(operation, EventBridgeOperation::PutEvents) {
        return Ok(());
    }

    if let Some(put_input) = input.downcast_mut::<PutEventsInput>() {
        inject_into_put_events(put_input, trace_headers)?;
    }
    Ok(())
}

pub(super) fn service_tags(operation: EventBridgeOperation, input: &Input) -> Vec<KeyValue> {
    match extract_rule_name(operation, input) {
        Some(name) => vec![KeyValue::new(RULE_NAME, name.to_owned())],
        None => vec![],
    }
}

fn extract_rule_name(operation: EventBridgeOperation, input: &Input) -> Option<&str> {
    match operation {
        EventBridgeOperation::PutRule => input
            .downcast_ref::<PutRuleInput>()
            .and_then(|i| i.name.as_deref()),
        EventBridgeOperation::DescribeRule => input
            .downcast_ref::<DescribeRuleInput>()
            .and_then(|i| i.name.as_deref()),
        EventBridgeOperation::DeleteRule => input
            .downcast_ref::<DeleteRuleInput>()
            .and_then(|i| i.name.as_deref()),
        EventBridgeOperation::EnableRule => input
            .downcast_ref::<EnableRuleInput>()
            .and_then(|i| i.name.as_deref()),
        EventBridgeOperation::DisableRule => input
            .downcast_ref::<DisableRuleInput>()
            .and_then(|i| i.name.as_deref()),
        EventBridgeOperation::PutTargets => input
            .downcast_ref::<PutTargetsInput>()
            .and_then(|i| i.rule.as_deref()),
        EventBridgeOperation::RemoveTargets => input
            .downcast_ref::<RemoveTargetsInput>()
            .and_then(|i| i.rule.as_deref()),
        EventBridgeOperation::PutEvents => None,
    }
}

fn inject_into_put_events(
    input: &mut PutEventsInput,
    trace_headers: &HashMap<String, String>,
) -> Result<(), BoxError> {
    let Some(entries) = input.entries.as_mut() else {
        return Ok(());
    };

    let start_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .to_string();

    let mut ctx: serde_json::Map<String, serde_json::Value> = trace_headers
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
        .collect();
    ctx.insert(START_TIME_KEY.into(), serde_json::Value::String(start_time));

    for entry in entries.iter_mut() {
        let mut entry_ctx = ctx.clone();
        if let Some(name) = entry.event_bus_name.as_deref() {
            entry_ctx.insert(
                DATADOG_RESOURCE_NAME_KEY.into(),
                serde_json::Value::String(name.into()),
            );
        }

        let trace_ctx = serde_json::Value::Object(entry_ctx);

        let detail = entry.detail.as_deref().unwrap_or("{}");
        let mut detail_map: serde_json::Map<String, serde_json::Value> =
            match serde_json::from_str(detail) {
                Ok(map) => map,
                Err(_) => continue,
            };

        detail_map.insert(DATADOG_ATTRIBUTE_KEY.into(), trace_ctx);

        let new_detail = match serde_json::to_string(&detail_map) {
            Ok(s) => s,
            Err(_) => continue,
        };

        // EventBridge entries have a 1 MB detail size limit.
        if new_detail.len() > ONE_MB {
            continue;
        }

        entry.detail = Some(new_detail);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::test_helpers::{
        collect_string_tags, sample_trace_headers, DATADOG_TRACE_ID_KEY,
    };
    use aws_sdk_eventbridge::types::PutEventsRequestEntry;
    use aws_smithy_runtime_api::client::interceptors::context::Input;

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
    fn skips_injection_for_invalid_put_events_detail() {
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
    fn skips_injection_when_put_events_detail_would_exceed_size_limit() {
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
    fn overwrites_existing_datadog_key_in_put_events_detail() {
        let trace_headers = sample_trace_headers();
        let entry = PutEventsRequestEntry::builder()
            .source("my.source")
            .detail_type("MyDetailType")
            .detail(r#"{"_datadog":{"stale":"context"},"existing":"data"}"#)
            .build();
        let mut input = PutEventsInput::builder().entries(entry).build().unwrap();

        inject_into_put_events(&mut input, &trace_headers).unwrap();

        let entries = input.entries.as_ref().unwrap();
        let detail = entries[0].detail.as_ref().unwrap();
        let dd = parse_detail_datadog(detail);
        assert_eq!(dd[DATADOG_TRACE_ID_KEY], "123456789");
        assert!(!dd.contains_key("stale"));
        let parsed: serde_json::Value = serde_json::from_str(detail).unwrap();
        assert_eq!(parsed["existing"], "data");
    }

    #[test]
    fn service_tags_for_put_events_returns_empty() {
        let input = Input::erase(PutEventsInput::builder().build().unwrap());

        let tags = collect_string_tags(service_tags(EventBridgeOperation::PutEvents, &input));
        assert!(!tags.contains_key(RULE_NAME));
    }

    #[test]
    fn unsupported_eventbridge_operation_returns_none() {
        assert!(EventBridgeOperation::from_name("ListRules").is_none());
    }
}
