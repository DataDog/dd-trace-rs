// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(test), deny(clippy::panic))]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(not(test), deny(clippy::expect_used))]

//! Datadog trace context injection for AWS SDK for Rust EventBridge operations.
//!
//! # Usage
//!
//! ```rust,ignore
//! use datadog_aws_eventbridge::EventBridgeInterceptor;
//!
//! let config = aws_sdk_eventbridge::config::Builder::from(&sdk_config)
//!     .interceptor(EventBridgeInterceptor::new())
//!     .build();
//! let client = aws_sdk_eventbridge::Client::from_conf(config);
//! ```

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
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
use aws_smithy_runtime_api::client::interceptors::context::{
    BeforeSerializationInterceptorContextMut, BeforeTransmitInterceptorContextRef,
    FinalizerInterceptorContextRef, Input,
};
use aws_smithy_runtime_api::client::interceptors::Intercept;
use aws_smithy_runtime_api::client::runtime_components::RuntimeComponents;
use aws_smithy_types::config_bag::ConfigBag;
use opentelemetry::KeyValue;
use serde::de::{self, Deserializer as _, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::Serializer as _;
use serde_json::value::RawValue;

use datadog_aws_core::attribute_keys::{
    DATADOG_ATTRIBUTE_KEY, DATADOG_RESOURCE_NAME_KEY, RULE_NAME, START_TIME_KEY,
};
use datadog_aws_core::limits::ONE_MB;
use datadog_aws_core::{AwsInterceptor, ServiceHandler};

const TRACER_NAME: &str = "datadog-aws-eventbridge";

/// [`ServiceHandler`] implementation for Amazon EventBridge.
struct EventBridgeHandler;

impl ServiceHandler for EventBridgeHandler {
    fn sdk_service_name(&self) -> &'static str {
        "EventBridge"
    }

    fn span_service_id(&self) -> &'static str {
        "eventbridge"
    }

    fn inject(
        &self,
        trace_headers: &HashMap<String, String>,
        input: &mut Input,
    ) -> Result<(), BoxError> {
        inject(trace_headers, input)
    }

    fn service_tags(&self, input: &Input, _region: &str, _partition: &str) -> Vec<KeyValue> {
        service_tags(input)
    }
}

/// AWS SDK interceptor that injects Datadog trace context into EventBridge requests
/// and creates spans representing EventBridge operations.
#[derive(Debug)]
pub struct EventBridgeInterceptor {
    inner: AwsInterceptor<EventBridgeHandler>,
}

impl EventBridgeInterceptor {
    pub fn new() -> Self {
        Self {
            inner: AwsInterceptor::new(EventBridgeHandler, TRACER_NAME),
        }
    }
}

impl Default for EventBridgeInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

impl Intercept for EventBridgeInterceptor {
    fn name(&self) -> &'static str {
        "EventBridgeInterceptor"
    }

    fn modify_before_serialization(
        &self,
        context: &mut BeforeSerializationInterceptorContextMut<'_>,
        runtime_components: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        self.inner
            .modify_before_serialization(context, runtime_components, cfg)
    }

    fn read_before_transmit(
        &self,
        context: &BeforeTransmitInterceptorContextRef<'_>,
        runtime_components: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        self.inner
            .read_before_transmit(context, runtime_components, cfg)
    }

    fn read_after_execution(
        &self,
        context: &FinalizerInterceptorContextRef<'_>,
        runtime_components: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        self.inner
            .read_after_execution(context, runtime_components, cfg)
    }
}

/// Dispatches trace context injection based on the concrete operation input type.
///
/// Only `PutEvents` carries a `detail` JSON payload that supports injection;
/// all other operations are no-ops.
fn inject(trace_headers: &HashMap<String, String>, input: &mut Input) -> Result<(), BoxError> {
    if let Some(put_input) = input.downcast_mut::<PutEventsInput>() {
        return inject_into_put_events(put_input, trace_headers);
    }

    Ok(())
}

/// Returns EventBridge-specific span tags: a `rulename` tag when a rule name
/// can be extracted from the operation input, otherwise an empty list.
fn service_tags(input: &Input) -> Vec<KeyValue> {
    match extract_rule_name(input) {
        Some(name) => vec![KeyValue::new(RULE_NAME, name.to_owned())],
        None => vec![],
    }
}

/// Extracts the rule name from an operation input for rule-management operations.
///
/// `PutEvents` has no rule and returns `None`. `PutTargets` and `RemoveTargets`
/// carry the rule name in the `rule` field; the remaining operations use `name`.
fn extract_rule_name(input: &Input) -> Option<&str> {
    if let Some(input) = input.downcast_ref::<PutRuleInput>() {
        return input.name.as_deref();
    }

    if let Some(input) = input.downcast_ref::<DescribeRuleInput>() {
        return input.name.as_deref();
    }

    if let Some(input) = input.downcast_ref::<DeleteRuleInput>() {
        return input.name.as_deref();
    }

    if let Some(input) = input.downcast_ref::<EnableRuleInput>() {
        return input.name.as_deref();
    }

    if let Some(input) = input.downcast_ref::<DisableRuleInput>() {
        return input.name.as_deref();
    }

    if let Some(input) = input.downcast_ref::<PutTargetsInput>() {
        return input.rule.as_deref();
    }

    if let Some(input) = input.downcast_ref::<RemoveTargetsInput>() {
        return input.rule.as_deref();
    }

    None
}

/// Injects Datadog trace context into each entry of a `PutEvents` input.
///
/// Context is inserted into each entry's `detail` JSON object under the `_datadog`
/// key, replacing any existing top-level `_datadog` value, along with a `start`
/// timestamp (milliseconds since epoch) and, when set, `resource.name` from
/// `event_bus_name`.
///
/// Entries with non-object JSON detail, invalid JSON, serialization failures, or a
/// resulting detail that would exceed the 1 MB EventBridge per-entry limit are
/// silently skipped.
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

    let serde_json::Value::Object(mut ctx) = serde_json::to_value(trace_headers)? else {
        return Ok(());
    };
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
        if detail.len() > ONE_MB {
            continue;
        }

        let new_detail = match rewrite_json_object_field(detail, DATADOG_ATTRIBUTE_KEY, &trace_ctx)
        {
            Ok(detail) => detail,
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

fn rewrite_json_object_field(
    detail: &str,
    field_name: &str,
    value: &serde_json::Value,
) -> Result<String, serde_json::Error> {
    let field_name_json_len = serde_json::to_string(field_name)?.len();
    let value_json_len = serde_json::to_vec(value)?.len();
    let mut output = Vec::with_capacity(detail.len() + field_name_json_len + 1 + value_json_len);
    let mut deserializer = serde_json::Deserializer::from_str(detail);
    deserializer.deserialize_map(JsonObjectReplaceAppendFieldVisitor {
        output: &mut output,
        field_name,
        value,
    })?;
    deserializer.end()?;
    Ok(String::from_utf8(output).unwrap_or_else(|_| unreachable!("serde_json only emits UTF-8")))
}

// Streams the top-level object, replacing or appending one field while
// copying other fields through as borrowed raw JSON.
struct JsonObjectReplaceAppendFieldVisitor<'a> {
    output: &'a mut Vec<u8>,
    field_name: &'a str,
    value: &'a serde_json::Value,
}

impl<'de> Visitor<'de> for JsonObjectReplaceAppendFieldVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut serializer = serde_json::Serializer::new(self.output);
        let mut output_map = serializer
            .serialize_map(None)
            .map_err(<M::Error as de::Error>::custom)?;
        let mut replaced_field = false;

        while let Some(key) = map.next_key::<Cow<'de, str>>()? {
            let value = map.next_value::<&'de RawValue>()?;

            if key.as_ref() == self.field_name {
                if !replaced_field {
                    output_map
                        .serialize_entry(self.field_name, self.value)
                        .map_err(<M::Error as de::Error>::custom)?;
                    replaced_field = true;
                }
                continue;
            }

            output_map
                .serialize_entry(key.as_ref(), value)
                .map_err(<M::Error as de::Error>::custom)?;
        }

        if !replaced_field {
            output_map
                .serialize_entry(self.field_name, self.value)
                .map_err(<M::Error as de::Error>::custom)?;
        }
        output_map.end().map_err(<M::Error as de::Error>::custom)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_eventbridge::types::PutEventsRequestEntry;
    use datadog_aws_core_test_utils::test_helpers::{
        collect_string_tags, sample_trace_headers, DATADOG_PARENT_ID_KEY,
        DATADOG_SAMPLING_PRIORITY_KEY, DATADOG_TRACE_ID_KEY,
    };

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
    fn skips_injection_for_non_object_put_events_detail() {
        let trace_headers = sample_trace_headers();
        let entry = PutEventsRequestEntry::builder()
            .source("my.source")
            .detail_type("MyDetailType")
            .detail(r#"["not","an","object"]"#)
            .build();
        let mut input = PutEventsInput::builder().entries(entry).build().unwrap();

        inject_into_put_events(&mut input, &trace_headers).unwrap();

        let entries = input.entries.as_ref().unwrap();
        assert_eq!(
            entries[0].detail.as_deref(),
            Some(r#"["not","an","object"]"#)
        );
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
    fn skips_only_entries_that_exceed_put_events_detail_size_limit() {
        let trace_headers = sample_trace_headers();
        let oversized_detail_value = "x".repeat(ONE_MB);
        let oversized_detail = format!("{{\"big\":\"{oversized_detail_value}\"}}");
        let oversized_entry = PutEventsRequestEntry::builder()
            .source("my.source")
            .detail_type("MyDetailType")
            .detail(&oversized_detail)
            .build();
        let small_entry = PutEventsRequestEntry::builder()
            .source("my.source")
            .detail_type("MyDetailType")
            .detail(r#"{"small":"payload"}"#)
            .build();
        let mut input = PutEventsInput::builder()
            .entries(oversized_entry)
            .entries(small_entry)
            .build()
            .unwrap();

        inject_into_put_events(&mut input, &trace_headers).unwrap();

        let entries = input.entries.as_ref().unwrap();
        assert_eq!(
            entries[0].detail.as_deref(),
            Some(oversized_detail.as_str())
        );

        let injected_detail = entries[1].detail.as_ref().unwrap();
        let dd = parse_detail_datadog(injected_detail);
        assert_eq!(dd[DATADOG_TRACE_ID_KEY], "123456789");

        let parsed: serde_json::Value = serde_json::from_str(injected_detail).unwrap();
        assert_eq!(parsed["small"], "payload");
    }

    #[test]
    fn replaces_existing_top_level_datadog_key_in_put_events_detail() {
        let trace_headers = sample_trace_headers();
        let entry = PutEventsRequestEntry::builder()
            .source("my.source")
            .detail_type("MyDetailType")
            .detail(
                r#"{"_datadog":{"x-datadog-trace-id":"1","x-datadog-parent-id":"2","x-datadog-sampling-priority":"0","stale":"context"},"existing":"data"}"#,
            )
            .build();
        let mut input = PutEventsInput::builder().entries(entry).build().unwrap();

        inject_into_put_events(&mut input, &trace_headers).unwrap();

        let entries = input.entries.as_ref().unwrap();
        let detail = entries[0].detail.as_ref().unwrap();
        let dd = parse_detail_datadog(detail);
        assert_eq!(dd[DATADOG_TRACE_ID_KEY], "123456789");
        assert_eq!(dd[DATADOG_PARENT_ID_KEY], "987654321");
        assert_eq!(dd[DATADOG_SAMPLING_PRIORITY_KEY], "1");
        assert!(!dd.contains_key("stale"));
        let parsed: serde_json::Value = serde_json::from_str(detail).unwrap();
        assert_eq!(parsed["existing"], "data");
    }

    #[test]
    fn appends_top_level_datadog_key_when_missing_in_put_events_detail() {
        let trace_headers = sample_trace_headers();
        let entry = PutEventsRequestEntry::builder()
            .source("my.source")
            .detail_type("MyDetailType")
            .detail(r#"{"existing":"data"}"#)
            .build();
        let mut input = PutEventsInput::builder().entries(entry).build().unwrap();

        inject_into_put_events(&mut input, &trace_headers).unwrap();

        let entries = input.entries.as_ref().unwrap();
        let detail = entries[0].detail.as_ref().unwrap();
        let dd = parse_detail_datadog(detail);
        assert_eq!(dd[DATADOG_TRACE_ID_KEY], "123456789");
        let parsed: serde_json::Value = serde_json::from_str(detail).unwrap();
        assert_eq!(parsed["existing"], "data");
    }

    #[test]
    fn injects_when_put_events_detail_contains_nested_datadog_key() {
        let trace_headers = sample_trace_headers();
        let entry = PutEventsRequestEntry::builder()
            .source("my.source")
            .detail_type("MyDetailType")
            .detail(r#"{"nested":{"_datadog":"keep-me"},"existing":"data"}"#)
            .build();
        let mut input = PutEventsInput::builder().entries(entry).build().unwrap();

        inject_into_put_events(&mut input, &trace_headers).unwrap();

        let entries = input.entries.as_ref().unwrap();
        let detail = entries[0].detail.as_ref().unwrap();
        let dd = parse_detail_datadog(detail);
        assert_eq!(dd[DATADOG_TRACE_ID_KEY], "123456789");
        let parsed: serde_json::Value = serde_json::from_str(detail).unwrap();
        assert_eq!(parsed["existing"], "data");
        assert_eq!(parsed["nested"]["_datadog"], "keep-me");
    }

    #[test]
    fn service_tags_for_put_events_returns_empty() {
        let input = Input::erase(PutEventsInput::builder().build().unwrap());

        let tags = collect_string_tags(service_tags(&input));
        assert!(!tags.contains_key(RULE_NAME));
    }

    #[test]
    fn inject_dispatches_by_input_type() {
        let trace_headers = sample_trace_headers();
        let entry = PutEventsRequestEntry::builder()
            .source("my.source")
            .detail_type("MyDetailType")
            .detail(r#"{"existing":"data"}"#)
            .build();
        let input = PutEventsInput::builder().entries(entry).build().unwrap();
        let mut input = Input::erase(input);

        inject(&trace_headers, &mut input).unwrap();

        let input = input.downcast_ref::<PutEventsInput>().unwrap();
        let detail = input.entries.as_ref().unwrap()[0].detail.as_ref().unwrap();
        let dd = parse_detail_datadog(detail);
        assert_eq!(dd[DATADOG_TRACE_ID_KEY], "123456789");
    }
}
