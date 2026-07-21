// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(test), deny(clippy::panic))]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(not(test), deny(clippy::expect_used))]

//! Datadog tracing for AWS SDK for Rust EventBridge operations.
//!
//! # Usage
//!
//! ```rust,ignore
//! use datadog_aws_eventbridge::ConfigExt as _;
//!
//! let config = aws_sdk_eventbridge::config::Builder::from(&sdk_config)
//!     .datadog_tracing()
//!     .build();
//! let client = aws_sdk_eventbridge::Client::from_conf(config);
//! ```

use std::borrow::Cow;
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
use opentelemetry::{global, otel_debug, Context, KeyValue};
use serde::de::{self, Deserializer as _, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::Serializer as _;
use serde_json::value::RawValue;

use datadog_aws_core as aws_core;
use datadog_aws_core::attribute_keys::{
    DATADOG_ATTRIBUTE_KEY, DATADOG_RESOURCE_NAME_KEY, RULE_NAME, START_TIME_KEY,
};

const TRACER_NAME: &str = "datadog-aws-eventbridge";
const SPAN_NAME: &str = "eventbridge.request";
const SPAN_OPERATION_NAME: &str = "aws.eventbridge.request";
const MAX_EVENT_DETAIL_BYTES: usize = 1024 * 1024;

/// AWS SDK interceptor that creates Datadog spans and injects trace context into EventBridge
/// requests.
///
/// Use [`ConfigExt::datadog_tracing`] to install it on an EventBridge config builder.
#[derive(Debug)]
struct EventBridgeInterceptor {
    tracer: global::BoxedTracer,
}

impl EventBridgeInterceptor {
    fn new() -> Self {
        Self {
            tracer: global::tracer(TRACER_NAME),
        }
    }
}

/// Extension methods for installing Datadog tracing on an Amazon EventBridge config builder.
pub trait ConfigExt {
    /// Installs Datadog tracing on this EventBridge config builder.
    fn datadog_tracing(self) -> Self;
}

impl ConfigExt for aws_sdk_eventbridge::config::Builder {
    fn datadog_tracing(self) -> Self {
        self.interceptor(EventBridgeInterceptor::new())
    }
}

impl Intercept for EventBridgeInterceptor {
    fn name(&self) -> &'static str {
        "EventBridgeInterceptor"
    }

    fn modify_before_serialization(
        &self,
        context: &mut BeforeSerializationInterceptorContextMut<'_>,
        _runtime_components: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        let Some(metadata) = aws_core::AwsRequestMetadata::from_config_bag(cfg) else {
            return Ok(());
        };

        let input = context.input();
        let mut rule_name = None;
        if let Some(input) = input.downcast_ref::<PutRuleInput>() {
            rule_name = input.name.as_deref();
        } else if let Some(input) = input.downcast_ref::<DescribeRuleInput>() {
            rule_name = input.name.as_deref();
        } else if let Some(input) = input.downcast_ref::<DeleteRuleInput>() {
            rule_name = input.name.as_deref();
        } else if let Some(input) = input.downcast_ref::<EnableRuleInput>() {
            rule_name = input.name.as_deref();
        } else if let Some(input) = input.downcast_ref::<DisableRuleInput>() {
            rule_name = input.name.as_deref();
        } else if let Some(input) = input.downcast_ref::<PutTargetsInput>() {
            rule_name = input.rule.as_deref();
        } else if let Some(input) = input.downcast_ref::<RemoveTargetsInput>() {
            rule_name = input.rule.as_deref();
        }

        let service_tags = [rule_name.map(|name| KeyValue::new(RULE_NAME, name.to_owned()))]
            .into_iter()
            .flatten();
        let span_context = aws_core::start_request_span(
            SPAN_NAME,
            SPAN_OPERATION_NAME,
            metadata,
            service_tags,
            &self.tracer,
            cfg,
        );
        inject(&span_context, context.input_mut());

        Ok(())
    }

    fn read_before_transmit(
        &self,
        context: &BeforeTransmitInterceptorContextRef<'_>,
        _runtime_components: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        aws_core::update_request_span(context, cfg);
        Ok(())
    }

    fn read_after_execution(
        &self,
        context: &FinalizerInterceptorContextRef<'_>,
        _runtime_components: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        aws_core::finish_request_span(context, cfg);
        Ok(())
    }
}

/// Dispatches trace context injection based on the concrete operation input type.
///
/// Only `PutEvents` carries a `detail` JSON payload that supports injection;
/// all other operations are no-ops.
fn inject(span_context: &Context, input: &mut Input) {
    if let Some(input) = input.downcast_mut::<PutEventsInput>() {
        let Some(entries) = input.entries.as_mut() else {
            return;
        };
        let Some(datadog_attr) = build_datadog_attribute(span_context) else {
            return;
        };

        for entry in entries.iter_mut() {
            let mut trace_ctx = datadog_attr.clone();
            if let (Some(ctx), Some(name)) =
                (trace_ctx.as_object_mut(), entry.event_bus_name.as_deref())
            {
                ctx.insert(
                    DATADOG_RESOURCE_NAME_KEY.into(),
                    serde_json::Value::String(name.into()),
                );
            }

            let detail = entry.detail.as_deref().unwrap_or("{}");
            // EventBridge limits the total PutEvents request size, computed from all
            // entry fields across all entries, not the detail field alone. This coarse
            // guard only avoids parsing detail payloads that are already too large to fit.
            if detail.len() > MAX_EVENT_DETAIL_BYTES {
                otel_debug!(
                    name: "EventBridge.Inject.DetailSizeExceeded",
                    max_size_bytes = MAX_EVENT_DETAIL_BYTES,
                    action = "context injection skipped",
                );
                continue;
            }

            let new_detail =
                match rewrite_json_object_field(detail, DATADOG_ATTRIBUTE_KEY, &trace_ctx) {
                    Ok(detail) => detail,
                    Err(err) => {
                        otel_debug!(
                            name: "EventBridge.Inject.DetailRewriteFailed",
                            reason = err.to_string(),
                            action = "context injection skipped",
                        );
                        continue;
                    }
                };

            entry.detail = Some(new_detail);
        }
    }
}

fn build_datadog_attribute(span_context: &Context) -> Option<serde_json::Value> {
    let trace_headers = aws_core::request_span_trace_headers(span_context);
    if trace_headers.is_empty() {
        return None;
    }

    let attribute = || -> Result<serde_json::Value, serde_json::Error> {
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .to_string();
        let mut attribute = serde_json::to_value(&trace_headers)?;
        if let serde_json::Value::Object(ctx) = &mut attribute {
            ctx.insert(START_TIME_KEY.into(), serde_json::Value::String(start_time));
        }
        Ok(attribute)
    };

    match attribute() {
        Ok(attr) => Some(attr),
        Err(err) => {
            otel_debug!(
                name: "EventBridge.Inject.DatadogAttributeBuildFailed",
                reason = err.to_string(),
                action = "context injection skipped",
            );
            None
        }
    }
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
    Ok(String::from_utf8_lossy(&output).into_owned())
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
    use std::collections::HashMap;

    use super::*;
    use aws_sdk_eventbridge::types::PutEventsRequestEntry;
    use datadog_aws_core_test_utils::test_helpers::{
        ensure_test_propagator, test_context, TEST_CONTEXT_INJECTED_KEY,
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
        let entry = PutEventsRequestEntry::builder()
            .source("my.source")
            .detail_type("MyDetailType")
            .detail("not json")
            .build();
        let mut input = Input::erase(PutEventsInput::builder().entries(entry).build().unwrap());

        inject(&Context::new(), &mut input);

        let input = input.downcast_ref::<PutEventsInput>().unwrap();
        let entries = input.entries.as_ref().unwrap();
        assert_eq!(entries[0].detail.as_deref(), Some("not json"));
    }

    #[test]
    fn skips_injection_for_non_object_put_events_detail() {
        let entry = PutEventsRequestEntry::builder()
            .source("my.source")
            .detail_type("MyDetailType")
            .detail(r#"["not","an","object"]"#)
            .build();
        let mut input = Input::erase(PutEventsInput::builder().entries(entry).build().unwrap());

        inject(&Context::new(), &mut input);

        let input = input.downcast_ref::<PutEventsInput>().unwrap();
        let entries = input.entries.as_ref().unwrap();
        assert_eq!(
            entries[0].detail.as_deref(),
            Some(r#"["not","an","object"]"#)
        );
    }

    #[test]
    fn skips_injection_when_put_events_detail_would_exceed_size_limit() {
        let large_value = "x".repeat(MAX_EVENT_DETAIL_BYTES);
        let detail = format!("{{\"big\":\"{large_value}\"}}");
        let entry = PutEventsRequestEntry::builder()
            .source("my.source")
            .detail_type("MyDetailType")
            .detail(&detail)
            .build();
        let mut input = Input::erase(PutEventsInput::builder().entries(entry).build().unwrap());

        inject(&Context::new(), &mut input);

        let input = input.downcast_ref::<PutEventsInput>().unwrap();
        let entries = input.entries.as_ref().unwrap();
        assert_eq!(entries[0].detail.as_deref(), Some(detail.as_str()));
    }

    #[test]
    fn skips_only_entries_that_exceed_put_events_detail_size_limit() {
        let oversized_detail_value = "x".repeat(MAX_EVENT_DETAIL_BYTES);
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
        let mut input = Input::erase(
            PutEventsInput::builder()
                .entries(oversized_entry)
                .entries(small_entry)
                .build()
                .unwrap(),
        );
        ensure_test_propagator();
        inject(&test_context(), &mut input);

        let input = input.downcast_ref::<PutEventsInput>().unwrap();
        let entries = input.entries.as_ref().unwrap();
        assert_eq!(
            entries[0].detail.as_deref(),
            Some(oversized_detail.as_str())
        );

        let injected_detail = entries[1].detail.as_ref().unwrap();
        let dd = parse_detail_datadog(injected_detail);
        assert_eq!(dd[TEST_CONTEXT_INJECTED_KEY], "true");

        let parsed: serde_json::Value = serde_json::from_str(injected_detail).unwrap();
        assert_eq!(parsed["small"], "payload");
    }

    #[test]
    fn replaces_existing_top_level_datadog_key_in_put_events_detail() {
        let entry = PutEventsRequestEntry::builder()
            .source("my.source")
            .detail_type("MyDetailType")
            .detail(
                r#"{"_datadog":{"x-datadog-trace-id":"1","x-datadog-parent-id":"2","x-datadog-sampling-priority":"0","stale":"context"},"existing":"data"}"#,
            )
            .build();
        let mut input = Input::erase(PutEventsInput::builder().entries(entry).build().unwrap());
        ensure_test_propagator();
        inject(&test_context(), &mut input);

        let input = input.downcast_ref::<PutEventsInput>().unwrap();
        let entries = input.entries.as_ref().unwrap();
        let detail = entries[0].detail.as_ref().unwrap();
        let dd = parse_detail_datadog(detail);
        assert_eq!(dd[TEST_CONTEXT_INJECTED_KEY], "true");
        assert!(!dd.contains_key("stale"));
        let parsed: serde_json::Value = serde_json::from_str(detail).unwrap();
        assert_eq!(parsed["existing"], "data");
    }

    #[test]
    fn appends_top_level_datadog_key_when_missing_in_put_events_detail() {
        let entry = PutEventsRequestEntry::builder()
            .source("my.source")
            .detail_type("MyDetailType")
            .detail(r#"{"existing":"data"}"#)
            .build();
        let mut input = Input::erase(PutEventsInput::builder().entries(entry).build().unwrap());
        ensure_test_propagator();
        inject(&test_context(), &mut input);

        let input = input.downcast_ref::<PutEventsInput>().unwrap();
        let entries = input.entries.as_ref().unwrap();
        let detail = entries[0].detail.as_ref().unwrap();
        let dd = parse_detail_datadog(detail);
        assert_eq!(dd[TEST_CONTEXT_INJECTED_KEY], "true");
        let parsed: serde_json::Value = serde_json::from_str(detail).unwrap();
        assert_eq!(parsed["existing"], "data");
    }

    #[test]
    fn injects_when_put_events_detail_contains_nested_datadog_key() {
        let entry = PutEventsRequestEntry::builder()
            .source("my.source")
            .detail_type("MyDetailType")
            .detail(r#"{"nested":{"_datadog":"keep-me"},"existing":"data"}"#)
            .build();
        let mut input = Input::erase(PutEventsInput::builder().entries(entry).build().unwrap());
        ensure_test_propagator();
        inject(&test_context(), &mut input);

        let input = input.downcast_ref::<PutEventsInput>().unwrap();
        let entries = input.entries.as_ref().unwrap();
        let detail = entries[0].detail.as_ref().unwrap();
        let dd = parse_detail_datadog(detail);
        assert_eq!(dd[TEST_CONTEXT_INJECTED_KEY], "true");
        let parsed: serde_json::Value = serde_json::from_str(detail).unwrap();
        assert_eq!(parsed["existing"], "data");
        assert_eq!(parsed["nested"]["_datadog"], "keep-me");
    }

    #[test]
    fn inject_dispatches_by_input_type() {
        let entry = PutEventsRequestEntry::builder()
            .source("my.source")
            .detail_type("MyDetailType")
            .detail(r#"{"existing":"data"}"#)
            .build();
        let input = PutEventsInput::builder().entries(entry).build().unwrap();
        let mut input = Input::erase(input);
        ensure_test_propagator();
        inject(&test_context(), &mut input);

        let input = input.downcast_ref::<PutEventsInput>().unwrap();
        let detail = input.entries.as_ref().unwrap()[0].detail.as_ref().unwrap();
        let dd = parse_detail_datadog(detail);
        assert_eq!(dd[TEST_CONTEXT_INJECTED_KEY], "true");
    }
}
