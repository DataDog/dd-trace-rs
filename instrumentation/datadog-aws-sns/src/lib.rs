// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(test), deny(clippy::panic))]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(not(test), deny(clippy::expect_used))]

//! Datadog tracing for AWS SDK for Rust SNS operations.
//!
//! # Usage
//!
//! ```rust,ignore
//! use datadog_aws_sns::ConfigExt as _;
//!
//! let config = aws_sdk_sns::config::Builder::from(&sdk_config)
//!     .datadog_tracing()
//!     .build();
//! let client = aws_sdk_sns::Client::from_conf(config);
//! ```

use std::collections::HashMap;

use aws_sdk_sns::operation::create_topic::CreateTopicInput;
use aws_sdk_sns::operation::get_topic_attributes::GetTopicAttributesInput;
use aws_sdk_sns::operation::list_subscriptions_by_topic::ListSubscriptionsByTopicInput;
use aws_sdk_sns::operation::publish::PublishInput;
use aws_sdk_sns::operation::publish_batch::PublishBatchInput;
use aws_sdk_sns::operation::remove_permission::RemovePermissionInput;
use aws_sdk_sns::operation::set_topic_attributes::SetTopicAttributesInput;
use aws_sdk_sns::operation::subscribe::SubscribeInput;
use aws_sdk_sns::types::MessageAttributeValue;
use aws_smithy_runtime_api::box_error::BoxError;
use aws_smithy_runtime_api::client::interceptors::context::{
    BeforeSerializationInterceptorContextMut, BeforeTransmitInterceptorContextRef,
    FinalizerInterceptorContextRef, Input,
};
use aws_smithy_runtime_api::client::interceptors::Intercept;
use aws_smithy_runtime_api::client::runtime_components::RuntimeComponents;
use aws_smithy_types::config_bag::ConfigBag;
use aws_smithy_types::Blob;
use opentelemetry::{global, KeyValue};

use datadog_aws_core as aws_core;
use datadog_aws_core::attribute_keys::{DATADOG_ATTRIBUTE_KEY, TARGET_NAME, TOPIC_NAME};
use datadog_aws_core::limits::MAX_MESSAGE_ATTRIBUTES;

const TRACER_NAME: &str = "datadog-aws-sns";
const SPAN_SERVICE_ID: &str = "sns";

/// AWS SDK interceptor that creates Datadog spans and injects trace context into SNS requests.
///
/// Use [`ConfigExt::datadog_tracing`] to install it on an SNS config builder.
#[derive(Debug)]
struct SnsInterceptor {
    tracer: global::BoxedTracer,
}

impl SnsInterceptor {
    fn new() -> Self {
        Self {
            tracer: global::tracer(TRACER_NAME),
        }
    }
}

/// Extension methods for installing Datadog tracing on an Amazon SNS config builder.
pub trait ConfigExt {
    /// Installs Datadog tracing on this SNS config builder.
    fn datadog_tracing(self) -> Self;
}

impl ConfigExt for aws_sdk_sns::config::Builder {
    fn datadog_tracing(self) -> Self {
        self.interceptor(SnsInterceptor::new())
    }
}

impl Intercept for SnsInterceptor {
    fn name(&self) -> &'static str {
        "SnsInterceptor"
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
        let mut direct_topic_name = None;
        let mut topic_arn = None;
        let mut target_arn = None;
        if let Some(input) = input.downcast_ref::<PublishInput>() {
            topic_arn = input.topic_arn.as_deref();
            target_arn = input.target_arn.as_deref();
        } else if let Some(input) = input.downcast_ref::<CreateTopicInput>() {
            direct_topic_name = input.name.as_deref();
        } else if let Some(input) = input.downcast_ref::<PublishBatchInput>() {
            topic_arn = input.topic_arn.as_deref();
        } else if let Some(input) = input.downcast_ref::<GetTopicAttributesInput>() {
            topic_arn = input.topic_arn.as_deref();
        } else if let Some(input) = input.downcast_ref::<ListSubscriptionsByTopicInput>() {
            topic_arn = input.topic_arn.as_deref();
        } else if let Some(input) = input.downcast_ref::<RemovePermissionInput>() {
            topic_arn = input.topic_arn.as_deref();
        } else if let Some(input) = input.downcast_ref::<SetTopicAttributesInput>() {
            topic_arn = input.topic_arn.as_deref();
        } else if let Some(input) = input.downcast_ref::<SubscribeInput>() {
            topic_arn = input.topic_arn.as_deref();
        }

        fn arn_resource_name(arn: &str) -> &str {
            arn.rsplit(':').next().unwrap_or(arn)
        }
        let topic_name = direct_topic_name.or_else(|| topic_arn.map(arn_resource_name));
        let target_name = if topic_name.is_none() {
            target_arn.map(arn_resource_name)
        } else {
            None
        };
        let service_tags = [
            topic_name.map(|name| KeyValue::new(TOPIC_NAME, name.to_owned())),
            target_name.map(|name| KeyValue::new(TARGET_NAME, name.to_owned())),
        ]
        .into_iter()
        .flatten();
        let trace_headers = aws_core::start_request_span(
            SPAN_SERVICE_ID,
            metadata,
            service_tags,
            &self.tracer,
            cfg,
        );
        if !trace_headers.is_empty() {
            inject(&trace_headers, context.input_mut());
        }

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
/// Only `Publish` and `PublishBatch` carry a message attributes payload that
/// supports injection; all other operations are no-ops.
fn inject(trace_headers: &HashMap<String, String>, input: &mut Input) {
    if let Some(publish_input) = input.downcast_mut::<PublishInput>() {
        inject_into_publish(publish_input, trace_headers);
        return;
    }

    if let Some(batch_input) = input.downcast_mut::<PublishBatchInput>() {
        inject_into_publish_batch(batch_input, trace_headers);
    }
}

/// Injects a `_datadog` Binary message attribute into a `Publish` input.
///
/// Skipped when the message already has 10 attributes and none is `_datadog`.
fn inject_into_publish(input: &mut PublishInput, trace_headers: &HashMap<String, String>) {
    let attrs = input.message_attributes.get_or_insert_with(HashMap::new);
    if should_skip_injection(attrs) {
        return;
    }
    let Ok(datadog_attr) = build_datadog_attribute(trace_headers) else {
        return;
    };
    attrs.insert(DATADOG_ATTRIBUTE_KEY.to_string(), datadog_attr);
}

/// Injects a `_datadog` Binary message attribute into each entry of a `PublishBatch` input.
///
/// The same skip/overwrite rules as [`inject_into_publish`] apply per entry.
fn inject_into_publish_batch(
    input: &mut PublishBatchInput,
    trace_headers: &HashMap<String, String>,
) {
    let Some(entries) = input.publish_batch_request_entries.as_mut() else {
        return;
    };
    let Ok(dd_attr) = build_datadog_attribute(trace_headers) else {
        return;
    };
    let dd_key = DATADOG_ATTRIBUTE_KEY.to_string();
    for entry in entries.iter_mut() {
        let attrs = entry.message_attributes.get_or_insert_with(HashMap::new);
        if should_skip_injection(attrs) {
            continue;
        }
        attrs.insert(dd_key.clone(), dd_attr.clone());
    }
}

/// Returns `true` when injection should be skipped to respect the 10-attribute cap.
///
/// An existing `_datadog` attribute counts as a slot we can reuse, so the cap
/// is only enforced when `_datadog` is absent.
fn should_skip_injection(attrs: &HashMap<String, MessageAttributeValue>) -> bool {
    attrs.len() >= MAX_MESSAGE_ATTRIBUTES && !attrs.contains_key(DATADOG_ATTRIBUTE_KEY)
}

/// Serialises `trace_headers` as a Binary-typed SNS message attribute.
///
/// SNS uses Binary (not String) so that SNS subscription filter policies do not
/// attempt to parse the Datadog JSON payload. String-typed attributes are
/// inspected by filter policies and silently drop messages they cannot parse.
fn build_datadog_attribute(
    trace_headers: &HashMap<String, String>,
) -> Result<MessageAttributeValue, BoxError> {
    let json_bytes = serde_json::to_vec(trace_headers)?;
    Ok(MessageAttributeValue::builder()
        .data_type("Binary")
        .binary_value(Blob::new(json_bytes))
        .build()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_sns::types::PublishBatchRequestEntry;
    use datadog_aws_core_test_utils::test_helpers::{
        sample_trace_headers, DATADOG_PARENT_ID_KEY, DATADOG_SAMPLING_PRIORITY_KEY,
        DATADOG_TRACE_ID_KEY,
    };

    fn parse_binary_attr(attr: &MessageAttributeValue) -> HashMap<String, String> {
        assert_eq!(attr.data_type(), "Binary");
        let blob = attr.binary_value().unwrap();
        serde_json::from_slice(blob.as_ref()).unwrap()
    }

    #[test]
    fn skips_injection_when_message_attributes_are_full() {
        let trace_headers = sample_trace_headers();
        let mut builder = PublishInput::builder()
            .topic_arn("arn:aws:sns:us-east-1:123456789012:test-topic")
            .message("test message");
        for i in 0..10 {
            let attr = MessageAttributeValue::builder()
                .data_type("String")
                .string_value(format!("value{i}"))
                .build()
                .unwrap();
            builder = builder.message_attributes(format!("attr{i}"), attr);
        }
        let mut input = builder.build().unwrap();

        inject_into_publish(&mut input, &trace_headers);

        let attrs = input.message_attributes.as_ref().unwrap();
        assert_eq!(attrs.len(), 10);
        assert!(!attrs.contains_key(DATADOG_ATTRIBUTE_KEY));
    }

    #[test]
    fn overwrites_existing_datadog_attribute_when_message_attributes_are_full() {
        let trace_headers = sample_trace_headers();
        let mut builder = PublishInput::builder()
            .topic_arn("arn:aws:sns:us-east-1:123456789012:test-topic")
            .message("test message");
        for i in 0..9 {
            let attr = MessageAttributeValue::builder()
                .data_type("String")
                .string_value(format!("value{i}"))
                .build()
                .unwrap();
            builder = builder.message_attributes(format!("attr{i}"), attr);
        }
        let stale = MessageAttributeValue::builder()
            .data_type("Binary")
            .binary_value(Blob::new(b"old".to_vec()))
            .build()
            .unwrap();
        builder = builder.message_attributes(DATADOG_ATTRIBUTE_KEY, stale);
        let mut input = builder.build().unwrap();

        inject_into_publish(&mut input, &trace_headers);

        let attrs = input.message_attributes.as_ref().unwrap();
        assert_eq!(attrs.len(), 10);
        let parsed = parse_binary_attr(&attrs[DATADOG_ATTRIBUTE_KEY]);
        assert_eq!(parsed[DATADOG_TRACE_ID_KEY], "123456789");
        assert_eq!(parsed[DATADOG_PARENT_ID_KEY], "987654321");
        assert_eq!(parsed[DATADOG_SAMPLING_PRIORITY_KEY], "1");
    }

    #[test]
    fn skips_injection_per_batch_entry_when_message_attributes_are_full() {
        let trace_headers = sample_trace_headers();
        let mut full_attrs = HashMap::new();
        for i in 0..10 {
            full_attrs.insert(
                format!("attr{i}"),
                MessageAttributeValue::builder()
                    .data_type("String")
                    .string_value(format!("value{i}"))
                    .build()
                    .unwrap(),
            );
        }
        let full_entry = PublishBatchRequestEntry::builder()
            .id("full")
            .message("body")
            .set_message_attributes(Some(full_attrs))
            .build()
            .unwrap();
        let empty_entry = PublishBatchRequestEntry::builder()
            .id("empty")
            .message("body")
            .build()
            .unwrap();
        let mut input = PublishBatchInput::builder()
            .topic_arn("arn:aws:sns:us-east-1:123456789012:test-topic")
            .publish_batch_request_entries(full_entry)
            .publish_batch_request_entries(empty_entry)
            .build()
            .unwrap();

        inject_into_publish_batch(&mut input, &trace_headers);

        let entries = input.publish_batch_request_entries.as_ref().unwrap();
        let full = &entries[0];
        assert_eq!(full.message_attributes.as_ref().unwrap().len(), 10);
        assert!(!full
            .message_attributes
            .as_ref()
            .unwrap()
            .contains_key(DATADOG_ATTRIBUTE_KEY));

        let empty = &entries[1];
        assert!(empty
            .message_attributes
            .as_ref()
            .unwrap()
            .contains_key(DATADOG_ATTRIBUTE_KEY));
    }

    #[test]
    fn overwrites_existing_datadog_attribute_in_batch_entries_when_message_attributes_are_full() {
        let trace_headers = sample_trace_headers();
        let mut full_attrs = HashMap::new();
        for i in 0..9 {
            full_attrs.insert(
                format!("attr{i}"),
                MessageAttributeValue::builder()
                    .data_type("String")
                    .string_value(format!("value{i}"))
                    .build()
                    .unwrap(),
            );
        }
        full_attrs.insert(
            DATADOG_ATTRIBUTE_KEY.to_string(),
            MessageAttributeValue::builder()
                .data_type("Binary")
                .binary_value(Blob::new(b"old".to_vec()))
                .build()
                .unwrap(),
        );
        let entry = PublishBatchRequestEntry::builder()
            .id("full")
            .message("body")
            .set_message_attributes(Some(full_attrs))
            .build()
            .unwrap();
        let mut input = PublishBatchInput::builder()
            .topic_arn("arn:aws:sns:us-east-1:123456789012:test-topic")
            .publish_batch_request_entries(entry)
            .build()
            .unwrap();

        inject_into_publish_batch(&mut input, &trace_headers);

        let entries = input.publish_batch_request_entries.as_ref().unwrap();
        let attrs = entries[0].message_attributes.as_ref().unwrap();
        assert_eq!(attrs.len(), 10);
        let parsed = parse_binary_attr(&attrs[DATADOG_ATTRIBUTE_KEY]);
        assert_eq!(parsed[DATADOG_TRACE_ID_KEY], "123456789");
        assert_eq!(parsed[DATADOG_PARENT_ID_KEY], "987654321");
        assert_eq!(parsed[DATADOG_SAMPLING_PRIORITY_KEY], "1");
    }

    #[test]
    fn overwrites_existing_datadog_attribute() {
        let trace_headers = sample_trace_headers();
        let existing = MessageAttributeValue::builder()
            .data_type("Binary")
            .binary_value(Blob::new(b"old".to_vec()))
            .build()
            .unwrap();
        let mut input = PublishInput::builder()
            .topic_arn("arn:aws:sns:us-east-1:123456789012:test-topic")
            .message("test message")
            .message_attributes(DATADOG_ATTRIBUTE_KEY, existing)
            .build()
            .unwrap();

        inject_into_publish(&mut input, &trace_headers);

        let attrs = input.message_attributes.as_ref().unwrap();
        let parsed = parse_binary_attr(&attrs[DATADOG_ATTRIBUTE_KEY]);
        assert_eq!(parsed[DATADOG_TRACE_ID_KEY], "123456789");
    }

    #[test]
    fn inject_dispatches_by_input_type() {
        let trace_headers = sample_trace_headers();
        let input = PublishInput::builder()
            .topic_arn("arn:aws:sns:us-east-1:123456789012:test-topic")
            .message("test message")
            .build()
            .unwrap();
        let mut input = Input::erase(input);

        inject(&trace_headers, &mut input);

        let input = input.downcast_ref::<PublishInput>().unwrap();
        let attrs = input.message_attributes.as_ref().unwrap();
        assert!(attrs.contains_key(DATADOG_ATTRIBUTE_KEY));
    }
}
