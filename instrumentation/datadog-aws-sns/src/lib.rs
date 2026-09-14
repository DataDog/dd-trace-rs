// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(test), deny(clippy::panic))]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(not(test), deny(clippy::expect_used))]

//! Datadog tracing for AWS SDK for Rust SNS operations.
//!
//! # What it instruments
//!
//! Installing [`ConfigExt::datadog_tracing`] adds an AWS SDK interceptor that creates one
//! `sns.request` client span for each SNS SDK operation as a child of the current OpenTelemetry
//! context. Spans are tagged with common AWS SDK metadata, HTTP method, URL, user agent, response
//! status, AWS request ID, and SDK errors.
//!
//! SNS-specific span tags include `topicname`, `targetname`, and
//! `messaging.batch.message_count` for `PublishBatch`.
//!
//! For `Publish` and `PublishBatch`, the interceptor injects the active request span context as an
//! SNS message attribute named `_datadog` with data type `Binary`. Existing `_datadog` attributes
//! are replaced. Injection is skipped when the message already has the maximum number of SNS
//! message attributes and no `_datadog` attribute is present. Other SNS operations create spans but
//! do not carry propagation context.
//!
//! # Payload Size Headroom
//!
//! Datadog trace context is injected into AWS payload fields before the SDK sends the request, so
//! applications should leave a small amount of room under the SNS message size limit. With the
//! default W3C trace-context propagator, the binary JSON attribute value is typically less than 100
//! bytes before AWS request serialization overhead. Baggage from the configured global
//! OpenTelemetry text-map propagator can add arbitrary bytes. SNS performs the authoritative size
//! validation, and this crate only applies cheap stable guards such as the message attribute count
//! limit.
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

use aws_sdk_sns::operation::add_permission::AddPermissionInput;
use aws_sdk_sns::operation::confirm_subscription::ConfirmSubscriptionInput;
use aws_sdk_sns::operation::create_topic::CreateTopicInput;
use aws_sdk_sns::operation::delete_topic::DeleteTopicInput;
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
use opentelemetry::{global, Context, KeyValue};

use datadog_aws_core::{
    attribute_keys::{
        DATADOG_ATTRIBUTE_KEY, MESSAGING_BATCH_MESSAGE_COUNT, TARGET_NAME, TOPIC_NAME,
    },
    finish_request_span, request_span_trace_headers, start_request_span, update_request_span,
    AwsRequestMetadata,
};

const TRACER_NAME: &str = "datadog-aws-sns";
const SPAN_NAME: &str = "sns.request";
const SPAN_OPERATION_NAME: &str = "aws.sns.request";
const MAX_MESSAGE_ATTRIBUTES: usize = 10;

/// AWS SDK interceptor that creates Datadog spans and injects trace context into SNS requests.
///
/// Use [`ConfigExt::datadog_tracing`] to install it on an SNS config builder.
#[derive(Debug)]
struct SnsInterceptor;

/// Extension methods for installing Datadog tracing on an Amazon SNS config builder.
pub trait ConfigExt {
    /// Installs Datadog tracing on this SNS config builder.
    fn datadog_tracing(self) -> Self;
}

impl ConfigExt for aws_sdk_sns::config::Builder {
    fn datadog_tracing(self) -> Self {
        self.interceptor(SnsInterceptor)
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
        let Some(metadata) = AwsRequestMetadata::from_config_bag(cfg) else {
            return Ok(());
        };

        let input = context.input();
        let mut direct_topic_name = None;
        let mut topic_arn = None;
        let mut target_arn = None;
        let mut batch_message_count = None;
        if let Some(input) = input.downcast_ref::<PublishInput>() {
            topic_arn = input.topic_arn.as_deref();
            target_arn = input.target_arn.as_deref();
        } else if let Some(input) = input.downcast_ref::<CreateTopicInput>() {
            direct_topic_name = input.name.as_deref();
        } else if let Some(input) = input.downcast_ref::<PublishBatchInput>() {
            topic_arn = input.topic_arn.as_deref();
            batch_message_count = Some(
                input
                    .publish_batch_request_entries
                    .as_ref()
                    .map_or(0, Vec::len) as i64,
            );
        } else if let Some(input) = input.downcast_ref::<AddPermissionInput>() {
            topic_arn = input.topic_arn.as_deref();
        } else if let Some(input) = input.downcast_ref::<ConfirmSubscriptionInput>() {
            topic_arn = input.topic_arn.as_deref();
        } else if let Some(input) = input.downcast_ref::<DeleteTopicInput>() {
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
            batch_message_count.map(|count| KeyValue::new(MESSAGING_BATCH_MESSAGE_COUNT, count)),
        ]
        .into_iter()
        .flatten();
        // Resolve at operation start so clients built before TracedService installs
        // the Datadog provider do not keep a no-op tracer.
        let tracer = global::tracer(TRACER_NAME);
        let span_context = start_request_span(
            SPAN_NAME,
            SPAN_OPERATION_NAME,
            metadata,
            service_tags,
            &tracer,
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
        update_request_span(context, cfg);
        Ok(())
    }

    fn read_after_execution(
        &self,
        context: &FinalizerInterceptorContextRef<'_>,
        _runtime_components: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        finish_request_span(context, cfg);
        Ok(())
    }
}

/// Dispatches trace context injection based on the concrete operation input type.
///
/// Only `Publish` and `PublishBatch` carry a message attributes payload that
/// supports injection; all other operations are no-ops.
fn inject(span_context: &Context, input: &mut Input) {
    if let Some(publish_input) = input.downcast_mut::<PublishInput>() {
        if let Some(dd_attr) = build_datadog_attribute(span_context) {
            inject_message_attribute(&mut publish_input.message_attributes, dd_attr);
        }
    } else if let Some(batch_input) = input.downcast_mut::<PublishBatchInput>() {
        if let Some(entries) = batch_input.publish_batch_request_entries.as_mut() {
            if let Some(dd_attr) = build_datadog_attribute(span_context) {
                for entry in entries.iter_mut() {
                    inject_message_attribute(&mut entry.message_attributes, dd_attr.clone());
                }
            }
        }
    }
}

fn build_datadog_attribute(span_context: &Context) -> Option<MessageAttributeValue> {
    let trace_headers = request_span_trace_headers(span_context);
    if trace_headers.is_empty() {
        return None;
    }

    let attribute = || -> Result<MessageAttributeValue, BoxError> {
        let json_bytes = serde_json::to_vec(&trace_headers)?;
        // Use Binary for SNS: SNS subscription filter policies can silently fail when JSON is
        // carried as a String message attribute. Keep this aligned with other Datadog tracers.
        MessageAttributeValue::builder()
            .data_type("Binary")
            .binary_value(Blob::new(json_bytes))
            .build()
            .map_err(Into::into)
    };

    match attribute() {
        Ok(attr) => Some(attr),
        Err(err) => {
            tracing::debug!(
                name: "Sns.Inject.DatadogAttributeBuildFailed",
                reason = %err,
                action = "context injection skipped",
            );
            None
        }
    }
}

fn inject_message_attribute(
    message_attributes: &mut Option<HashMap<String, MessageAttributeValue>>,
    datadog_attr: MessageAttributeValue,
) {
    let attrs = message_attributes.get_or_insert_with(HashMap::new);
    if attrs.len() < MAX_MESSAGE_ATTRIBUTES || attrs.contains_key(DATADOG_ATTRIBUTE_KEY) {
        attrs.insert(DATADOG_ATTRIBUTE_KEY.to_string(), datadog_attr);
    } else {
        tracing::debug!(
            name: "Sns.Inject.MessageAttributesFull",
            max_message_attributes = MAX_MESSAGE_ATTRIBUTES,
            action = "context injection skipped",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_sns::types::PublishBatchRequestEntry;
    use datadog_aws_core_test_utils::test_helpers::{
        ensure_test_propagator, test_context, TEST_CONTEXT_INJECTED_KEY,
    };

    fn parse_binary_attr(attr: &MessageAttributeValue) -> HashMap<String, String> {
        assert_eq!(attr.data_type(), "Binary");
        let blob = attr.binary_value().unwrap();
        serde_json::from_slice(blob.as_ref()).unwrap()
    }

    #[test]
    fn skips_injection_when_message_attributes_are_full() {
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
        let mut input = Input::erase(builder.build().unwrap());

        inject(&Context::new(), &mut input);

        let input = input.downcast_ref::<PublishInput>().unwrap();
        let attrs = input.message_attributes.as_ref().unwrap();
        assert_eq!(attrs.len(), 10);
        assert!(!attrs.contains_key(DATADOG_ATTRIBUTE_KEY));
    }

    #[test]
    fn overwrites_existing_datadog_attribute_when_message_attributes_are_full() {
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
        let mut input = Input::erase(builder.build().unwrap());
        ensure_test_propagator();
        inject(&test_context(), &mut input);

        let input = input.downcast_ref::<PublishInput>().unwrap();
        let attrs = input.message_attributes.as_ref().unwrap();
        assert_eq!(attrs.len(), 10);
        let parsed = parse_binary_attr(&attrs[DATADOG_ATTRIBUTE_KEY]);
        assert_eq!(parsed[TEST_CONTEXT_INJECTED_KEY], "true");
    }

    #[test]
    fn skips_injection_per_batch_entry_when_message_attributes_are_full() {
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
        let mut input = Input::erase(
            PublishBatchInput::builder()
                .topic_arn("arn:aws:sns:us-east-1:123456789012:test-topic")
                .publish_batch_request_entries(full_entry)
                .publish_batch_request_entries(empty_entry)
                .build()
                .unwrap(),
        );
        ensure_test_propagator();
        inject(&test_context(), &mut input);

        let input = input.downcast_ref::<PublishBatchInput>().unwrap();
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
        let mut input = Input::erase(
            PublishBatchInput::builder()
                .topic_arn("arn:aws:sns:us-east-1:123456789012:test-topic")
                .publish_batch_request_entries(entry)
                .build()
                .unwrap(),
        );
        ensure_test_propagator();
        inject(&test_context(), &mut input);

        let input = input.downcast_ref::<PublishBatchInput>().unwrap();
        let entries = input.publish_batch_request_entries.as_ref().unwrap();
        let attrs = entries[0].message_attributes.as_ref().unwrap();
        assert_eq!(attrs.len(), 10);
        let parsed = parse_binary_attr(&attrs[DATADOG_ATTRIBUTE_KEY]);
        assert_eq!(parsed[TEST_CONTEXT_INJECTED_KEY], "true");
    }

    #[test]
    fn overwrites_existing_datadog_attribute() {
        let existing = MessageAttributeValue::builder()
            .data_type("Binary")
            .binary_value(Blob::new(b"old".to_vec()))
            .build()
            .unwrap();
        let mut input = Input::erase(
            PublishInput::builder()
                .topic_arn("arn:aws:sns:us-east-1:123456789012:test-topic")
                .message("test message")
                .message_attributes(DATADOG_ATTRIBUTE_KEY, existing)
                .build()
                .unwrap(),
        );
        ensure_test_propagator();
        inject(&test_context(), &mut input);

        let input = input.downcast_ref::<PublishInput>().unwrap();
        let attrs = input.message_attributes.as_ref().unwrap();
        let parsed = parse_binary_attr(&attrs[DATADOG_ATTRIBUTE_KEY]);
        assert_eq!(parsed[TEST_CONTEXT_INJECTED_KEY], "true");
    }

    #[test]
    fn inject_dispatches_by_input_type() {
        let input = PublishInput::builder()
            .topic_arn("arn:aws:sns:us-east-1:123456789012:test-topic")
            .message("test message")
            .build()
            .unwrap();
        let mut input = Input::erase(input);
        ensure_test_propagator();
        inject(&test_context(), &mut input);

        let input = input.downcast_ref::<PublishInput>().unwrap();
        let attrs = input.message_attributes.as_ref().unwrap();
        assert!(attrs.contains_key(DATADOG_ATTRIBUTE_KEY));
    }
}
