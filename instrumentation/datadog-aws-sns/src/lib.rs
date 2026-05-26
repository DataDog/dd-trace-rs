// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(test), deny(clippy::panic))]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(not(test), deny(clippy::expect_used))]

//! Datadog trace context injection for AWS SDK for Rust SNS operations.
//!
//! # Usage
//!
//! ```rust,ignore
//! use datadog_aws_sns::SnsInterceptor;
//!
//! let config = aws_sdk_sns::config::Builder::from(&sdk_config)
//!     .interceptor(SnsInterceptor::new())
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
    FinalizerInterceptorContextRef,
};
use aws_smithy_runtime_api::client::interceptors::Intercept;
use aws_smithy_runtime_api::client::runtime_components::RuntimeComponents;
use aws_smithy_types::config_bag::ConfigBag;
use aws_smithy_types::Blob;
use opentelemetry::KeyValue;

use datadog_aws_core::attribute_keys::{DATADOG_ATTRIBUTE_KEY, TARGET_NAME, TOPIC_NAME};
use datadog_aws_core::limits::MAX_MESSAGE_ATTRIBUTES;
use datadog_aws_core::{AwsInterceptor, ServiceHandler};

const TRACER_NAME: &str = "datadog-aws-sns";

/// SNS operations that this interceptor recognises.
///
/// Only `Publish` and `PublishBatch` support trace context injection.
/// The remaining variants are tracked to produce accurate span tags for
/// topic/target ARN lookups without injecting into management operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnsOperation {
    Publish,
    PublishBatch,
    GetTopicAttributes,
    ListSubscriptionsByTopic,
    RemovePermission,
    SetTopicAttributes,
    Subscribe,
    CreateTopic,
}

impl SnsOperation {
    /// Maps an SDK operation name string to the enum variant, or `None` for
    /// operations this interceptor does not handle.
    fn from_name(operation: &str) -> Option<Self> {
        match operation {
            "Publish" => Some(Self::Publish),
            "PublishBatch" => Some(Self::PublishBatch),
            "GetTopicAttributes" => Some(Self::GetTopicAttributes),
            "ListSubscriptionsByTopic" => Some(Self::ListSubscriptionsByTopic),
            "RemovePermission" => Some(Self::RemovePermission),
            "SetTopicAttributes" => Some(Self::SetTopicAttributes),
            "Subscribe" => Some(Self::Subscribe),
            "CreateTopic" => Some(Self::CreateTopic),
            _ => None,
        }
    }
}

/// [`ServiceHandler`] implementation for Amazon SNS.
struct SnsHandler;

impl ServiceHandler for SnsHandler {
    fn sdk_service_name(&self) -> &'static str {
        "SNS"
    }

    fn span_service_id(&self) -> &'static str {
        "sns"
    }

    fn inject(
        &self,
        operation: &str,
        trace_headers: &HashMap<String, String>,
        input: &mut aws_smithy_runtime_api::client::interceptors::context::Input,
    ) -> Result<(), BoxError> {
        if let Some(op) = SnsOperation::from_name(operation) {
            inject(op, trace_headers, input)?;
        }
        Ok(())
    }

    fn service_tags(
        &self,
        operation: &str,
        input: &aws_smithy_runtime_api::client::interceptors::context::Input,
        _region: &str,
        _partition: &str,
    ) -> Vec<KeyValue> {
        SnsOperation::from_name(operation)
            .map(|op| service_tags(op, input))
            .unwrap_or_default()
    }
}

/// AWS SDK interceptor that injects Datadog trace context into SNS requests
/// and creates spans representing SNS operations.
#[derive(Debug)]
pub struct SnsInterceptor {
    inner: AwsInterceptor<SnsHandler>,
}

impl SnsInterceptor {
    pub fn new() -> Self {
        Self {
            inner: AwsInterceptor::new(SnsHandler, TRACER_NAME),
        }
    }
}

impl Default for SnsInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

impl Intercept for SnsInterceptor {
    fn name(&self) -> &'static str {
        "SnsInterceptor"
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

/// Dispatches trace context injection to the appropriate per-operation function.
///
/// Only `Publish` and `PublishBatch` carry a message attributes payload that
/// supports injection; all other operations are no-ops.
fn inject(
    operation: SnsOperation,
    trace_headers: &HashMap<String, String>,
    input: &mut aws_smithy_runtime_api::client::interceptors::context::Input,
) -> Result<(), BoxError> {
    match operation {
        SnsOperation::Publish => {
            if let Some(publish_input) = input.downcast_mut::<PublishInput>() {
                inject_into_publish(publish_input, trace_headers)?;
            }
        }
        SnsOperation::PublishBatch => {
            if let Some(batch_input) = input.downcast_mut::<PublishBatchInput>() {
                inject_into_publish_batch(batch_input, trace_headers)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Returns SNS-specific span tags for the given operation.
///
/// For `Publish`, includes `topicname` (from `topic_arn`) or `targetname` (from
/// `target_arn`). For all other topic operations, includes `topicname`.
/// For `CreateTopic`, uses the `name` parameter directly instead of an ARN.
fn service_tags(
    operation: SnsOperation,
    input: &aws_smithy_runtime_api::client::interceptors::context::Input,
) -> Vec<KeyValue> {
    match operation {
        SnsOperation::Publish => {
            let Some(input) = input.downcast_ref::<PublishInput>() else {
                return vec![];
            };
            if let Some(arn) = input.topic_arn.as_deref() {
                vec![KeyValue::new(TOPIC_NAME, arn_resource_name(arn).to_owned())]
            } else if let Some(arn) = input.target_arn.as_deref() {
                vec![KeyValue::new(
                    TARGET_NAME,
                    arn_resource_name(arn).to_owned(),
                )]
            } else {
                vec![]
            }
        }
        SnsOperation::PublishBatch => topic_arn_tag::<PublishBatchInput>(input),
        SnsOperation::GetTopicAttributes => topic_arn_tag::<GetTopicAttributesInput>(input),
        SnsOperation::ListSubscriptionsByTopic => {
            topic_arn_tag::<ListSubscriptionsByTopicInput>(input)
        }
        SnsOperation::RemovePermission => topic_arn_tag::<RemovePermissionInput>(input),
        SnsOperation::SetTopicAttributes => topic_arn_tag::<SetTopicAttributesInput>(input),
        SnsOperation::Subscribe => topic_arn_tag::<SubscribeInput>(input),
        SnsOperation::CreateTopic => input
            .downcast_ref::<CreateTopicInput>()
            .and_then(|i| i.name.as_deref())
            .map(|name| vec![KeyValue::new(TOPIC_NAME, name.to_owned())])
            .unwrap_or_default(),
    }
}

/// Injects a `_datadog` Binary message attribute into a `Publish` input.
///
/// Skipped when the message already has 10 attributes and none is `_datadog`.
fn inject_into_publish(
    input: &mut PublishInput,
    trace_headers: &HashMap<String, String>,
) -> Result<(), BoxError> {
    let attrs = input.message_attributes.get_or_insert_with(HashMap::new);
    if should_skip_injection(attrs) {
        return Ok(());
    }
    attrs.insert(
        DATADOG_ATTRIBUTE_KEY.to_string(),
        build_datadog_attribute(trace_headers)?,
    );
    Ok(())
}

/// Injects a `_datadog` Binary message attribute into each entry of a `PublishBatch` input.
///
/// The same skip/overwrite rules as [`inject_into_publish`] apply per entry.
fn inject_into_publish_batch(
    input: &mut PublishBatchInput,
    trace_headers: &HashMap<String, String>,
) -> Result<(), BoxError> {
    let Some(entries) = input.publish_batch_request_entries.as_mut() else {
        return Ok(());
    };
    let dd_key = DATADOG_ATTRIBUTE_KEY.to_string();
    let dd_attr = build_datadog_attribute(trace_headers)?;
    for entry in entries.iter_mut() {
        let attrs = entry.message_attributes.get_or_insert_with(HashMap::new);
        if should_skip_injection(attrs) {
            continue;
        }
        attrs.insert(dd_key.clone(), dd_attr.clone());
    }
    Ok(())
}

/// Returns `true` when injection should be skipped to respect the 10-attribute cap.
///
/// An existing `_datadog` attribute counts as a slot we can reuse, so the cap
/// is only enforced when `_datadog` is absent.
fn should_skip_injection(attrs: &HashMap<String, MessageAttributeValue>) -> bool {
    attrs.len() >= MAX_MESSAGE_ATTRIBUTES && !attrs.contains_key(DATADOG_ATTRIBUTE_KEY)
}

/// Helper trait for extracting a topic ARN from SNS input types that carry one.
trait HasTopicArn: std::fmt::Debug + 'static {
    fn topic_arn(&self) -> Option<&str>;
}

macro_rules! impl_has_topic_arn {
    ($($ty:ty),+ $(,)?) => {
        $(impl HasTopicArn for $ty {
            fn topic_arn(&self) -> Option<&str> { self.topic_arn.as_deref() }
        })+
    };
}

impl_has_topic_arn!(
    PublishBatchInput,
    GetTopicAttributesInput,
    ListSubscriptionsByTopicInput,
    RemovePermissionInput,
    SetTopicAttributesInput,
    SubscribeInput,
);

/// Extracts the topic ARN from an input implementing [`HasTopicArn`] and returns
/// a `topicname` tag with the resource name portion of the ARN.
fn topic_arn_tag<T: HasTopicArn + Send + Sync>(
    input: &aws_smithy_runtime_api::client::interceptors::context::Input,
) -> Vec<KeyValue> {
    input
        .downcast_ref::<T>()
        .and_then(|i| i.topic_arn())
        .map(|arn| vec![KeyValue::new(TOPIC_NAME, arn_resource_name(arn).to_owned())])
        .unwrap_or_default()
}

/// Returns the resource name (last colon-separated segment) from an ARN string.
fn arn_resource_name(arn: &str) -> &str {
    arn.rsplit(':').next().unwrap_or(arn)
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

        inject_into_publish(&mut input, &trace_headers).unwrap();

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

        inject_into_publish(&mut input, &trace_headers).unwrap();

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

        inject_into_publish_batch(&mut input, &trace_headers).unwrap();

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

        inject_into_publish_batch(&mut input, &trace_headers).unwrap();

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

        inject_into_publish(&mut input, &trace_headers).unwrap();

        let attrs = input.message_attributes.as_ref().unwrap();
        let parsed = parse_binary_attr(&attrs[DATADOG_ATTRIBUTE_KEY]);
        assert_eq!(parsed[DATADOG_TRACE_ID_KEY], "123456789");
    }

    #[test]
    fn unsupported_sns_operation_returns_none() {
        assert!(SnsOperation::from_name("Puppy").is_none());
    }
}
