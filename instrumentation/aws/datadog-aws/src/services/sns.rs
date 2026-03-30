// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

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
use aws_smithy_runtime_api::client::interceptors::context::Input;
use aws_smithy_types::Blob;
use opentelemetry::KeyValue;

use crate::attribute_keys::{DATADOG_ATTRIBUTE_KEY, TARGET_NAME, TOPIC_NAME};

use super::MAX_MESSAGE_ATTRIBUTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SnsOperation {
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
    pub(super) fn from_name(operation: &str) -> Option<Self> {
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

pub(super) fn inject(
    operation: SnsOperation,
    trace_headers: &HashMap<String, String>,
    input: &mut Input,
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

pub(super) fn service_tags(operation: SnsOperation, input: &Input) -> Vec<KeyValue> {
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

// Respect the 10-attribute cap unless replacing an existing _datadog attribute.
fn should_skip_injection(attrs: &HashMap<String, MessageAttributeValue>) -> bool {
    attrs.len() >= MAX_MESSAGE_ATTRIBUTES && !attrs.contains_key(DATADOG_ATTRIBUTE_KEY)
}

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

// `Input` is type-erased at this layer, so SNS operations that carry a `topic_arn`
// downcast to their concrete input type and all derive the same `topic.name` tag
// from the ARN resource component.
fn topic_arn_tag<T: HasTopicArn + Send + Sync>(input: &Input) -> Vec<KeyValue> {
    input
        .downcast_ref::<T>()
        .and_then(|i| i.topic_arn())
        .map(|arn| vec![KeyValue::new(TOPIC_NAME, arn_resource_name(arn).to_owned())])
        .unwrap_or_default()
}

fn arn_resource_name(arn: &str) -> &str {
    arn.rsplit(':').next().unwrap_or(arn)
}

// SNS trace context is a Binary-typed attribute. String-typed JSON attributes interfere
// with SNS subscription filter policies, which silently drop messages they cannot parse.
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
    use crate::services::test_helpers::{
        collect_string_tags, sample_trace_headers, DATADOG_PARENT_ID_KEY,
        DATADOG_SAMPLING_PRIORITY_KEY, DATADOG_TRACE_ID_KEY,
    };
    use aws_sdk_sns::types::PublishBatchRequestEntry;
    use aws_smithy_runtime_api::client::interceptors::context::Input;

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
