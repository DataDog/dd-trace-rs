// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

mod eventbridge;
mod sns;
mod sqs;

use std::collections::HashMap;

use aws_smithy_runtime_api::box_error::BoxError;
use aws_smithy_runtime_api::client::interceptors::context::Input;
use opentelemetry::KeyValue;

use crate::attribute_keys::{
    AWS_OPERATION, AWS_PARTITION, AWS_REGION, AWS_SERVICE, COMPONENT, OPERATION_NAME, RESOURCE_NAME,
    SPAN_KIND, TRACER_NAME,
};

// SQS and SNS both cap message attributes at 10.
pub(crate) const MAX_MESSAGE_ATTRIBUTES: usize = 10;
// EventBridge entry detail size limit.
pub(crate) const ONE_MB: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub(crate) enum AwsService {
    Sqs,
    Sns,
    EventBridge,
}

impl AwsService {
    pub(crate) fn from_sdk_service(name: &str) -> Option<Self> {
        match name {
            "SQS" => Some(Self::Sqs),
            "SNS" => Some(Self::Sns),
            "EventBridge" => Some(Self::EventBridge),
            _ => None,
        }
    }

    pub(crate) fn span_service_id(self) -> &'static str {
        match self {
            Self::Sqs => "sqs",
            Self::Sns => "sns",
            Self::EventBridge => "eventbridge",
        }
    }

    pub(crate) fn sdk_service_name(self) -> &'static str {
        match self {
            Self::Sqs => "SQS",
            Self::Sns => "SNS",
            Self::EventBridge => "EventBridge",
        }
    }

    pub(crate) fn inject(
        self,
        operation: &str,
        trace_headers: &HashMap<String, String>,
        input: &mut Input,
    ) -> Result<(), BoxError> {
        match self {
            Self::Sqs => {
                if let Some(op) = sqs::SqsOperation::from_name(operation) {
                    sqs::inject(op, trace_headers, input)?;
                }
                Ok(())
            }
            Self::Sns => {
                if let Some(op) = sns::SnsOperation::from_name(operation) {
                    sns::inject(op, trace_headers, input)?;
                }
                Ok(())
            }
            Self::EventBridge => {
                if let Some(op) = eventbridge::EventBridgeOperation::from_name(operation) {
                    eventbridge::inject(op, trace_headers, input)?;
                }
                Ok(())
            }
        }
    }

    pub(crate) fn service_tags(
        self,
        operation: &str,
        input: &Input,
        region: &str,
        partition: &str,
    ) -> Vec<KeyValue> {
        match self {
            Self::Sqs => sqs::SqsOperation::from_name(operation)
                .map(|op| sqs::service_tags(op, input, region, partition))
                .unwrap_or_default(),
            Self::Sns => sns::SnsOperation::from_name(operation)
                .map(|op| sns::service_tags(op, input))
                .unwrap_or_default(),
            Self::EventBridge => eventbridge::EventBridgeOperation::from_name(operation)
                .map(|op| eventbridge::service_tags(op, input))
                .unwrap_or_default(),
        }
    }
}

/// Base tags common to all AWS service spans.
pub(crate) fn base_tags(
    service_id: &'static str,
    sdk_service_name: &'static str,
    operation: &str,
    region: &str,
    partition: &str,
) -> Vec<KeyValue> {
    vec![
        KeyValue::new(OPERATION_NAME, format!("aws.{service_id}.request")),
        KeyValue::new(AWS_SERVICE, sdk_service_name),
        KeyValue::new(AWS_OPERATION, operation.to_owned()),
        KeyValue::new(AWS_REGION, region.to_owned()),
        KeyValue::new(AWS_PARTITION, partition.to_owned()),
        KeyValue::new(RESOURCE_NAME, format!("{service_id}.{operation}")),
        KeyValue::new(COMPONENT, TRACER_NAME),
        KeyValue::new(SPAN_KIND, "client"),
    ]
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use std::collections::HashMap;

    use opentelemetry::{KeyValue, Value};

    pub(crate) const DATADOG_TRACE_ID_KEY: &str = "x-datadog-trace-id";
    pub(crate) const DATADOG_PARENT_ID_KEY: &str = "x-datadog-parent-id";
    pub(crate) const DATADOG_SAMPLING_PRIORITY_KEY: &str = "x-datadog-sampling-priority";

    pub(crate) fn sample_trace_headers() -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert(DATADOG_TRACE_ID_KEY.to_string(), "123456789".to_string());
        headers.insert(DATADOG_PARENT_ID_KEY.to_string(), "987654321".to_string());
        headers.insert(DATADOG_SAMPLING_PRIORITY_KEY.to_string(), "1".to_string());
        headers
    }

    pub(crate) fn collect_string_tags(tags: Vec<KeyValue>) -> HashMap<String, String> {
        tags.into_iter()
            .map(|KeyValue { key, value, .. }| {
                let Value::String(value) = value else {
                    panic!("expected string tag value for {}", key.as_str());
                };
                (key.as_str().to_string(), value.to_string())
            })
            .collect()
    }
}
