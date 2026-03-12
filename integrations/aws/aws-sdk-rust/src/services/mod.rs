// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

mod sns;
mod sqs;

use std::collections::HashMap;

use aws_smithy_runtime_api::box_error::BoxError;
use aws_smithy_runtime_api::client::interceptors::context::Input;

pub(crate) const DATADOG_ATTRIBUTE_KEY: &str = "_datadog";
pub(crate) const MAX_MESSAGE_ATTRIBUTES: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum AwsService {
    Sqs,
    Sns,
}

impl AwsService {
    pub(crate) fn from_service_id(service_id: &str) -> Option<Self> {
        match service_id {
            "SQS" => Some(Self::Sqs),
            "SNS" => Some(Self::Sns),
            _ => None,
        }
    }

    pub(crate) fn inject(
        &self,
        operation: &str,
        trace_headers: HashMap<String, String>,
        input: &mut Input,
    ) -> Result<(), BoxError> {
        match self {
            Self::Sqs => sqs::inject(operation, trace_headers, input),
            Self::Sns => sns::inject(operation, trace_headers, input),
        }
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use std::collections::HashMap;

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
}
