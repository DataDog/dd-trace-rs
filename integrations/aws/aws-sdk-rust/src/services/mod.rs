// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

mod eventbridge;
mod sns;
mod sqs;

use std::collections::HashMap;

use aws_smithy_runtime_api::box_error::BoxError;
use aws_smithy_runtime_api::client::interceptors::context::Input;

use crate::attribute_keys::{
    AWS_OPERATION, AWS_PARTITION, AWS_REGION, AWS_SERVICE, RESOURCE_NAME, SERVICE_NAME,
};

pub(crate) use eventbridge::EventBridgeService;
pub(crate) use sns::SnsService;
pub(crate) use sqs::SqsService;

pub(crate) const MAX_MESSAGE_ATTRIBUTES: usize = 10;
pub(crate) const ONE_MB: usize = 1024 * 1024;

pub(crate) trait AwsServiceHandler {
    fn service_id(&self) -> &'static str;

    fn inject(
        &self,
        operation: &str,
        trace_headers: HashMap<String, String>,
        input: &mut Input,
    ) -> Result<(), BoxError>;

    fn extract_request_metadata(
        &self,
        operation: &str,
        input: &Input,
        region: &str,
        partition: &str,
    ) -> Option<RequestMetadata>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequestMetadata {
    pub(crate) service_name: String,
    pub(crate) resource_name: String,
    pub(crate) tags: HashMap<&'static str, String>,
}

pub(crate) fn base_request_metadata(
    service_id: &'static str,
    operation: &str,
    region: &str,
    partition: &str,
) -> RequestMetadata {
    let service_name = format!("aws.{service_id}");
    let resource_name = format!("{service_id}.{operation}");
    let tags = HashMap::from([
        (AWS_SERVICE, service_id.to_string()),
        (AWS_OPERATION, operation.to_string()),
        (AWS_REGION, region.to_string()),
        (AWS_PARTITION, partition.to_string()),
        (SERVICE_NAME, service_name.clone()),
        (RESOURCE_NAME, resource_name.clone()),
    ]);

    RequestMetadata {
        service_name,
        resource_name,
        tags,
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
