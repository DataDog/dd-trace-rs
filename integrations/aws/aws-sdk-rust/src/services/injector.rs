// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Service-specific trace context injector trait.

use std::collections::HashMap;

use aws_smithy_runtime_api::box_error::BoxError;
use aws_smithy_runtime_api::client::interceptors::context::Input;

pub(crate) const DATADOG_ATTRIBUTE_KEY: &str = "_datadog";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum AwsService {
    Sqs,
    Sns,
    Kinesis,
    EventBridge,
}

impl AwsService {
    pub(crate) fn from_service_id(service_id: &str) -> Option<Self> {
        match service_id {
            "SQS" => Some(Self::Sqs),
            "SNS" => Some(Self::Sns),
            "Kinesis" => Some(Self::Kinesis),
            "EventBridge" => Some(Self::EventBridge),
            _ => None,
        }
    }
}

#[allow(dead_code)]
pub(crate) trait ServiceInjector {
    fn service(&self) -> AwsService;

    /// `trace_headers` contains the Datadog trace context extracted from the current OTel context.
    fn inject(
        &self,
        operation: &str,
        trace_headers: &HashMap<String, String>,
        input: &mut Input,
    ) -> Result<(), BoxError>;
}
