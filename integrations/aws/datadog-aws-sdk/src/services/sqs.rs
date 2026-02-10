// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! SQS-specific trace context enrichment.
//!
//! Injects trace context into MessageAttributes with DataType: String.

use std::collections::HashMap;

use super::{AwsService, ServiceInjector};
use aws_smithy_runtime_api::box_error::BoxError;
use aws_smithy_runtime_api::client::interceptors::context::BeforeTransmitInterceptorContextMut;

pub(crate) struct SqsInjector;

impl ServiceInjector for SqsInjector {
    fn service(&self) -> AwsService {
        AwsService::Sqs
    }

    fn inject(
        &self,
        operation: &str,
        trace_headers: &HashMap<String, String>,
        context: &mut BeforeTransmitInterceptorContextMut<'_>,
    ) -> Result<(), BoxError> {
        let _ = (operation, trace_headers, context);
        // TODO: Serialize trace_headers to JSON, inject into MessageAttributes
        Ok(())
    }
}
