// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! SNS-specific trace context enrichment.
//!
//! Injects trace context into MessageAttributes with DataType: Binary.
//! Binary format is critical for SNS subscription filter policies.

use std::collections::HashMap;

use super::{AwsService, ServiceInjector};
use aws_smithy_runtime_api::box_error::BoxError;
use aws_smithy_runtime_api::client::interceptors::context::Input;

pub(crate) struct SnsInjector;

impl ServiceInjector for SnsInjector {
    fn service(&self) -> AwsService {
        AwsService::Sns
    }

    fn inject(
        &self,
        operation: &str,
        trace_headers: &HashMap<String, String>,
        input: &mut Input,
    ) -> Result<(), BoxError> {
        let _ = (operation, trace_headers, input);
        // TODO: Serialize trace_headers to JSON bytes, inject into MessageAttributes (Binary)
        Ok(())
    }
}
