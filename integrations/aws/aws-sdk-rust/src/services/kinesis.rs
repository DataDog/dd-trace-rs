// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Kinesis-specific trace context enrichment.

use std::collections::HashMap;

use super::{AwsService, ServiceInjector};
use aws_smithy_runtime_api::box_error::BoxError;
use aws_smithy_runtime_api::client::interceptors::context::Input;

pub(crate) struct KinesisInjector;

impl ServiceInjector for KinesisInjector {
    fn service(&self) -> AwsService {
        AwsService::Kinesis
    }

    fn inject(
        &self,
        operation: &str,
        trace_headers: &HashMap<String, String>,
        input: &mut Input,
    ) -> Result<(), BoxError> {
        let _ = (operation, trace_headers, input);
        // TODO: Implement Kinesis trace context injection
        Ok(())
    }
}
