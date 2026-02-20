// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! EventBridge-specific trace context enrichment.

use std::collections::HashMap;

use super::{AwsService, ServiceInjector};
use aws_smithy_runtime_api::box_error::BoxError;
use aws_smithy_runtime_api::client::interceptors::context::Input;

pub(crate) struct EventBridgeInjector;

impl ServiceInjector for EventBridgeInjector {
    fn service(&self) -> AwsService {
        AwsService::EventBridge
    }

    fn inject(
        &self,
        operation: &str,
        trace_headers: &HashMap<String, String>,
        input: &mut Input,
    ) -> Result<(), BoxError> {
        let _ = (operation, trace_headers, input);
        // TODO: Implement EventBridge Detail field injection
        Ok(())
    }
}
