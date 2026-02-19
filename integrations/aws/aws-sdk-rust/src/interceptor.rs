// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! AWS SDK interceptor for automatic Datadog trace context propagation.
//!
//! This module provides the core interceptor that hooks into the AWS SDK
//! request lifecycle to inject trace context into service-specific inputs
//! (e.g. SQS MessageAttributes) before serialization.

use std::collections::HashMap;

use aws_smithy_runtime_api::box_error::BoxError;
use aws_smithy_runtime_api::client::interceptors::context::BeforeSerializationInterceptorContextMut;
use aws_smithy_runtime_api::client::interceptors::Intercept;
use aws_smithy_runtime_api::client::orchestrator::Metadata;
use aws_smithy_runtime_api::client::runtime_components::RuntimeComponents;
use aws_smithy_types::config_bag::ConfigBag;
use opentelemetry::Context;

use crate::services::{AwsService, ServiceInjector, SqsInjector};

/// AWS SDK interceptor that automatically injects Datadog trace context into requests.
///
/// This interceptor hooks into the AWS SDK request lifecycle and injects trace propagation
/// context before the request is serialized. It uses the current OpenTelemetry context to
/// determine which trace context to propagate.
///
/// Currently supported services:
/// - **SQS**: Injects `_datadog` MessageAttribute (JSON-serialized trace headers)
///
/// # Example
///
/// ```rust,ignore
/// use datadog_aws_sdk::DatadogInterceptor;
///
/// let sqs_config = aws_sdk_sqs::config::Builder::from(&sdk_config)
///     .interceptor(DatadogInterceptor::new())
///     .build();
/// let sqs_client = aws_sdk_sqs::Client::from_conf(sqs_config);
/// ```
#[derive(Debug, Clone)]
pub struct DatadogInterceptor {}

impl DatadogInterceptor {
    /// Creates a new interceptor.
    ///
    /// The interceptor will use the global Datadog propagator configured
    /// in the OpenTelemetry global provider.
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for DatadogInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

struct PropagatorCarrier(HashMap<String, String>);

impl opentelemetry::propagation::Injector for PropagatorCarrier {
    fn set(&mut self, key: &str, value: String) {
        self.0.insert(key.to_string(), value);
    }
}

fn extract_trace_headers() -> HashMap<String, String> {
    let cx = Context::current();
    opentelemetry::global::get_text_map_propagator(|p| {
        let mut carrier = PropagatorCarrier(HashMap::new());
        p.inject_context(&cx, &mut carrier);
        carrier.0
    })
}

impl Intercept for DatadogInterceptor {
    fn name(&self) -> &'static str {
        "DatadogInterceptor"
    }

    fn modify_before_serialization(
        &self,
        context: &mut BeforeSerializationInterceptorContextMut<'_>,
        _runtime_components: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        let metadata = match cfg.load::<Metadata>() {
            Some(m) => m,
            None => return Ok(()),
        };

        let service = match AwsService::from_service_id(metadata.service()) {
            Some(s) => s,
            None => return Ok(()),
        };

        let operation = metadata.name();

        let trace_headers = extract_trace_headers();
        if trace_headers.is_empty() {
            return Ok(());
        }

        let input = context.input_mut();

        // Swallow injection errors — trace propagation must never fail the AWS call.
        let _ = match service {
            AwsService::Sqs => SqsInjector.inject(operation, &trace_headers, input),
            AwsService::Sns => Ok(()),
            AwsService::Kinesis => Ok(()),
            AwsService::EventBridge => Ok(()),
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interceptor_creation() {
        let interceptor = DatadogInterceptor::new();
        assert_eq!(interceptor.name(), "DatadogInterceptor");
    }

    #[test]
    fn test_extract_trace_headers_empty_without_span() {
        let headers = extract_trace_headers();
        assert!(headers.is_empty());
    }
}
