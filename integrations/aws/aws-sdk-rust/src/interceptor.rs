// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use aws_smithy_runtime_api::box_error::BoxError;
use aws_smithy_runtime_api::client::interceptors::context::BeforeSerializationInterceptorContextMut;
use aws_smithy_runtime_api::client::interceptors::Intercept;
use aws_smithy_runtime_api::client::orchestrator::Metadata;
use aws_smithy_runtime_api::client::runtime_components::RuntimeComponents;
use aws_smithy_types::config_bag::ConfigBag;
use opentelemetry::Context;

use crate::services::AwsService;

/// AWS SDK interceptor that injects Datadog trace context into messaging payloads.
///
/// # Example
///
/// ```rust,ignore
/// use datadog_aws_sdk::DatadogAwsInterceptor;
///
/// let sqs_config = aws_sdk_sqs::config::Builder::from(&sdk_config)
///     .interceptor(DatadogAwsInterceptor::new())
///     .build();
/// let sqs_client = aws_sdk_sqs::Client::from_conf(sqs_config);
/// ```
#[derive(Debug, Clone)]
pub struct DatadogAwsInterceptor {}

impl DatadogAwsInterceptor {
    /// Creates a new [`DatadogAwsInterceptor`].
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for DatadogAwsInterceptor {
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

fn extract_trace_headers(cx: &Context) -> HashMap<String, String> {
    opentelemetry::global::get_text_map_propagator(|p| {
        let mut carrier = PropagatorCarrier(HashMap::new());
        p.inject_context(cx, &mut carrier);
        carrier.0
    })
}

impl Intercept for DatadogAwsInterceptor {
    fn name(&self) -> &'static str {
        "DatadogAwsInterceptor"
    }

    fn modify_before_serialization(
        &self,
        context: &mut BeforeSerializationInterceptorContextMut<'_>,
        _runtime_components: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        let Some((service, operation)) = cfg.load::<Metadata>().and_then(|m| {
            let op = m.name();
            AwsService::from_service_id(m.service()).map(|s| (s, op))
        }) else {
            return Ok(());
        };

        let cx = Context::current();
        let trace_headers = extract_trace_headers(&cx);
        if trace_headers.is_empty() {
            return Ok(());
        }

        // Swallow injection errors -- trace propagation must never fail the AWS call.
        if let Err(err) = service.inject(operation, trace_headers, context.input_mut()) {
            tracing::debug!(
                error = %err,
                service = ?service,
                operation,
                "failed to inject Datadog trace context"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_interceptor_creation() {
        let interceptor = DatadogAwsInterceptor::new();
        assert_eq!(interceptor.name(), "DatadogAwsInterceptor");
    }

    #[test]
    fn test_extract_trace_headers_empty_without_span() {
        let cx = Context::current();
        let headers = extract_trace_headers(&cx);
        assert!(headers.is_empty());
    }

    #[test]
    fn test_interceptor_default() {
        let interceptor = DatadogAwsInterceptor::default();
        assert_eq!(interceptor.name(), "DatadogAwsInterceptor");
    }
}
