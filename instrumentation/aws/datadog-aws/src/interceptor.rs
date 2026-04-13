// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use aws_smithy_runtime_api::box_error::BoxError;
use aws_smithy_runtime_api::client::interceptors::context::{
    BeforeDeserializationInterceptorContextRef, BeforeSerializationInterceptorContextMut,
    BeforeTransmitInterceptorContextRef, FinalizerInterceptorContextRef,
};
use aws_smithy_runtime_api::client::interceptors::Intercept;
use aws_smithy_runtime_api::client::orchestrator::Metadata;
use aws_smithy_runtime_api::client::runtime_components::RuntimeComponents;
use aws_smithy_types::config_bag::{ConfigBag, Storable, StoreReplace};
use aws_types::region::Region;
use opentelemetry::trace::{SpanKind, Status, TraceContextExt, Tracer};
use opentelemetry::{global, Context, KeyValue};

use crate::attribute_keys::{
    AWS_AGENT, AWS_REQUEST_ID, HTTP_METHOD, HTTP_STATUS_CODE, HTTP_URL, PARTITION_AWS,
    PARTITION_AWS_CN, PARTITION_AWS_GOV, PARTITION_AWS_ISO, PARTITION_AWS_ISO_B,
    PARTITION_AWS_ISO_E, PARTITION_AWS_ISO_F, TRACER_NAME,
};
use crate::services::{base_tags, AwsService};

/// AWS SDK interceptor that injects Datadog trace context into messaging payloads
/// and creates spans representing managed service operations.
///
/// # Example
///
/// ```rust,ignore
/// use datadog_aws_sdk::AwsInterceptor;
///
/// let sqs_config = aws_sdk_sqs::config::Builder::from(&sdk_config)
///     .interceptor(AwsInterceptor::new())
///     .build();
/// let sqs_client = aws_sdk_sqs::Client::from_conf(sqs_config);
/// ```
#[derive(Debug, Clone)]
pub struct AwsInterceptor {}

impl AwsInterceptor {
    /// Creates a new [`AwsInterceptor`].
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for AwsInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

// Stores the OTel Context (which owns the active span) in ConfigBag so it can
// be accessed across interceptor hooks for the same request.
struct SpanContext(Context);

impl fmt::Debug for SpanContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpanContext").finish_non_exhaustive()
    }
}

impl Storable for SpanContext {
    type Storer = StoreReplace<Self>;
}

struct PropagatorCarrier(std::collections::HashMap<String, String>);

impl opentelemetry::propagation::Injector for PropagatorCarrier {
    fn set(&mut self, key: &str, value: String) {
        self.0.insert(key.to_string(), value);
    }
}

fn extract_trace_headers(cx: &Context) -> std::collections::HashMap<String, String> {
    global::get_text_map_propagator(|p| {
        let mut carrier = PropagatorCarrier(std::collections::HashMap::new());
        p.inject_context(cx, &mut carrier);
        carrier.0
    })
}

fn set_response_tags(
    span: &opentelemetry::trace::SpanRef<'_>,
    response: &aws_smithy_runtime_api::http::Response,
) {
    span.set_attribute(KeyValue::new(
        HTTP_STATUS_CODE,
        response.status().as_u16() as i64,
    ));
    if let Some(request_id) = response.headers().get("x-amzn-requestid") {
        span.set_attribute(KeyValue::new(AWS_REQUEST_ID, request_id.to_owned()));
    }
}

// The AWS SDK for Rust does not expose partition publicly, so we derive it from the region prefix.
// Longest-prefix-first: us-isof- and us-isob- must be checked before the shorter us-iso- prefix.
fn partition_from_region(region: &str) -> &'static str {
    if region.starts_with("cn-") {
        PARTITION_AWS_CN
    } else if region.starts_with("us-gov-") {
        PARTITION_AWS_GOV
    } else if region.starts_with("us-isof-") {
        PARTITION_AWS_ISO_F
    } else if region.starts_with("us-isob-") {
        PARTITION_AWS_ISO_B
    } else if region.starts_with("us-iso-") {
        PARTITION_AWS_ISO
    } else if region.starts_with("eu-isoe-") {
        PARTITION_AWS_ISO_E
    } else {
        PARTITION_AWS
    }
}

impl Intercept for AwsInterceptor {
    fn name(&self) -> &'static str {
        "AwsInterceptor"
    }

    fn modify_before_serialization(
        &self,
        context: &mut BeforeSerializationInterceptorContextMut<'_>,
        _runtime_components: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        let Some(metadata) = cfg.load::<Metadata>() else {
            return Ok(());
        };
        let service = metadata.service();
        let operation = metadata.name();
        let region = cfg.load::<Region>().map(|r| r.as_ref()).unwrap_or_default();
        let partition = partition_from_region(region);

        // Resolve the service handler; skip span creation for unsupported services.
        let Some(handler) = AwsService::from_sdk_service(service) else {
            return Ok(());
        };
        let service_id = handler.span_service_id();
        let sdk_service_name = handler.sdk_service_name();
        let mut tags = base_tags(service_id, sdk_service_name, operation, region, partition);
        tags.extend(handler.service_tags(operation, context.input(), region, partition));

        // Create the span as a child of the current context. This must happen
        // before extracting trace headers so the injected context points to
        // this span, not the caller's span.
        let parent_cx = Context::current();
        let tracer = global::tracer(TRACER_NAME);
        let span = tracer
            .span_builder(format!("{service_id}.request"))
            .with_kind(SpanKind::Client)
            .with_attributes(tags)
            .start_with_context(&tracer, &parent_cx);
        let cx = parent_cx.with_span(span);

        // Extract trace headers from the new span's context so downstream
        // services see this span as their parent.
        let trace_headers = extract_trace_headers(&cx);

        // Swallow injection errors - trace propagation must never fail the AWS call.
        if !trace_headers.is_empty() {
            if let Err(err) = handler.inject(operation, &trace_headers, context.input_mut()) {
                tracing::debug!(
                    error = %err,
                    service = handler.span_service_id(),
                    operation,
                    "failed to inject Datadog trace context"
                );
            }
        }

        cfg.interceptor_state().store_put(SpanContext(cx));
        Ok(())
    }

    fn read_before_transmit(
        &self,
        context: &BeforeTransmitInterceptorContextRef<'_>,
        _runtime_components: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        let Some(span_ctx) = cfg.load::<SpanContext>() else {
            return Ok(());
        };
        let span = span_ctx.0.span();
        let request = context.request();
        span.set_attribute(KeyValue::new(HTTP_METHOD, request.method().to_string()));
        span.set_attribute(KeyValue::new(HTTP_URL, request.uri().to_string()));
        if let Some(user_agent) = request.headers().get("user-agent") {
            span.set_attribute(KeyValue::new(AWS_AGENT, user_agent.to_owned()));
        }
        Ok(())
    }

    fn read_after_transmit(
        &self,
        context: &BeforeDeserializationInterceptorContextRef<'_>,
        _runtime_components: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        let Some(span_ctx) = cfg.load::<SpanContext>() else {
            return Ok(());
        };
        set_response_tags(&span_ctx.0.span(), context.response());
        Ok(())
    }

    fn read_after_execution(
        &self,
        context: &FinalizerInterceptorContextRef<'_>,
        _runtime_components: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        let Some(span_ctx) = cfg.load::<SpanContext>() else {
            return Ok(());
        };
        let span = span_ctx.0.span();

        // Re-set response tags to cover cases where read_after_transmit did not run
        // (e.g. the request failed before transmission or was retried with a different response).
        if let Some(response) = context.response() {
            set_response_tags(&span, response);
        }

        if let Some(Err(err)) = context.output_or_error() {
            span.set_status(Status::error(err.to_string()));
        }

        span.end();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_no_trace_headers_without_active_span() {
        let cx = Context::current();
        let headers = extract_trace_headers(&cx);
        assert!(headers.is_empty());
    }

    #[test]
    fn partition_from_region_standard() {
        assert_eq!(partition_from_region("us-east-1"), PARTITION_AWS);
        assert_eq!(partition_from_region("eu-west-1"), PARTITION_AWS);
        assert_eq!(partition_from_region("ap-southeast-2"), PARTITION_AWS);
    }

    #[test]
    fn partition_from_region_china() {
        assert_eq!(partition_from_region("cn-north-1"), PARTITION_AWS_CN);
        assert_eq!(partition_from_region("cn-northwest-1"), PARTITION_AWS_CN);
    }

    #[test]
    fn partition_from_region_govcloud() {
        assert_eq!(partition_from_region("us-gov-east-1"), PARTITION_AWS_GOV);
        assert_eq!(partition_from_region("us-gov-west-1"), PARTITION_AWS_GOV);
    }

    #[test]
    fn partition_from_region_isolated() {
        assert_eq!(partition_from_region("us-iso-east-1"), PARTITION_AWS_ISO);
        assert_eq!(partition_from_region("us-iso-west-1"), PARTITION_AWS_ISO);
        assert_eq!(partition_from_region("us-isob-east-1"), PARTITION_AWS_ISO_B);
        assert_eq!(
            partition_from_region("us-isof-south-1"),
            PARTITION_AWS_ISO_F
        );
        assert_eq!(partition_from_region("eu-isoe-west-1"), PARTITION_AWS_ISO_E);
    }
}
