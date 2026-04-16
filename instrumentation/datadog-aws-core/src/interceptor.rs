// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt;

use aws_smithy_runtime_api::box_error::BoxError;
use aws_smithy_runtime_api::client::interceptors::context::{
    BeforeSerializationInterceptorContextMut, BeforeTransmitInterceptorContextRef,
    FinalizerInterceptorContextRef,
};
use aws_smithy_runtime_api::client::interceptors::Intercept;
use aws_smithy_runtime_api::client::orchestrator::Metadata;
use aws_smithy_runtime_api::client::runtime_components::RuntimeComponents;
use aws_smithy_types::config_bag::{ConfigBag, Storable, StoreReplace};
use aws_types::region::Region;
use opentelemetry::trace::{SpanKind, Status, TraceContextExt, Tracer};
use opentelemetry::{global, Context, KeyValue};

use crate::attribute_keys::{
    AWS_AGENT, AWS_OPERATION, AWS_PARTITION, AWS_REGION, AWS_SERVICE, COMPONENT, HTTP_METHOD,
    HTTP_STATUS_CODE, HTTP_URL, OPERATION_NAME, PARTITION_AWS, PARTITION_AWS_CN, PARTITION_AWS_GOV,
    PARTITION_AWS_ISO, PARTITION_AWS_ISO_B, PARTITION_AWS_ISO_E, PARTITION_AWS_ISO_F, RESOURCE_NAME,
    SPAN_KIND, TRACER_NAME, AWS_REQUEST_ID,
};

/// Trait implemented by each service crate to provide service-specific
/// injection logic and span tags.
pub trait ServiceHandler: Send + Sync + 'static {
    /// The AWS SDK service name as reported by the SDK metadata (e.g. `"SQS"`).
    fn sdk_service_name(&self) -> &'static str;
    /// Short identifier used in span names and `operation.name` (e.g. `"sqs"`).
    fn span_service_id(&self) -> &'static str;
    /// Inject trace context into the outbound request input for the given operation.
    /// Errors are swallowed by the caller — injection must never fail an AWS call.
    fn inject(
        &self,
        operation: &str,
        trace_headers: &HashMap<String, String>,
        input: &mut aws_smithy_runtime_api::client::interceptors::context::Input,
    ) -> Result<(), BoxError>;
    /// Return service-specific span tags for the given operation.
    fn service_tags(
        &self,
        operation: &str,
        input: &aws_smithy_runtime_api::client::interceptors::context::Input,
        region: &str,
        partition: &str,
    ) -> Vec<KeyValue>;
}

/// Generic AWS SDK interceptor that creates a Datadog span and injects trace
/// context for the service described by the provided [`ServiceHandler`].
///
/// Not intended to be used directly — each service crate exposes a named
/// wrapper type (`SqsInterceptor`, `SnsInterceptor`, `EventBridgeInterceptor`).
pub struct AwsInterceptor {
    handler: Box<dyn ServiceHandler>,
    tracer: global::BoxedTracer,
}

impl AwsInterceptor {
    pub fn new(handler: Box<dyn ServiceHandler>) -> Self {
        Self {
            tracer: global::tracer(TRACER_NAME),
            handler,
        }
    }
}

impl fmt::Debug for AwsInterceptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsInterceptor")
            .field("service", &self.handler.sdk_service_name())
            .finish_non_exhaustive()
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

fn extract_trace_headers(cx: &Context) -> HashMap<String, String> {
    global::get_text_map_propagator(|p| {
        let mut carrier = HashMap::new();
        p.inject_context(cx, &mut carrier);
        carrier
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
pub(crate) fn partition_from_region(region: &str) -> &'static str {
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

/// Base tags common to all AWS service spans.
pub(crate) fn base_tags(
    service_id: &'static str,
    sdk_service_name: &'static str,
    operation: &str,
    region: &str,
    partition: &str,
) -> Vec<KeyValue> {
    vec![
        KeyValue::new(OPERATION_NAME, format!("aws.{service_id}.request")),
        KeyValue::new(AWS_SERVICE, sdk_service_name),
        KeyValue::new(AWS_OPERATION, operation.to_owned()),
        KeyValue::new(AWS_REGION, region.to_owned()),
        KeyValue::new(AWS_PARTITION, partition.to_owned()),
        KeyValue::new(RESOURCE_NAME, format!("{sdk_service_name}.{operation}")),
        KeyValue::new(COMPONENT, TRACER_NAME),
        KeyValue::new(SPAN_KIND, "client"),
    ]
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

        // Skip span creation for services this handler doesn't own.
        if service != self.handler.sdk_service_name() {
            return Ok(());
        }

        let operation = metadata.name();
        let region = cfg.load::<Region>().map(|r| r.as_ref()).unwrap_or_default();
        let partition = partition_from_region(region);

        let service_id = self.handler.span_service_id();
        let sdk_service_name = self.handler.sdk_service_name();
        let mut tags = base_tags(service_id, sdk_service_name, operation, region, partition);
        tags.extend(
            self.handler
                .service_tags(operation, context.input(), region, partition),
        );

        let parent_cx = Context::current();
        let tracer = &self.tracer;
        let span = tracer
            .span_builder(format!("{service_id}.request"))
            .with_kind(SpanKind::Client)
            .with_attributes(tags)
            .start_with_context(tracer, &parent_cx);
        let cx = parent_cx.with_span(span);

        let trace_headers = extract_trace_headers(&cx);

        if !trace_headers.is_empty() {
            if let Err(err) =
                self.handler
                    .inject(operation, &trace_headers, context.input_mut())
            {
                tracing::debug!(
                    error = %err,
                    service = service_id,
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
