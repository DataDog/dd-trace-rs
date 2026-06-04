// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Generic AWS SDK interceptor and supporting utilities shared by all service crates.
//!
//! [`AwsInterceptor`] hooks into the AWS SDK for Rust request pipeline via the
//! [`Intercept`] trait. For each request it:
//! 1. Creates a Datadog client span with base + service-specific tags
//!    (`modify_before_serialization`).
//! 2. Injects propagation headers into the outbound request payload via the [`ServiceHandler`]
//!    implementation (`modify_before_serialization`).
//! 3. Adds HTTP-level tags once the final request is known (`read_before_transmit`).
//! 4. Records the response status and any error, then ends the span (`read_after_execution`).
//!
//! The [`SpanContext`] type ferries the active OTel [`Context`] through the
//! SDK's [`ConfigBag`] between hooks.

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
    AWS_AGENT, AWS_OPERATION, AWS_PARTITION, AWS_REGION, AWS_REQUEST_ID, AWS_SERVICE, HTTP_METHOD,
    HTTP_STATUS_CODE, HTTP_URL, OPERATION_NAME, PARTITION_AWS, PARTITION_AWS_CN, PARTITION_AWS_GOV,
    PARTITION_AWS_ISO, PARTITION_AWS_ISO_B, PARTITION_AWS_ISO_E, PARTITION_AWS_ISO_F,
    RESOURCE_NAME, SPAN_KIND,
};

/// Trait implemented by each service crate to provide service-specific
/// injection logic and span tags.
pub trait ServiceHandler: Send + Sync + 'static {
    /// The AWS SDK service name as reported by the SDK metadata (e.g. `"SQS"`).
    fn sdk_service_name(&self) -> &'static str;
    /// Short identifier used in span names and `operation.name` (e.g. `"sqs"`).
    fn span_service_id(&self) -> &'static str;
    /// Inject trace context into the outbound request input.
    /// Errors are swallowed by the caller — injection must never fail an AWS call.
    fn inject(
        &self,
        trace_headers: &HashMap<String, String>,
        input: &mut aws_smithy_runtime_api::client::interceptors::context::Input,
    ) -> Result<(), BoxError>;
    /// Return service-specific span tags for the given operation input.
    fn service_tags(
        &self,
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
pub struct AwsInterceptor<H: ServiceHandler> {
    handler: H,
    tracer: global::BoxedTracer,
}

impl<H: ServiceHandler> AwsInterceptor<H> {
    /// Creates a new interceptor delegating service-specific behaviour to `handler`,
    /// using `tracer_name` as the OTel tracer scope name.
    pub fn new(handler: H, tracer_name: &'static str) -> Self {
        Self {
            tracer: global::tracer(tracer_name),
            handler,
        }
    }
}

impl<H: ServiceHandler> fmt::Debug for AwsInterceptor<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsInterceptor")
            .field("service", &self.handler.sdk_service_name())
            .finish_non_exhaustive()
    }
}

/// Carries the OTel [`Context`] (and its active span) through the SDK's [`ConfigBag`]
/// so that `modify_before_serialization`, `read_before_transmit`, and
/// `read_after_execution` can all operate on the same span.
struct SpanContext(Context);

impl fmt::Debug for SpanContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpanContext").finish_non_exhaustive()
    }
}

impl Storable for SpanContext {
    type Storer = StoreReplace<Self>;
}

/// Serialises the active span's trace context into a carrier map using the global propagator.
///
/// Keys depend on the configured propagator — e.g. W3C TraceContext produces
/// `traceparent`/`tracestate`, Datadog produces `x-datadog-trace-id` etc.
/// Returns an empty map when there is no active span.
fn extract_trace_headers(cx: &Context) -> HashMap<String, String> {
    global::get_text_map_propagator(|p| {
        let mut carrier = HashMap::new();
        p.inject_context(cx, &mut carrier);
        carrier
    })
}

/// Adds HTTP response tags to `span`: status code and, when present, the AWS request ID.
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

/// Derives the AWS partition identifier from a region string.
///
/// The AWS SDK for Rust does not expose partition publicly, so we infer it from
/// the region prefix. Prefixes are checked longest-first: `us-isof-` and `us-isob-`
/// must be matched before the shorter `us-iso-` prefix to avoid false positives.
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

/// Builds the set of span tags shared by every AWS service span.
///
/// Includes `operation.name`, `aws.service`, `aws.operation`, `aws.region`,
/// `aws.partition`, `resource.name`, and `span.kind`.
/// Service crates extend this list with their own tags via [`ServiceHandler::service_tags`].
pub(crate) fn base_tags(
    service_id: &'static str,
    sdk_service_name: &'static str,
    operation: &str,
    region: &str,
    partition: &'static str,
) -> Vec<KeyValue> {
    vec![
        KeyValue::new(OPERATION_NAME, format!("aws.{service_id}.request")),
        KeyValue::new(AWS_SERVICE, sdk_service_name),
        KeyValue::new(AWS_OPERATION, operation.to_owned()),
        KeyValue::new(AWS_REGION, region.to_owned()),
        KeyValue::new(AWS_PARTITION, partition),
        KeyValue::new(RESOURCE_NAME, format!("{sdk_service_name}.{operation}")),
        KeyValue::new(SPAN_KIND, "client"),
    ]
}

impl<H: ServiceHandler> Intercept for AwsInterceptor<H> {
    fn name(&self) -> &'static str {
        "AwsInterceptor"
    }

    /// Creates the Datadog span and injects trace context into the request payload.
    ///
    /// Called before the SDK serializes the request, so the input is still mutable.
    /// The created [`SpanContext`] is stashed in `cfg` for the later hooks.
    /// Injection errors are logged at `debug` level and swallowed — they must never
    /// fail the underlying AWS call.
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
                .service_tags(context.input(), region, partition),
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
            if let Err(err) = self.handler.inject(&trace_headers, context.input_mut()) {
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

    /// Adds HTTP-level tags once the final serialized request is available.
    ///
    /// Records `http.method`, `http.url`, and `http.useragent` on the span.
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

    /// Records the response status and any SDK error, then ends the span.
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
