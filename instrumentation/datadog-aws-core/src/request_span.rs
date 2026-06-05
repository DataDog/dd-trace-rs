// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! AWS SDK request-span utilities shared by the service crates.
//!
//! Each service crate owns its concrete
//! [`Intercept`](aws_smithy_runtime_api::client::interceptors::Intercept) implementation and
//! uses these helpers for the common span lifecycle:
//! 1. Read [`AwsRequestMetadata`] from the SDK [`ConfigBag`].
//! 2. Start the request span with base and service-specific tags ([`start_request_span`]).
//! 3. Inject the returned propagation headers into the service request payload.
//! 4. Add HTTP-level tags once the final request is known ([`update_request_span`]).
//! 5. Record the response status and any error, then end the span ([`finish_request_span`]).

use std::collections::HashMap;
use std::fmt;

use aws_smithy_runtime_api::client::interceptors::context::{
    BeforeTransmitInterceptorContextRef, FinalizerInterceptorContextRef,
};
use aws_smithy_runtime_api::client::orchestrator::Metadata;
use aws_smithy_types::config_bag::{ConfigBag, Storable, StoreReplace};
use aws_types::region::Region;
use opentelemetry::trace::{SpanKind, Status, TraceContextExt, Tracer};
use opentelemetry::{global, Context, KeyValue};

use crate::attribute_keys::{
    AWS_AGENT, AWS_OPERATION, AWS_PARTITION, AWS_REGION, AWS_REQUEST_ID, AWS_SERVICE, HTTP_METHOD,
    HTTP_STATUS_CODE, HTTP_URL, OPERATION_NAME, RESOURCE_NAME, SPAN_KIND,
};

pub struct AwsRequestMetadata {
    pub operation: String,
    pub region: String,
    pub partition: &'static str,
    pub service: String,
}

impl AwsRequestMetadata {
    pub fn from_config_bag(cfg: &ConfigBag) -> Option<AwsRequestMetadata> {
        let metadata = cfg.load::<Metadata>()?;
        let region = cfg
            .load::<Region>()
            .map(|r| r.as_ref())
            .unwrap_or_default()
            .to_owned();
        let partition = partition_from_region(&region);

        Some(AwsRequestMetadata {
            operation: metadata.name().to_owned(),
            region,
            partition,
            service: metadata.service().to_owned(),
        })
    }
}

/// Starts the AWS request span and returns propagation headers for service-specific injection.
///
/// The span context is stored in `cfg` so [`update_request_span`] can add HTTP
/// request attributes and [`finish_request_span`] can record the response and
/// end the span in later interceptor hooks.
pub fn start_request_span(
    service_id: &'static str,
    metadata: AwsRequestMetadata,
    service_tags: impl IntoIterator<Item = KeyValue>,
    tracer: &global::BoxedTracer,
    cfg: &mut ConfigBag,
) -> HashMap<String, String> {
    let resource_name = format!("{}.{}", metadata.service, metadata.operation);
    let base_tags = [
        KeyValue::new(OPERATION_NAME, format!("aws.{service_id}.request")),
        KeyValue::new(AWS_SERVICE, metadata.service),
        KeyValue::new(AWS_OPERATION, metadata.operation),
        KeyValue::new(AWS_REGION, metadata.region),
        KeyValue::new(AWS_PARTITION, metadata.partition),
        KeyValue::new(RESOURCE_NAME, resource_name),
        KeyValue::new(SPAN_KIND, "client"),
    ];
    let parent_cx = Context::current();
    let span = tracer
        .span_builder(format!("{service_id}.request"))
        .with_kind(SpanKind::Client)
        .with_attributes(base_tags.into_iter().chain(service_tags))
        .start_with_context(tracer, &parent_cx);
    let cx = parent_cx.with_span(span);
    let trace_headers = global::get_text_map_propagator(|p| {
        let mut carrier = HashMap::new();
        p.inject_context(&cx, &mut carrier);
        carrier
    });

    cfg.interceptor_state().store_put(RequestSpanContext(cx));
    trace_headers
}

/// Adds HTTP-level tags once the final serialized request is available.
///
/// Records `http.method`, `http.url`, and `http.useragent` on the span.
pub fn update_request_span(context: &BeforeTransmitInterceptorContextRef<'_>, cfg: &mut ConfigBag) {
    let Some(span_ctx) = cfg.load::<RequestSpanContext>() else {
        return;
    };
    let span = span_ctx.0.span();
    let request = context.request();
    let method = KeyValue::new(HTTP_METHOD, request.method().to_string());
    let url = KeyValue::new(HTTP_URL, request.uri().to_string());
    let user_agent = request
        .headers()
        .get("user-agent")
        .map(|user_agent| KeyValue::new(AWS_AGENT, user_agent.to_owned()));

    span.set_attributes([Some(method), Some(url), user_agent].into_iter().flatten());
}

/// Records the response status and any SDK error, then ends the span.
pub fn finish_request_span(context: &FinalizerInterceptorContextRef<'_>, cfg: &mut ConfigBag) {
    let Some(span_ctx) = cfg.load::<RequestSpanContext>() else {
        return;
    };
    let span = span_ctx.0.span();

    if let Some(response) = context.response() {
        let status_code = KeyValue::new(HTTP_STATUS_CODE, response.status().as_u16() as i64);
        let request_id = response.headers().get("x-amzn-requestid");
        let request_id = request_id.map(|id| KeyValue::new(AWS_REQUEST_ID, id.to_owned()));
        span.set_attributes([Some(status_code), request_id].into_iter().flatten());
    }

    if let Some(Err(err)) = context.output_or_error() {
        span.set_status(Status::error(err.to_string()));
    }

    span.end();
}

/// Carries the OTel [`Context`] and active span through the SDK's [`ConfigBag`]
/// so the later interceptor hooks can update and finish the span started before
/// serialization.
struct RequestSpanContext(Context);

impl fmt::Debug for RequestSpanContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestSpanContext").finish_non_exhaustive()
    }
}

impl Storable for RequestSpanContext {
    type Storer = StoreReplace<Self>;
}

/// Derives the AWS partition identifier from a region string.
///
/// The AWS SDK for Rust does not expose partition publicly, so we infer it from
/// the region prefix. Prefixes are checked longest-first: `us-isof-` and `us-isob-`
/// must be matched before the shorter `us-iso-` prefix to avoid false positives.
fn partition_from_region(region: &str) -> &'static str {
    if region.starts_with("cn-") {
        "aws-cn"
    } else if region.starts_with("us-gov-") {
        "aws-us-gov"
    } else if region.starts_with("us-isof-") {
        "aws-iso-f"
    } else if region.starts_with("us-isob-") {
        "aws-iso-b"
    } else if region.starts_with("us-iso-") {
        "aws-iso"
    } else if region.starts_with("eu-isoe-") {
        "aws-iso-e"
    } else {
        "aws"
    }
}
