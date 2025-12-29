// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Span conversion logic from Opentelemetry to Datadog

mod cached_config;
mod sdk_span;
mod transform;

pub(super) use cached_config::CachedConfig;
pub(super) use cached_config::VERSION_KEY;
pub(super) use sdk_span::SdkSpan;
pub use transform::otel_span_to_dd_span;
pub(super) use transform::otel_util::{
    get_dd_key_for_otlp_attribute, get_otel_env, get_otel_operation_name_v2, get_otel_resource_v2,
    get_otel_service, get_otel_status_code,
};
pub(super) use transform::{
    attribute_keys::{AttributeIndices, AttributeKey},
    otel_util::{OtelSpan, DEFAULT_OTLP_SERVICE_NAME},
    DdSpan, SpanStr,
};

#[cfg(feature = "test-utils")]
pub use transform::{semconv_shim, transform_tests};
