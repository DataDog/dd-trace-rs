// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Span conversion logic from Opentelemetry to Datadog

// This module is `pub` only under `test-utils` (and otherwise `pub(crate)`).
// Keep inner items `pub` so benches/tests can use them when the feature is on.
#![cfg_attr(not(feature = "test-utils"), allow(unreachable_pub))]

mod cached_config;
mod sdk_span;
mod transform;

pub(super) use cached_config::CachedConfig;
pub(super) use cached_config::VERSION_KEY;
pub(super) use sdk_span::SdkSpan;
pub use transform::otel_span_to_dd_span;
pub(super) use transform::otel_util::{
    get_dd_env, get_dd_http_status_code, get_dd_key_for_otlp_attribute, get_otel_operation_name_v2,
    get_otel_resource_v2, get_otel_service,
};
// Re-exported `pub` so they are reachable from benches/tests under the test-utils feature
// (the mappings module itself is only public in that configuration); in normal builds
// the module is `pub(crate)`, so this stays crate-visible only.
pub(crate) use transform::otel_util::OtelSpan;
pub use transform::{
    attribute_keys::{AttributeIndices, AttributeKey},
    otel_util::DEFAULT_OTLP_SERVICE_NAME,
    otel_value_string_repr, DdSpan, SpanStr,
};

#[cfg(feature = "test-utils")]
pub use transform::{semconv_shim, transform_tests};
