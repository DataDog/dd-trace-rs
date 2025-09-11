// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

mod cached_config;
mod sdk_span;
mod transform;

pub use cached_config::CachedConfig;
pub use cached_config::VERSION_KEY;
pub use sdk_span::SdkSpan;
pub use transform::otel_util::{
    get_dd_key_for_otlp_attribute, get_otel_env, get_otel_operation_name_v2, get_otel_resource_v2,
    get_otel_service, get_otel_status_code,
};
pub use transform::{
    attribute_keys::{AttributeIndices, AttributeKey},
    otel_span_to_dd_span,
    otel_util::{OtelSpan, DEFAULT_OTLP_SERVICE_NAME},
};

#[cfg(feature = "test-utils")]
pub use transform::transform_tests;

// Exposed for testing in the sampler
pub use transform::semconv;
pub use transform::semconv_shim;
