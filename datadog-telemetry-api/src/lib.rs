// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! # Datadog Telemetry API
//!
//! This library provides the API to interact with the
//! [datadog-opentelemetry](https://docs.rs/datadog-opentelemetry/0.5.3/datadog_opentelemetry/)
//! library at runtime, without depending on the full crate and the SDK implementation.
//!
//! This library is made to work in tandem with the [`opentelemetry`] crate, extending the API
//! with features not implementable in the Otel model.
//!
//! ## Usage
//!
//! The tracing libraries implement [`DatadogTelemetryApi`] and install a global instance with
//! [`set_global`], so the API can be used from anywhere in the code, without a reference to the
//! tracer
//!
//! ```rust ,no_run
//! use opentelemetry::global;
//! use opentelemetry::trace::{TraceContextExt, Tracer};
//!
//! // `datadog_opentelemetry::tracing().init()` installs the global telemetry automatically
//! global::tracer("my-service").in_span("my-operation", |cx| {
//!     datadog_telemetry_api::set_sampling_decision(
//!         cx.span().span_context().clone(),
//!         datadog_telemetry_api::SamplingDecision::Keep,
//!     );
//! });
//! ```
//!
//! The decision is applied to the trace the span belongs to: a kept trace is exported with a
//! USER_KEEP sampling priority, a dropped one with USER_REJECT.

#![deny(missing_docs)]

use std::sync::Arc;

use arc_swap::ArcSwapOption;

/// A manual sampling decision to apply to a trace
pub enum SamplingDecision {
    /// The trace is kept, with a USER_KEEP sampling priority.
    Keep,
    /// The trace is dropped, with a USER_REJECT sampling priority.
    Drop,
}

/// Runtime interaction with the Datadog tracing libraries
///
/// It is implemented by
/// [datadog_opentelemetry](https://docs.rs/datadog-opentelemetry/0.5.3/datadog_opentelemetry/)
/// and gives access to tracing features, such as the
/// sampling decisions of the live traces, without a reference to the tracer.
pub trait DatadogTelemetryApi {
    /// Applies a manual sampling decision to the trace the given span context belongs to
    ///
    /// If the trace isn't known to the tracer, the decision is ignored.
    fn set_sampling_decision(
        &self,
        span: opentelemetry::trace::SpanContext,
        decision: SamplingDecision,
    );
}

static DATADOG_TELEMETRY: ArcSwapOption<Box<dyn DatadogTelemetryApi + Sync + Send>> =
    ArcSwapOption::const_empty();

/// Sets the process-global implementation of [`DatadogTelemetryApi`]
///
/// It replaces the previously installed implementation, if any.
/// This should be called during initialization.
pub fn set_global<T: DatadogTelemetryApi + Sync + Send + 'static>(global: T) {
    DATADOG_TELEMETRY.swap(Some(Arc::new(Box::new(global))));
}

/// Applies a manual sampling decision to the trace the given span context belongs to, through the
/// process-global implementation of [`DatadogTelemetryApi`] installed by [`set_global`]
///
/// Does nothing while no implementation has been installed.
pub fn set_sampling_decision(span: opentelemetry::trace::SpanContext, decision: SamplingDecision) {
    let setter = DATADOG_TELEMETRY.load();
    let Some(setter) = setter.as_deref() else {
        return;
    };
    setter.set_sampling_decision(span, decision);
}
