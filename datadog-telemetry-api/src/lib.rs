// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! # Datadog Telemetry API
//!
//! This library provides the API to interact with the
//! [datadog-opentelemetry](https://docs.rs/datadog-opentelemetry/latest/datadog_opentelemetry/)
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
//!         cx.span().span_context(),
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
/// [datadog_opentelemetry](https://docs.rs/datadog-opentelemetry/latest/datadog_opentelemetry/)
/// and gives access to tracing features, such as the
/// sampling decisions of the live traces, without a reference to the tracer.
pub trait DatadogTelemetryApi {
    /// Applies a manual sampling decision to the trace the given span context belongs to
    ///
    /// If the trace isn't known to the tracer, the decision is ignored.
    fn set_sampling_decision(
        &self,
        span: &opentelemetry::trace::SpanContext,
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
pub fn set_sampling_decision(span: &opentelemetry::trace::SpanContext, decision: SamplingDecision) {
    let setter = DATADOG_TELEMETRY.load();
    let Some(setter) = setter.as_deref() else {
        return;
    };
    setter.set_sampling_decision(span, decision);
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use opentelemetry::trace::{SpanContext, SpanId, TraceFlags, TraceId, TraceState};

    use super::*;

    /// Records the trace id and whether the decision was a keep, for every call it receives
    struct RecordingTelemetry {
        calls: Arc<Mutex<Vec<(TraceId, bool)>>>,
    }

    impl DatadogTelemetryApi for RecordingTelemetry {
        fn set_sampling_decision(&self, span: &SpanContext, decision: SamplingDecision) {
            let is_keep = matches!(decision, SamplingDecision::Keep);
            self.calls.lock().unwrap().push((span.trace_id(), is_keep));
        }
    }

    fn span_context(trace_id: u128) -> SpanContext {
        SpanContext::new(
            TraceId::from(trace_id),
            SpanId::from(1),
            TraceFlags::SAMPLED,
            false,
            TraceState::NONE,
        )
    }

    /// The global is process-wide and `cargo test` runs tests in parallel threads of the same
    /// process, so every step touching it lives in this single test.
    #[test]
    fn test_set_sampling_decision_routes_to_the_last_global() {
        // Without a global installed, the decision is ignored
        set_sampling_decision(&span_context(1), SamplingDecision::Keep);

        let first_calls = Arc::new(Mutex::new(Vec::new()));
        set_global(RecordingTelemetry {
            calls: Arc::clone(&first_calls),
        });
        set_sampling_decision(&span_context(2), SamplingDecision::Keep);
        set_sampling_decision(&span_context(3), SamplingDecision::Drop);
        assert_eq!(
            *first_calls.lock().unwrap(),
            vec![(TraceId::from(2), true), (TraceId::from(3), false)],
            "the installed global must receive the decisions, and only the ones made after it was installed"
        );

        let second_calls = Arc::new(Mutex::new(Vec::new()));
        set_global(RecordingTelemetry {
            calls: Arc::clone(&second_calls),
        });
        set_sampling_decision(&span_context(4), SamplingDecision::Keep);
        assert_eq!(
            *second_calls.lock().unwrap(),
            vec![(TraceId::from(4), true)],
            "the replacing global must receive the decisions made after it was installed"
        );
        assert_eq!(
            first_calls.lock().unwrap().len(),
            2,
            "the replaced global must not receive any decision anymore"
        );
    }
}
