// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Per-thread OTel context publishing for the eBPF profiler.
//!
//! This module keeps the thread-local symbol `otel_thread_ctx_v1` (defined in [OTEP 4947: Thread
//! Context]) in sync with the OTel span that is currently active on each thread. An out-of-process
//! reader such as the Datadog eBPF profiler can then correlate CPU profiles with live traces
//! without any in-process instrumentation beyond SDK initialization.
//!
//! The integration hooks into the [`ContextObserver`] extension of `opentelemetry`. Each newly
//! created [`Context`] gets a [`DatadogContextView`] built once through
//! [`ContextObserver::make_view`], and the observer's enter/exit callbacks then publish that
//! pre-built record into the TLS slot, or detach the slot when the destination has no active span.
//!
//! The whole module is Linux-only and gated behind the `otel-thread-ctx` feature.
//!
//! [OTEP 4947: Thread Context]: https://github.com/open-telemetry/opentelemetry-specification/blob/main/oteps/profiles/4947-thread-ctx.md
//! [`ContextGuard`]: opentelemetry::ContextGuard

use std::{any::Any, sync::Arc};

use libdd_otel_thread_ctx::linux::{SharedThreadContext, ThreadContext};
use opentelemetry::{
    context::{ContextObserver, GlobalContextObserver, ObserverContextView},
    trace::TraceContextExt,
    Context,
};

use crate::{dd_warn, span_processor::TraceRegistry};

/// Observer-side view of an OTel [`Context`], stored in the context's `observer_view` slot.
///
/// It is a transparent newtype over a pre-built, immutable [`ThreadContext`]. `observer_view`
/// already stores the view behind an `Arc`, so we wrap the record directly (rather than holding an
/// `Arc<ThreadContext>`). We can then use it as a [SharedThreadContext] (see
/// [`Self::to_shared_thread_ctx`]).
///
/// The record is built at most once per [`Context`] value, when the context is created, and reused
/// on every enter/exit of that context value.
#[repr(transparent)]
struct DatadogContextView(ThreadContext);

impl DatadogContextView {
    /// Converts a [DatadogContextView] stored in the context as a `&Arc<dyn ObserverContextView>`
    /// to a [SharedThreadContext].
    ///
    /// Returns `None` if view doesn't actually contain a `DatadogContextView`, but a different
    /// implementer of `ObserverContextView`. This is a safety net and should not happen in
    /// practice.
    fn to_shared_thread_ctx(view: &Arc<dyn ObserverContextView>) -> Option<SharedThreadContext> {
        // `view` is an `Arc<dyn ObserverContextView>`. This cast should always succeed once the
        // observer is installed (we are the sole writer of this slot), but the check is cheap and
        // keeps us safe.
        let view: Arc<Self> = Arc::downcast(view.clone()).ok()?;
        let ctx_raw = Arc::into_raw(view);
        // SAFETY: `DatadogContextView` is `#[repr(transparent)]` over `ThreadContext`. The two
        // therefore have identical size and alignment, and the `Arc<_>` layout is also identical,
        // making the `into_raw` and `from_raw` interoperable.
        Some(unsafe { Arc::from_raw(ctx_raw.cast::<ThreadContext>()) }.into())
    }
}

impl ObserverContextView for DatadogContextView {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// The Datadog [`ContextObserver`]. Publishes the active span context to the TLS slot on every
/// context enter/exit.
struct DatadogContextObserver {
    registry: TraceRegistry,
}

impl DatadogContextObserver {
    fn new(registry: TraceRegistry) -> Self {
        Self { registry }
    }
}

/// Attach a context to the TLS slot to reflect `cx`'s active span, if there is one. In any case,
/// detach and drop the previously attached context (more precisely, we drop the published `Arc`
/// copy of the [ThreadContext]).
fn publish(cx: &Context) {
    let thread_ctx = cx
        .observer_view()
        .as_ref()
        .and_then(DatadogContextView::to_shared_thread_ctx);

    // We drop the previously attached context, decrementing the refcount. The `Context` owning it
    // keeps its own reference, so the record stays alive for as long as that context does.
    let _ = if let Some(thread_ctx) = thread_ctx {
        thread_ctx.attach()
    } else {
        SharedThreadContext::detach()
    };
}

impl ContextObserver for DatadogContextObserver {
    fn on_context_enter(&self, _from: &Context, to: &Context) {
        publish(to);
    }

    fn on_context_exit(&self, _from: &Context, to: &Context) {
        // On exit, `to` is the outer context we are returning to: restore its span if any, and
        // detach `_from`.
        publish(to);
    }

    /// Builds the thread context record for a newly created [`Context`]. Returns `None` when `cx`
    /// has no valid span, in which case entering `cx` detaches the current thread context.
    fn make_view(&self, cx: &Context) -> Option<Arc<dyn ObserverContextView>> {
        let span = cx.span();
        let span_ctx = span.span_context();

        if !span_ctx.is_valid() {
            return None;
        }

        let trace_id = span_ctx.trace_id().to_bytes();
        let span_id = span_ctx.span_id().to_bytes();

        // If the local root span isn't registered yet (e.g. a freshly extracted remote context,
        // before the first local child span starts), we could fall back to the current span id,
        // hoping that the context created for the first local span will carry the correct local
        // root span id.
        //
        // However, no local root span happens in case of:
        //
        // - double initialization of the the global tracer and the observer (we don't support)
        // - dropped local root spans (we don't record)
        // - a new remote context (which shouldn't have the span from the remote service as the
        //   local root).
        //
        // Those cases are pathological (they can happen but we aren't expected to operate normally
        // in these conditions). In the case of the double init, the proposed fallback would make
        // _all the spans_ as local roots, which could be a problem. We default to not publishing
        // such spans without root span id associated (by giving them a `None` view) instead.
        // Missing data is the lesser evil.
        let local_root_span_id = self.registry.get_local_root_span_id(trace_id)?;

        Some(Arc::new(DatadogContextView(ThreadContext::new(
            trace_id,
            span_id,
            span_ctx.trace_flags().to_u8(),
            local_root_span_id,
            &[],
        ))))
    }
}

/// Register the Datadog context observer globally.
///
/// **Must be called only once** during SDK initialization, before any span is started. Because
/// [`GlobalContextObserver`] is backed by a `OnceLock`, subsequent calls are silently ignored (with
/// a warning log).
///
/// If called multiple times, the old trace registry will be used for resolution, leading to missing
/// data. The current behavior of the observer will then be to ignore spans, effectively disabling
/// OTel thread context sharing (though the behavior in case of multiple installation is an
/// implementation detail that might change in the future).
pub(crate) fn install_observer(registry: TraceRegistry) {
    use std::sync::atomic::{AtomicBool, Ordering};

    if let Err(e) = libdd_otel_thread_ctx::sanity_check::sanity_check() {
        dd_warn!(
            "OTel thread context: this binary may not expose its context to external readers properly. Thread context sharing requires a custom build step that appears to be missing; please refer to dd-trace-rs's README (sanity check failed: {e})"
        );
    }

    static IS_INIT: AtomicBool = AtomicBool::new(false);

    if IS_INIT.swap(true, Ordering::Relaxed) {
        dd_warn!(
            "Multiple initializations of the global tracer detected. This mode is not supported: the tracer should only be initialized once globally."
        );
    } else {
        GlobalContextObserver::set(Arc::new(DatadogContextObserver::new(registry)));
    }
}

#[cfg(test)]
mod tests {
    use opentelemetry::trace::{
        Span, SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState, Tracer,
        TracerProvider,
    };
    use opentelemetry_sdk::trace::SdkTracerProvider;

    use super::*;
    use crate::Config;

    fn registry() -> TraceRegistry {
        TraceRegistry::new(Arc::new(Config::builder().build()))
    }

    /// Starts the first local span of a trace with a real SDK tracer, under a freshly extracted
    /// remote context, and registers it as the local root of the trace. This mirrors what
    /// `DatadogSpanProcessor::on_start` does when a local span starts with a remote parent: the
    /// span becomes the local root and is registered in the trace registry, making it (and its
    /// children) publishable to the OTel thread context.
    fn start_local_root_span(
        tracer: &opentelemetry_sdk::trace::Tracer,
        registry: &TraceRegistry,
        trace_id: TraceId,
    ) -> opentelemetry_sdk::trace::Span {
        let remote_parent_cx = Context::new().with_remote_span_context(SpanContext::new(
            trace_id,
            SpanId::from(0x9988_7766_5544_3322),
            TraceFlags::SAMPLED,
            true,
            TraceState::default(),
        ));
        let span = tracer.start_with_context("local-root", &remote_parent_cx);
        registry.register_local_root_span(
            trace_id.to_bytes(),
            span.span_context().span_id().to_bytes(),
        );
        span
    }

    #[test]
    fn make_view_skips_contexts_without_a_valid_span() {
        let observer = DatadogContextObserver::new(registry());
        assert!(observer.make_view(&Context::new()).is_none());
    }

    /// A freshly extracted remote context has no local root registered (there is no local span
    /// yet), so it must not get a view.
    #[test]
    fn make_view_skips_remote_contexts_without_a_local_root() {
        let observer = DatadogContextObserver::new(registry());
        let remote_cx = Context::new().with_remote_span_context(SpanContext::new(
            TraceId::from(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10),
            SpanId::from(0x1122_3344_5566_7788),
            TraceFlags::SAMPLED,
            true,
            TraceState::default(),
        ));
        assert!(observer.make_view(&remote_cx).is_none());
    }

    #[test]
    fn make_view_builds_a_downcastable_view_for_a_local_span() {
        let registry = registry();
        let observer = DatadogContextObserver::new(registry.clone());
        let provider = SdkTracerProvider::builder().build();
        let tracer = provider.tracer("thread-ctx-tests");

        let cx = Context::current_with_span(start_local_root_span(
            &tracer,
            &registry,
            TraceId::from(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10),
        ));

        let view = observer
            .make_view(&cx)
            .expect("a context with a local span must get a view");
        assert!(DatadogContextView::to_shared_thread_ctx(&view).is_some());
    }

    /// `install_observer` sets a process-global `OnceLock` and `publish` writes to a thread-local
    /// slot, so this test relies on `nextest` running each test in its own process.
    #[test]
    fn publish_attaches_then_detaches_the_tls_slot() {
        let registry = registry();
        install_observer(registry.clone());
        let provider = SdkTracerProvider::builder().build();
        let tracer = provider.tracer("thread-ctx-tests");

        // Building the context with an active local span is what triggers the (global) observer
        // to build the view that `publish` then attaches to the TLS slot.
        let cx = Context::current_with_span(start_local_root_span(
            &tracer,
            &registry,
            TraceId::from(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10),
        ));

        publish(&cx);
        assert!(
            SharedThreadContext::detach().is_some(),
            "a context with a local span must attach a record"
        );

        // Entering a context without a span retracts whatever was attached.
        publish(&Context::new());
        assert!(
            SharedThreadContext::detach().is_none(),
            "a context without a span must leave the slot empty"
        );
    }
}
