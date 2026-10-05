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

use crate::span_processor::TraceRegistry;

/// Observer-side view of an OTel [`Context`], stored in the context's `observer_view` slot.
///
/// It is a transparent newtype over a pre-built, immutable [`ThreadContext`]. `observer_view`
/// already stores the view behind an `Arc`, so wrapping the record directly (rather than holding an
/// `Arc<ThreadContext>`). We can then use it as a [SharedThreadContext] directly (see
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
        // before the first local child span starts), fall back to the current span id. The context
        // created for the first local span will carry the correct local root span id.
        let local_root_span_id = self
            .registry
            .get_local_root_span_id(trace_id)
            .unwrap_or(span_id);

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
/// Must be called once, during SDK initialization, before any span is started. Because
/// [`GlobalContextObserver`] is backed by a `OnceLock`, subsequent calls are silently ignored
/// (with an `opentelemetry` warning log).
pub(crate) fn install_observer(registry: TraceRegistry) {
    GlobalContextObserver::set(Arc::new(DatadogContextObserver::new(registry)));
}

#[cfg(test)]
mod tests {
    use opentelemetry::trace::{SpanContext, SpanId, TraceFlags, TraceId, TraceState};

    use super::*;
    use crate::Config;

    fn registry() -> TraceRegistry {
        TraceRegistry::new(Arc::new(Config::builder().build()))
    }

    /// A context carrying a valid (remote) span context. Going through
    /// [`TraceContextExt::with_remote_span_context`] is what populates the observer view, so this
    /// exercises the same creation path as a locally started span.
    fn cx_with_span() -> Context {
        Context::new().with_remote_span_context(SpanContext::new(
            TraceId::from(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10),
            SpanId::from(0x1122_3344_5566_7788),
            TraceFlags::SAMPLED,
            true,
            TraceState::default(),
        ))
    }

    #[test]
    fn make_view_skips_contexts_without_a_valid_span() {
        let observer = DatadogContextObserver::new(registry());
        assert!(observer.make_view(&Context::new()).is_none());
    }

    #[test]
    fn make_view_builds_a_downcastable_view() {
        let observer = DatadogContextObserver::new(registry());
        let view = observer
            .make_view(&cx_with_span())
            .expect("a context with a valid span must get a view");
        assert!(DatadogContextView::to_shared_thread_ctx(&view).is_some());
    }

    /// `install_observer` sets a process-global `OnceLock` and `publish` writes to a thread-local
    /// slot, so this test relies on `nextest` running each test in its own process.
    #[test]
    fn publish_attaches_then_detaches_the_tls_slot() {
        install_observer(registry());

        publish(&cx_with_span());
        assert!(
            SharedThreadContext::detach().is_some(),
            "a context with a span must attach a record"
        );

        // Entering a context without a span retracts whatever was attached.
        publish(&cx_with_span());
        publish(&Context::new());
        assert!(
            SharedThreadContext::detach().is_none(),
            "a context without a span must leave the slot empty"
        );
    }
}
