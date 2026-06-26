// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Per-thread OTel context publishing for the eBPF profiler.
//!
//! This module keeps the per-thread `otel_thread_ctx_v1` TLS slot (defined in [OTEP #4947]) in sync
//! with the OTel span that is currently active on each thread. An out-of-process reader such as the
//! Datadog eBPF profiler can then correlate CPU profiles with live traces without any in-process
//! instrumentation beyond SDK initialization.
//!
//! The integration hooks into the [`ContextObserver`] extension of `opentelemetry`, which fires a
//! callback on every context push/pop (i.e. every [`ContextGuard`] enter/exit). On each switch we
//! publish the destination context's pre-built record into the TLS slot, or detach the slot when
//! the destination has no active span.
//!
//! The whole module is Linux-only and gated behind the `profiling-thread-ctx` feature.
//!
//! [OTEP #4947]: https://github.com/open-telemetry/opentelemetry-specification/pull/4947
//! [`ContextGuard`]: opentelemetry::ContextGuard

use std::any::Any;
use std::sync::Arc;

use libdd_otel_thread_ctx::linux::{SharedThreadContext, ThreadContext};
use opentelemetry::{
    context::{ContextObserver, GlobalContextObserver, ObserverContextView},
    trace::TraceContextExt,
    Context,
};

use crate::span_processor::TraceRegistry;

/// Observer-side view of an OTel [`Context`], cached in the context's `observer_cx_view` slot.
///
/// It is a transparent newtype over a pre-built, immutable [`ThreadContext`]. `observer_cx_view`
/// already stores the view behind an `Arc`, so wrapping the record directly (rather than holding
/// an inner `Arc<ThreadContext>`) means a single heap allocation per [`Context`] value: that same
/// allocation is reused as the [`SharedThreadContext`] published to the TLS slot (see
/// [`view_thread_ctx`]).
///
/// On every context switch the `Arc` is cloned (a single atomic increment) and its record pointer
/// is swapped into the thread's TLS slot — no trace/span data is copied on the hot path. The
/// record is built at most once per [`Context`] value, on the first `on_context_enter`, and reused
/// on every subsequent re-entry into the same context value.
#[repr(transparent)]
struct DatadogContextView(ThreadContext);

impl ObserverContextView for DatadogContextView {}

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

/// Returns the `Arc<ThreadContext>` to attach for `cx`, building and caching it in the context's
/// `observer_cx_view` slot on first use. Returns `None` when `cx` has no valid span — in that case
/// the caller should detach the TLS slot.
fn view_thread_ctx(cx: &Context, registry: &TraceRegistry) -> Option<Arc<ThreadContext>> {
    let span = cx.span();
    let span_ctx = span.span_context();
    if !span_ctx.is_valid() {
        return None;
    }
    let trace_id = span_ctx.trace_id().to_bytes();
    let span_id = span_ctx.span_id().to_bytes();

    let view = cx.observer_cx_view().get_or_init(|| {
        // If the local root span isn't registered yet (e.g. a freshly extracted remote context,
        // before the first local child span starts), fall back to the current span id. The next
        // context enter for the first local span will carry the correct local root span id.
        let local_root_span_id = registry.get_local_root_span_id(trace_id).unwrap_or(span_id);
        let view: Arc<dyn ObserverContextView> = Arc::new(DatadogContextView(ThreadContext::new(
            trace_id,
            span_id,
            local_root_span_id,
            &[],
        )));
        view
    });

    // `view` is an `Arc<dyn ObserverContextView>`. Confirm it really points at our concrete type
    // before reinterpreting the allocation. This is always the case once the observer is installed
    // (we are the sole writer of this slot), but the check is cheap and keeps the cast honest.
    (view.as_ref() as &dyn Any).downcast_ref::<DatadogContextView>()?;

    // Reuse the view's own allocation as the `Arc<ThreadContext>` to attach, avoiding a second
    // allocation. Cloning bumps the strong count to balance the reference we hand out.
    //
    // SAFETY: the slot holds a `DatadogContextView` (checked above), which is `#[repr(transparent)]`
    // over `ThreadContext`. The two therefore have identical size and alignment, so the `Arc`
    // refcount header lives at the same offset and `Arc::<ThreadContext>::from_raw` reclaims the
    // very allocation `Arc::into_raw` produced. Casting the `dyn ObserverContextView` fat pointer
    // to a thin `*const ThreadContext` yields the record's data address.
    let record = Arc::into_raw(Arc::clone(view)) as *const ThreadContext;
    Some(unsafe { Arc::from_raw(record) })
}

/// Publish (or detach) the TLS slot to reflect `cx`'s active span.
fn publish(cx: &Context, registry: &TraceRegistry) {
    match view_thread_ctx(cx, registry) {
        // Cloning the `Arc` bumps the refcount; `attach` moves that reference into the TLS slot
        // and returns the previously attached context, which we drop immediately (decrementing the
        // outgoing context's refcount — its cached `DatadogContextView` keeps the record alive).
        Some(thread_ctx) => {
            let _ = SharedThreadContext::from(thread_ctx).attach();
        }
        // No active span in the destination context → clear the slot.
        None => {
            let _ = SharedThreadContext::detach();
        }
    }
}

impl ContextObserver for DatadogContextObserver {
    fn on_context_enter(&self, _from: &Context, to: &Context) {
        publish(to, &self.registry);
    }

    fn on_context_exit(&self, _from: &Context, to: &Context) {
        // On exit, `to` is the outer context we are returning to: restore its span (or detach).
        publish(to, &self.registry);
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
