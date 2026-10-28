use std::sync::Arc;

use arc_swap::ArcSwapOption;

pub enum SamplingDecision {
    Keep,
    Drop,
}

pub trait DatadogTelemetryApi {
    fn set_sampling_decision(
        &self,
        span: opentelemetry::trace::SpanContext,
        decision: SamplingDecision,
    );
}

static DATADOG_TELEMETRY: ArcSwapOption<Box<dyn DatadogTelemetryApi + Sync + Send>> =
    ArcSwapOption::const_empty();

pub fn set_global<T: DatadogTelemetryApi + Sync + Send + 'static>(global: T) {
    DATADOG_TELEMETRY.swap(Some(Arc::new(Box::new(global))));
}

pub fn set_sampling_decision(span: opentelemetry::trace::SpanContext, decision: SamplingDecision) {
    let setter = DATADOG_TELEMETRY.load();
    let Some(setter) = setter.as_deref() else {
        return;
    };
    setter.set_sampling_decision(span, decision);
}
