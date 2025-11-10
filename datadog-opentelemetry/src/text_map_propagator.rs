// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, sync::Arc};

use dd_trace::{catch_panic, sampling::priority, Config};
use opentelemetry::{
    propagation::{text_map_propagator::FieldIter, TextMapPropagator},
    trace::TraceContextExt,
};

use dd_trace_propagation::{
    context::{InjectSpanContext, InjectTraceState, Sampling, SpanContext, SpanLink},
    DatadogCompositePropagator,
};

use crate::TraceRegistry;

pub(crate) const TRACE_FLAG_DEFERRED: opentelemetry::TraceFlags =
    opentelemetry::TraceFlags::new(0x02);

#[derive(Clone, Default, Debug)]
pub struct DatadogExtractData {
    pub links: Vec<SpanLink>,
    pub origin: Option<String>,
    pub internal_tags: HashMap<String, String>,
    pub sampling: Sampling,
}

impl DatadogExtractData {
    fn from_span_context(
        SpanContext {
            origin,
            tags,
            links,
            sampling,
            ..
        }: SpanContext,
    ) -> Self {
        let internal_tags = tags
            .iter()
            .filter_map(|tag| {
                if tag.0.starts_with("_dd.") {
                    Some((tag.0.clone(), tag.1.clone()))
                } else {
                    None
                }
            })
            .collect();

        DatadogExtractData {
            links,
            origin,
            internal_tags,
            sampling,
        }
    }
}

#[derive(Debug)]
pub struct DatadogPropagator {
    inner: DatadogCompositePropagator,
    registry: TraceRegistry,
    cfg: Arc<Config>,
}

impl DatadogPropagator {
    pub(crate) fn new(config: Arc<Config>, registry: TraceRegistry) -> Self {
        DatadogPropagator {
            inner: DatadogCompositePropagator::new(config.clone()),
            registry,
            cfg: config,
        }
    }

    /// Injects otel context delegating into [`DatadogCompositePropagator`]
    /// Before delegating, it converts otel SpanContext into a DD SpanContext obtaining propagation
    /// data from [`TraceRegistry`]
    fn inject_context(
        &self,
        cx: &opentelemetry::Context,
        mut injector: &mut dyn opentelemetry::propagation::Injector,
    ) {
        let span = cx.span();
        let otel_span_context = span.span_context();

        if !otel_span_context.is_valid() {
            return;
        }

        let trace_id = otel_span_context.trace_id().to_bytes();
        let mut propagation_data = self.registry.get_trace_propagation_data(trace_id);

        // get Trace's sampling decision and if it is not present obtain it from otel's SpanContext
        // flags
        let sampling = if let Some(priority) = propagation_data.sampling_decision.priority {
            Sampling {
                priority: Some(priority),
                mechanism: propagation_data.sampling_decision.mechanism,
            }
        } else {
            Sampling {
                priority: Some(if otel_span_context.trace_flags().is_sampled() {
                    priority::AUTO_KEEP
                } else {
                    priority::AUTO_REJECT
                }),
                mechanism: None,
            }
        };

        // otel tracestate only contains 'additional_values'
        // TODO: optimize Tracestate conversion
        let otel_tracestate = otel_span_context.trace_state();
        let tracestate = if *otel_tracestate == opentelemetry::trace::TraceState::NONE {
            None
        } else {
            Some(InjectTraceState::from_header(otel_tracestate.header()))
        };

        let tags = if let Some(propagation_tags) = &mut propagation_data.tags {
            propagation_tags
        } else {
            &mut HashMap::new()
        };

        let dd_span_context = &mut InjectSpanContext {
            trace_id: u128::from_be_bytes(trace_id),
            span_id: u64::from_be_bytes(otel_span_context.span_id().to_bytes()),
            is_remote: otel_span_context.is_remote(),
            sampling,
            origin: propagation_data.origin.as_deref(),
            tags,
            tracestate,
        };

        self.inner.inject(dd_span_context, &mut injector)
    }

    /// Extracts otel remote context delegating into [`DatadogCompositePropagator`]
    /// Specific DD's propagation data is stored as a [`DatadogExtractData`] value in the otel
    /// Context to be later used by [`DatadogSpanProcessor`] at the start of the root span
    ///
    /// [`DatadogCompositePropagator`]: dd_trace_propagation::DatadogCompositePropagator
    /// [`DatadogSpanProcessor`]: crate::span_processor::DatadogSpanProcessor
    fn extract_with_context(
        &self,
        cx: &opentelemetry::Context,
        extractor: &dyn opentelemetry::propagation::Extractor,
    ) -> opentelemetry::Context {
        self.inner
            .extract(&extractor)
            .map(|dd_span_context| {
                let trace_flags = extract_trace_flags(&dd_span_context);
                let trace_state = extract_trace_state_from_context(&dd_span_context);

                let otel_span_context = opentelemetry::trace::SpanContext::new(
                    opentelemetry::TraceId::from(dd_span_context.trace_id),
                    opentelemetry::SpanId::from(dd_span_context.span_id),
                    trace_flags,
                    dd_span_context.is_remote,
                    trace_state,
                );

                cx.with_remote_span_context(otel_span_context)
                    .with_value(DatadogExtractData::from_span_context(dd_span_context))
            })
            .unwrap_or_else(|| cx.clone())
    }
}

impl TextMapPropagator for DatadogPropagator {
    fn inject_context(
        &self,
        cx: &opentelemetry::Context,
        injector: &mut dyn opentelemetry::propagation::Injector,
    ) {
        if !self.cfg.enabled() {
            return;
        }
        catch_panic!(DatadogPropagator::inject_context(self, cx, injector));
    }

    fn extract_with_context(
        &self,
        cx: &opentelemetry::Context,
        extractor: &dyn opentelemetry::propagation::Extractor,
    ) -> opentelemetry::Context {
        if !self.cfg.enabled() {
            return cx.clone();
        }

        catch_panic!(
            DatadogPropagator::extract_with_context(self, cx, extractor),
            cx.clone()
        )
    }

    fn fields(&self) -> opentelemetry::propagation::text_map_propagator::FieldIter<'_> {
        let fields = if self.cfg.enabled() {
            self.inner.keys()
        } else {
            &[]
        };
        FieldIter::new(fields)
    }
}

fn extract_trace_flags(sc: &SpanContext) -> opentelemetry::TraceFlags {
    match sc.sampling.priority {
        Some(priority) => {
            if priority.is_keep() {
                opentelemetry::TraceFlags::SAMPLED
            } else {
                opentelemetry::TraceFlags::default()
            }
        }
        None => TRACE_FLAG_DEFERRED,
    }
}

fn extract_trace_state_from_context(sc: &SpanContext) -> opentelemetry::trace::TraceState {
    let tracestate = match &sc.tracestate {
        Some(tracestate) => match &tracestate.additional_values {
            Some(additional) => {
                opentelemetry::trace::TraceState::from_key_value(additional.clone()).ok()
            }
            None => None,
        },
        None => None,
    };

    tracestate.unwrap_or_default()
}

#[cfg(test)]
pub mod tests {
    use std::{borrow::Cow, collections::HashMap, str::FromStr, sync::Arc};

    use assert_unordered::assert_eq_unordered;
    use dd_trace::{configuration::TracePropagationStyle, sampling::SamplingDecision, Config};
    use opentelemetry::{
        propagation::{Extractor, TextMapPropagator},
        trace::{Span, SpanContext as OtelSpanContext, Status, TraceContextExt, TraceState},
        Context, KeyValue, SpanId, TraceFlags, TraceId,
    };

    use dd_trace_propagation::{
        context::Tracestate,
        tracecontext::{TRACEPARENT_KEY, TRACESTATE_KEY},
    };

    use crate::{
        span_processor::TracePropagationData, text_map_propagator::DatadogExtractData,
        TraceRegistry,
    };

    use super::DatadogPropagator;

    const DATADOG_TRACE_ID_KEY: &str = "x-datadog-trace-id";
    const DATADOG_PARENT_ID_KEY: &str = "x-datadog-parent-id";

    fn get_propagator(styles: Option<Vec<TracePropagationStyle>>) -> DatadogPropagator {
        let config = if let Some(ref styles) = styles {
            Config::builder()
                .set_trace_propagation_style(styles.to_vec())
                .build()
        } else {
            Config::builder()
                .set_trace_propagation_style_extract(vec![
                    TracePropagationStyle::Datadog,
                    TracePropagationStyle::TraceContext,
                ])
                .build()
        };
        let config = Arc::new(config);

        DatadogPropagator::new(config.clone(), TraceRegistry::new(config))
    }

    #[derive(Debug)]
    pub struct TestSpan(pub OtelSpanContext);

    impl Span for TestSpan {
        fn add_event_with_timestamp<T>(
            &mut self,
            _name: T,
            _timestamp: std::time::SystemTime,
            _attributes: Vec<KeyValue>,
        ) where
            T: Into<Cow<'static, str>>,
        {
        }
        fn span_context(&self) -> &OtelSpanContext {
            &self.0
        }
        fn is_recording(&self) -> bool {
            false
        }
        fn set_attribute(&mut self, _attribute: KeyValue) {}
        fn set_status(&mut self, _status: Status) {}
        fn update_name<T>(&mut self, _new_name: T)
        where
            T: Into<Cow<'static, str>>,
        {
        }

        fn add_link(&mut self, _span_context: OtelSpanContext, _attributes: Vec<KeyValue>) {}
        fn end_with_timestamp(&mut self, _timestamp: std::time::SystemTime) {}
    }

    #[rustfmt::skip]
    fn extract_data() -> Vec<(&'static str, &'static str, OtelSpanContext)> {
        vec![
            ("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00", "foo=bar", OtelSpanContext::new(TraceId::from(0x4bf9_2f35_77b3_4da6_a3ce_929d_0e0e_4736), SpanId::from(0x00f0_67aa_0ba9_02b7), TraceFlags::default(), true, TraceState::from_str("foo=bar").unwrap())),
            ("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", "foo=bar", OtelSpanContext::new(TraceId::from(0x4bf9_2f35_77b3_4da6_a3ce_929d_0e0e_4736), SpanId::from(0x00f0_67aa_0ba9_02b7), TraceFlags::SAMPLED, true, TraceState::from_str("foo=bar").unwrap())),
            ("02-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", "foo=bar", OtelSpanContext::new(TraceId::from(0x4bf9_2f35_77b3_4da6_a3ce_929d_0e0e_4736), SpanId::from(0x00f0_67aa_0ba9_02b7), TraceFlags::SAMPLED, true, TraceState::from_str("foo=bar").unwrap())),
            ("02-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-09", "foo=bar", OtelSpanContext::new(TraceId::from(0x4bf9_2f35_77b3_4da6_a3ce_929d_0e0e_4736), SpanId::from(0x00f0_67aa_0ba9_02b7), TraceFlags::SAMPLED, true, TraceState::from_str("foo=bar").unwrap())),
            ("02-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-08", "foo=bar", OtelSpanContext::new(TraceId::from(0x4bf9_2f35_77b3_4da6_a3ce_929d_0e0e_4736), SpanId::from(0x00f0_67aa_0ba9_02b7), TraceFlags::default(), true, TraceState::from_str("foo=bar").unwrap())),
            ("02-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-09-XYZxsf09", "foo=bar", OtelSpanContext::new(TraceId::from(0x4bf9_2f35_77b3_4da6_a3ce_929d_0e0e_4736), SpanId::from(0x00f0_67aa_0ba9_02b7), TraceFlags::SAMPLED, true, TraceState::from_str("foo=bar").unwrap())),
            ("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-", "foo=bar", OtelSpanContext::new(TraceId::from(0x4bf9_2f35_77b3_4da6_a3ce_929d_0e0e_4736), SpanId::from(0x00f0_67aa_0ba9_02b7), TraceFlags::SAMPLED, true, TraceState::from_str("foo=bar").unwrap())),
            ("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-09-", "foo=bar", OtelSpanContext::new(TraceId::from(0x4bf9_2f35_77b3_4da6_a3ce_929d_0e0e_4736), SpanId::from(0x00f0_67aa_0ba9_02b7), TraceFlags::SAMPLED, true, TraceState::from_str("foo=bar").unwrap())),
            (" 01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-09", "foo=bar", OtelSpanContext::new(TraceId::from(0x4bf9_2f35_77b3_4da6_a3ce_929d_0e0e_4736), SpanId::from(0x00f0_67aa_0ba9_02b7), TraceFlags::SAMPLED, true, TraceState::from_str("foo=bar").unwrap())),
            ("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-09 ", "foo=bar", OtelSpanContext::new(TraceId::from(0x4bf9_2f35_77b3_4da6_a3ce_929d_0e0e_4736), SpanId::from(0x00f0_67aa_0ba9_02b7), TraceFlags::SAMPLED, true, TraceState::from_str("foo=bar").unwrap())),
            ("\t01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-09", "foo=bar", OtelSpanContext::new(TraceId::from(0x4bf9_2f35_77b3_4da6_a3ce_929d_0e0e_4736), SpanId::from(0x00f0_67aa_0ba9_02b7), TraceFlags::SAMPLED, true, TraceState::from_str("foo=bar").unwrap())),
            ("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-09\t", "foo=bar", OtelSpanContext::new(TraceId::from(0x4bf9_2f35_77b3_4da6_a3ce_929d_0e0e_4736), SpanId::from(0x00f0_67aa_0ba9_02b7), TraceFlags::SAMPLED, true, TraceState::from_str("foo=bar").unwrap())),
            ("\t 01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-09\t", "foo=bar", OtelSpanContext::new(TraceId::from(0x4bf9_2f35_77b3_4da6_a3ce_929d_0e0e_4736), SpanId::from(0x00f0_67aa_0ba9_02b7), TraceFlags::SAMPLED, true, TraceState::from_str("foo=bar").unwrap())),
        ]
    }

    #[rustfmt::skip]
    fn extract_data_invalid() -> Vec<(&'static str, &'static str)> {
        vec![
            ("0000-00000000000000000000000000000000-0000000000000000-01", "wrong version length"),
            ("00-ab00000000000000000000000000000000-cd00000000000000-01", "wrong trace ID length"),
            ("00-ab000000000000000000000000000000-cd0000000000000000-01", "wrong span ID length"),
            ("00-ab000000000000000000000000000000-cd00000000000000-0100", "wrong trace flag length"),
            ("qw-00000000000000000000000000000000-0000000000000000-01",   "bogus version"),
            ("00-qw000000000000000000000000000000-cd00000000000000-01",   "bogus trace ID"),
            ("00-ab000000000000000000000000000000-qw00000000000000-01",   "bogus span ID"),
            ("00-ab000000000000000000000000000000-cd00000000000000-qw",   "bogus trace flag"),
            ("A0-00000000000000000000000000000000-0000000000000000-01",   "upper case version"),
            ("00-AB000000000000000000000000000000-cd00000000000000-01",   "upper case trace ID"),
            ("00-ab000000000000000000000000000000-CD00000000000000-01",   "upper case span ID"),
            ("00-ab000000000000000000000000000000-cd00000000000000-A1",   "upper case trace flag"),
            ("00-00000000000000000000000000000000-0000000000000000-01",   "zero trace ID and span ID"),
            ("00-ab000000000000000000000000000000-cd00000000000000-09",   "trace-flag unused bits set"),
            ("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",      "missing options"),
            ("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-",     "empty options"),
        ]
    }

    #[rustfmt::skip]
    fn inject_data() -> Vec<(&'static str, &'static str, OtelSpanContext)> {
        vec![
            ("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", "dd=s:1;p:00f067aa0ba902b7;t.tid:4bf92f3577b34da6,foo=bar", OtelSpanContext::new(TraceId::from(0x4bf9_2f35_77b3_4da6_a3ce_929d_0e0e_4736), SpanId::from(0x00f0_67aa_0ba9_02b7), TraceFlags::SAMPLED, true, TraceState::from_str("foo=bar").unwrap())),
            ("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00", "dd=s:0;p:00f067aa0ba902b7;t.tid:4bf92f3577b34da6,foo=bar", OtelSpanContext::new(TraceId::from(0x4bf9_2f35_77b3_4da6_a3ce_929d_0e0e_4736), SpanId::from(0x00f0_67aa_0ba9_02b7), TraceFlags::default(), true, TraceState::from_str("foo=bar").unwrap())),
            ("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", "dd=s:1;p:00f067aa0ba902b7;t.tid:4bf92f3577b34da6,foo=bar", OtelSpanContext::new(TraceId::from(0x4bf9_2f35_77b3_4da6_a3ce_929d_0e0e_4736), SpanId::from(0x00f0_67aa_0ba9_02b7), TraceFlags::new(0xff), true, TraceState::from_str("foo=bar").unwrap())),
            ("", "", OtelSpanContext::empty_context()),
        ]
    }

    #[rustfmt::skip]
    fn extract_inject_data() -> Vec<(&'static str, &'static str, TraceState)> {
        vec![
            ("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", "foo=bar", TraceState::from_str("dd=s:1;p:00f067aa0ba902b7;t.dm:-0;t.tid:4bf92f3577b34da6,foo=bar").unwrap()),
            ("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", "foo=bar,dd=o:rum;t.pfoo:bar", TraceState::from_str("dd=s:1;o:rum;p:00f067aa0ba902b7;t.pfoo:bar;t.dm:-0;t.tid:4bf92f3577b34da6,foo=bar").unwrap()),
        ]
    }

    #[rustfmt::skip]
    fn tracestate() -> Vec<(&'static str, bool)> {
        vec![
            ("foo=1,=2,=4", true),
            ("foo=1,2", false),
            ("foo=1,,,", false),
            ("foo=1,bar=2=2", false),
            ("foo=öï,bar=2", true),
            ("föö=oi,bar=2", false),
            ("foo=\t öï  \t\t ", true),
            ("foo=\t valid  \t\t ", true),
            ("\t\t  foo=valid", false),
            ("   foo=valid", false),
            ("dd=\t  o:valid  \t\t ", true),
            ("dd=o:välïd  \t\t ", true),
            ("dd=\t  o:valid;;s:1; \t", true),
            ("dd=\t  o:valid;;s:1; \t,foo=1", true),
        ]
    }

    #[test]
    fn extract_w3c() {
        let propagator = get_propagator(None);

        for (trace_parent, trace_state, expected_context) in extract_data() {
            let mut extractor = HashMap::new();
            extractor.insert(TRACEPARENT_KEY.to_string(), trace_parent.to_string());
            extractor.insert(TRACESTATE_KEY.to_string(), trace_state.to_string());

            assert_eq!(
                propagator.extract(&extractor).span().span_context(),
                &expected_context,
                "Error with traceparent: {trace_parent}, tracestate: {trace_state}",
            )
        }
    }

    #[test]
    fn extract_w3c_tracestate() {
        let propagator = get_propagator(None);
        let state = "foo=bar".to_string();
        let parent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00".to_string();

        let mut extractor = HashMap::new();
        extractor.insert(TRACEPARENT_KEY.to_string(), parent);
        extractor.insert(TRACESTATE_KEY.to_string(), state.clone());

        assert_eq!(
            propagator
                .extract(&extractor)
                .span()
                .span_context()
                .trace_state()
                .header(),
            state
        )
    }

    #[test]
    fn extract_w3c_reject_invalid() {
        let propagator = get_propagator(None);

        for (invalid_header, reason) in extract_data_invalid() {
            let mut extractor = HashMap::new();
            extractor.insert(TRACEPARENT_KEY.to_string(), invalid_header.to_string());

            assert_eq!(
                propagator.extract(&extractor).span().span_context(),
                &opentelemetry::trace::SpanContext::empty_context(),
                "{reason}",
            )
        }
    }

    #[test]
    fn extract_w3c_but_hide_dd_part_to_otel() {
        let propagator = get_propagator(None);

        let state = "foo=1,dd=s:1;o:rum,bar=2".to_string();
        let parent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00".to_string();

        let mut extractor = HashMap::new();
        extractor.insert(TRACEPARENT_KEY.to_string(), parent);
        extractor.insert(TRACESTATE_KEY.to_string(), state.clone());

        let context = propagator.extract(&extractor);

        let span = context.span();
        let trace_state = span.span_context().trace_state();

        assert_eq!(trace_state.get("dd"), None);
        assert_eq!(trace_state.get("foo").unwrap(), "1");
        assert_eq!(trace_state.get("bar").unwrap(), "2");
    }

    #[test]
    fn extract_w3c_but_hide_dd_part_with_no_additional_to_otel() {
        let propagator = get_propagator(None);

        let state = "dd=s:1;o:rum".to_string();
        let parent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00".to_string();

        let mut extractor = HashMap::new();
        extractor.insert(TRACEPARENT_KEY.to_string(), parent);
        extractor.insert(TRACESTATE_KEY.to_string(), state.clone());

        let context = propagator.extract(&extractor);

        let span = context.span();
        let trace_state = span.span_context().trace_state();

        assert_eq!(*trace_state, opentelemetry::trace::TraceState::default());
    }

    #[test]
    fn extract_w3c_but_hide_invalid_dd_part_to_otel() {
        let propagator = get_propagator(None);

        let state = "foo=1,dd=s:1;o:rüm,bar=2".to_string();
        let parent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00".to_string();

        let mut extractor = HashMap::new();
        extractor.insert(TRACEPARENT_KEY.to_string(), parent);
        extractor.insert(TRACESTATE_KEY.to_string(), state.clone());

        let context = propagator.extract(&extractor);

        let span = context.span();
        let trace_state = span.span_context().trace_state();

        assert_eq!(trace_state.get("dd"), None);
        assert_eq!(trace_state.get("foo").unwrap(), "1");
        assert_eq!(trace_state.get("bar").unwrap(), "2");
    }

    #[test]
    fn extract_w3c_adds_dd_propagation_tags() {
        let propagator = get_propagator(None);

        let parent = "00-12345678901234567890123456789012-1234567890123456-01".to_string();
        let state = "dd=s:2;o:rum;p:0123456789abcdef;t.dm:-4;".to_string();

        let mut extractor = HashMap::new();
        extractor.insert(TRACEPARENT_KEY.to_string(), parent);
        extractor.insert(TRACESTATE_KEY.to_string(), state.clone());

        let context = propagator.extract(&extractor);

        let extract_data = context.get::<DatadogExtractData>().unwrap();

        assert!(extract_data.internal_tags.contains_key("_dd.parent_id"));
        assert!(extract_data.internal_tags.contains_key("_dd.p.dm"));
        assert!(!extract_data.internal_tags.contains_key("tracestate"));
    }

    #[test]
    fn extract_datadog_does_not_propagate_tracecontext_data_to_otel() {
        let propagator = get_propagator(Some(vec![TracePropagationStyle::Datadog]));

        let state = "foo=1,dd=s:1;o:rüm,bar=2".to_string();
        let parent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00".to_string();

        let mut extractor = HashMap::new();
        extractor.insert(DATADOG_TRACE_ID_KEY.to_string(), "1234".to_string());
        extractor.insert(DATADOG_PARENT_ID_KEY.to_string(), "5678".to_string());
        extractor.insert(TRACEPARENT_KEY.to_string(), parent);
        extractor.insert(TRACESTATE_KEY.to_string(), state.clone());

        let context = propagator.extract(&extractor);

        let span = context.span();
        let trace_state = span.span_context().trace_state();

        assert_eq!(*trace_state, opentelemetry::trace::TraceState::default());
    }

    #[test]
    fn inject_w3c() {
        let propagator = get_propagator(None);

        for (expected_trace_parent, expected_trace_state, context) in inject_data() {
            let mut injector = HashMap::new();
            propagator.inject_context(
                &Context::current_with_span(TestSpan(context)),
                &mut injector,
            );

            assert_eq!(
                Extractor::get(&injector, TRACEPARENT_KEY).unwrap_or(""),
                expected_trace_parent
            );

            assert_eq!(
                Extractor::get(&injector, TRACESTATE_KEY).unwrap_or(""),
                expected_trace_state
            );
        }
    }

    #[test]
    fn extract_inject_w3c() {
        for (trace_parent, trace_state, expected_trace_state) in extract_inject_data() {
            let builder = Config::builder();
            let config = Arc::new(builder.build());
            let registry = TraceRegistry::new(config.clone());
            let propagator = DatadogPropagator::new(config, registry.clone());

            let mut extractor = HashMap::new();
            extractor.insert(TRACEPARENT_KEY.to_string(), trace_parent.to_string());
            extractor.insert(TRACESTATE_KEY.to_string(), trace_state.to_string());

            let extracted_context = propagator.extract(&extractor);

            let span = extracted_context.span();
            let span_context = span.span_context();
            let trace_id = span_context.trace_id().to_bytes();
            let span_id = span_context.span_id().to_bytes();

            let mut origin = None;
            let mut tags = HashMap::from([("_dd.p.dm".to_string(), "-0".to_string())]);

            if trace_state.contains("dd=") {
                origin = Some("rum".to_string());
                tags.insert("_dd.p.pfoo".to_string(), "bar".to_string());
            }

            // fake span register
            registry.register_span(
                trace_id,
                span_id,
                TracePropagationData {
                    origin,
                    sampling_decision: SamplingDecision {
                        priority: None,
                        mechanism: None,
                    },
                    tags: Some(tags),
                },
                "test_span".to_string(),
            );

            let mut injector = HashMap::new();
            propagator.inject_context(&extracted_context, &mut injector);

            let injected_trace_state =
                TraceState::from_str(Extractor::get(&injector, TRACESTATE_KEY).unwrap_or(""))
                    .unwrap();

            assert_eq_unordered!(
                expected_trace_state
                    .get("dd")
                    .unwrap_or_default()
                    .split(';')
                    .collect::<Vec<_>>(),
                injected_trace_state
                    .get("dd")
                    .unwrap_or_default()
                    .split(';')
                    .collect::<Vec<_>>()
            );

            assert_eq!(
                expected_trace_state.get("foo").unwrap_or_default(),
                injected_trace_state.get("foo").unwrap_or_default()
            )
        }
    }

    #[test]
    fn tracestate_parse_check() {
        for (tracestate, success) in tracestate() {
            let otel_trace_state = TraceState::from_str(tracestate);
            let dd_trace_state = Tracestate::from_str(tracestate);
            if success {
                assert!(
                    otel_trace_state.is_ok(),
                    "otel `{tracestate}` should be correct"
                );
                assert!(
                    dd_trace_state.is_ok(),
                    "dd `{tracestate}` should be correct"
                );

                let otel = otel_trace_state.unwrap();
                let dd = dd_trace_state.unwrap();

                if let Some(additional_values) = dd.additional_values {
                    let dd_header = additional_values
                        .into_iter()
                        .map(|(key, value)| format!("{key}={value}"))
                        .collect::<Vec<String>>()
                        .join(",");

                    assert!(otel.header().to_string().contains(&dd_header));
                }
            } else {
                assert!(
                    otel_trace_state.is_err(),
                    "otel `{tracestate}` should be incorrect"
                );
                assert!(
                    dd_trace_state.is_err(),
                    "dd `{tracestate}` should be incorrect"
                );
            }
        }
    }
}
