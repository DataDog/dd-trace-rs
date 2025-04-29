// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, str::FromStr, vec};

use dd_trace::Config;
use opentelemetry::{
    propagation::{text_map_propagator::FieldIter, TextMapPropagator},
    trace::TraceContextExt,
};

use dd_trace_propagation::{
    carrier::{Extractor, Injector},
    context::{Sampling, SamplingPriority, SpanContext, Tracestate},
    tracecontext::TRACESTATE_KEY,
    DatadogCompositePropagator, Propagator,
};

const TRACE_FLAG_DEFERRED: opentelemetry::TraceFlags = opentelemetry::TraceFlags::new(0x02);

// impl Extractor for &dyn opentelemetry::propagation::Extractor {
//     fn get(&self, key: &str) -> Option<&str> {
//         opentelemetry::propagation::Extractor::get(*self, key)
//     }

//     fn keys(&self) -> Vec<&str> {
//         opentelemetry::propagation::Extractor::keys(*self)
//     }
// }

// impl Injector for &mut dyn opentelemetry::propagation::Injector {
//     fn set(&mut self, key: &str, value: String) {
//         opentelemetry::propagation::Injector::set(*self, key, value);
//     }
// }

struct ExtractorWrapper<'a> {
    extractor: &'a dyn opentelemetry::propagation::Extractor,
}

impl Extractor for ExtractorWrapper<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.extractor.get(key)
    }

    fn keys(&self) -> Vec<&str> {
        self.extractor.keys()
    }
}

struct InjectorWrapper<'a> {
    injector: &'a mut dyn opentelemetry::propagation::Injector,
}

impl Injector for InjectorWrapper<'_> {
    fn set(&mut self, key: &str, value: String) {
        self.injector.set(key, value);
    }
}

struct PropagationSpanData {
    origin: Option<String>,
    tags: HashMap<String, String>,
    tracestate: Option<Tracestate>,
}

impl PropagationSpanData {
    fn from(span_context: SpanContext) -> Self {
        PropagationSpanData {
            origin: span_context.origin,
            tags: span_context.tags,
            tracestate: span_context.tracestate,
        }
    }
}

#[derive(Debug)]
pub struct DatadogPropagator {
    inner: DatadogCompositePropagator,
}

impl DatadogPropagator {
    pub fn new(config: &Config) -> Self {
        DatadogPropagator {
            inner: DatadogCompositePropagator::new(config),
        }
    }
}

impl TextMapPropagator for DatadogPropagator {
    fn inject_context(
        &self,
        cx: &opentelemetry::Context,
        injector: &mut dyn opentelemetry::propagation::Injector,
    ) {
        let span = cx.span();
        let otel_span_context = span.span_context();

        let sampling = Some(Sampling {
            priority: Some(SamplingPriority::from_flags(
                otel_span_context.trace_flags().to_u8(),
            )),
            mechanism: None,
        });

        let (origin, tags, tracestate) =
            get_dd_propagation_data(cx, otel_span_context.trace_state());

        let dd_span_context = &mut SpanContext {
            trace_id: u128::from_be_bytes(otel_span_context.trace_id().to_bytes()),
            span_id: u64::from_be_bytes(otel_span_context.span_id().to_bytes()),
            is_remote: otel_span_context.is_remote(),
            links: vec![],
            sampling,
            origin,
            tags,
            tracestate,
        };

        let _ = &self
            .inner
            .inject(dd_span_context, &mut InjectorWrapper { injector });
    }

    fn extract_with_context(
        &self,
        cx: &opentelemetry::Context,
        extractor: &dyn opentelemetry::propagation::Extractor,
    ) -> opentelemetry::Context {
        self.inner
            .extract(&ExtractorWrapper { extractor })
            .map(|dd_span_context| {
                let trace_flags = extract_trace_flags(&dd_span_context);
                let trace_state = extract_trace_state(&dd_span_context);

                let otel_span_context = opentelemetry::trace::SpanContext::new(
                    opentelemetry::TraceId::from(dd_span_context.trace_id),
                    opentelemetry::SpanId::from(dd_span_context.span_id),
                    trace_flags,
                    dd_span_context.is_remote,
                    trace_state,
                );

                cx.with_remote_span_context(otel_span_context)
                    .with_value(PropagationSpanData::from(dd_span_context))
            })
            .unwrap_or_else(|| cx.clone())
    }

    fn fields(&self) -> opentelemetry::propagation::text_map_propagator::FieldIter<'_> {
        FieldIter::new(self.inner.keys())
    }
}

fn get_dd_propagation_data(
    cx: &opentelemetry::Context,
    trace_state: &opentelemetry::trace::TraceState,
) -> (Option<String>, HashMap<String, String>, Option<Tracestate>) {
    // Taking into account that Tracestate has not been modified by otel
    if let Some(span_context) = cx.get::<PropagationSpanData>() {
        (
            span_context.origin.clone(),
            span_context.tags.clone(),
            span_context.tracestate.clone(),
        )
    } else {
        (
            None,
            HashMap::new(),
            Tracestate::from_str(&trace_state.header()).ok(), // TODO: review
        )
    }
}

fn extract_trace_flags(sc: &SpanContext) -> opentelemetry::TraceFlags {
    match sc.sampling {
        Some(sampling) => match sampling.priority {
            Some(priority) => {
                if priority.is_keep() {
                    opentelemetry::TraceFlags::SAMPLED
                } else {
                    opentelemetry::TraceFlags::default()
                }
            }
            None => TRACE_FLAG_DEFERRED,
        },
        None => TRACE_FLAG_DEFERRED,
    }
}

fn extract_trace_state(sc: &SpanContext) -> opentelemetry::trace::TraceState {
    // TODO: we are parsing twice tracestate
    match sc.tags.get(TRACESTATE_KEY) {
        Some(trace_state) => {
            opentelemetry::trace::TraceState::from_str(trace_state).unwrap_or_default()
        }
        None => opentelemetry::trace::TraceState::default(),
    }
}

#[cfg(test)]
pub mod tests {
    use std::{borrow::Cow, collections::HashMap, str::FromStr};

    use dd_trace::{configuration::TracePropagationStyle, Config};
    use opentelemetry::{
        propagation::{Extractor, TextMapPropagator},
        trace::{Span, SpanContext as OtelSpanContext, Status, TraceContextExt, TraceState},
        Context, KeyValue, SpanId, TraceFlags, TraceId,
    };

    use dd_trace_propagation::tracecontext::{TRACEPARENT_KEY, TRACESTATE_KEY};

    use super::DatadogPropagator;

    fn get_propagator(styles: Option<Vec<TracePropagationStyle>>) -> DatadogPropagator {
        let mut builder = Config::builder();

        if let Some(ref styles) = styles {
            builder.set_trace_propagation_style(styles.to_vec());
        } else {
            builder.set_trace_propagation_style_extract(vec![
                TracePropagationStyle::Datadog,
                TracePropagationStyle::TraceContext,
            ]);
        }

        DatadogPropagator::new(&builder.build())
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
                "Error with traceparent: {}, tracestate: {}",
                trace_parent,
                trace_state
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
                "{}",
                reason
            )
        }
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
}
