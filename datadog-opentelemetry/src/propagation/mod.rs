// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::{
    core::{configuration::TracePropagationStyle, Config},
    dd_debug,
    propagation::context::{InjectSpanContext, SpanContext, SpanLink},
};
use carrier::{Extractor, Injector};
use config::{get_extractors, get_injectors};
use datadog::DATADOG_LAST_PARENT_ID_KEY;
use tracecontext::TRACESTATE_KEY;

pub mod carrier;
pub mod config;
pub mod context;
mod datadog;
mod error;
pub mod trace_propagation_style;
pub mod tracecontext;

pub trait Propagator {
    fn extract(&self, carrier: &dyn Extractor, config: &Config) -> Option<SpanContext>;
    fn inject(&self, context: &mut InjectSpanContext, carrier: &mut dyn Injector, config: &Config);
    fn keys(&self) -> &[String];
}

#[derive(Debug)]
pub struct DatadogCompositePropagator {
    config: Arc<Config>,
    extractors: Vec<TracePropagationStyle>,
    injectors: Vec<TracePropagationStyle>,
    keys: Vec<String>,
}

impl DatadogCompositePropagator {
    #[must_use]
    pub fn new(config: Arc<Config>) -> Self {
        let extractors = get_extractors(&config);
        let mut num_propagators = extractors.len();
        if config.trace_propagation_extract_first() {
            num_propagators = 1;
        };

        let extractors: Vec<TracePropagationStyle> = extractors
            .iter()
            .take(num_propagators)
            .filter(|style| **style != TracePropagationStyle::None)
            .copied()
            .collect();

        let injectors: Vec<TracePropagationStyle> = get_injectors(&config)
            .iter()
            .filter(|style| **style != TracePropagationStyle::None)
            .copied()
            .collect();

        let keys = extractors.iter().fold(Vec::new(), |mut keys, extractor| {
            extractor
                .keys()
                .iter()
                .for_each(|key| keys.push(key.clone()));
            keys
        });

        Self {
            config,
            extractors,
            injectors,
            keys,
        }
    }

    pub fn extract(&self, carrier: &dyn Extractor) -> Option<SpanContext> {
        let contexts = self.extract_available_contexts(carrier, &self.config);
        if contexts.is_empty() {
            return None;
        }

        let context = Self::resolve_contexts(contexts, carrier);

        Some(context)
    }

    pub fn inject(&self, context: &mut InjectSpanContext, carrier: &mut dyn Injector) {
        self.injectors
            .iter()
            .for_each(|propagator| propagator.inject(context, carrier, &self.config));
    }

    pub fn keys(&self) -> &[String] {
        &self.keys
    }

    fn extract_available_contexts(
        &self,
        carrier: &dyn Extractor,
        config: &Config,
    ) -> Vec<(SpanContext, TracePropagationStyle)> {
        let mut contexts = vec![];

        for propagator in self.extractors.iter() {
            if let Some(context) = propagator.extract(carrier, config) {
                dd_debug!("Propagator ({propagator}): extracted {context:#?}");
                contexts.push((context, *propagator));
            }
        }

        contexts
    }

    fn resolve_contexts(
        contexts: Vec<(SpanContext, TracePropagationStyle)>,
        _carrier: &dyn Extractor,
    ) -> SpanContext {
        dd_debug!(
            "DatadogCompositePropagator: resolving contexts: received {}",
            contexts.len()
        );

        let mut primary_context = contexts[0].0.clone();
        let mut links = Vec::<SpanLink>::new();

        for context_and_style in contexts.iter().skip(1) {
            let style = context_and_style.1;
            let context = &context_and_style.0;

            if context.span_id != 0
                && context.trace_id != 0
                && context.trace_id != primary_context.trace_id
            {
                links.push(SpanLink::terminated_context(context, style));
                dd_debug!(
                    "DatadogCompositePropagator: terminated context (trace_id: {:#?}, span_id: {:#?})",
                    context.trace_id,
                    context.span_id
                );
            } else if style == TracePropagationStyle::TraceContext {
                if let Some(tracestate) = context.tags.get(TRACESTATE_KEY) {
                    primary_context
                        .tags
                        .insert(TRACESTATE_KEY.to_string(), tracestate.clone());
                    primary_context.tracestate = context.tracestate.clone();
                    dd_debug!(
                        "DatadogCompositePropagator: setting tracestate from tracecontext context in the datadog context"
                    );
                }

                if primary_context.trace_id == context.trace_id
                    && primary_context.span_id != context.span_id
                {
                    let dd_context = contexts
                        .iter()
                        .find(|(_, style)| *style == TracePropagationStyle::Datadog)
                        .map(|(context, _)| context);

                    if let Some(parent_id) = context.tags.get(DATADOG_LAST_PARENT_ID_KEY) {
                        primary_context
                            .tags
                            .insert(DATADOG_LAST_PARENT_ID_KEY.to_string(), parent_id.clone());
                    } else if let Some(sc) = dd_context {
                        primary_context.tags.insert(
                            DATADOG_LAST_PARENT_ID_KEY.to_string(),
                            format!("{:016x}", sc.span_id),
                        );
                    }

                    dd_debug!(
                        "DatadogCompositePropagator: spanId differences between extrated contexts. (resolved spanId: {}, {DATADOG_LAST_PARENT_ID_KEY}: {} ",
                            context.span_id,
                            primary_context.tags.get(DATADOG_LAST_PARENT_ID_KEY).unwrap_or(&"".to_string())
                    );

                    primary_context.span_id = context.span_id;
                }
            }
        }

        primary_context.links = links;

        primary_context
    }
}

pub(crate) const fn const_append(source: &[u8], dest: &mut [u8], at: usize) {
    let mut i = 0;
    loop {
        if i >= source.len() {
            break;
        }
        dest[i + at] = source[i];
        i += 1;
    }
}

macro_rules! const_concat {
    ($($s:expr,)+) => {{
        const LEN: usize = 0 $( + $s.len())*;
        const CONCATENATED: [u8; LEN] = {
            let mut concatenated: [u8; LEN] = [0; LEN];
            let mut at = 0;
            $(
                let part: &str = $s;
                super::const_append(part.as_bytes(), &mut concatenated, at);
                at += $s.len();
            )*
            let _ = at;
            concatenated
        };
        std::str::from_utf8(&CONCATENATED).expect("the concatenation of valid utf-8 strings is always a valid utf-8 string")
    }};
}
pub(crate) use const_concat;

#[cfg(test)]
pub mod tests {
    use std::{collections::HashMap, str::FromStr, sync::LazyLock, vec};

    use assert_unordered::assert_eq_unordered;

    use crate::core::sampling::{mechanism, priority};
    use pretty_assertions::assert_eq;

    use crate::propagation::context::{Sampling, Tracestate};

    use super::*;

    const fn lower_64_bits(value: u128) -> u64 {
        (value & 0xFFFF_FFFF_FFFF_FFFF) as u64
    }

    const TRACE_ID: u128 = 171_395_628_812_617_415_352_188_477_958_425_669_623;
    const TRACE_ID_LOWER_ORDER_BITS: u64 = lower_64_bits(TRACE_ID);
    const TRACE_ID_HEX: &str = "80f198ee56343ba864fe8b2a57d3eff7";
    static VALID_TRACECONTEXT_HEADERS_BASIC: LazyLock<HashMap<String, String>> =
        LazyLock::new(|| {
            HashMap::from([
                (
                    "traceparent".to_string(),
                    format!("00-{}-00f067aa0ba902b7-01", TRACE_ID_HEX),
                ),
                (
                    "tracestate".to_string(),
                    "dd=p:00f067aa0ba902b7;s:2;o:rum".to_string(),
                ),
            ])
        });
    // TraceContext Headers
    static VALID_TRACECONTEXT_HEADERS_RUM_NO_SAMPLING_DECISION: LazyLock<HashMap<String, String>> =
        LazyLock::new(|| {
            HashMap::from([
                (
                    "traceparent".to_string(),
                    format!("00-{}-00f067aa0ba902b7-00", TRACE_ID_HEX),
                ),
                ("tracestate".to_string(), "dd=o:rum".to_string()),
            ])
        });
    static VALID_TRACECONTEXT_HEADERS: LazyLock<HashMap<String, String>> = LazyLock::new(|| {
        HashMap::from([
            (
                "traceparent".to_string(),
                format!("00-{}-00f067aa0ba902b7-01", TRACE_ID_HEX),
            ),
            (
                "tracestate".to_string(),
                "dd=s:2;o:rum;t.dm:-4;t.usr.id:baz64,congo=t61rcWkgMz".to_string(),
            ),
        ])
    });
    static VALID_TRACECONTEXT_HEADERS_VALID_64_BIT_TRACE_ID: LazyLock<HashMap<String, String>> =
        LazyLock::new(|| {
            HashMap::from([
                (
                    "traceparent".to_string(),
                    "00-000000000000000064fe8b2a57d3eff7-00f067aa0ba902b7-01".to_string(),
                ),
                (
                    "tracestate".to_string(),
                    "dd=s:2;o:rum;t.dm:-4;t.usr.id:baz64,congo=t61rcWkgMzE".to_string(),
                ),
            ])
        });

    // Datadog Headers
    static VALID_DATADOG_HEADERS: LazyLock<HashMap<String, String>> = LazyLock::new(|| {
        HashMap::from([
            (
                "x-datadog-trace-id".to_string(),
                "13088165645273925489".to_string(),
            ),
            ("x-datadog-parent-id".to_string(), "5678".to_string()),
            ("x-datadog-sampling-priority".to_string(), "1".to_string()),
            ("x-datadog-origin".to_string(), "synthetics".to_string()),
            ("x-datadog-tags".to_string(), "_dd.p.dm=-4".to_string()),
        ])
    });
    static VALID_DATADOG_HEADERS_NO_PRIORITY: LazyLock<HashMap<String, String>> =
        LazyLock::new(|| {
            HashMap::from([
                (
                    "x-datadog-trace-id".to_string(),
                    "13088165645273925489".to_string(),
                ),
                ("x-datadog-parent-id".to_string(), "5678".to_string()),
                ("x-datadog-origin".to_string(), "synthetics".to_string()),
            ])
        });
    static VALID_DATADOG_HEADERS_MATCHING_TRACE_CONTEXT_VALID_TRACE_ID: LazyLock<
        HashMap<String, String>,
    > = LazyLock::new(|| {
        HashMap::from([
            (
                "x-datadog-trace-id".to_string(),
                TRACE_ID_LOWER_ORDER_BITS.to_string(),
            ),
            ("x-datadog-parent-id".to_string(), "5678".to_string()),
            ("x-datadog-origin".to_string(), "synthetics".to_string()),
            ("x-datadog-sampling-priority".to_string(), "1".to_string()),
        ])
    });
    static INVALID_DATADOG_HEADERS: LazyLock<HashMap<String, String>> = LazyLock::new(|| {
        HashMap::from([
            (
                "x-datadog-trace-id".to_string(),
                "13088165645273925489".to_string(),
            ),
            ("x-datadog-parent-id".to_string(), "parent_id".to_string()),
            (
                "x-datadog-sampling-priority".to_string(),
                "sample".to_string(),
            ),
        ])
    });

    // Fixtures
    //
    static ALL_VALID_HEADERS: LazyLock<HashMap<String, String>> = LazyLock::new(|| {
        let mut h = HashMap::new();
        h.extend(VALID_DATADOG_HEADERS.clone());
        h.extend(VALID_TRACECONTEXT_HEADERS.clone());
        // todo: add b3
        h
    });
    static DATADOG_TRACECONTEXT_MATCHING_TRACE_ID_HEADERS: LazyLock<HashMap<String, String>> =
        LazyLock::new(|| {
            let mut h = HashMap::new();
            h.extend(VALID_DATADOG_HEADERS_MATCHING_TRACE_CONTEXT_VALID_TRACE_ID.clone());
            // We use 64-bit traceparent trace id value here so it can match for
            // both 128-bit enabled and disabled
            h.extend(VALID_TRACECONTEXT_HEADERS_VALID_64_BIT_TRACE_ID.clone());
            h
        });
    // Edge cases
    static ALL_HEADERS_CHAOTIC_2: LazyLock<HashMap<String, String>> = LazyLock::new(|| {
        let mut h = HashMap::new();
        h.extend(VALID_DATADOG_HEADERS.clone());
        h.extend(VALID_TRACECONTEXT_HEADERS_VALID_64_BIT_TRACE_ID.clone());
        // todo: add b3
        h
    });
    static NO_TRACESTATE_SUPPORT_NOT_MATCHING_TRACE_ID: LazyLock<HashMap<String, String>> =
        LazyLock::new(|| {
            let mut h = HashMap::new();
            h.extend(VALID_DATADOG_HEADERS.clone());
            h.extend(VALID_TRACECONTEXT_HEADERS_RUM_NO_SAMPLING_DECISION.clone());
            h
        });

    macro_rules! test_propagation_extract {
        ($($name:ident: $value:expr,)*) => {
            $(
                #[test]
                fn $name() {
                    let (styles, carrier, expected) = $value;
                    let config = if let Some(styles) = styles {
                        let mut builder = Config::builder();
                        builder.set_trace_propagation_style_extract(styles.to_vec());
                        builder.build()
                    } else {
                        Config::builder().build()
                    };

                    let propagator = DatadogCompositePropagator::new(Arc::new(config));
                    let context = propagator.extract(&carrier).unwrap_or_default();
                    assert_eq!(context.trace_id, expected.trace_id);
                    assert_eq!(context.span_id, expected.span_id);
                    assert_eq!(context.sampling, expected.sampling);
                    assert_eq!(context.origin, expected.origin);
                    assert_eq_unordered!(context.tags, expected.tags);
                    assert_eq!(context.links, expected.links);
                    assert_eq!(context.is_remote, expected.is_remote);

                    if expected.tracestate.is_some() {
                        let expected_ts = expected.tracestate.unwrap();
                        let context_ts = context.tracestate.unwrap();

                        assert_eq!(context_ts.sampling, expected_ts.sampling);
                        assert_eq!(context_ts.origin, expected_ts.origin);
                        assert_eq!(context_ts.lower_order_trace_id, expected_ts.lower_order_trace_id);
                        assert_eq_unordered!(context_ts.propagation_tags, expected_ts.propagation_tags);
                    } else {
                        assert_eq!(context.tracestate, expected.tracestate);
                    }
                }
            )*
        }
    }

    test_propagation_extract! {
        // Datadog Headers
        valid_datadog_default: (
            None::<Vec<TracePropagationStyle>>,
            VALID_DATADOG_HEADERS.clone(),
            SpanContext {
                trace_id: 13_088_165_645_273_925_489,
                span_id: 5678,
                sampling: Sampling {
                    priority: Some(priority::AUTO_KEEP),
                    mechanism: Some(mechanism::MANUAL),
                },
                origin: Some("synthetics".to_string()),
                tags: HashMap::from([
                    ("_dd.p.dm".to_string(), "-4".to_string())
                ]),
                links: vec![],
                is_remote: true,
                tracestate: None
            }
        ),
        valid_datadog_no_priority: (
            None::<Vec<TracePropagationStyle>>,
            VALID_DATADOG_HEADERS_NO_PRIORITY.clone(),
            SpanContext {
                trace_id: 13_088_165_645_273_925_489,
                span_id: 5678,
                sampling: Sampling {
                    priority: None,
                    mechanism: None,
                },
                origin: Some("synthetics".to_string()),
                tags: HashMap::new(),
                links: vec![],
                is_remote: true,
                tracestate: None
            },
        ),
        invalid_datadog: (
            Some(vec![TracePropagationStyle::Datadog]),
            INVALID_DATADOG_HEADERS.clone(),
            SpanContext {
                trace_id: 13_088_165_645_273_925_489,
                span_id: 0,
                sampling: Sampling {
                    priority: None,
                    mechanism: None,
                },
                origin: None,
                tags: HashMap::new(),
                links: vec![],
                is_remote: true,
                tracestate: None
            },
        ),
        valid_datadog_explicit_style: (
            Some(vec![TracePropagationStyle::Datadog]),
            VALID_DATADOG_HEADERS.clone(),
            SpanContext {
                trace_id: 13_088_165_645_273_925_489,
                span_id: 5678,
                sampling: Sampling {
                    priority: Some(priority::AUTO_KEEP),
                    mechanism: Some(mechanism::MANUAL),
                },
                origin: Some("synthetics".to_string()),
                tags: HashMap::from([
                    ("_dd.p.dm".to_string(), "-4".to_string())
                ]),
                links: vec![],
                is_remote: true,
                tracestate: None
            },
        ),
        invalid_datadog_negative_trace_id: (
            Some(vec![TracePropagationStyle::Datadog]),
            HashMap::from([
                (
                    "x-datadog-trace-id".to_string(),
                    "-1".to_string(),
                ),
                ("x-datadog-parent-id".to_string(), "5678".to_string(),),
                ("x-datadog-sampling-priority".to_string(), "1".to_string()),
                ("x-datadog-origin".to_string(), "synthetics".to_string()),
            ]),
            SpanContext::default(),
        ),
        valid_datadog_no_datadog_style: (
            Some(vec![TracePropagationStyle::TraceContext]),
            VALID_DATADOG_HEADERS.clone(),
            SpanContext::default(),
        ),
        // TraceContext Headers
        valid_tracecontext_simple: (
            Some(vec![TracePropagationStyle::TraceContext]),
            VALID_TRACECONTEXT_HEADERS_BASIC.clone(),
            SpanContext {
                trace_id: TRACE_ID,
                span_id: 67_667_974_448_284_343,
                sampling: Sampling {
                    priority: Some(priority::USER_KEEP),
                    mechanism: None,
                },
                origin: Some("rum".to_string()),
                tags: HashMap::from([
                    ("tracestate".to_string(), "dd=p:00f067aa0ba902b7;s:2;o:rum".to_string()),
                    ("traceparent".to_string(), "00-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-01".to_string()),
                    ("_dd.parent_id".to_string(), "00f067aa0ba902b7".to_string()),
                ]),
                links: vec![],
                is_remote: true,
                tracestate: Tracestate::from_str("dd=p:00f067aa0ba902b7;s:2;o:rum").ok()
            }
        ),
        valid_tracecontext_rum_no_sampling_decision: (
            Some(vec![TracePropagationStyle::TraceContext]),
            VALID_TRACECONTEXT_HEADERS_RUM_NO_SAMPLING_DECISION.clone(),
            SpanContext {
                trace_id: TRACE_ID,
                span_id: 67_667_974_448_284_343,
                sampling: Sampling {
                    priority: Some(priority::AUTO_REJECT),
                    mechanism: None,
                },
                origin: Some("rum".to_string()),
                tags: HashMap::from([
                    ("tracestate".to_string(), "dd=o:rum".to_string()),
                    ("traceparent".to_string(), "00-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-00".to_string()),
                ]),
                links: vec![],
                is_remote: true,
                tracestate: Tracestate::from_str("dd=o:rum").ok()
            }
        ),
        // B3 Headers
        // todo: all of them
        // B3 single Headers
        // todo: all of them
        // All Headers
        valid_all_headers: (
            None::<Vec<TracePropagationStyle>>,
            ALL_VALID_HEADERS.clone(),
            SpanContext {
                trace_id: 13_088_165_645_273_925_489,
                span_id: 5678,
                sampling: Sampling {
                    priority: Some(priority::AUTO_KEEP),
                    mechanism: Some(mechanism::MANUAL),
                },
                origin: Some("synthetics".to_string()),
                tags: HashMap::from([
                    ("_dd.p.dm".to_string(), "-4".to_string())
                ]),
                links: vec![
                    SpanLink {
                        trace_id: 7_277_407_061_855_694_839,
                        trace_id_high: Some(9291375655657946024),
                        span_id: 67_667_974_448_284_343,
                        flags: Some(1),
                        tracestate: Some("dd=s:2;o:rum;t.dm:-4;t.usr.id:baz64,congo=t61rcWkgMz".to_string()),
                        attributes: Some(HashMap::from([
                            ("reason".to_string(), "terminated_context".to_string()),
                            ("context_headers".to_string(), "tracecontext".to_string()),
                        ])),
                    }
                ],
                is_remote: true,
                tracestate: None
            },
        ),
        valid_all_headers_all_styles: (
            Some(vec![TracePropagationStyle::Datadog, TracePropagationStyle::TraceContext]),
            ALL_VALID_HEADERS.clone(),
            SpanContext {
                trace_id: 13_088_165_645_273_925_489,
                span_id: 5678,
                sampling: Sampling {
                    priority: Some(priority::AUTO_KEEP),
                    mechanism: Some(mechanism::MANUAL),
                },
                origin: Some("synthetics".to_string()),
                tags: HashMap::from([
                    ("_dd.p.dm".to_string(), "-4".to_string())
                ]),
                links: vec![
                    SpanLink {
                        trace_id: 7_277_407_061_855_694_839,
                        trace_id_high: Some(9291375655657946024),
                        span_id: 67_667_974_448_284_343,
                        flags: Some(1),
                        tracestate: Some("dd=s:2;o:rum;t.dm:-4;t.usr.id:baz64,congo=t61rcWkgMz".to_string()),
                        attributes: Some(HashMap::from([
                            ("reason".to_string(), "terminated_context".to_string()),
                            ("context_headers".to_string(), "tracecontext".to_string()),
                        ])),
                    }
                    // todo: b3 span links
                ],
                is_remote: true,
                tracestate: None
            },
        ),
        valid_all_headers_datadog_style: (
            Some(vec![TracePropagationStyle::Datadog]),
            ALL_VALID_HEADERS.clone(),
            SpanContext {
                trace_id: 13_088_165_645_273_925_489,
                span_id: 5678,
                sampling: Sampling {
                    priority: Some(priority::AUTO_KEEP),
                    mechanism: Some(mechanism::MANUAL),
                },
                origin: Some("synthetics".to_string()),
                tags: HashMap::from([
                    ("_dd.p.dm".to_string(), "-4".to_string())
                ]),
                links: vec![],
                is_remote: true,
                tracestate: None
            },
        ),
        // todo: valid_all_headers_b3_style
        // todo: valid_all_headers_both_b3_styles
        // todo: valid_all_headers_b3_single_style
        none_style: (
            Some(vec![TracePropagationStyle::None]),
            ALL_VALID_HEADERS.clone(),
            SpanContext::default(),
        ),
        valid_style_and_none_still_extracts: (
            Some(vec![TracePropagationStyle::Datadog, TracePropagationStyle::None]),
            ALL_VALID_HEADERS.clone(),
            SpanContext {
                trace_id: 13_088_165_645_273_925_489,
                span_id: 5678,
                sampling: Sampling {
                    priority: Some(priority::AUTO_KEEP),
                    mechanism: Some(mechanism::MANUAL),
                },
                origin: Some("synthetics".to_string()),
                tags: HashMap::from([
                    ("_dd.p.dm".to_string(), "-4".to_string())
                ]),
                links: vec![],
                is_remote: true,
                tracestate: None
            }
        ),
        // Order matters
        // todo: order_matters_b3_single_header_first
        // todo: order_matters_b3_first
        // todo: order_matters_b3_second_no_datadog_headers
        // Tracestate is still added when TraceContext style comes later and matches
        // first style's `trace_id`
        additional_tracestate_support_when_present_and_matches_first_style_trace_id: (
            Some(vec![TracePropagationStyle::Datadog, TracePropagationStyle::TraceContext]),
            DATADOG_TRACECONTEXT_MATCHING_TRACE_ID_HEADERS.clone(),
            SpanContext {
                trace_id: 7_277_407_061_855_694_839,
                span_id: 67_667_974_448_284_343,
                sampling: Sampling {
                    priority: Some(priority::AUTO_KEEP),
                    mechanism: None,
                },
                origin: Some("synthetics".to_string()),
                tags: HashMap::from([
                    ("_dd.parent_id".to_string(), "000000000000162e".to_string()),
                    (TRACESTATE_KEY.to_string(), "dd=s:2;o:rum;t.dm:-4;t.usr.id:baz64,congo=t61rcWkgMzE".to_string())
                ]),
                links: vec![],
                is_remote: true,
                tracestate: Some(Tracestate::from_str("dd=s:2;o:rum;t.dm:-4;t.usr.id:baz64,congo=t61rcWkgMzE").unwrap())
            }
        ),
        // Tracestate is not added when TraceContext style comes later and does not
        // match first style's `trace_id`
        no_additional_tracestate_support_when_present_and_trace_id_does_not_match: (
            Some(vec![TracePropagationStyle::Datadog, TracePropagationStyle::TraceContext]),
            NO_TRACESTATE_SUPPORT_NOT_MATCHING_TRACE_ID.clone(),
            SpanContext {
                trace_id: 13_088_165_645_273_925_489,
                span_id: 5678,
                sampling: Sampling {
                    priority: Some(priority::AUTO_KEEP),
                    mechanism: Some(mechanism::MANUAL),
                },
                origin: Some("synthetics".to_string()),
                tags: HashMap::from([
                    ("_dd.p.dm".to_string(), "-4".to_string())
                ]),
                links: vec![
                    SpanLink {
                        trace_id: 7_277_407_061_855_694_839,
                        trace_id_high: Some(9291375655657946024),
                        span_id: 67_667_974_448_284_343,
                        flags: Some(0),
                        tracestate: Some("dd=o:rum".to_string()),
                        attributes: Some(HashMap::from([
                            ("reason".to_string(), "terminated_context".to_string()),
                            ("context_headers".to_string(), "tracecontext".to_string()),
                        ])),
                    }
                ],
                is_remote: true,
                tracestate: None
            }
        ),
        valid_all_headers_no_style: (
            Some(vec![]),
            ALL_VALID_HEADERS.clone(),
            SpanContext::default(),
        ),
        datadog_tracecontext_conflicting_span_ids: (
            Some(vec![TracePropagationStyle::Datadog, TracePropagationStyle::TraceContext]),
            HashMap::from([
                (
                    "x-datadog-trace-id".to_string(),
                    "9291375655657946024".to_string(),
                ),
                ("x-datadog-parent-id".to_string(), "15".to_string(),),
                ("traceparent".to_string(), "00-000000000000000080f198ee56343ba8-000000000000000a-01".to_string()),
            ]),
            SpanContext {
                trace_id: 9_291_375_655_657_946_024,
                span_id: 10,
                sampling: Sampling {
                    priority: None,
                    mechanism: None,
                },
                origin: None,
                tags: HashMap::from([
                    ("_dd.parent_id".to_string(), "000000000000000f".to_string()),
                ]),
                links: vec![],
                is_remote: true,
                tracestate: None
            }
        ),
        // todo: all_headers_all_styles_tracecontext_t_id_match_no_span_link
        all_headers_all_styles_do_not_create_span_link_for_context_w_out_span_id: (
            Some(vec![TracePropagationStyle::TraceContext, TracePropagationStyle::Datadog]),
            ALL_HEADERS_CHAOTIC_2.clone(),
            SpanContext {
                trace_id: 7_277_407_061_855_694_839,
                span_id: 67_667_974_448_284_343,
                sampling: Sampling {
                    priority: Some(priority::USER_KEEP),
                    mechanism: Some(mechanism::MANUAL),
                },
                origin: Some("rum".to_string()),
                tags: HashMap::from([
                    ("_dd.p.dm".to_string(), "-4".to_string()),
                    ("_dd.p.usr.id".to_string(), "baz64".to_string()),
                    ("traceparent".to_string(), "00-000000000000000064fe8b2a57d3eff7-00f067aa0ba902b7-01".to_string()),
                    ("tracestate".to_string(), "dd=s:2;o:rum;t.dm:-4;t.usr.id:baz64,congo=t61rcWkgMzE".to_string()),
                ]),
                links: vec![
                    SpanLink {
                        trace_id: 13_088_165_645_273_925_489,
                        trace_id_high: None,
                        span_id: 5678,
                        flags: Some(1),
                        tracestate: None,
                        attributes: Some(HashMap::from([
                            ("context_headers".to_string(), "datadog".to_string()),
                            ("reason".to_string(), "terminated_context".to_string()),
                        ])),
                    }
                ],
                is_remote: true,
                tracestate: Tracestate::from_str("dd=s:2;o:rum;t.dm:-4;t.usr.id:baz64,congo=t61rcWkgMzE").ok()
            }
        ),
        all_headers_all_styles_tracecontext_primary_only_datadog_t_id_diff: (
            Some(vec![TracePropagationStyle::TraceContext, TracePropagationStyle::Datadog]),
            ALL_VALID_HEADERS.clone(),
            SpanContext {
                trace_id: TRACE_ID,
                span_id: 67_667_974_448_284_343,
                sampling: Sampling {
                    priority: Some(priority::USER_KEEP),
                    mechanism: Some(mechanism::MANUAL),
                },
                origin: Some("rum".to_string()),
                tags: HashMap::from([
                    ("_dd.p.dm".to_string(), "-4".to_string()),
                    ("_dd.p.usr.id".to_string(), "baz64".to_string()),
                    ("traceparent".to_string(), "00-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-01".to_string()),
                    ("tracestate".to_string(), "dd=s:2;o:rum;t.dm:-4;t.usr.id:baz64,congo=t61rcWkgMz".to_string()),
                ]),
                links: vec![
                    SpanLink {
                        trace_id: 13_088_165_645_273_925_489,
                        trace_id_high: None,
                        span_id: 5678,
                        flags: Some(1),
                        tracestate: None,
                        attributes: Some(HashMap::from([
                            ("reason".to_string(), "terminated_context".to_string()),
                            ("context_headers".to_string(), "datadog".to_string()),
                        ])),
                    }
                ],
                is_remote: true,
                tracestate: Some(Tracestate {
                    sampling: Some(Sampling { priority: Some(priority::USER_KEEP), mechanism: Some(mechanism::MANUAL) }),
                    origin: Some("rum".to_string()),
                    lower_order_trace_id: None,
                    propagation_tags: Some(HashMap::from([("t.usr.id".to_string(), "baz64".to_string()), ("t.dm".to_string(), "-4".to_string())])),
                    additional_values: Some(vec![("congo".to_string(), "t61rcWkgMz".to_string())])
                }),
            }
        ),

        all_headers_all_styles_datadog_primary_only_datadog_t_id_diff: (
            Some(vec![TracePropagationStyle::Datadog, TracePropagationStyle::TraceContext]),
            ALL_VALID_HEADERS.clone(),
            SpanContext {
                trace_id: 13_088_165_645_273_925_489,
                span_id: 5678,
                sampling: Sampling {
                    priority: Some(priority::AUTO_KEEP),
                    mechanism: Some(mechanism::MANUAL),
                },
                origin: Some("synthetics".to_string()),
                tags: HashMap::from([
                    ("_dd.p.dm".to_string(), "-4".to_string())
                ]),
                links: vec![
                    SpanLink {
                        trace_id: 7_277_407_061_855_694_839,
                        trace_id_high: Some(9291375655657946024),
                        span_id: 67_667_974_448_284_343,
                        flags: Some(1),
                        tracestate: Some("dd=s:2;o:rum;t.dm:-4;t.usr.id:baz64,congo=t61rcWkgMz".to_string()),
                        attributes: Some(HashMap::from([
                            ("reason".to_string(), "terminated_context".to_string()),
                            ("context_headers".to_string(), "tracecontext".to_string()),
                        ])),
                    }
                ],
                is_remote: true,
                tracestate: None
            }
        ),
        // todo: datadog_primary_match_tracecontext_dif_from_b3_b3multi_invalid
    }

    fn get_config(
        extract: Option<Vec<TracePropagationStyle>>,
        _: Option<Vec<TracePropagationStyle>>,
    ) -> Arc<Config> {
        let mut builder = Config::builder();
        builder.set_trace_propagation_style_extract(extract.unwrap_or_default());
        Arc::new(builder.build())
    }

    #[test]
    fn test_new_filter_propagators() {
        let extract = Some(vec![
            TracePropagationStyle::Datadog,
            TracePropagationStyle::TraceContext,
        ]);
        let config = get_config(extract, None);
        let propagator = DatadogCompositePropagator::new(config);

        assert_eq!(propagator.extractors.len(), 2);
    }

    #[test]
    fn test_new_filter_empty_list_propagators() {
        let extract = Some(vec![]);
        let config = get_config(extract, None);
        let propagator = DatadogCompositePropagator::new(config);

        assert_eq!(propagator.extractors.len(), 0);
    }

    #[test]
    fn test_new_no_propagators() {
        let extract = Some(vec![TracePropagationStyle::None]);
        let config = get_config(extract, None);
        let propagator = DatadogCompositePropagator::new(config);

        assert_eq!(propagator.extractors.len(), 0);
    }

    #[test]
    fn test_extract_available_contexts() {
        let extract = Some(vec![
            TracePropagationStyle::Datadog,
            TracePropagationStyle::TraceContext,
        ]);
        let config = get_config(extract, None);

        let propagator = DatadogCompositePropagator::new(config.clone());

        let carrier = HashMap::from([
            (
                "traceparent".to_string(),
                "00-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-01".to_string(),
            ),
            (
                "tracestate".to_string(),
                "dd=p:00f067aa0ba902b7;s:2;o:rum".to_string(),
            ),
            (
                "x-datadog-trace-id".to_string(),
                "7277407061855694839".to_string(),
            ),
            (
                "x-datadog-parent-id".to_string(),
                "67667974448284343".to_string(),
            ),
            ("x-datadog-sampling-priority".to_string(), "2".to_string()),
            ("x-datadog-origin".to_string(), "rum".to_string()),
            (
                "x-datadog-tags".to_string(),
                "_dd.p.test=value,_dd.p.tid=9291375655657946024,any=tag".to_string(),
            ),
        ]);
        let contexts = propagator.extract_available_contexts(&carrier, &config);

        assert_eq!(contexts.len(), 2);
    }

    #[test]
    fn test_extract_available_contexts_no_contexts() {
        let extract = Some(vec![TracePropagationStyle::Datadog]);
        let config = get_config(extract, None);

        let propagator = DatadogCompositePropagator::new(config.clone());

        let carrier = HashMap::from([
            (
                "traceparent".to_string(),
                "00-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-01".to_string(),
            ),
            (
                "tracestate".to_string(),
                "dd=p:00f067aa0ba902b7;s:2;o:rum".to_string(),
            ),
        ]);
        let contexts = propagator.extract_available_contexts(&carrier, &config);

        assert_eq!(contexts.len(), 0);
    }

    #[test]
    fn test_extract_first_datadog() {
        let extract = vec![
            TracePropagationStyle::Datadog,
            TracePropagationStyle::TraceContext,
        ];

        let mut builder = Config::builder();
        builder.set_trace_propagation_style_extract(extract);
        builder.set_trace_propagation_extract_first(true);
        let config = Arc::new(builder.build());

        let propagator = DatadogCompositePropagator::new(config);

        let carrier = HashMap::from([
            (
                "traceparent".to_string(),
                "00-11111111111111110000000000000001-000000000000000f-01".to_string(),
            ),
            (
                "tracestate".to_string(),
                "dd=s:2;p:0123456789abcdef,foo=1".to_string(),
            ),
            ("x-datadog-trace-id".to_string(), "1".to_string()),
            ("x-datadog-parent-id".to_string(), "987654320".to_string()),
            (
                "x-datadog-tags".to_string(),
                "_dd.p.tid=1111111111111111".to_string(),
            ),
        ]);
        let context = propagator.extract(&carrier).expect("context is extracted");

        assert_eq!(context.span_id, 987654320);
        assert!(!context.tags.contains_key(DATADOG_LAST_PARENT_ID_KEY));
    }

    fn assert_hashmap_keys(hm1: &HashMap<String, String>, hm2: &HashMap<String, String>) {
        for (k, expected_value) in hm1.clone() {
            assert!(
                hm2.get(&k).is_some(),
                "{k} is missing in {hm2:?}. Compared to {hm1:?}"
            );

            if let Some(carrier_value) = &hm2.get(&k) {
                match k.as_str() {
                    "x-datadog-tags" => assert_eq_unordered!(
                        carrier_value.split(',').collect::<Vec<&str>>(),
                        expected_value.split(',').collect::<Vec<&str>>(),
                        "wrong x-datadog-tags"
                    ),
                    "tracestate" => assert_eq_unordered!(
                        carrier_value.split(';').collect::<Vec<&str>>(),
                        expected_value.split(';').collect::<Vec<&str>>(),
                        "wrong tracestate"
                    ),
                    _ => assert_eq!(**carrier_value, expected_value),
                }
            }
        }
    }

    macro_rules! test_propagation_inject {
        ($($name:ident: $value:expr,)*) => {
            $(
                #[test]
                fn $name() {
                    use crate::propagation::context::span_context_to_inject;

                    let (styles, mut context, expected) = $value;

                    let builder = if let Some(styles) = styles {
                        let mut b = Config::builder();
                        b.set_trace_propagation_style_inject(styles.to_vec());
                        b
                    } else {
                        Config::builder()
                    };

                    let config = Arc::new(builder.build());
                    let propagator = DatadogCompositePropagator::new(config);

                    let mut inject_context = span_context_to_inject(&mut context);
                    let mut carrier = HashMap::new();
                    propagator.inject(&mut inject_context, &mut carrier);

                    assert_hashmap_keys(&expected, &carrier);
                    assert_hashmap_keys(&carrier, &expected);
                }
            )*
        }
    }

    static INJECT_DATADOG_VALID_HEADERS_128BIT: LazyLock<HashMap<String, String>> =
        LazyLock::new(|| {
            HashMap::from([
                (
                    "x-datadog-trace-id".to_string(),
                    TRACE_ID_LOWER_ORDER_BITS.to_string(),
                ),
                ("x-datadog-parent-id".to_string(), "5678".to_string()),
                ("x-datadog-origin".to_string(), "synthetics".to_string()),
                ("x-datadog-sampling-priority".to_string(), "1".to_string()),
                (
                    "x-datadog-tags".to_string(),
                    "_dd.p.tid=80f198ee56343ba8,_dd.p.dm=-3".to_string(),
                ),
            ])
        });
    static INJECT_TRACECONTEXT_VALID_HEADERS_128BIT: LazyLock<HashMap<String, String>> =
        LazyLock::new(|| {
            HashMap::from([
                (
                    "traceparent".to_string(),
                    "00-80f198ee56343ba864fe8b2a57d3eff7-000000000000162e-01".to_string(),
                ),
                (
                    "tracestate".to_string(),
                    "dd=s:1;o:synthetics;p:000000000000162e;t.dm:-3".to_string(),
                ),
            ])
        });
    static INJECT_ALL_VALID_HEADERS_128BIT: LazyLock<HashMap<String, String>> =
        LazyLock::new(|| {
            let mut h = HashMap::new();
            h.extend(INJECT_DATADOG_VALID_HEADERS_128BIT.clone());
            h.extend(INJECT_TRACECONTEXT_VALID_HEADERS_128BIT.clone());

            // datadog propagator adds _dd.p.tid tag when injecting and it ends up in tracestate
            h.insert(
                "tracestate".to_string(),
                h["tracestate"].clone() + ";t.tid:80f198ee56343ba8",
            );
            h
        });
    static INJECT_ALL_VALID_HEADERS_128BIT_WITHOUT_TID: LazyLock<HashMap<String, String>> =
        LazyLock::new(|| {
            let mut h = HashMap::new();
            h.extend(INJECT_DATADOG_VALID_HEADERS_128BIT.clone());
            h.extend(INJECT_TRACECONTEXT_VALID_HEADERS_128BIT.clone());

            h
        });
    static INJECT_ALL_VALID_HEADERS: LazyLock<HashMap<String, String>> = LazyLock::new(|| {
        HashMap::from([
            (
                "x-datadog-trace-id".to_string(),
                TRACE_ID_LOWER_ORDER_BITS.to_string(),
            ),
            ("x-datadog-parent-id".to_string(), "5678".to_string()),
            ("x-datadog-origin".to_string(), "synthetics".to_string()),
            ("x-datadog-sampling-priority".to_string(), "1".to_string()),
            ("x-datadog-tags".to_string(), "_dd.p.dm=-3".to_string()),
            (
                "traceparent".to_string(),
                "00-000000000000000064fe8b2a57d3eff7-000000000000162e-01".to_string(),
            ),
            (
                "tracestate".to_string(),
                "dd=s:1;o:synthetics;p:000000000000162e;t.dm:-3".to_string(),
            ),
        ])
    });

    test_propagation_inject! {
        inject_default_64bit_trace_id: (
            None::<Vec<TracePropagationStyle>>,
            &mut SpanContext {
                trace_id: TRACE_ID_LOWER_ORDER_BITS as u128,
                span_id: 5678,
                sampling: Sampling {
                    priority: Some(priority::AUTO_KEEP),
                    mechanism: Some(mechanism::LOCAL_USER_TRACE_SAMPLING_RULE),
                },
                origin: Some("synthetics".to_string()),
                tags: HashMap::from([
                    ("_dd.p.dm".to_string(), "-3".to_string())
                ]),
                links: vec![],
                is_remote: true,
                tracestate: None
            },
            INJECT_ALL_VALID_HEADERS.clone()
        ),

        inject_default_128bit_trace_id: (
            None::<Vec<TracePropagationStyle>>,
            &mut SpanContext {
                trace_id: TRACE_ID,
                span_id: 5678,
                sampling: Sampling {
                    priority: Some(priority::AUTO_KEEP),
                    mechanism: Some(mechanism::LOCAL_USER_TRACE_SAMPLING_RULE),
                },
                origin: Some("synthetics".to_string()),
                tags: HashMap::from([
                    ("_dd.p.dm".to_string(), "-3".to_string())
                ]),
                links: vec![],
                is_remote: true,
                tracestate: None
            },
            INJECT_ALL_VALID_HEADERS_128BIT.clone()
        ),

        inject_datadog_128bit_trace_id: (
            Some(vec![TracePropagationStyle::Datadog]),
            &mut SpanContext {
                trace_id: TRACE_ID,
                span_id: 5678,
                sampling: Sampling {
                    priority: Some(priority::AUTO_KEEP),
                    mechanism: Some(mechanism::LOCAL_USER_TRACE_SAMPLING_RULE),
                },
                origin: Some("synthetics".to_string()),
                tags: HashMap::from([
                    ("_dd.p.dm".to_string(), "-3".to_string())
                ]),
                links: vec![],
                is_remote: true,
                tracestate: None
            },
            INJECT_DATADOG_VALID_HEADERS_128BIT.clone()
        ),

        inject_tracecontext_128bit_trace_id: (
            Some(vec![TracePropagationStyle::TraceContext]),
            &mut SpanContext {
                trace_id: TRACE_ID,
                span_id: 5678,
                sampling: Sampling {
                    priority: Some(priority::AUTO_KEEP),
                    mechanism: None,
                },
                origin: Some("synthetics".to_string()),
                tags: HashMap::from([
                    ("_dd.p.dm".to_string(), "-3".to_string())
                ]),
                links: vec![],
                is_remote: true,
                tracestate: None
            },
            INJECT_TRACECONTEXT_VALID_HEADERS_128BIT.clone()
        ),

        inject_tracecontext_tracecontext_and_datadog: (
            Some(vec![TracePropagationStyle::TraceContext, TracePropagationStyle::Datadog]),
            &mut SpanContext {
                trace_id: TRACE_ID,
                span_id: 5678,
                sampling: Sampling {
                    priority: Some(priority::AUTO_KEEP),
                    mechanism: None,
                },
                origin: Some("synthetics".to_string()),
                tags: HashMap::from([
                    ("_dd.p.dm".to_string(), "-3".to_string())
                ]),
                links: vec![],
                is_remote: true,
                tracestate: None
            },
            INJECT_ALL_VALID_HEADERS_128BIT_WITHOUT_TID.clone()
        ),

        inject_tracecontext_empty_config: (
            Some(vec![]),
            &mut SpanContext {
                trace_id: TRACE_ID,
                span_id: 5678,
                sampling: Sampling {
                    priority: Some(priority::AUTO_KEEP),
                    mechanism: None,
                },
                origin: Some("synthetics".to_string()),
                tags: HashMap::from([
                    ("_dd.p.dm".to_string(), "-3".to_string())
                ]),
                links: vec![],
                is_remote: true,
                tracestate: None
            },
            HashMap::<String,String>::new()
        ),

        inject_tracecontext_style_none: (
            Some(vec![TracePropagationStyle::None]),
            &mut SpanContext {
                trace_id: TRACE_ID,
                span_id: 5678,
                sampling: Sampling {
                    priority: Some(priority::AUTO_KEEP),
                    mechanism: None,
                },
                origin: Some("synthetics".to_string()),
                tags: HashMap::from([
                    ("_dd.p.dm".to_string(), "-3".to_string())
                ]),
                links: vec![],
                is_remote: true,
                tracestate: None
            },
            HashMap::<String,String>::new()
        ),
    }

    #[test]
    fn test_default_keys() {
        let extract = Some(vec![
            TracePropagationStyle::Datadog,
            TracePropagationStyle::TraceContext,
        ]);
        let config = get_config(extract, None);

        let propagator = DatadogCompositePropagator::new(config);

        assert_eq!(
            vec![
                "x-datadog-trace-id",
                "x-datadog-origin",
                "x-datadog-parent-id",
                "x-datadog-sampling-priority",
                "x-datadog-tags",
                "traceparent",
                "tracestate"
            ],
            propagator.keys()
        )
    }

    #[test]
    fn test_tracecontext_keys() {
        let extract = Some(vec![TracePropagationStyle::TraceContext]);
        let config = get_config(extract, None);

        let propagator = DatadogCompositePropagator::new(config);

        assert_eq!(vec!["traceparent", "tracestate"], propagator.keys())
    }

    #[test]
    fn test_datadog_keys() {
        let extract = Some(vec![TracePropagationStyle::Datadog]);
        let config = get_config(extract, None);

        let propagator = DatadogCompositePropagator::new(config);

        assert_eq!(
            vec![
                "x-datadog-trace-id",
                "x-datadog-origin",
                "x-datadog-parent-id",
                "x-datadog-sampling-priority",
                "x-datadog-tags",
            ],
            propagator.keys()
        )
    }
}
