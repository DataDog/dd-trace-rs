// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use lazy_static::lazy_static;
use regex::Regex;
use std::{collections::HashMap, str::FromStr};

use crate::{
    carrier::{Extractor, Injector},
    context::{Sampling, SpanContext, Traceparent, Tracestate, DATADOG_PROPAGATION_TAG_PREFIX},
    datadog::{DATADOG_LAST_PARENT_ID_KEY, INVALID_SEGMENT_REGEX},
    error::Error,
};

use dd_trace::{
    constants::SAMPLING_DECISION_MAKER_TAG_KEY,
    sampling::{mechanism, priority, SamplingMechanism, SamplingPriority},
};

use dd_trace::{dd_error, dd_warn};

// Traceparent Keys
pub const TRACEPARENT_KEY: &str = "traceparent";
pub const TRACESTATE_KEY: &str = "tracestate";

const TRACESTATE_VALUES_SEPARATOR: &str = ",";
pub const TRACESTATE_DATADOG_PROPAGATION_TAG_PREFIX: &str = "t.";

lazy_static! {
    static ref TRACEPARENT_REGEX: Regex =
        Regex::new(r"^([a-f0-9]{2})-([a-f0-9]{32})-([a-f0-9]{16})-([a-f0-9]{2})(-.*)?$")
            .expect("failed creating regex");
    static ref TRACECONTEXT_HEADER_KEYS: [String; 2] =
        [TRACEPARENT_KEY.to_owned(), TRACESTATE_KEY.to_owned()];
}

pub fn inject(context: &mut SpanContext, carrier: &mut dyn Injector) {
    if context.trace_id != 0 && context.span_id != 0 {
        inject_traceparent(context, carrier);
        inject_tracestate(context, carrier);
    }
}

fn inject_traceparent(context: &SpanContext, carrier: &mut dyn Injector) {
    // TODO: if higher trace_id 64bits are 0, we should verify _dd.p.tid is unset
    // if not 0, verify that `_dd.p.tid` is either unset or set to the encoded value of
    // the higher-order 64 bits
    let trace_id = format!("{:032x}", context.trace_id);
    let parent_id = format!("{:016x}", context.span_id);

    let flags = context
        .sampling
        .and_then(|sampling| sampling.priority)
        .map(|priority| if priority.is_keep() { "01" } else { "00" })
        .unwrap_or("00");

    let traceparent = format!("00-{trace_id}-{parent_id}-{flags}");

    carrier.set(TRACEPARENT_KEY, traceparent);
}

fn inject_tracestate(context: &SpanContext, carrier: &mut dyn Injector) {
    let all_parts = Tracestate::from_context(context);

    carrier.set(
        TRACESTATE_KEY,
        all_parts
            .into_iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(TRACESTATE_VALUES_SEPARATOR),
    );
}

pub fn extract(carrier: &dyn Extractor) -> Option<SpanContext> {
    let tp = carrier.get(TRACEPARENT_KEY)?.trim();

    match extract_traceparent(tp) {
        Ok(traceparent) => {
            let mut tags = HashMap::new();
            tags.insert(TRACEPARENT_KEY.to_string(), tp.to_string());

            let mut origin = None;
            let mut sampling_priority = traceparent.sampling_priority;
            let mut mechanism = None;
            let tracestate: Option<Tracestate> = if let Some(ts) = carrier.get(TRACESTATE_KEY) {
                if let Ok(tracestate) = Tracestate::from_str(ts) {
                    tags.insert(TRACESTATE_KEY.to_string(), ts.to_string());

                    // Convert from `t.` to `_dd.p.`
                    if let Some(propagation_tags) = &tracestate.propagation_tags {
                        for (k, v) in propagation_tags {
                            if let Some(stripped) =
                                k.strip_prefix(TRACESTATE_DATADOG_PROPAGATION_TAG_PREFIX)
                            {
                                let nk = format!("{DATADOG_PROPAGATION_TAG_PREFIX}{stripped}");
                                tags.insert(nk, v.to_string());
                            }
                        }
                    }

                    if let Some(ref lpid) = tracestate.lower_order_trace_id {
                        tags.insert(DATADOG_LAST_PARENT_ID_KEY.to_string(), lpid.clone());
                    }

                    origin.clone_from(&tracestate.origin);

                    sampling_priority = define_sampling_priority(
                        traceparent.sampling_priority,
                        tracestate.sampling.unwrap_or_default().priority,
                        &mut tags,
                    );

                    mechanism = tags
                        .get(SAMPLING_DECISION_MAKER_TAG_KEY)
                        .and_then(|sm| SamplingMechanism::from_str(sm).ok());

                    Some(tracestate)
                } else {
                    None
                }
            } else {
                None
            };

            Some(SpanContext {
                trace_id: traceparent.trace_id,
                span_id: traceparent.span_id,
                sampling: Some(Sampling {
                    priority: Some(sampling_priority),
                    mechanism,
                }),
                origin,
                tags,
                links: Vec::new(),
                is_remote: true,
                tracestate,
            })
        }
        Err(e) => {
            dd_error!("Failed to extract traceparent: {e}");
            None
        }
    }
}

fn define_sampling_priority(
    traceparent_sampling_priority: SamplingPriority,
    tracestate_sampling_priority: Option<SamplingPriority>,
    tags: &mut HashMap<String, String>,
) -> SamplingPriority {
    if let Some(ts_sp) = tracestate_sampling_priority {
        // If the both traceparent and tracestate headers are sampled, keep the tracestate sampling
        // priority.
        if (traceparent_sampling_priority == priority::AUTO_KEEP && ts_sp.is_keep())
            || (traceparent_sampling_priority == priority::AUTO_REJECT && !ts_sp.is_keep())
        {
            return ts_sp;
        }
    }

    // If
    // * the tracestate sampling priority is missing
    // * the traceparent disagrees with the tracestate
    // Use the traceparent
    match traceparent_sampling_priority {
        priority::AUTO_KEEP => tags.insert(
            SAMPLING_DECISION_MAKER_TAG_KEY.to_string(),
            mechanism::DEFAULT.to_cow().into_owned(),
        ),
        priority::AUTO_REJECT => tags.remove(SAMPLING_DECISION_MAKER_TAG_KEY),
        _ => None,
    };

    traceparent_sampling_priority
}

fn extract_traceparent(traceparent: &str) -> Result<Traceparent, Error> {
    let captures = TRACEPARENT_REGEX
        .captures(traceparent)
        .ok_or_else(|| Error::extract("invalid traceparent", "traceparent"))?;

    let version = &captures[1];
    let trace_id = &captures[2];
    let span_id = &captures[3];
    let flags = &captures[4];
    let tail = captures.get(5).map_or("", |m| m.as_str());

    let trace_id = extract_trace_id(trace_id)?;

    let span_id = extract_span_id(span_id)?;
    let trace_flags = extract_trace_flags(flags)?;

    extract_version(version, tail, trace_flags)?;

    let is_sampled = (trace_flags & 0x1) == 1;
    let sampling_priority = if is_sampled {
        priority::AUTO_KEEP
    } else {
        priority::AUTO_REJECT
    };

    Ok(Traceparent {
        sampling_priority,
        trace_id,
        span_id,
    })
}

fn extract_version(version: &str, tail: &str, trace_flags: u8) -> Result<(), Error> {
    match version {
        "ff" => {
            return Err(Error::extract(
                "`ff` is an invalid traceparent version",
                "traceparent",
            ))
        }
        "00" => {
            if !tail.is_empty() && tail != "-" {
                return Err(Error::extract(
                    "Traceparent with version `00` should contain only 4 values delimited by `-`",
                    "traceparent",
                ));
            }
            if trace_flags > 2 {
                return Err(Error::extract(
                    "invalid trace flags for version 00",
                    "traceparent",
                ));
            }
        }
        _ => {
            dd_warn!("Unsupported traceparent version {version}, still atempenting to parse");
        }
    }

    Ok(())
}

fn extract_trace_id(trace_id: &str) -> Result<u128, Error> {
    if INVALID_SEGMENT_REGEX.is_match(trace_id) {
        return Err(Error::extract(
            "`0` value for trace_id is invalid",
            "traceparent",
        ));
    }

    u128::from_str_radix(trace_id, 16)
        .map_err(|_| Error::extract("Failed to decode trace_id", "traceparent"))
}

fn extract_span_id(span_id: &str) -> Result<u64, Error> {
    if INVALID_SEGMENT_REGEX.is_match(span_id) {
        return Err(Error::extract(
            "`0` value for span_id is invalid",
            "traceparent",
        ));
    }

    u64::from_str_radix(span_id, 16)
        .map_err(|_| Error::extract("Failed to decode span_id", "traceparent"))
}

fn extract_trace_flags(flags: &str) -> Result<u8, Error> {
    if flags.len() != 2 {
        return Err(Error::extract("Invalid trace flags length", "traceparent"));
    }

    u8::from_str_radix(flags, 16)
        .map_err(|_| Error::extract("Failed to decode trace_flags", "traceparent"))
}

pub fn keys() -> &'static [String] {
    TRACECONTEXT_HEADER_KEYS.as_slice()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use dd_trace::{configuration::TracePropagationStyle, sampling::priority};

    use crate::Propagator;

    use super::*;

    #[test]
    fn test_extract_traceparent_propagator() {
        let headers = HashMap::from([
            (
                "traceparent".to_string(),
                "00-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-01".to_string(),
            ),
            (
                "tracestate".to_string(),
                "dd=p:00f067aa0ba902b7;s:2;o:rum".to_string(),
            ),
        ]);

        let propagator = TracePropagationStyle::TraceContext;

        let context = propagator
            .extract(&headers)
            .expect("couldn't extract trace context");

        assert_eq!(
            context.trace_id,
            171_395_628_812_617_415_352_188_477_958_425_669_623
        );
        assert_eq!(context.span_id, 67_667_974_448_284_343);
        assert_eq!(
            context.sampling.unwrap().priority,
            Some(priority::USER_KEEP)
        );
        assert_eq!(context.origin, Some("rum".to_string()));
        assert_eq!(
            context.tags.get("traceparent").unwrap(),
            "00-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-01"
        );
        assert_eq!(
            context.tags.get("tracestate").unwrap(),
            "dd=p:00f067aa0ba902b7;s:2;o:rum"
        );
        assert_eq!(
            context.tags.get("_dd.parent_id").unwrap(),
            "00f067aa0ba902b7"
        );
    }

    #[test]
    fn test_extract_traceparent_dm_default() {
        let headers = HashMap::from([
            (
                "traceparent".to_string(),
                "00-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-01".to_string(),
            ),
            (
                "tracestate".to_string(),
                "dd=p:00f067aa0ba902b7;o:rum".to_string(),
            ),
        ]);

        let propagator = TracePropagationStyle::TraceContext;

        let context = propagator
            .extract(&headers)
            .expect("couldn't extract trace context");

        assert_eq!(context.tags["_dd.p.dm"], "-0");
    }

    #[test]
    fn test_extract_traceparent_dm_default_with_tracestate_s_0() {
        let headers = HashMap::from([
            (
                "traceparent".to_string(),
                "00-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-01".to_string(),
            ),
            (
                "tracestate".to_string(),
                "dd=p:00f067aa0ba902b7;s:0;o:rum".to_string(),
            ),
        ]);

        let propagator = TracePropagationStyle::TraceContext;

        let context = propagator
            .extract(&headers)
            .expect("couldn't extract trace context");

        assert_eq!(context.tags["_dd.p.dm"], "-0");
    }

    #[test]
    fn test_extract_traceparent_drop_dm_with_tracestate_s_not_present() {
        let headers = HashMap::from([
            (
                "traceparent".to_string(),
                "00-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-00".to_string(),
            ),
            (
                "tracestate".to_string(),
                "dd=p:00f067aa0ba902b7;o:rum".to_string(),
            ),
        ]);

        let propagator = TracePropagationStyle::TraceContext;

        let context = propagator
            .extract(&headers)
            .expect("couldn't extract trace context");

        assert_eq!(context.tags.get("_dd.p.dm"), None);
    }

    #[test]
    fn test_extract_traceparent_drop_dm_with_tracestate_s_1() {
        let headers = HashMap::from([
            (
                "traceparent".to_string(),
                "00-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-00".to_string(),
            ),
            (
                "tracestate".to_string(),
                "dd=p:00f067aa0ba902b7;s:1;o:rum".to_string(),
            ),
        ]);

        let propagator = TracePropagationStyle::TraceContext;

        let context = propagator
            .extract(&headers)
            .expect("couldn't extract trace context");

        assert_eq!(context.tags.get("_dd.p.dm"), None);
    }

    #[test]
    fn test_extract_traceparent_incorrect_trace_flags() {
        let headers = HashMap::from([(
            "traceparent".to_string(),
            "00-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-1x".to_string(),
        )]);

        let propagator = TracePropagationStyle::TraceContext;

        let context = propagator.extract(&headers);

        assert!(context.is_none());
    }

    #[test]
    fn test_extract_tracestate_incorrect_priority() {
        let headers = HashMap::from([
            (
                "traceparent".to_string(),
                "01-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-02".to_string(),
            ),
            (
                "tracestate".to_string(),
                "dd=p:00f067aa0ba902b7;s:incorrect".to_string(),
            ),
        ]);

        let propagator = TracePropagationStyle::TraceContext;

        let context = propagator
            .extract(&headers)
            .expect("couldn't extract trace context");

        assert!(context.sampling.is_some());
        assert!(context.sampling.unwrap().priority.is_some());
        assert_eq!(
            context.sampling.unwrap().priority.unwrap(),
            priority::AUTO_REJECT
        );
    }

    #[test]
    fn test_extract_tracestate_ows_handling() {
        let headers = HashMap::from([
            (
                "traceparent".to_string(),
                "00-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-01".to_string(),
            ),
            (
                "tracestate".to_string(),
                "dd= \t p:00f067aa0ba902b7;s:1,foo=1,bar= \t 2".to_string(),
            ),
        ]);

        let propagator = TracePropagationStyle::TraceContext;

        let tracestate = propagator
            .extract(&headers)
            .expect("couldn't extract trace context")
            .tracestate
            .expect("tracestate should be extracted");

        assert_eq!(
            tracestate.sampling.unwrap().priority.unwrap(),
            priority::AUTO_KEEP
        );

        assert!(tracestate.additional_values.is_some());
        assert_eq!(
            tracestate.additional_values.unwrap(),
            vec![
                ("foo".to_string(), "1".to_string()),
                ("bar".to_string(), " \t 2".to_string()),
            ]
        );
    }

    #[test]
    fn test_inject_traceparent() {
        let mut context = SpanContext {
            trace_id: u128::from_str_radix("1111aaaa2222bbbb3333cccc4444dddd", 16).unwrap(),
            span_id: u64::from_str_radix("5555eeee6666ffff", 16).unwrap(),
            sampling: Some(Sampling {
                priority: Some(priority::USER_KEEP),
                mechanism: Some(mechanism::MANUAL),
            }),
            origin: Some("foo,bar=".to_string()),
            tags: HashMap::from([(
                "_dd.p.foo bar,baz=".to_string(),
                "abc~!@#$%^&*()_+`-=".to_string(),
            )]),
            links: vec![],
            is_remote: false,
            tracestate: Tracestate::from_str("other=bleh,atel=test,dd=s:2;o:foo_bar_;t.dm:-4").ok(),
        };

        let mut carrier: HashMap<String, String> = HashMap::new();
        TracePropagationStyle::TraceContext.inject(&mut context, &mut carrier);

        assert_eq!(
            carrier[TRACEPARENT_KEY],
            "00-1111aaaa2222bbbb3333cccc4444dddd-5555eeee6666ffff-01"
        );

        assert_eq!(
            carrier[TRACESTATE_KEY],
            "dd=s:2;o:foo_bar~;p:5555eeee6666ffff;t.foo_bar_baz_:abc_!@#$%^&*()_+`-~,other=bleh,atel=test"
        );
    }

    #[test]
    fn test_inject_traceparent_with_256_max_length() {
        let mut context = SpanContext {
            trace_id: u128::from_str_radix("1111aaaa2222bbbb3333cccc4444dddd", 16).unwrap(),
            span_id: u64::from_str_radix("5555eeee6666ffff", 16).unwrap(),
            sampling: Some(Sampling {
                priority: Some(priority::USER_KEEP),
                mechanism: Some(mechanism::MANUAL),
            }),
            origin: Some("abc".repeat(200)),
            tags: HashMap::from([("_dd.p.foo".to_string(), "abc".to_string())]),
            links: vec![],
            is_remote: false,
            tracestate: None,
        };

        let mut carrier: HashMap<String, String> = HashMap::new();
        TracePropagationStyle::TraceContext.inject(&mut context, &mut carrier);

        assert_eq!(
            carrier[TRACEPARENT_KEY],
            "00-1111aaaa2222bbbb3333cccc4444dddd-5555eeee6666ffff-01"
        );

        assert_eq!(
            carrier[TRACESTATE_KEY],
            "dd=s:2;p:5555eeee6666ffff;t.foo:abc"
        );
    }

    #[test]
    fn test_inject_traceparent_with_up_to_32_vendor_parts() {
        let mut tracestate = vec![];
        for index in 0..35 {
            tracestate.push(format!("state{index}=value-{index}"));
        }

        let mut context = SpanContext {
            trace_id: u128::from_str_radix("1111aaaa2222bbbb3333cccc4444dddd", 16).unwrap(),
            span_id: u64::from_str_radix("5555eeee6666ffff", 16).unwrap(),
            sampling: Some(Sampling {
                priority: Some(priority::USER_KEEP),
                mechanism: Some(mechanism::MANUAL),
            }),
            origin: Some("rum".to_string()),
            tags: HashMap::from([("_dd.p.foo".to_string(), "abc".to_string())]),
            links: vec![],
            is_remote: false,
            tracestate: Tracestate::from_str(&tracestate.join(",")).ok(),
        };

        let mut carrier: HashMap<String, String> = HashMap::new();
        TracePropagationStyle::TraceContext.inject(&mut context, &mut carrier);

        assert_eq!(
            carrier[TRACEPARENT_KEY],
            "00-1111aaaa2222bbbb3333cccc4444dddd-5555eeee6666ffff-01"
        );

        assert!(carrier[TRACESTATE_KEY]
            .starts_with("dd=s:2;o:rum;p:5555eeee6666ffff;t.foo:abc,state0=value-0"));

        assert!(carrier[TRACESTATE_KEY].ends_with("state30=value-30"));
    }
}
