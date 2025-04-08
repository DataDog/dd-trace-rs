// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use lazy_static::lazy_static;
use regex::Regex;
use std::{borrow::Cow, collections::HashMap, fmt::Display, str::FromStr, vec};

use dd_trace::{configuration::TracePropagationStyle, dd_debug};

use crate::tracecontext::TRACESTATE_KEY;

lazy_static! {
    static ref INVALID_ASCII_CHARACTERS_REGEX: Regex =
        Regex::new(r"[^\x20-\x7E]+").expect("failed creating regex");
}

pub const DATADOG_PROPAGATION_TAG_PREFIX: &str = "_dd.p.";
pub const DATADOG_SAMPLING_DECISION_KEY: &str = "_dd.p.dm";

#[derive(Copy, Clone, Default, Debug, PartialEq)]
pub struct Sampling {
    pub priority: Option<SamplingPriority>,
    pub mechanism: Option<SamplingMechanism>,
}

#[derive(Copy, Clone, Default, Debug, PartialEq)]
pub enum SamplingMechanism {
    #[default]
    Default = 0,
    Agent = 1,
    Rule = 3,
    Manual = 4,
    Appsec = 5,
    Span = 8,
    User = 11,
    Dynamic = 12,
}

impl Display for SamplingMechanism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prio = match self {
            Self::Default => "-0",
            Self::Agent => "-1",
            Self::Rule => "-3",
            Self::Manual => "-4",
            Self::Appsec => "-5",
            Self::Span => "-8",
            Self::User => "-11",
            Self::Dynamic => "-12",
        };
        write!(f, "{prio}")
    }
}

impl FromStr for SamplingMechanism {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "-0" => Ok(Self::Default),
            "-1" => Ok(Self::Agent),
            "-3" => Ok(Self::Rule),
            "-4" => Ok(Self::Manual),
            "-5" => Ok(Self::Appsec),
            "-8" => Ok(Self::Span),
            "-11" => Ok(Self::User),
            "-12" => Ok(Self::Dynamic),
            _ => Err(format!("Unknown Sampling mechanism: {s}")),
        }
    }
}

#[derive(Copy, Clone, Default, Debug, PartialEq)]
pub enum SamplingPriority {
    UserReject = -1,
    AutoReject = 0,

    #[default]
    AutoKeep = 1,
    UserKeep = 2,
}

impl SamplingPriority {
    pub fn is_keep(&self) -> bool {
        *self == Self::AutoKeep || *self == Self::UserKeep
    }

    pub fn from_flags(flags: u8) -> Self {
        match flags {
            0 => Self::AutoReject,
            1 => Self::AutoKeep,
            _ => Self::default(),
        }
    }
}

impl Display for SamplingPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prio = match self {
            Self::UserReject => "-1",
            Self::AutoReject => "0",
            Self::AutoKeep => "1",
            Self::UserKeep => "2",
        };
        write!(f, "{prio}")
    }
}

impl FromStr for SamplingPriority {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "-1" => Ok(Self::UserReject),
            "0" => Ok(Self::AutoReject),
            "1" => Ok(Self::AutoKeep),
            "2" => Ok(Self::UserKeep),
            _ => Err(format!("Unknown Sampling priority: {s}")),
        }
    }
}

#[derive(Clone, Default, Debug, PartialEq)]
pub struct SpanLink {
    pub trace_id: u64,
    pub trace_id_high: Option<u64>,
    pub span_id: u64,
    pub attributes: Option<HashMap<String, String>>,
    pub tracestate: Option<String>,
    pub flags: Option<u32>,
}

impl SpanLink {
    pub fn terminated_context(context: &SpanContext, style: TracePropagationStyle) -> Self {
        let flags = context
            .sampling
            .and_then(|sampling| sampling.priority)
            .map(|priority| u32::from(priority.is_keep()));

        let tracestate: Option<String> = match style {
            TracePropagationStyle::TraceContext => context.tags.get(TRACESTATE_KEY).cloned(),
            _ => None,
        };

        let attributes = Some(HashMap::from([
            ("reason".to_string(), "terminated_context".to_string()),
            ("context_headers".to_string(), style.to_string()),
        ]));

        let (trace_id_high, trace_id) = split_trace_id(context.trace_id);

        SpanLink {
            trace_id,
            trace_id_high,
            span_id: context.span_id,
            attributes,
            tracestate,
            flags,
        }
    }
}
#[derive(Clone, Default, Debug, PartialEq)]
pub struct SpanContext {
    pub trace_id: u128,
    pub span_id: u64,
    pub sampling: Option<Sampling>,
    pub origin: Option<String>,
    pub tags: HashMap<String, String>,
    pub links: Vec<SpanLink>,
    pub is_remote: bool,
    pub tracestate: Option<Tracestate>,
}

#[derive(Clone, Default, Debug, PartialEq)]
pub struct Traceparent {
    pub sampling_priority: SamplingPriority,
    pub trace_id: u128,
    pub span_id: u64,
}

#[derive(Clone, Default, Debug, PartialEq)]
pub struct Tracestate {
    pub sampling: Option<Sampling>,
    pub origin: Option<String>,
    pub lower_order_trace_id: Option<String>,
    pub propagation_tags: Option<HashMap<String, String>>,
    pub additional_values: Option<Vec<String>>,
}

impl FromStr for Tracestate {
    type Err = String;
    fn from_str(tracestate: &str) -> Result<Self, Self::Err> {
        let ts_v = tracestate.split(',').map(str::trim);
        let ts = ts_v.clone().collect::<Vec<&str>>().join(",");

        if INVALID_ASCII_CHARACTERS_REGEX.is_match(&ts) {
            dd_debug!("Received invalid tracestate header {tracestate}");
            return Err(String::from("Invalid tracestate"));
        }

        let mut dd: Option<HashMap<String, String>> = None;
        let mut additional_values = vec![];
        for v in ts_v {
            if let Some(stripped) = v.strip_prefix("dd=") {
                dd = Some(
                    stripped
                        .split(';')
                        .filter_map(|item| {
                            let mut parts = item.splitn(2, ':');
                            Some((parts.next()?.to_string(), decode_tag_value(parts.next()?)))
                        })
                        .collect(),
                );
            } else if !v.is_empty() {
                additional_values.push(v.to_string());
            }
        }

        let mut tracestate = Tracestate {
            sampling: None,
            origin: None,
            lower_order_trace_id: None,
            propagation_tags: None,
            additional_values: None,
        };

        // the original order must be maintained
        if !additional_values.is_empty() {
            tracestate.additional_values = Some(additional_values);
        }

        let propagation_tags = if let Some(dd) = dd {
            let mut tags = HashMap::new();
            let mut priority = None;
            let mut mechanism = None;

            for (k, v) in dd {
                match k.as_str() {
                    "s" => {
                        if let Ok(p_sp) = SamplingPriority::from_str(&v) {
                            priority = Some(p_sp);
                        }
                    }
                    "o" => tracestate.origin = Some(decode_tag_value(&v)),
                    "p" => tracestate.lower_order_trace_id = Some(v.to_string()),
                    "t.dm" => {
                        if let Ok(p_sm) = SamplingMechanism::from_str(&v) {
                            mechanism = Some(p_sm);
                        }
                        tags.insert(k, v);
                    }
                    _ => {
                        tags.insert(k, v);
                    }
                }
            }

            tracestate.sampling = Some(Sampling {
                priority,
                mechanism,
            });

            Some(tags)
        } else {
            None
        };

        tracestate.propagation_tags = propagation_tags;

        Ok(tracestate)
    }
}

fn decode_tag_value(value: &str) -> String {
    value.replace('~', "=")
}

pub fn encode_tag_value(value: Cow<'_, str>) -> String {
    value.replace('=', "~")
}

pub fn split_trace_id(trace_id: u128) -> (Option<u64>, u64) {
    let trace_id_lower_order_bits = trace_id as u64;

    let higher = (trace_id >> 64) as u64;
    let trace_id_higher_order_bits = if higher > 0 { Some(higher) } else { None };

    (trace_id_higher_order_bits, trace_id_lower_order_bits)
}

pub fn combine_trace_id(trace_id: u64, higher_bits_hex: Option<&String>) -> u128 {
    if let Some(combined_trace_id) = higher_bits_hex
        .and_then(|higher| u64::from_str_radix(higher, 16).ok())
        .map(|higher| {
            let higher = higher as u128;
            (higher << 64) + (trace_id as u128)
        })
    {
        combined_trace_id
    } else {
        trace_id as u128
    }
}

#[cfg(test)]
mod test {
    use crate::context::{combine_trace_id, split_trace_id};

    #[test]
    fn test_combine() {
        let trace_id = u128::MAX;

        let (higher, lower) = split_trace_id(trace_id);

        let higher_hex = format!("{:016x}", higher.unwrap());

        let combined = combine_trace_id(lower, Some(&higher_hex));

        assert_eq!(trace_id, combined)
    }
}
