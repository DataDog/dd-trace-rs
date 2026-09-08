// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Configuration types for trace context propagation.
//!
//! This module holds the propagation style and behavior enums shared by the propagators
//! in this crate and by consumers that implement [`PropagationConfig`].

use std::fmt::Display;
use std::str::FromStr;

/// DD_TRACE_PROPAGATION_BEHAVIOR_EXTRACT
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TracePropagationBehaviorExtract {
    /// `continue` (default) - incoming trace context is used as the local trace context. Baggage
    /// is propagated.
    #[default]
    Continue,
    /// `restart` - starts a new trace with a fresh trace ID and sampling decision. Incoming
    /// context is referenced via a span link with reason=propagation_behavior_extract. Baggage is
    /// propagated.
    Restart,
    /// `ignore` - discards the entire incoming trace context. Creates new trace with no parent.
    /// Baggage is discarded.
    Ignore,
}

impl FromStr for TracePropagationBehaviorExtract {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "" => Ok(TracePropagationBehaviorExtract::default()),
            "continue" => Ok(TracePropagationBehaviorExtract::Continue),
            "restart" => Ok(TracePropagationBehaviorExtract::Restart),
            "ignore" => Ok(TracePropagationBehaviorExtract::Ignore),
            _ => Err(format!("Unknown trace propagation behavior extract: '{s}'")),
        }
    }
}

impl Display for TracePropagationBehaviorExtract {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let behavior = match self {
            TracePropagationBehaviorExtract::Continue => "continue",
            TracePropagationBehaviorExtract::Restart => "restart",
            TracePropagationBehaviorExtract::Ignore => "ignore",
        };
        write!(f, "{behavior}")
    }
}

/// Trace context propagation style.
///
/// Defines how trace context is propagated across service boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TracePropagationStyle {
    /// Datadog proprietary propagation format using `x-datadog-*` headers.
    Datadog,
    /// W3C Trace Context propagation format using `traceparent` and `tracestate` headers.
    TraceContext,
    /// W3C Baggage propagation format using the `baggage` header.
    Baggage,
    /// B3 multi-header propagation format using `x-b3-*` headers.
    B3Multi,
    /// B3 single-header propagation format using the `b3` header.
    B3SingleHeader,
    /// No propagation - trace context is not propagated.
    None,
}

impl FromStr for TracePropagationStyle {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "datadog" => Ok(TracePropagationStyle::Datadog),
            "tracecontext" => Ok(TracePropagationStyle::TraceContext),
            "baggage" => Ok(TracePropagationStyle::Baggage),
            "b3multi" => Ok(TracePropagationStyle::B3Multi),
            "b3" => Ok(TracePropagationStyle::B3SingleHeader),
            "none" => Ok(TracePropagationStyle::None),
            _ => Err(format!("Unknown trace propagation style: '{s}'")),
        }
    }
}

impl Display for TracePropagationStyle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let style = match self {
            TracePropagationStyle::Datadog => "datadog",
            TracePropagationStyle::TraceContext => "tracecontext",
            TracePropagationStyle::Baggage => "baggage",
            TracePropagationStyle::B3Multi => "b3multi",
            TracePropagationStyle::B3SingleHeader => "b3",
            TracePropagationStyle::None => "none",
        };
        write!(f, "{style}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_propagation_behavior_extract_from_str() {
        assert_eq!(
            "continue".parse::<TracePropagationBehaviorExtract>(),
            Ok(TracePropagationBehaviorExtract::Continue)
        );
        assert_eq!(
            "restart".parse::<TracePropagationBehaviorExtract>(),
            Ok(TracePropagationBehaviorExtract::Restart)
        );
        assert_eq!(
            "ignore".parse::<TracePropagationBehaviorExtract>(),
            Ok(TracePropagationBehaviorExtract::Ignore)
        );
        assert_eq!(
            "".parse::<TracePropagationBehaviorExtract>(),
            Ok(TracePropagationBehaviorExtract::Continue)
        );
        assert_eq!(
            " RESTART ".parse::<TracePropagationBehaviorExtract>(),
            Ok(TracePropagationBehaviorExtract::Restart)
        );
        assert!("bogus".parse::<TracePropagationBehaviorExtract>().is_err());
    }

    #[test]
    fn test_trace_propagation_behavior_extract_display() {
        assert_eq!(
            TracePropagationBehaviorExtract::Continue.to_string(),
            "continue"
        );
        assert_eq!(
            TracePropagationBehaviorExtract::Restart.to_string(),
            "restart"
        );
        assert_eq!(
            TracePropagationBehaviorExtract::Ignore.to_string(),
            "ignore"
        );
    }

    #[test]
    fn test_trace_propagation_style_from_str() {
        assert_eq!(
            "datadog".parse::<TracePropagationStyle>(),
            Ok(TracePropagationStyle::Datadog)
        );
        assert_eq!(
            "tracecontext".parse::<TracePropagationStyle>(),
            Ok(TracePropagationStyle::TraceContext)
        );
        assert_eq!(
            "baggage".parse::<TracePropagationStyle>(),
            Ok(TracePropagationStyle::Baggage)
        );
        assert_eq!(
            "b3multi".parse::<TracePropagationStyle>(),
            Ok(TracePropagationStyle::B3Multi)
        );
        assert_eq!(
            "b3".parse::<TracePropagationStyle>(),
            Ok(TracePropagationStyle::B3SingleHeader)
        );
        assert_eq!(
            "none".parse::<TracePropagationStyle>(),
            Ok(TracePropagationStyle::None)
        );
        assert_eq!(
            " DATADOG ".parse::<TracePropagationStyle>(),
            Ok(TracePropagationStyle::Datadog)
        );
        assert!("bogus".parse::<TracePropagationStyle>().is_err());
    }

    #[test]
    fn test_trace_propagation_style_display() {
        assert_eq!(TracePropagationStyle::Datadog.to_string(), "datadog");
        assert_eq!(
            TracePropagationStyle::TraceContext.to_string(),
            "tracecontext"
        );
        assert_eq!(TracePropagationStyle::Baggage.to_string(), "baggage");
        assert_eq!(TracePropagationStyle::B3Multi.to_string(), "b3multi");
        assert_eq!(TracePropagationStyle::B3SingleHeader.to_string(), "b3");
        assert_eq!(TracePropagationStyle::None.to_string(), "none");
    }
}
