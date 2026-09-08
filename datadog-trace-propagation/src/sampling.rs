// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Sampling primitives used by trace context propagation.
//!
//! This module provides the sampling priority and sampling mechanism types that travel
//! alongside propagated trace context (for example via the `x-datadog-sampling-priority`
//! header or the `_dd.p.dm` tracestate member). It mirrors the corresponding
//! `libdd-sampling` types without depending on them.

use std::{borrow::Cow, fmt, str::FromStr};

/// Key of the `_dd.p.dm` propagation tag, which carries the sampling decision maker.
pub(crate) const SAMPLING_DECISION_MAKER_TAG_KEY: &str = "_dd.p.dm";

/// Represents the sampling priority of a trace.
///
/// Positive values indicate the trace should be kept, while zero or negative
/// values indicate rejection. Use the constants in the [`priority`] module
/// for standard priority values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SamplingPriority {
    value: i8,
}

impl SamplingPriority {
    /// Creates a sampling priority from an `i8` value.
    #[must_use]
    pub const fn from_i8(value: i8) -> Self {
        Self { value }
    }

    /// Returns the sampling priority as an `i8` value.
    #[must_use]
    pub fn into_i8(self) -> i8 {
        self.value
    }

    /// Returns whether this sampling priority indicates the trace should be kept.
    ///
    /// # Returns
    ///
    /// `true` if the priority value is positive (indicating the trace should be kept),
    /// `false` otherwise (indicating the trace should be dropped).
    ///
    /// # Examples
    ///
    /// ```
    /// use datadog_trace_propagation::sampling::priority;
    ///
    /// assert!(priority::AUTO_KEEP.is_keep());
    /// assert!(priority::USER_KEEP.is_keep());
    /// assert!(!priority::AUTO_REJECT.is_keep());
    /// assert!(!priority::USER_REJECT.is_keep());
    /// ```
    #[inline(always)]
    pub fn is_keep(&self) -> bool {
        self.value > 0
    }
}

/// Sampling priority constants.
///
/// These values indicate whether a trace should be kept or rejected,
/// and whether the decision was made automatically or by the user.
pub mod priority {
    use super::SamplingPriority;

    /// User explicitly rejected this trace (priority -1).
    pub const USER_REJECT: SamplingPriority = SamplingPriority::from_i8(-1);
    /// User explicitly requested to keep this trace (priority 2).
    pub const USER_KEEP: SamplingPriority = SamplingPriority::from_i8(2);
    /// Automatically rejected by the sampler (priority 0).
    pub const AUTO_REJECT: SamplingPriority = SamplingPriority::from_i8(0);
    /// Automatically kept by the sampler (priority 1).
    pub const AUTO_KEEP: SamplingPriority = SamplingPriority::from_i8(1);
}

impl fmt::Display for SamplingPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl FromStr for SamplingPriority {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse::<i8>() {
            Ok(value) => Ok(SamplingPriority::from_i8(value)),
            Err(_) => Err(()),
        }
    }
}

/// Represents the mechanism that made a sampling decision.
///
/// The sampling mechanism identifies which component or rule determined
/// whether a trace should be sampled (kept or rejected).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SamplingMechanism {
    value: u8,
}

impl SamplingMechanism {
    /// Creates a sampling mechanism from a `u8` value.
    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        Self { value }
    }

    /// Returns the sampling mechanism as a `u8` value.
    #[must_use]
    pub fn into_u8(self) -> u8 {
        self.value
    }

    /// Returns the default sampling priority associated with this mechanism.
    ///
    /// Mechanisms whose decision is expected to be overridden by user rules map to the
    /// user priority pair (`USER_KEEP`/`USER_REJECT`); all others map to the automatic
    /// pair (`AUTO_KEEP`/`AUTO_REJECT`).
    #[must_use]
    pub fn to_priority(self, is_keep: bool) -> SamplingPriority {
        const AUTO_PAIR: PriorityPair = PriorityPair {
            keep: priority::AUTO_KEEP,
            reject: priority::AUTO_REJECT,
        };
        const USER_PAIR: PriorityPair = PriorityPair {
            keep: priority::USER_KEEP,
            reject: priority::USER_REJECT,
        };
        let pair = match self {
            mechanism::AGENT_RATE_BY_SERVICE | mechanism::DEFAULT => AUTO_PAIR,
            mechanism::MANUAL
            | mechanism::LOCAL_USER_TRACE_SAMPLING_RULE
            | mechanism::REMOTE_USER_TRACE_SAMPLING_RULE
            | mechanism::REMOTE_DYNAMIC_TRACE_SAMPLING_RULE
            | mechanism::SPAN_SAMPLING_RULE
            | mechanism::DATA_JOBS_MONITORING => USER_PAIR,
            mechanism::APPSEC => AUTO_PAIR,

            _ => AUTO_PAIR,
        };
        if is_keep {
            pair.keep
        } else {
            pair.reject
        }
    }

    /// Returns whether this mechanism is a probability (rate-based) sampling
    /// decision, for OTel consistent-probability tracestate (`ot.th`).
    ///
    /// `OTLP_INGEST_PROBABILISTIC_SAMPLING` is excluded: it's the sender's own OTel
    /// decision, with no rate or trace-id-hash contract available here to derive `th`.
    #[must_use]
    pub fn is_probability(&self) -> bool {
        matches!(
            *self,
            mechanism::DEFAULT
                | mechanism::AGENT_RATE_BY_SERVICE
                | mechanism::REMOTE_RATE
                | mechanism::REMOTE_RATE_USER
                | mechanism::REMOTE_RATE_DATADOG
                | mechanism::LOCAL_USER_TRACE_SAMPLING_RULE
                | mechanism::REMOTE_USER_TRACE_SAMPLING_RULE
                | mechanism::REMOTE_DYNAMIC_TRACE_SAMPLING_RULE
        )
    }

    /// Returns the string representation of the sampling mechanism.
    ///
    /// The format is `"-N"` (e.g. `"-4"` for manual sampling). The leading `-` comes from the
    /// propagation tags RFC, which initially had a prefix component before the `-`; that prefix
    /// was dropped, but the `-` was retained as-is for backwards compatibility with existing
    /// tracers.
    #[must_use]
    pub fn to_cow(self) -> Cow<'static, str> {
        match self {
            mechanism::DEFAULT => Cow::Borrowed("-0"),
            mechanism::AGENT_RATE_BY_SERVICE => Cow::Borrowed("-1"),
            mechanism::REMOTE_RATE => Cow::Borrowed("-2"),
            mechanism::LOCAL_USER_TRACE_SAMPLING_RULE => Cow::Borrowed("-3"),
            mechanism::MANUAL => Cow::Borrowed("-4"),
            mechanism::APPSEC => Cow::Borrowed("-5"),
            mechanism::REMOTE_RATE_USER => Cow::Borrowed("-6"),
            mechanism::REMOTE_RATE_DATADOG => Cow::Borrowed("-7"),
            mechanism::SPAN_SAMPLING_RULE => Cow::Borrowed("-8"),
            mechanism::OTLP_INGEST_PROBABILISTIC_SAMPLING => Cow::Borrowed("-9"),
            mechanism::DATA_JOBS_MONITORING => Cow::Borrowed("-10"),
            mechanism::REMOTE_USER_TRACE_SAMPLING_RULE => Cow::Borrowed("-11"),
            mechanism::REMOTE_DYNAMIC_TRACE_SAMPLING_RULE => Cow::Borrowed("-12"),
            _ => Cow::Owned(self.to_string()),
        }
    }
}

/// Sampling mechanism constants.
///
/// These constants identify which component or rule made a sampling decision.
pub mod mechanism {
    use super::SamplingMechanism;

    /// Default sampling mechanism.
    pub const DEFAULT: SamplingMechanism = SamplingMechanism::from_u8(0);
    /// Agent-based rate sampling by service.
    pub const AGENT_RATE_BY_SERVICE: SamplingMechanism = SamplingMechanism::from_u8(1);
    /// Remote configuration rate sampling.
    pub const REMOTE_RATE: SamplingMechanism = SamplingMechanism::from_u8(2);
    /// Local user-defined trace sampling rule.
    pub const LOCAL_USER_TRACE_SAMPLING_RULE: SamplingMechanism = SamplingMechanism::from_u8(3);
    /// Manual sampling decision via API.
    pub const MANUAL: SamplingMechanism = SamplingMechanism::from_u8(4);
    /// Application Security (AppSec) sampling.
    pub const APPSEC: SamplingMechanism = SamplingMechanism::from_u8(5);
    /// Remote user rate sampling.
    pub const REMOTE_RATE_USER: SamplingMechanism = SamplingMechanism::from_u8(6);
    /// Remote Datadog rate sampling.
    pub const REMOTE_RATE_DATADOG: SamplingMechanism = SamplingMechanism::from_u8(7);
    /// Span-level sampling rule.
    pub const SPAN_SAMPLING_RULE: SamplingMechanism = SamplingMechanism::from_u8(8);
    /// OTLP ingest probabilistic sampling.
    pub const OTLP_INGEST_PROBABILISTIC_SAMPLING: SamplingMechanism = SamplingMechanism::from_u8(9);
    /// Data Jobs Monitoring sampling.
    pub const DATA_JOBS_MONITORING: SamplingMechanism = SamplingMechanism::from_u8(10);
    /// Remote user-defined trace sampling rule.
    pub const REMOTE_USER_TRACE_SAMPLING_RULE: SamplingMechanism = SamplingMechanism::from_u8(11);
    /// Remote dynamic trace sampling rule.
    pub const REMOTE_DYNAMIC_TRACE_SAMPLING_RULE: SamplingMechanism =
        SamplingMechanism::from_u8(12);
}

impl fmt::Display for SamplingMechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "-{}", self.into_u8())
    }
}

impl FromStr for SamplingMechanism {
    type Err = ();

    /// Gets the sampling mechanism from its string representation.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let val: i16 = s.parse().map_err(drop)?;
        if val > 0 {
            return Err(());
        }
        let val = val.checked_neg().ok_or(())?;
        if val > u8::MAX as i16 {
            return Err(());
        }
        Ok(SamplingMechanism::from_u8(val as u8))
    }
}

struct PriorityPair {
    keep: SamplingPriority,
    reject: SamplingPriority,
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- SamplingPriority ---

    #[test]
    fn test_priority_into_i8() {
        assert_eq!(priority::AUTO_KEEP.into_i8(), 1);
        assert_eq!(priority::USER_KEEP.into_i8(), 2);
        assert_eq!(priority::AUTO_REJECT.into_i8(), 0);
        assert_eq!(priority::USER_REJECT.into_i8(), -1);
    }

    #[test]
    fn test_priority_roundtrip() {
        for value in [-128i8, -1, 0, 1, 2, 127] {
            let priority = SamplingPriority::from_i8(value);
            assert_eq!(priority.into_i8(), value);
        }
    }

    #[test]
    fn test_priority_is_keep() {
        assert!(priority::AUTO_KEEP.is_keep());
        assert!(priority::USER_KEEP.is_keep());
        assert!(!priority::AUTO_REJECT.is_keep());
        assert!(!priority::USER_REJECT.is_keep());
        assert!(!SamplingPriority::from_i8(-42).is_keep());
        assert!(SamplingPriority::from_i8(42).is_keep());
    }

    #[test]
    fn test_priority_display() {
        assert_eq!(priority::AUTO_KEEP.to_string(), "1");
        assert_eq!(priority::USER_REJECT.to_string(), "-1");
    }

    #[test]
    fn test_priority_from_str() {
        assert_eq!("1".parse::<SamplingPriority>(), Ok(priority::AUTO_KEEP));
        assert_eq!("-1".parse::<SamplingPriority>(), Ok(priority::USER_REJECT));
        assert_eq!("not-a-number".parse::<SamplingPriority>(), Err(()));
    }

    // --- SamplingMechanism ---

    #[test]
    fn test_mechanism_into_u8() {
        assert_eq!(mechanism::DEFAULT.into_u8(), 0);
        assert_eq!(mechanism::MANUAL.into_u8(), 4);
        assert_eq!(mechanism::REMOTE_DYNAMIC_TRACE_SAMPLING_RULE.into_u8(), 12);
    }

    #[test]
    fn test_mechanism_roundtrip() {
        for value in [0u8, 1, 4, 12, 255] {
            let mechanism = SamplingMechanism::from_u8(value);
            assert_eq!(mechanism.into_u8(), value);
        }
    }

    #[test]
    fn test_mechanism_to_cow() {
        assert_eq!(mechanism::DEFAULT.to_cow(), "-0");
        assert_eq!(mechanism::MANUAL.to_cow(), "-4");
        assert_eq!(
            mechanism::REMOTE_DYNAMIC_TRACE_SAMPLING_RULE.to_cow(),
            "-12"
        );
        // Unknown mechanisms fall back to the Display representation
        assert_eq!(SamplingMechanism::from_u8(200).to_cow(), "-200");
    }

    #[test]
    fn test_mechanism_from_str() {
        assert_eq!("-4".parse::<SamplingMechanism>(), Ok(mechanism::MANUAL));
        assert_eq!("-0".parse::<SamplingMechanism>(), Ok(mechanism::DEFAULT));
        assert_eq!(
            "-255".parse::<SamplingMechanism>(),
            Ok(SamplingMechanism::from_u8(u8::MAX))
        );
        assert_eq!("4".parse::<SamplingMechanism>(), Err(()));
        assert_eq!("-256".parse::<SamplingMechanism>(), Err(()));
        assert_eq!(i16::MIN.to_string().parse::<SamplingMechanism>(), Err(()));
        assert_eq!("abc".parse::<SamplingMechanism>(), Err(()));
    }

    #[test]
    fn test_mechanism_is_probability() {
        assert!(mechanism::DEFAULT.is_probability());
        assert!(mechanism::AGENT_RATE_BY_SERVICE.is_probability());
        assert!(mechanism::LOCAL_USER_TRACE_SAMPLING_RULE.is_probability());
        assert!(!mechanism::MANUAL.is_probability());
        assert!(!mechanism::APPSEC.is_probability());
        assert!(!mechanism::OTLP_INGEST_PROBABILISTIC_SAMPLING.is_probability());
    }

    #[test]
    fn test_mechanism_to_priority() {
        // AUTO pair
        assert_eq!(mechanism::DEFAULT.to_priority(true), priority::AUTO_KEEP);
        assert_eq!(mechanism::DEFAULT.to_priority(false), priority::AUTO_REJECT);
        assert_eq!(
            mechanism::AGENT_RATE_BY_SERVICE.to_priority(true),
            priority::AUTO_KEEP
        );
        // USER pair
        assert_eq!(mechanism::MANUAL.to_priority(true), priority::USER_KEEP);
        assert_eq!(mechanism::MANUAL.to_priority(false), priority::USER_REJECT);
        assert_eq!(
            mechanism::LOCAL_USER_TRACE_SAMPLING_RULE.to_priority(true),
            priority::USER_KEEP
        );
    }

    #[test]
    fn test_sampling_decision_maker_tag_key() {
        assert_eq!(SAMPLING_DECISION_MAKER_TAG_KEY, "_dd.p.dm");
    }
}
