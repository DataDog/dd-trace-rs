// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Datadog sampling logic

pub(crate) mod otel_mappings;
pub(crate) mod utils;

/// Conversions between the libdd-sampling types and the
/// `datadog-trace-propagation` sampling types.
pub(crate) mod conversion {
    use crate::core::sampling as libdd_sampling;
    use datadog_trace_propagation::sampling as propagation_sampling;

    /// Converts a libdd [`libdd_sampling::SamplingPriority`] into the
    /// `datadog-trace-propagation` equivalent.
    pub(crate) fn priority_into_propagation(
        priority: libdd_sampling::SamplingPriority,
    ) -> propagation_sampling::SamplingPriority {
        propagation_sampling::SamplingPriority::from_i8(priority.into_i8())
    }

    /// Converts a `datadog-trace-propagation`
    /// [`propagation_sampling::SamplingPriority`](datadog_trace_propagation::sampling::SamplingPriority)
    /// into the libdd equivalent.
    pub(crate) fn priority_from_propagation(
        priority: propagation_sampling::SamplingPriority,
    ) -> libdd_sampling::SamplingPriority {
        libdd_sampling::SamplingPriority::from_i8(priority.into_i8())
    }

    /// Converts a libdd [`libdd_sampling::SamplingMechanism`] into the
    /// `datadog-trace-propagation` equivalent.
    pub(crate) fn mechanism_into_propagation(
        mechanism: libdd_sampling::SamplingMechanism,
    ) -> propagation_sampling::SamplingMechanism {
        propagation_sampling::SamplingMechanism::from_u8(mechanism.into_u8())
    }

    /// Converts a `datadog-trace-propagation`
    /// [`propagation_sampling::SamplingMechanism`](datadog_trace_propagation::sampling::SamplingMechanism)
    /// into the libdd equivalent.
    pub(crate) fn mechanism_from_propagation(
        mechanism: propagation_sampling::SamplingMechanism,
    ) -> libdd_sampling::SamplingMechanism {
        libdd_sampling::SamplingMechanism::from_u8(mechanism.into_u8())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_sampling_priority_round_trip() {
            for value in [i8::MIN, -2, -1, 0, 1, 2, i8::MAX] {
                let libdd_priority = libdd_sampling::SamplingPriority::from_i8(value);
                let propagation_priority = priority_into_propagation(libdd_priority);
                assert_eq!(propagation_priority.into_i8(), value);
                let round_tripped = priority_from_propagation(propagation_priority);
                assert_eq!(round_tripped, libdd_priority);
            }
        }

        #[test]
        fn test_sampling_mechanism_round_trip() {
            for value in [0u8, 1, 4, 8, 11, 12, u8::MAX] {
                let libdd_mechanism = libdd_sampling::SamplingMechanism::from_u8(value);
                let propagation_mechanism = mechanism_into_propagation(libdd_mechanism);
                assert_eq!(propagation_mechanism.into_u8(), value);
                let round_tripped = mechanism_from_propagation(propagation_mechanism);
                assert_eq!(round_tripped, libdd_mechanism);
            }
        }
    }
}

// Re-export from libdd-sampling
pub use libdd_sampling::{
    AttributeFactory, AttributeLike, DatadogSampler, SamplingData, SamplingRule,
    SamplingRulesCallback, SpanProperties, TraceIdLike, ValueLike,
};

// Re-export key public types
pub use otel_mappings::{OtelAttributeFactory, OtelSamplingData};
