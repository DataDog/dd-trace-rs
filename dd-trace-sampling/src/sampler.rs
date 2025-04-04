// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use opentelemetry::trace::{SamplingDecision, SamplingResult, TraceContextExt, TraceId};
use opentelemetry::Context;
use opentelemetry_sdk::trace::ShouldSample;
use std::fmt;

// Knuth's multiplicative hashing factor
const KNUTH_FACTOR: u64 = 1_111_111_111_111_111_111;
// Maximum value for u64, used for sampling calculation
const MAX_UINT_64BITS: u64 = u64::MAX;

/// Sampler based on a rate.
/// Keeps (100 * `sample_rate`)% of the traces randomly. Its main purpose is to reduce
/// the instrumentation footprint.
#[derive(Clone)]
pub struct RateSampler {
    sample_rate: f64,
    sampling_id_threshold: u64,
}

impl fmt::Debug for RateSampler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RateSampler")
            .field("sample_rate", &self.sample_rate)
            .finish()
    }
}

impl RateSampler {
    /// Creates a new `RateSampler`.
    /// `sample_rate` is clamped between 0.0 and 1.0 inclusive.
    pub fn new(sample_rate: f64) -> Self {
        let clamped_rate = sample_rate.clamp(0.0, 1.0);
        // Calculate the threshold using wrapping multiplication for u64.
        // Equivalent to (sample_rate * MAX_UINT_64BITS) but avoids f64 intermediate if rate is 1.0
        let sampling_id_threshold = if clamped_rate >= 1.0 {
            MAX_UINT_64BITS
        } else {
            (clamped_rate * (MAX_UINT_64BITS as f64)) as u64
        };

        RateSampler {
            sample_rate: clamped_rate,
            sampling_id_threshold,
        }
    }

    /// Sets a new sample rate for the sampler.
    /// `sample_rate` is clamped between 0.0 and 1.0 inclusive.
    pub fn set_sample_rate(&mut self, sample_rate: f64) {
        let clamped_rate = sample_rate.clamp(0.0, 1.0);
        self.sample_rate = clamped_rate;
        // Calculate the threshold using wrapping multiplication for u64.
        self.sampling_id_threshold = if clamped_rate >= 1.0 {
            MAX_UINT_64BITS
        } else {
            (clamped_rate * (MAX_UINT_64BITS as f64)) as u64
        };
    }
}

impl ShouldSample for RateSampler {
    fn should_sample(
        &self,
        parent_context: Option<&Context>,
        trace_id: TraceId,
        _name: &str,
        _span_kind: &opentelemetry::trace::SpanKind,
        _attributes: &[opentelemetry::KeyValue],
        _links: &[opentelemetry::trace::Link],
    ) -> SamplingResult {
        // Check if there is a parent span context and if it has an active span
        if let Some(parent_ctx) = parent_context.filter(|cx| cx.has_active_span()) {
            // If a parent exists, inherit its sampling decision and trace state
            let span = parent_ctx.span();
            let parent_span_context = span.span_context();
            let decision = if parent_span_context.is_sampled() {
                SamplingDecision::RecordAndSample
            } else {
                SamplingDecision::Drop
            };
            return SamplingResult {
                decision,
                attributes: Vec::new(), // Attributes are not modified by this sampler
                trace_state: parent_span_context.trace_state().clone(),
            };
        }

        // --- No parent context or parent is not active: Apply rate-based sampling ---

        // Extract the lower 64 bits from the 128-bit trace_id
        let trace_id_u128 = u128::from_be_bytes(trace_id.to_bytes());
        let trace_id_64bits = trace_id_u128 as u64; // Cast to u64 takes the lower 64 bits

        // Perform Knuth's multiplicative hashing using wrapping multiplication
        let hashed_trace_id = trace_id_64bits.wrapping_mul(KNUTH_FACTOR);

        let decision = if hashed_trace_id <= self.sampling_id_threshold {
            SamplingDecision::RecordAndSample
        } else {
            SamplingDecision::Drop
        };

        SamplingResult {
            decision,
            attributes: Vec::new(),
            trace_state: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::trace::SamplingDecision;

    #[test]
    fn test_rate_sampler_new() {
        let sampler_zero = RateSampler::new(0.0);
        assert_eq!(sampler_zero.sample_rate, 0.0);
        assert_eq!(sampler_zero.sampling_id_threshold, 0);

        let sampler_half = RateSampler::new(0.5);
        assert_eq!(sampler_half.sample_rate, 0.5);
        assert_eq!(
            sampler_half.sampling_id_threshold,
            (0.5 * (MAX_UINT_64BITS as f64)) as u64
        );

        let sampler_one = RateSampler::new(1.0);
        assert_eq!(sampler_one.sample_rate, 1.0);
        assert_eq!(sampler_one.sampling_id_threshold, MAX_UINT_64BITS);

        // Test clamping
        let sampler_neg = RateSampler::new(-0.5);
        assert_eq!(sampler_neg.sample_rate, 0.0);
        assert_eq!(sampler_neg.sampling_id_threshold, 0);

        let sampler_two = RateSampler::new(2.0);
        assert_eq!(sampler_two.sample_rate, 1.0);
        assert_eq!(sampler_two.sampling_id_threshold, MAX_UINT_64BITS);
    }

    #[test]
    fn test_rate_sampler_set_rate() {
        let mut sampler = RateSampler::new(0.25);
        assert_eq!(sampler.sample_rate, 0.25);

        sampler.set_sample_rate(0.75);
        assert_eq!(sampler.sample_rate, 0.75);
        assert_eq!(
            sampler.sampling_id_threshold,
            (0.75 * (MAX_UINT_64BITS as f64)) as u64
        );

        // Test clamping
        sampler.set_sample_rate(-1.0);
        assert_eq!(sampler.sample_rate, 0.0);
        assert_eq!(sampler.sampling_id_threshold, 0);

        sampler.set_sample_rate(1.5);
        assert_eq!(sampler.sample_rate, 1.0);
        assert_eq!(sampler.sampling_id_threshold, MAX_UINT_64BITS);
    }

    #[test]
    fn test_rate_sampler_should_sample() {
        // Sample Rate 0.0: Should always drop
        let sampler_zero = RateSampler::new(0.0);
        for i in 0..10u64 {
            // Create a trace ID with some bytes where the lower 64 bits are set to i
            let mut bytes = [0u8; 16];
            let i_bytes = i.to_le_bytes();
            bytes[8..16].copy_from_slice(&i_bytes);
            let trace_id = TraceId::from_bytes(bytes);

            let result = sampler_zero.should_sample(
                None,
                trace_id,
                "",
                &opentelemetry::trace::SpanKind::Client,
                &[],
                &[],
            );
            assert_eq!(result.decision, SamplingDecision::Drop);
        }

        // Sample Rate 1.0: Should always sample
        let sampler_one = RateSampler::new(1.0);
        for i in 0..10u64 {
            // Create a trace ID with some bytes where the lower 64 bits are set to i
            let mut bytes = [0u8; 16];
            let i_bytes = i.to_le_bytes();
            bytes[8..16].copy_from_slice(&i_bytes);
            let trace_id = TraceId::from_bytes(bytes);

            let result = sampler_one.should_sample(
                None,
                trace_id,
                "",
                &opentelemetry::trace::SpanKind::Client,
                &[],
                &[],
            );
            assert_eq!(result.decision, SamplingDecision::RecordAndSample);
        }

        // Sample Rate 0.5: Should sample roughly half based on trace ID hashing
        // We can't deterministically check the exact outcome without knowing the hash result,
        // but we can test boundary conditions based on the known threshold.
        let sampler_half = RateSampler::new(0.5);
        let threshold = sampler_half.sampling_id_threshold;

        // Find a trace ID that should be sampled based on our hashing algorithm
        let mut found_sampled = false;
        let mut found_dropped = false;
        let mut sampled_trace_id = TraceId::INVALID;
        let mut dropped_trace_id = TraceId::INVALID;

        for i in 1..=10000u64 {
            let mut bytes = [0u8; 16];
            let i_bytes = i.to_le_bytes();
            bytes[8..16].copy_from_slice(&i_bytes);
            let trace_id = TraceId::from_bytes(bytes);

            // Extract the lower 64 bits from the 128-bit trace_id
            let trace_id_u128 = u128::from_be_bytes(trace_id.to_bytes());
            let trace_id_64bits = trace_id_u128 as u64; // Cast to u64 takes the lower 64 bits

            let hashed_trace_id = trace_id_64bits.wrapping_mul(KNUTH_FACTOR);

            if !found_sampled && hashed_trace_id <= threshold {
                sampled_trace_id = trace_id;
                found_sampled = true;
            }

            if !found_dropped && hashed_trace_id > threshold {
                dropped_trace_id = trace_id;
                found_dropped = true;
            }

            if found_sampled && found_dropped {
                break;
            }
        }

        // Verify the sampled trace ID
        if found_sampled {
            let result_sampled = sampler_half.should_sample(
                None,
                sampled_trace_id,
                "",
                &opentelemetry::trace::SpanKind::Client,
                &[],
                &[],
            );
            assert_eq!(result_sampled.decision, SamplingDecision::RecordAndSample);

            // Double check the logic
            let trace_id_u128 = u128::from_be_bytes(sampled_trace_id.to_bytes());
            let trace_id_64bits = trace_id_u128 as u64; // Cast to u64 takes the lower 64 bits
            let hashed_trace_id = trace_id_64bits.wrapping_mul(KNUTH_FACTOR);
            assert!(
                hashed_trace_id <= threshold,
                "Expected hashed ID to be below threshold"
            );
        }

        // Verify the dropped trace ID
        if found_dropped {
            let result_dropped = sampler_half.should_sample(
                None,
                dropped_trace_id,
                "",
                &opentelemetry::trace::SpanKind::Client,
                &[],
                &[],
            );
            assert_eq!(result_dropped.decision, SamplingDecision::Drop);

            // Double check the logic
            let trace_id_u128 = u128::from_be_bytes(dropped_trace_id.to_bytes());
            let trace_id_64bits = trace_id_u128 as u64; // Cast to u64 takes the lower 64 bits
            let hashed_trace_id = trace_id_64bits.wrapping_mul(KNUTH_FACTOR);
            assert!(
                hashed_trace_id > threshold,
                "Expected hashed ID to be above threshold"
            );
        }

        // Make sure we found at least one example of each
        assert!(found_sampled, "Failed to find a sampled trace ID");
        assert!(found_dropped, "Failed to find a dropped trace ID");
    }

    #[test]
    fn check_debug_impl() {
        let sampler = RateSampler::new(0.75);
        assert_eq!(
            format!("{:?}", sampler),
            "RateSampler { sample_rate: 0.75 }"
        );
    }
}
