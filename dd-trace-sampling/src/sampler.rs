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

        // Fast-path for sample rate of 0.0 (always drop) or 1.0 (always sample)
        if self.sample_rate <= 0.0 {
            return SamplingResult {
                decision: SamplingDecision::Drop,
                attributes: Vec::new(),
                trace_state: Default::default(),
            };
        }

        if self.sample_rate >= 1.0 {
            return SamplingResult {
                decision: SamplingDecision::RecordAndSample,
                attributes: Vec::new(),
                trace_state: Default::default(),
            };
        }

        // Convert trace_id to u128 and then cast to u64 to get the lower 64 bits
        let trace_id_u128 = u128::from_be_bytes(trace_id.to_bytes());
        let trace_id_64bits = trace_id_u128 as u64;

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
        for i in 0..1u64 {
            // Just test one ID to keep output readable
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
            assert_eq!(
                result.decision,
                SamplingDecision::Drop,
                "sampler_zero should drop all IDs"
            );
        }

        // Sample Rate 1.0: Should always sample
        let sampler_one = RateSampler::new(1.0);
        for i in 0..1u64 {
            // Just test one ID to keep output readable
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
            assert_eq!(
                result.decision,
                SamplingDecision::RecordAndSample,
                "sampler_one should sample all IDs"
            );
        }

        // Sample Rate 0.5: Create deterministic test cases
        let sampler_half = RateSampler::new(0.5);
        let threshold = sampler_half.sampling_id_threshold;

        // Test case for a trace ID that should be sampled (hashed value < threshold)
        // We'll use a trace ID of all zeros which hashes to 0 (guaranteed below threshold)
        let bytes_sample = [0u8; 16];
        let trace_id_sample = TraceId::from_bytes(bytes_sample);

        // Test case for a trace ID that should be dropped (hashed value > threshold)
        // We'll use a specific trace ID that we know will hash above the threshold
        let mut bytes_drop = [0u8; 16];
        // This value is carefully chosen to hash to a value above the threshold
        bytes_drop[8] = 0x80; // Set high bit to ensure it hashes above threshold
        let mut trace_id_drop = TraceId::from_bytes(bytes_drop);

        // Verify these trace IDs hash as expected, using casting approach
        let trace_id_sample_u128 = u128::from_be_bytes(trace_id_sample.to_bytes());
        let sample_u64 = trace_id_sample_u128 as u64;
        let sample_hash = sample_u64.wrapping_mul(KNUTH_FACTOR);

        let trace_id_drop_u128 = u128::from_be_bytes(trace_id_drop.to_bytes());
        let drop_u64 = trace_id_drop_u128 as u64;
        let mut drop_hash = drop_u64.wrapping_mul(KNUTH_FACTOR);

        // If our chosen value doesn't hash correctly, let's find one that does
        if drop_hash <= threshold {
            for i in 1..1000u64 {
                let mut test_bytes = [0u8; 16];
                let i_bytes = i.to_le_bytes();
                test_bytes[8..16].copy_from_slice(&i_bytes);
                let test_id = TraceId::from_bytes(test_bytes);

                let test_id_u128 = u128::from_be_bytes(test_id.to_bytes());
                let test_u64 = test_id_u128 as u64;
                let test_hash = test_u64.wrapping_mul(KNUTH_FACTOR);

                if test_hash > threshold {
                    // Found a suitable value
                    bytes_drop = test_bytes;
                    trace_id_drop = TraceId::from_bytes(bytes_drop);
                    // Update hash value for assertions
                    drop_hash = test_hash;
                    break;
                }

                if i == 999 {
                    panic!("Failed to find a value that hashes above threshold!");
                }
            }
        }

        assert!(
            sample_hash <= threshold,
            "Sample hash should be <= threshold"
        );
        assert!(drop_hash > threshold, "Drop hash should be > threshold");

        // Test the sampling decisions
        let result_sample = sampler_half.should_sample(
            None,
            trace_id_sample,
            "",
            &opentelemetry::trace::SpanKind::Client,
            &[],
            &[],
        );
        assert_eq!(
            result_sample.decision,
            SamplingDecision::RecordAndSample,
            "Sample ID should be sampled"
        );

        let result_drop = sampler_half.should_sample(
            None,
            trace_id_drop,
            "",
            &opentelemetry::trace::SpanKind::Client,
            &[],
            &[],
        );
        assert_eq!(
            result_drop.decision,
            SamplingDecision::Drop,
            "Drop ID should be dropped"
        );
    }

    #[test]
    fn check_debug_impl() {
        let sampler = RateSampler::new(0.75);
        assert_eq!(
            format!("{:?}", sampler),
            "RateSampler { sample_rate: 0.75 }"
        );
    }

    #[test]
    fn test_endianness() {
        // Create a trace ID with a value of 1 in the lower 64 bits
        let mut bytes = [0u8; 16];
        // Set just one bit in a way we can easily track
        bytes[15] = 1; // This sets the least significant byte to 1
        let trace_id = TraceId::from_bytes(bytes);

        // Extract using simplified casting approach
        let trace_id_u128 = u128::from_be_bytes(trace_id.to_bytes());
        let extracted_u64 = trace_id_u128 as u64;

        assert_eq!(extracted_u64, 1, "Expected to extract the value 1");

        // Create a sampler with sample rate 1.0 (should always sample)
        let sampler = RateSampler::new(1.0);
        let result = sampler.should_sample(
            None,
            trace_id,
            "",
            &opentelemetry::trace::SpanKind::Client,
            &[],
            &[],
        );

        assert_eq!(result.decision, SamplingDecision::RecordAndSample);
    }

    #[test]
    fn test_half_rate_sampling() {
        // Create a sampler with 0.5 rate
        let sampler_half = RateSampler::new(0.5);
        let threshold = sampler_half.sampling_id_threshold;

        // Test with a trace ID that should be sampled (e.g., hashed value < threshold)
        // We'll create one with all zeros which will hash to zero (below any threshold > 0)
        let bytes_to_sample = [0u8; 16];
        let trace_id_to_sample = TraceId::from_bytes(bytes_to_sample);

        // Get the hashed value for verification using casting approach
        let trace_id_u128 = u128::from_be_bytes(trace_id_to_sample.to_bytes());
        let extracted_u64 = trace_id_u128 as u64;
        let hashed_id = extracted_u64.wrapping_mul(KNUTH_FACTOR);

        // This should always be true since 0 * anything = 0 which is below threshold
        assert!(
            hashed_id <= threshold,
            "Zero ID should hash below threshold"
        );

        // Test sampling
        let result = sampler_half.should_sample(
            None,
            trace_id_to_sample,
            "",
            &opentelemetry::trace::SpanKind::Client,
            &[],
            &[],
        );

        // This should always pass - a zero trace ID will hash to zero, which is below the threshold
        assert_eq!(result.decision, SamplingDecision::RecordAndSample);
    }
}
