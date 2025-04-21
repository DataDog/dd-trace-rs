// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use opentelemetry::trace::{SamplingDecision, SamplingResult, TraceId};
use opentelemetry::Context;
use opentelemetry_sdk::trace::ShouldSample;
use std::fmt;

use crate::constants::{numeric, rate};
use numeric::{KNUTH_FACTOR, MAX_UINT_64BITS};

/// Keeps (100 * `sample_rate`)% of the traces randomly.
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
    // Helper method to calculate the threshold from a rate
    fn calculate_threshold(rate: f64) -> u64 {
        if rate >= rate::MAX_SAMPLE_RATE {
            MAX_UINT_64BITS
        } else {
            (rate * (MAX_UINT_64BITS as f64)) as u64
        }
    }

    /// `sample_rate` is clamped between 0.0 and 1.0 inclusive.
    pub fn new(sample_rate: f64) -> Self {
        let clamped_rate = sample_rate.clamp(rate::MIN_SAMPLE_RATE, rate::MAX_SAMPLE_RATE);
        let sampling_id_threshold = Self::calculate_threshold(clamped_rate);

        RateSampler {
            sample_rate: clamped_rate,
            sampling_id_threshold,
        }
    }

    /// Returns the current sample rate
    pub fn sample_rate(&self) -> f64 {
        self.sample_rate
    }

    /// Sets a new sample rate for the sampler.
    /// `sample_rate` is clamped between 0.0 and 1.0 inclusive.
    pub fn set_sample_rate(&mut self, sample_rate: f64) {
        let clamped_rate = sample_rate.clamp(rate::MIN_SAMPLE_RATE, rate::MAX_SAMPLE_RATE);
        self.sample_rate = clamped_rate;
        self.sampling_id_threshold = Self::calculate_threshold(clamped_rate);
    }
}

impl ShouldSample for RateSampler {
    fn should_sample(
        &self,
        _parent_context: Option<&Context>,
        trace_id: TraceId,
        _name: &str,
        _span_kind: &opentelemetry::trace::SpanKind,
        _attributes: &[opentelemetry::KeyValue],
        _links: &[opentelemetry::trace::Link],
    ) -> SamplingResult {

        // Fast-path for sample rate of 0.0 (always drop) or 1.0 (always sample)
        if self.sample_rate <= rate::MIN_SAMPLE_RATE {
            return SamplingResult {
                decision: SamplingDecision::Drop,
                attributes: Vec::new(),
                trace_state: Default::default(),
            };
        }

        if self.sample_rate >= rate::MAX_SAMPLE_RATE {
            return SamplingResult {
                decision: SamplingDecision::RecordAndSample,
                attributes: Vec::new(),
                trace_state: Default::default(),
            };
        }

        // Convert trace_id to u128 and then cast to u64 to get the lower 64 bits
        let trace_id_u128 = u128::from_be_bytes(trace_id.to_bytes());
        let trace_id_64bits = trace_id_u128 as u64;

        let hashed_id = trace_id_64bits.wrapping_mul(KNUTH_FACTOR);

        // If the hashed ID is less than the threshold, sample the trace
        let decision = if hashed_id <= self.sampling_id_threshold {
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
    use opentelemetry::trace::TraceId;

    #[test]
    fn check_debug_impl() {
        let sampler = RateSampler::new(0.5);
        let debug_output = format!("{:?}", sampler);
        assert!(debug_output.contains("RateSampler"));
        assert!(debug_output.contains("sample_rate: 0.5"));
    }

    #[test]
    fn test_rate_sampler_new() {
        // Standard rates
        let sampler_zero = RateSampler::new(0.0);
        assert_eq!(sampler_zero.sample_rate, 0.0);
        assert_eq!(sampler_zero.sampling_id_threshold, 0);

        let sampler_quarter = RateSampler::new(0.25);
        assert_eq!(sampler_quarter.sample_rate, 0.25);
        assert_eq!(
            sampler_quarter.sampling_id_threshold,
            (0.25 * (MAX_UINT_64BITS as f64)) as u64
        );

        let sampler_half = RateSampler::new(0.5);
        assert_eq!(sampler_half.sample_rate, 0.5);
        assert_eq!(
            sampler_half.sampling_id_threshold,
            (0.5 * (MAX_UINT_64BITS as f64)) as u64
        );

        let sampler_one = RateSampler::new(1.0);
        assert_eq!(sampler_one.sample_rate, 1.0);
        assert_eq!(sampler_one.sampling_id_threshold, MAX_UINT_64BITS);

        // Boundary handling
        let sampler_negative = RateSampler::new(-0.1);
        assert_eq!(sampler_negative.sample_rate, 0.0);

        let sampler_over_one = RateSampler::new(1.1);
        assert_eq!(sampler_over_one.sample_rate, 1.0);
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
        // Setting multiple bits to ensure it hashes above the threshold
        let mut bytes_drop = [0u8; 16];
        bytes_drop[8] = 0xFF; // Setting full byte to ensure high value after hashing
        bytes_drop[9] = 0xFF; // Setting another byte for good measure
        let trace_id_drop = TraceId::from_bytes(bytes_drop);

        // Verify these trace IDs hash as expected, using casting approach
        let trace_id_sample_u128 = u128::from_be_bytes(trace_id_sample.to_bytes());
        let sample_u64 = trace_id_sample_u128 as u64;
        let sample_hash = sample_u64.wrapping_mul(KNUTH_FACTOR);

        let trace_id_drop_u128 = u128::from_be_bytes(trace_id_drop.to_bytes());
        let drop_u64 = trace_id_drop_u128 as u64;
        let drop_hash = drop_u64.wrapping_mul(KNUTH_FACTOR);

        // Manually verify the hashing behavior to make sure our assumptions are correct
        assert!(
            sample_hash <= threshold,
            "Sample hash {} should be <= threshold {}",
            sample_hash,
            threshold
        );
        assert!(
            drop_hash > threshold,
            "Drop hash {} should be > threshold {}",
            drop_hash,
            threshold
        );

        // Now verify the sampler behaves correctly with these trace IDs
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
            "sampler_half should sample trace_id_sample"
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
            "sampler_half should drop trace_id_drop"
        );
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
