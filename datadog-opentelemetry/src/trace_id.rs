// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::cell::RefCell;

use rand::{rngs::OsRng, Rng, RngCore, SeedableRng};

#[derive(Debug)]
pub(crate) struct TraceidGenerator {
    secure_random: bool,
}

impl TraceidGenerator {
    pub(crate) fn new(secure_random: bool) -> Self {
        Self { secure_random }
    }
}

thread_local! {
    // Used only when DD_TRACE_SECURE_RANDOM is not set.
    // TODO: Restart entropy in forked thread in case of fork
    static RNG: RefCell<rand::rngs::SmallRng> = RefCell::new(rand::rngs::SmallRng::from_entropy());
}

impl opentelemetry_sdk::trace::IdGenerator for TraceidGenerator {
    fn new_trace_id(&self) -> opentelemetry::TraceId {
        // The trace id follows the following format:
        // 32 bits timestamp | 32 bits of zeroes | 64 bits of random
        // The timestamp is the number of seconds since the UNIX epoch

        let lower_half = if self.secure_random {
            OsRng.next_u64()
        } else {
            RNG.with(|rng| rng.borrow_mut().gen::<u64>())
        };
        let timestamp = std::time::UNIX_EPOCH
            .elapsed()
            .map(|d| d.as_secs())
            .unwrap_or(1 << 31);
        let upper_half = timestamp << 32;
        let mut trace_id = [0_u8; 16];
        trace_id[..8].copy_from_slice(&upper_half.to_be_bytes());
        trace_id[8..].copy_from_slice(&lower_half.to_be_bytes());

        opentelemetry::TraceId::from_bytes(trace_id)
    }

    fn new_span_id(&self) -> opentelemetry::SpanId {
        let id = if self.secure_random {
            OsRng.next_u64()
        } else {
            RNG.with(|rng| rng.borrow_mut().gen::<u64>())
        };
        let span_id = id.to_be_bytes();
        opentelemetry::SpanId::from_bytes(span_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_sdk::trace::IdGenerator;

    #[test]
    fn test_trace_id_generator() {
        let generator = TraceidGenerator::new(false);
        let trace_id = u128::from_be_bytes(generator.new_trace_id().to_bytes());
        // Format should be 32 bits timestamp | 32 bits of zeroes | 64 bits of random
        assert!(trace_id & 0x0000_0000_FFFF_FFFF_0000_0000_0000_0000 == 0);
        let ts = (trace_id >> 96) as u64;
        let now = std::time::UNIX_EPOCH
            .elapsed()
            .expect("negative timestamp")
            .as_secs();
        // Check that the timestamp is within 2 minutes of the current time
        assert!(now - 120 < ts && ts < now + 120);
        // Check that the lower half is not zero
        assert!(trace_id & 0x0000_0000_0000_0000_FFFF_FFFF_FFFF_FFFF != 0);
    }

    #[test]
    fn test_new_trace_id_nonzero() {
        let gen = TraceidGenerator::new(false);
        let id = gen.new_trace_id();
        assert_ne!(id, opentelemetry::TraceId::INVALID);
    }

    #[test]
    fn test_new_span_id_nonzero() {
        let gen = TraceidGenerator::new(false);
        let id = gen.new_span_id();
        assert_ne!(id, opentelemetry::SpanId::INVALID);
    }

    #[test]
    fn test_osrng_produces_varied_values() {
        use std::collections::HashSet;
        let values: HashSet<u64> = (0..100).map(|_| OsRng.next_u64()).collect();
        assert!(
            values.len() > 90,
            "Expected diverse OsRng values, got {}",
            values.len()
        );
    }

    #[test]
    fn test_secure_random_trace_id_format() {
        let gen = TraceidGenerator::new(true);
        let trace_id = u128::from_be_bytes(gen.new_trace_id().to_bytes());
        // Must still follow: 32 bits timestamp | 32 bits zeroes | 64 bits random
        assert!(trace_id & 0x0000_0000_FFFF_FFFF_0000_0000_0000_0000 == 0);
        let ts = (trace_id >> 96) as u64;
        let now = std::time::UNIX_EPOCH
            .elapsed()
            .expect("negative timestamp")
            .as_secs();
        assert!(now - 120 < ts && ts < now + 120);
        assert_ne!(trace_id & 0x0000_0000_0000_0000_FFFF_FFFF_FFFF_FFFF, 0);
    }

    #[test]
    fn test_secure_random_span_id_nonzero() {
        let gen = TraceidGenerator::new(true);
        let id = gen.new_span_id();
        assert_ne!(id, opentelemetry::SpanId::INVALID);
    }

    #[test]
    fn test_secure_random_produces_varied_values() {
        use std::collections::HashSet;
        let gen = TraceidGenerator::new(true);
        let ids: HashSet<[u8; 8]> = (0..100).map(|_| gen.new_span_id().to_bytes()).collect();
        assert!(ids.len() > 90, "Expected diverse IDs, got {}", ids.len());
    }
}
