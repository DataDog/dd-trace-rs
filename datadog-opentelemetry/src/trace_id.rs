// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::cell::RefCell;

use rand::{Rng, SeedableRng};

#[derive(Debug)]
pub(crate) struct TraceidGenerator;

thread_local! {
    /// TODO: Restart entropy in forked thread in case of fork
    static RNG: RefCell<rand::rngs::SmallRng> = RefCell::new(rand::rngs::SmallRng::from_entropy());
}

impl opentelemetry_sdk::trace::IdGenerator for TraceidGenerator {
    fn new_trace_id(&self) -> opentelemetry::TraceId {
        // The trace id follows the following format:
        // 32 bits timestamp | 32 bits of zeroes | 64 bits of random
        // The timestamp is the number of seconds since the UNIX epoch

        let lower_half = RNG.with(|rng| rng.borrow_mut().gen::<u64>());
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
        let span_id = RNG.with(|rng| rng.borrow_mut().gen::<u64>()).to_be_bytes();
        opentelemetry::SpanId::from_bytes(span_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_sdk::trace::IdGenerator;

    #[test]
    fn test_trace_id_generator() {
        let generator = TraceidGenerator;
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
}
