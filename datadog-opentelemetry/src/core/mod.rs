// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Core components of the SDK

pub mod configuration;
pub(crate) mod constants;
pub mod sampling;

mod error;

pub mod log;
pub(crate) mod telemetry;
pub(crate) mod utils;

#[cfg(feature = "test-utils")]
pub mod test_utils;

/// Macro to catch panics and return a fallback value with error logging
/// The fallback is only evaluated if a panic occurs
#[macro_export]
#[doc(hidden)]
macro_rules! catch_panic {
    ($operation:expr, $fallback:expr) => {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $operation)) {
            Ok(result) => result,
            Err(error) => {
                $crate::dd_error!("Panic caught {error:?}");
                $fallback
            }
        }
    };

    ($operation:expr) => {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $operation)) {
            Ok(result) => result,
            Err(error) => {
                $crate::dd_error!("Panic caught {error:?}");
            }
        }
    };
}
