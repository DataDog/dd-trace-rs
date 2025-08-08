// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

pub mod configuration;
pub mod constants;
pub mod sampling;
pub use configuration::Config;

mod error;
pub use error::{Error, Result};

pub mod log;
pub mod telemetry;

/// Macro to catch panics and return a fallback value with error logging
/// The fallback is only evaluated if a panic occurs
#[macro_export]
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
