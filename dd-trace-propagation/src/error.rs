// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use dd_trace::log::Level;
use thiserror::Error;

#[derive(Error, Debug, Copy, Clone)]
#[error("Cannot {} from {}, {}", operation, propagator_name, message)]
pub struct Error {
    pub message: &'static str,
    // which propagator this error comes from
    propagator_name: &'static str,
    // what operation was attempted
    operation: &'static str,
    // error log level
    pub log_level: Level,
}

impl Error {
    /// Error when extracting a value from a carrier
    #[must_use]
    pub fn extract(message: &'static str, propagator_name: &'static str) -> Self {
        Self {
            message,
            propagator_name,
            operation: "extract",
            log_level: Level::Error,
        }
    }

    pub fn extract_with_level(
        message: &'static str,
        propagator_name: &'static str,
        log_level: Level,
    ) -> Self {
        Self {
            message,
            propagator_name,
            operation: "extract",
            log_level,
        }
    }

    /// Error when injecting a value into a carrier
    #[allow(clippy::must_use_candidate)]
    pub fn inject(message: &'static str, propagator_name: &'static str) -> Self {
        Self {
            message,
            propagator_name,
            operation: "inject",
            log_level: Level::Error,
        }
    }
}
