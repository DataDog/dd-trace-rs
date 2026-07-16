// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;

use thiserror::Error;

#[derive(Error, Debug, Clone)]
#[error("Cannot {} from {}, {}", operation, propagator_name, message)]
pub struct Error {
    pub message: Cow<'static, str>,
    // which propagator this error comes from
    propagator_name: &'static str,
    // what operation was attempted
    operation: &'static str,
}

impl Error {
    /// Error when extracting a value from a carrier
    #[must_use]
    pub fn extract(message: impl Into<Cow<'static, str>>, propagator_name: &'static str) -> Self {
        Self {
            message: message.into(),
            propagator_name,
            operation: "extract",
        }
    }

    /// Error when injecting a value into a carrier
    #[allow(clippy::must_use_candidate)]
    pub fn inject(message: impl Into<Cow<'static, str>>, propagator_name: &'static str) -> Self {
        Self {
            message: message.into(),
            propagator_name,
            operation: "inject",
        }
    }
}
