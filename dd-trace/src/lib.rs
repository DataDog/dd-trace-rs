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
