// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Shared test utilities for the Datadog AWS instrumentation crates.

/// Helpers for integration tests that exercise AWS SDK clients against mock endpoints.
pub mod integration_test_helpers;

/// Helpers for unit tests that need deterministic OpenTelemetry context propagation.
pub mod test_helpers;
