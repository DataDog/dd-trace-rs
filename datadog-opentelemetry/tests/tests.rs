// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

#[cfg(not(windows))]
#[cfg_attr(miri, ignore)]
mod integration_tests;

#[test]
fn empty() {}
