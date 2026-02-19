// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Datadog trace propagation header constants.

pub(crate) const DATADOG_TRACE_ID_KEY: &str = "x-datadog-trace-id";
pub(crate) const DATADOG_PARENT_ID_KEY: &str = "x-datadog-parent-id";
pub(crate) const DATADOG_SPAN_ID_KEY: &str = "x-datadog-span-id";
pub(crate) const DATADOG_SAMPLING_PRIORITY_KEY: &str = "x-datadog-sampling-priority";
pub(crate) const DATADOG_TAGS_KEY: &str = "x-datadog-tags";
