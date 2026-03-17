// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

// Datadog-native span attribute keys
pub(crate) const OPERATION_NAME: &str = "operation_name";
pub(crate) const RESOURCE_NAME: &str = "resource.name";
pub(crate) const SPAN_TYPE: &str = "span.type";
pub(crate) const ERROR: &str = "error";
pub(crate) const ERROR_MESSAGE: &str = "error.message";

// Root span tags
pub(crate) const LANGUAGE: &str = "language";
pub(crate) const REQUEST_ID: &str = "request_id";
pub(crate) const COLD_START: &str = "cold_start";
pub(crate) const ASYNC_INVOCATION: &str = "async_invocation";
pub(crate) const FUNCTION_ARN: &str = "function_arn";
pub(crate) const FUNCTION_VERSION: &str = "function_version";
pub(crate) const FUNCTION_NAME: &str = "functionname";
pub(crate) const RESOURCE_NAMES: &str = "resource_names";
pub(crate) const DD_ORIGIN: &str = "_dd.origin";
pub(crate) const FUNCTION_TRIGGER_EVENT_SOURCE: &str = "function_trigger.event_source";
pub(crate) const FUNCTION_TRIGGER_EVENT_SOURCE_ARN: &str = "function_trigger.event_source_arn";

// OpenTelemetry semantic convention keys
pub(crate) use opentelemetry_semantic_conventions::attribute::{PEER_SERVICE, SERVICE_NAME};
