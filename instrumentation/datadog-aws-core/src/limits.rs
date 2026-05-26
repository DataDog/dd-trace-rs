// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

/// Maximum number of message attributes allowed per message in SQS and SNS.
pub const MAX_MESSAGE_ATTRIBUTES: usize = 10;

/// One mebibyte in bytes. Used by services that enforce a 1 MiB payload limit
/// (e.g. EventBridge per-entry detail, SQS message body).
pub const ONE_MB: usize = 1024 * 1024;
