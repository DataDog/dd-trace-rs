// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Extension-specific constants (port, Lambda headers).

pub(super) const EXTENSION_PORT: u16 = 8124;
pub(super) const LAMBDA_REQUEST_ID_HEADER: &str = "lambda-runtime-aws-request-id";
