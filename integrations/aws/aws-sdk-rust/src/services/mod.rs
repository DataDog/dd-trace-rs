// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Service-specific trace context enrichment.

mod injector;

pub(crate) mod eventbridge;
pub(crate) mod kinesis;
pub(crate) mod sns;
pub(crate) mod sqs;

#[allow(unused_imports)]
pub(crate) use eventbridge::EventBridgeInjector;
pub(crate) use injector::{AwsService, ServiceInjector, DATADOG_ATTRIBUTE_KEY};
#[allow(unused_imports)]
pub(crate) use kinesis::KinesisInjector;
#[allow(unused_imports)]
pub(crate) use sns::SnsInjector;
pub(crate) use sqs::SqsInjector;
