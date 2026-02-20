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

#[cfg(test)]
pub(crate) mod test_helpers {
    use std::collections::HashMap;

    pub(crate) const DATADOG_TRACE_ID_KEY: &str = "x-datadog-trace-id";
    pub(crate) const DATADOG_PARENT_ID_KEY: &str = "x-datadog-parent-id";
    pub(crate) const DATADOG_SAMPLING_PRIORITY_KEY: &str = "x-datadog-sampling-priority";

    pub(crate) fn sample_trace_headers() -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert(DATADOG_TRACE_ID_KEY.to_string(), "123456789".to_string());
        headers.insert(DATADOG_PARENT_ID_KEY.to_string(), "987654321".to_string());
        headers.insert(DATADOG_SAMPLING_PRIORITY_KEY.to_string(), "1".to_string());
        headers
    }
}
