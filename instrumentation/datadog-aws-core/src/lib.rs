// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

pub mod attribute_keys;
mod interceptor;

pub use interceptor::{base_tags, AwsInterceptor, ServiceHandler};

#[cfg(any(test, feature = "test-utils"))]
pub mod test_helpers {
    use std::collections::HashMap;

    use opentelemetry::{KeyValue, Value};

    pub const DATADOG_TRACE_ID_KEY: &str = "x-datadog-trace-id";
    pub const DATADOG_PARENT_ID_KEY: &str = "x-datadog-parent-id";
    pub const DATADOG_SAMPLING_PRIORITY_KEY: &str = "x-datadog-sampling-priority";

    pub fn sample_trace_headers() -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert(DATADOG_TRACE_ID_KEY.to_string(), "123456789".to_string());
        headers.insert(DATADOG_PARENT_ID_KEY.to_string(), "987654321".to_string());
        headers.insert(
            DATADOG_SAMPLING_PRIORITY_KEY.to_string(),
            "1".to_string(),
        );
        headers
    }

    pub fn collect_string_tags(tags: Vec<KeyValue>) -> HashMap<String, String> {
        tags.into_iter()
            .map(|KeyValue { key, value, .. }| {
                let Value::String(value) = value else {
                    panic!("expected string tag value for {}", key.as_str());
                };
                (key.as_str().to_string(), value.to_string())
            })
            .collect()
    }
}
