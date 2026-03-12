// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod eventbridge;
pub(crate) mod sns;
pub(crate) mod sqs;

use self::eventbridge::EventBridgeEvent;
use self::sns::SnsEvent;
use self::sqs::SqsEvent;
use super::InferredSpan;
use serde_json::Value;
use std::collections::HashMap;

/// Identified Lambda trigger with deserialized event data.
///
/// Order matters: SQS before SNS because SNS-in-SQS must be detected
/// by the SQS handler (it checks the body for nested SNS).
pub(crate) enum Trigger {
    Sqs(SqsEvent),
    Sns(SnsEvent),
    EventBridge(EventBridgeEvent),
    Unknown,
}

impl Trigger {
    pub(crate) fn from_payload(payload: &Value) -> Self {
        if sqs::is_match(payload) {
            if let Ok(event) = serde_json::from_value(payload.clone()) {
                return Self::Sqs(event);
            }
        } else if sns::is_match(payload) {
            if let Ok(event) = serde_json::from_value(payload.clone()) {
                return Self::Sns(event);
            }
        } else if eventbridge::is_match(payload) {
            if let Ok(event) = serde_json::from_value(payload.clone()) {
                return Self::EventBridge(event);
            }
        }
        Self::Unknown
    }

    pub(crate) fn extract(self) -> Option<(HashMap<String, String>, Vec<InferredSpan>)> {
        match self {
            Self::Sqs(event) => event.into_first_record()?.extract(),
            Self::Sns(event) => event.into_first_entity()?.extract(),
            Self::EventBridge(event) => event.extract(),
            Self::Unknown => None,
        }
    }
}

pub(crate) fn extract(payload: &Value) -> Option<(HashMap<String, String>, Vec<InferredSpan>)> {
    Trigger::from_payload(payload).extract()
}

#[cfg(test)]
pub(crate) mod test_utils {
    use std::fs;
    use std::path::PathBuf;

    #[must_use]
    pub fn read_json_file(file_name: &str) -> String {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests/payloads");
        path.push(file_name);
        fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
    }

    #[must_use]
    pub fn load_payload(file_name: &str) -> serde_json::Value {
        let contents = read_json_file(file_name);
        serde_json::from_str(&contents)
            .unwrap_or_else(|e| panic!("failed to parse {file_name}: {e}"))
    }
}
