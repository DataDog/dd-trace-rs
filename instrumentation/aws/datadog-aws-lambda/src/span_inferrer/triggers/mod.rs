// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod api_gateway_http;
pub(crate) mod api_gateway_rest;
pub(crate) mod eventbridge;
pub(crate) mod lambda_function_url;
pub(crate) mod sns;
pub(crate) mod sqs;
pub(crate) mod url_utils;

use self::eventbridge::EventBridgeEvent;
use self::sns::SnsEvent;
use self::sqs::SqsEvent;
use super::InferredSpan;
use serde_json::Value;
use std::collections::HashMap;

/// Returns the AWS partition for the given region.
pub(crate) fn get_aws_partition_by_region(region: &str) -> &'static str {
    if region.starts_with("us-gov-") {
        "aws-us-gov"
    } else if region.starts_with("cn-") {
        "aws-cn"
    } else {
        "aws"
    }
}

/// Read the AWS region from the Lambda environment.
pub(crate) fn aws_region() -> String {
    std::env::var("AWS_REGION")
        .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
        .unwrap_or_default()
}

/// Result of trigger extraction: carrier + inferred spans + event metadata.
pub(crate) struct TriggerResult {
    pub carrier: HashMap<String, String>,
    pub inferred_span: Option<InferredSpan>,
    /// Short name of the trigger source, e.g. `"sqs"`, `"api-gateway"`.
    pub event_source: &'static str,
    /// ARN of the outermost trigger resource, if available.
    pub event_source_arn: Option<String>,
}

/// Identified Lambda trigger type.
///
/// Dispatch order mirrors the extension (HTTP-based first, then queue/stream):
/// 1. `APIGatewayHttp`    — version=="2.0" + rawQueryString, NOT lambda-url
/// 2. `APIGatewayRest`    — requestContext.stage + httpMethod + resource
/// 3. `LambdaFunctionUrl` — requestContext.domainName contains "lambda-url"
/// 4. `Sqs`               — Records[0].eventSource == "aws:sqs"
/// 5. `Sns`               — Records[0].Sns exists
/// 6. `EventBridge`       — detail-type + source != "aws.events"
enum Trigger {
    ApiGatewayHttp(api_gateway_http::ApiGatewayHttpEvent),
    ApiGatewayRest(api_gateway_rest::ApiGatewayRestEvent),
    LambdaFunctionUrl(lambda_function_url::LambdaFunctionUrlEvent),
    Sqs(SqsEvent),
    Sns(SnsEvent),
    EventBridge(EventBridgeEvent),
    Unknown,
}

impl Trigger {
    fn from_payload(payload: &Value) -> Self {
        if api_gateway_http::is_match(payload) {
            if let Ok(e) = serde_json::from_value(payload.clone()) {
                return Self::ApiGatewayHttp(e);
            }
        }
        if api_gateway_rest::is_match(payload) {
            if let Ok(e) = serde_json::from_value(payload.clone()) {
                return Self::ApiGatewayRest(e);
            }
        }
        if lambda_function_url::is_match(payload) {
            if let Ok(e) = serde_json::from_value(payload.clone()) {
                return Self::LambdaFunctionUrl(e);
            }
        }
        if sqs::is_match(payload) {
            if let Ok(e) = serde_json::from_value(payload.clone()) {
                return Self::Sqs(e);
            }
        }
        if sns::is_match(payload) {
            if let Ok(e) = serde_json::from_value(payload.clone()) {
                return Self::Sns(e);
            }
        }
        if eventbridge::is_match(payload) {
            if let Ok(e) = serde_json::from_value(payload.clone()) {
                return Self::EventBridge(e);
            }
        }
        Self::Unknown
    }

    fn extract(self, _payload: &Value) -> Option<TriggerResult> {
        match self {
            Self::ApiGatewayHttp(e) => {
                let (carrier, span) = e.extract()?;
                Some(TriggerResult {
                    carrier,
                    event_source: span.outermost().trigger_source,
                    event_source_arn: None,
                    inferred_span: Some(span),
                })
            }
            Self::ApiGatewayRest(e) => {
                let (carrier, span) = e.extract()?;
                Some(TriggerResult {
                    carrier,
                    event_source: span.outermost().trigger_source,
                    event_source_arn: None,
                    inferred_span: Some(span),
                })
            }
            Self::LambdaFunctionUrl(e) => {
                let (carrier, span) = e.extract();
                Some(TriggerResult {
                    carrier,
                    event_source: span.outermost().trigger_source,
                    event_source_arn: None,
                    inferred_span: Some(span),
                })
            }
            Self::Sqs(event) => {
                let record = event.into_first_record()?;
                let (carrier, span) = record.extract()?;
                Some(TriggerResult {
                    carrier,
                    event_source_arn: span.outermost().trigger_arn.clone(),
                    event_source: span.outermost().trigger_source,
                    inferred_span: Some(span),
                })
            }
            Self::Sns(event) => {
                let record = event.into_first_record()?;
                let (carrier, span) = record.extract()?;
                Some(TriggerResult {
                    carrier,
                    event_source_arn: span.outermost().trigger_arn.clone(),
                    event_source: span.outermost().trigger_source,
                    inferred_span: Some(span),
                })
            }
            Self::EventBridge(event) => {
                let (carrier, span) = event.extract()?;
                Some(TriggerResult {
                    carrier,
                    event_source: span.outermost().trigger_source,
                    event_source_arn: None,
                    inferred_span: Some(span),
                })
            }
            Self::Unknown => None,
        }
    }
}

pub(crate) fn extract(payload: &Value) -> Option<TriggerResult> {
    Trigger::from_payload(payload).extract(payload)
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
