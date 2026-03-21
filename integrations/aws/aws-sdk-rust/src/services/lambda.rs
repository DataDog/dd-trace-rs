// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use aws_sdk_lambda::operation::invoke::InvokeInput;
use aws_smithy_runtime_api::box_error::BoxError;
use aws_smithy_runtime_api::client::interceptors::context::Input;
use base64::prelude::*;

use crate::attribute_keys::FUNCTION_NAME;

use super::{base_request_metadata, AwsServiceHandler, RequestMetadata};

// AWS hard limit on the X-Amz-Client-Context header (base64-encoded).
const CLIENT_CONTEXT_MAX_BYTES: usize = 3583;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct LambdaService;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LambdaOperation {
    Invoke,
}

impl LambdaOperation {
    fn from_name(operation: &str) -> Option<Self> {
        match operation {
            "Invoke" => Some(Self::Invoke),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Invoke => "Invoke",
        }
    }
}

impl AwsServiceHandler for LambdaService {
    fn service_id(&self) -> &'static str {
        "Lambda"
    }

    fn inject(
        &self,
        operation: &str,
        trace_headers: HashMap<String, String>,
        input: &mut Input,
    ) -> Result<(), BoxError> {
        inject(operation, trace_headers, input)
    }

    fn extract_request_metadata(
        &self,
        operation: &str,
        input: &Input,
        region: &str,
        partition: &str,
    ) -> Option<RequestMetadata> {
        let operation = LambdaOperation::from_name(operation)?;
        let function_name = input
            .downcast_ref::<InvokeInput>()?
            .function_name
            .clone()
            .unwrap_or_default();
        let mut request_metadata =
            base_request_metadata(self.service_id(), operation.name(), region, partition);
        request_metadata.tags.insert(FUNCTION_NAME, function_name);
        Some(request_metadata)
    }
}

pub(super) fn inject(
    operation: &str,
    trace_headers: HashMap<String, String>,
    input: &mut Input,
) -> Result<(), BoxError> {
    if let Some(LambdaOperation::Invoke) = LambdaOperation::from_name(operation) {
        if let Some(invoke_input) = input.downcast_mut::<InvokeInput>() {
            inject_into_invoke(invoke_input, &trace_headers)?;
        }
    }
    Ok(())
}

fn inject_into_invoke(
    input: &mut InvokeInput,
    trace_headers: &HashMap<String, String>,
) -> Result<(), BoxError> {
    let mut ctx: serde_json::Value = match input.client_context.as_deref() {
        Some(encoded) => {
            let decoded = BASE64_STANDARD.decode(encoded)?;
            serde_json::from_slice(&decoded)?
        }
        None => serde_json::json!({"custom": {}}),
    };

    let custom = ctx
        .as_object_mut()
        .and_then(|obj| {
            if !obj.contains_key("custom") {
                obj.insert("custom".to_string(), serde_json::json!({}));
            }
            obj.get_mut("custom")?.as_object_mut()
        })
        .ok_or("client_context.custom is not an object")?;

    for (key, value) in trace_headers {
        custom.insert(key.clone(), serde_json::Value::String(value.clone()));
    }

    let encoded = BASE64_STANDARD.encode(serde_json::to_string(&ctx)?);
    if encoded.len() > CLIENT_CONTEXT_MAX_BYTES {
        tracing::debug!(
            size = encoded.len(),
            limit = CLIENT_CONTEXT_MAX_BYTES,
            "skipping Lambda invoke trace injection: encoded client_context exceeds AWS limit"
        );
        return Ok(());
    }

    input.client_context = Some(encoded);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::test_helpers::{
        sample_trace_headers, DATADOG_PARENT_ID_KEY, DATADOG_SAMPLING_PRIORITY_KEY,
        DATADOG_TRACE_ID_KEY,
    };
    use aws_smithy_runtime_api::client::interceptors::context::Input;

    fn decode_client_context_custom(client_context: &str) -> HashMap<String, String> {
        let decoded = BASE64_STANDARD.decode(client_context).unwrap();
        let ctx: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        ctx["custom"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
            .collect()
    }

    #[test]
    fn injects_trace_context_into_invoke() {
        let trace_headers = sample_trace_headers();
        let mut input = InvokeInput::builder()
            .function_name("my-function")
            .build()
            .unwrap();

        inject_into_invoke(&mut input, &trace_headers).unwrap();

        let custom = decode_client_context_custom(input.client_context.as_ref().unwrap());
        assert_eq!(custom[DATADOG_TRACE_ID_KEY], "123456789");
        assert_eq!(custom[DATADOG_PARENT_ID_KEY], "987654321");
        assert_eq!(custom[DATADOG_SAMPLING_PRIORITY_KEY], "1");
    }

    #[test]
    fn merges_with_existing_client_context() {
        let trace_headers = sample_trace_headers();
        let existing =
            serde_json::json!({"custom": {"user-key": "user-value"}, "env": {"KEY": "VALUE"}});
        let encoded = BASE64_STANDARD.encode(serde_json::to_string(&existing).unwrap());
        let mut input = InvokeInput::builder()
            .function_name("my-function")
            .client_context(encoded)
            .build()
            .unwrap();

        inject_into_invoke(&mut input, &trace_headers).unwrap();

        let decoded = BASE64_STANDARD
            .decode(input.client_context.as_ref().unwrap())
            .unwrap();
        let ctx: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(ctx["custom"]["user-key"].as_str().unwrap(), "user-value");
        assert_eq!(
            ctx["custom"][DATADOG_TRACE_ID_KEY].as_str().unwrap(),
            "123456789"
        );
        assert_eq!(ctx["env"]["KEY"].as_str().unwrap(), "VALUE");
    }

    #[test]
    fn skips_injection_when_encoded_client_context_would_exceed_limit() {
        let trace_headers = sample_trace_headers();
        let mut big_custom = serde_json::Map::new();
        for i in 0..100 {
            big_custom.insert(format!("key-{i:03}"), serde_json::json!("x".repeat(40)));
        }
        let existing = serde_json::json!({"custom": big_custom});
        let encoded = BASE64_STANDARD.encode(serde_json::to_string(&existing).unwrap());
        let original_encoded = encoded.clone();
        let mut input = InvokeInput::builder()
            .function_name("my-function")
            .client_context(encoded)
            .build()
            .unwrap();

        inject_into_invoke(&mut input, &trace_headers).unwrap();

        assert_eq!(input.client_context.as_deref().unwrap(), original_encoded);
    }

    #[test]
    fn does_not_inject_for_unsupported_lambda_operations() {
        let trace_headers = sample_trace_headers();
        let invoke_input = InvokeInput::builder()
            .function_name("my-function")
            .build()
            .unwrap();
        let mut input = Input::erase(invoke_input);

        inject("ListFunctions", trace_headers, &mut input).unwrap();

        let invoke_input = input.downcast_ref::<InvokeInput>().unwrap();
        assert!(invoke_input.client_context.is_none());
    }

    #[test]
    fn extracts_invoke_request_metadata() {
        let input = InvokeInput::builder()
            .function_name("arn:aws:lambda:us-east-1:123456789012:function:my-function")
            .build()
            .unwrap();
        let input = Input::erase(input);

        let metadata = LambdaService
            .extract_request_metadata("Invoke", &input, "us-east-1", "aws")
            .unwrap();

        assert_eq!(metadata.service_name, "aws.Lambda");
        assert_eq!(metadata.resource_name, "Lambda.Invoke");
        assert_eq!(
            metadata.tags[FUNCTION_NAME],
            "arn:aws:lambda:us-east-1:123456789012:function:my-function"
        );
        assert_eq!(metadata.tags["aws.service"], "Lambda");
        assert_eq!(metadata.tags["aws.operation"], "Invoke");
        assert_eq!(metadata.tags["region"], "us-east-1");
        assert_eq!(metadata.tags["aws.partition"], "aws");
        assert_eq!(metadata.tags["service.name"], "aws.Lambda");
        assert_eq!(metadata.tags["resource.name"], "Lambda.Invoke");
    }

    #[test]
    fn extract_returns_none_for_unsupported_operations() {
        let input = InvokeInput::builder()
            .function_name("my-function")
            .build()
            .unwrap();
        let input = Input::erase(input);

        let metadata =
            LambdaService.extract_request_metadata("ListFunctions", &input, "us-east-1", "aws");

        assert!(metadata.is_none());
    }
}
