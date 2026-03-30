// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use super::{api_gateway_http::lowercased_headers, InferredSpan};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;

const MS_TO_NS: i64 = 1_000_000;

/// Lambda Function URL event.
///
/// Detection: `requestContext.domainName` contains `"lambda-url"`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LambdaFunctionUrlEvent {
    #[serde(default)]
    headers: HashMap<String, String>,
    request_context: RequestContext,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequestContext {
    domain_name: String,
    request_id: String,
    time_epoch: i64,
    http: HttpInfo,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpInfo {
    method: String,
    path: String,
    protocol: String,
    source_ip: String,
    user_agent: String,
}

impl LambdaFunctionUrlEvent {
    pub(crate) fn extract(&self) -> (HashMap<String, String>, InferredSpan) {
        let carrier = lowercased_headers(&self.headers);
        let is_async = carrier
            .get("x-amz-invocation-type")
            .is_some_and(|v| v == "Event");

        let path = &self.request_context.http.path;
        let resource = format!("{} {}", self.request_context.http.method, path);
        let http_url = format!("https://{}{}", self.request_context.domain_name, path);
        let start_time_ns = Some(self.request_context.time_epoch * MS_TO_NS);

        let mut tags = HashMap::new();
        tags.insert("endpoint".to_owned(), path.clone());
        tags.insert("http.url".to_owned(), http_url);
        tags.insert(
            "http.method".to_owned(),
            self.request_context.http.method.clone(),
        );
        tags.insert(
            "http.user_agent".to_owned(),
            self.request_context.http.user_agent.clone(),
        );
        tags.insert(
            "http.source_ip".to_owned(),
            self.request_context.http.source_ip.clone(),
        );
        tags.insert(
            "http.protocol".to_owned(),
            self.request_context.http.protocol.clone(),
        );
        tags.insert(
            "request_id".to_owned(),
            self.request_context.request_id.clone(),
        );

        let span = InferredSpan {
            operation: "aws.lambda.url",
            trigger_source: "lambda-function-url",
            trigger_arn: None,
            service: self.request_context.domain_name.clone(),
            resource,
            span_type: "http",
            start_time_ns,
            is_async,
            tags,
            wrapped_by: None,
        };

        (carrier, span)
    }
}

pub(crate) fn is_match(payload: &Value) -> bool {
    payload
        .get("requestContext")
        .and_then(|rc| rc.get("domainName"))
        .and_then(|d| d.as_str())
        .is_some_and(|s| s.contains("lambda-url"))
}

#[cfg(test)]
mod tests {
    use super::super::test_utils::load_payload;
    use super::*;

    fn extract(payload: &Value) -> (HashMap<String, String>, InferredSpan) {
        let event: LambdaFunctionUrlEvent = serde_json::from_value(payload.clone()).unwrap();
        event.extract()
    }

    #[test]
    fn matches_lambda_url_event() {
        let event = load_payload("lambda_function_url_event.json");
        assert!(is_match(&event));
    }

    #[test]
    fn rejects_http_api_event() {
        let event = load_payload("api_gateway_http_event.json");
        assert!(!is_match(&event));
    }

    #[test]
    fn extracts_inferred_span() {
        let event = load_payload("lambda_function_url_event.json");
        let (carrier, span) = extract(&event);

        // The fixture has no Datadog headers so the carrier is empty.
        assert!(!carrier.contains_key("x-datadog-trace-id"));
        assert_eq!(span.operation, "aws.lambda.url");
        assert_eq!(
            span.service,
            "a8hyhsshac.lambda-url.eu-south-1.amazonaws.com"
        );
        assert_eq!(span.resource, "GET /");
        assert_eq!(span.span_type, "http");
        assert_eq!(span.tags.get("endpoint").unwrap(), "/");
        assert_eq!(
            span.tags.get("http.url").unwrap(),
            "https://a8hyhsshac.lambda-url.eu-south-1.amazonaws.com/"
        );
        assert_eq!(span.tags.get("http.method").unwrap(), "GET");
        assert_eq!(span.tags.get("http.protocol").unwrap(), "HTTP/1.1");
        assert_eq!(span.tags.get("http.source_ip").unwrap(), "71.195.30.42");
        assert_eq!(
            span.tags.get("http.user_agent").unwrap(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36"
        );
        assert_eq!(
            span.tags.get("request_id").unwrap(),
            "ec4d58f8-2b8b-4ceb-a1d5-2be7bff58505"
        );
    }
}
