// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use super::{url_utils::parameterize_api_resource, InferredSpan};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;

const MS_TO_NS: i64 = 1_000_000;

/// API Gateway HTTP API (v2) event.
///
/// Detection: `version == "2.0"` + `rawQueryString` present + domain is NOT a Lambda URL.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApiGatewayHttpEvent {
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

impl ApiGatewayHttpEvent {
    pub(crate) fn extract(&self) -> Option<(HashMap<String, String>, InferredSpan)> {
        let carrier = lowercased_headers(&self.headers);
        let is_async = carrier
            .get("x-amz-invocation-type")
            .is_some_and(|v| v == "Event");

        let path = &self.request_context.http.path;
        let resource = format!(
            "{} {}",
            self.request_context.http.method,
            parameterize_api_resource(path)
        );
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
            "http.protocol".to_owned(),
            self.request_context.http.protocol.clone(),
        );
        tags.insert(
            "http.source_ip".to_owned(),
            self.request_context.http.source_ip.clone(),
        );
        tags.insert(
            "http.user_agent".to_owned(),
            self.request_context.http.user_agent.clone(),
        );
        tags.insert(
            "request_id".to_owned(),
            self.request_context.request_id.clone(),
        );

        let span = InferredSpan {
            operation: "aws.httpapi",
            trigger_source: "api-gateway",
            trigger_arn: None,
            service: self.request_context.domain_name.clone(),
            resource,
            span_type: "web",
            start_time_ns,
            is_async,
            tags,
            wrapped_by: None,
        };

        Some((carrier, span))
    }
}

pub(crate) fn is_match(payload: &Value) -> bool {
    payload.get("version").and_then(|v| v.as_str()) == Some("2.0")
        && payload.get("rawQueryString").is_some()
        && payload
            .get("requestContext")
            .and_then(|rc| rc.get("domainName"))
            .and_then(|d| d.as_str())
            .is_none_or(|s| !s.contains("lambda-url"))
}

/// Build a lowercase header map for carrier extraction.
pub(crate) fn lowercased_headers(headers: &HashMap<String, String>) -> HashMap<String, String> {
    headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::test_utils::load_payload;
    use super::*;

    fn extract(payload: &Value) -> Option<(HashMap<String, String>, InferredSpan)> {
        let event: ApiGatewayHttpEvent = serde_json::from_value(payload.clone()).ok()?;
        event.extract()
    }

    #[test]
    fn matches_http_api_event() {
        let event = load_payload("api_gateway_http_event.json");
        assert!(is_match(&event));
    }

    #[test]
    fn rejects_lambda_url() {
        let event = load_payload("lambda_function_url_event.json");
        assert!(!is_match(&event));
    }

    #[test]
    fn rejects_proxy_event() {
        let event = load_payload("api_gateway_proxy_event.json");
        assert!(!is_match(&event));
    }

    #[test]
    fn extracts_carrier_and_inferred_span() {
        let event = load_payload("api_gateway_http_event.json");
        let (carrier, span) = extract(&event).unwrap();

        assert_eq!(carrier.get("x-datadog-trace-id").unwrap(), "12345");
        assert_eq!(span.operation, "aws.httpapi");
        assert_eq!(
            span.service,
            "x02yirxc7a.execute-api.sa-east-1.amazonaws.com"
        );
        assert_eq!(span.resource, "GET /httpapi/get");
        assert_eq!(span.span_type, "web");
        assert_eq!(span.tags.get("endpoint").unwrap(), "/httpapi/get");
        assert_eq!(
            span.tags.get("http.url").unwrap(),
            "https://x02yirxc7a.execute-api.sa-east-1.amazonaws.com/httpapi/get"
        );
        assert_eq!(span.tags.get("http.method").unwrap(), "GET");
        assert_eq!(span.tags.get("http.protocol").unwrap(), "HTTP/1.1");
        assert_eq!(span.tags.get("http.source_ip").unwrap(), "38.122.226.210");
        assert_eq!(span.tags.get("http.user_agent").unwrap(), "curl/7.64.1");
        assert_eq!(span.tags.get("request_id").unwrap(), "FaHnXjKCGjQEJ7A=");
    }

    #[test]
    fn parameterizes_path_in_resource() {
        let event = load_payload("api_gateway_http_event_parameterized.json");
        let (_, span) = extract(&event).unwrap();
        assert_eq!(
            span.service,
            "9vj54we5ih.execute-api.sa-east-1.amazonaws.com"
        );
        assert_eq!(span.resource, "GET /user/{user_id}");
        assert_eq!(span.span_type, "web");
        assert_eq!(span.tags.get("endpoint").unwrap(), "/user/42");
        assert_eq!(
            span.tags.get("http.url").unwrap(),
            "https://9vj54we5ih.execute-api.sa-east-1.amazonaws.com/user/42"
        );
        assert_eq!(span.tags.get("http.method").unwrap(), "GET");
        assert_eq!(span.tags.get("http.protocol").unwrap(), "HTTP/1.1");
        assert_eq!(span.tags.get("http.source_ip").unwrap(), "76.115.124.192");
        assert_eq!(span.tags.get("http.user_agent").unwrap(), "curl/8.1.2");
        assert_eq!(span.tags.get("request_id").unwrap(), "Ur2JtjEfGjQEPOg=");
    }
}
