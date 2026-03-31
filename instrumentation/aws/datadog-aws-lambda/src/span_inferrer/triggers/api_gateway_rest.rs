// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use super::{
    api_gateway_http::lowercased_headers, url_utils::parameterize_api_resource, InferredSpan,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;

const MS_TO_NS: i64 = 1_000_000;

/// API Gateway REST (v1) event.
///
/// Detection: `requestContext.stage` + `requestContext.httpMethod` + `resource` all present.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApiGatewayRestEvent {
    #[serde(default)]
    headers: HashMap<String, String>,
    request_context: RequestContext,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequestContext {
    #[serde(default)]
    api_id: String,
    #[serde(default)]
    stage: String,
    domain_name: Option<String>,
    request_id: String,
    #[serde(rename = "requestTimeEpoch", default)]
    time_epoch: i64,
    #[serde(rename = "httpMethod", default)]
    http_method: String,
    path: String,
    protocol: Option<String>,
    #[serde(rename = "resourcePath", default)]
    resource_path: String,
    identity: Option<Identity>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Identity {
    source_ip: Option<String>,
    user_agent: Option<String>,
}

impl ApiGatewayRestEvent {
    pub(crate) fn extract(&self) -> Option<(HashMap<String, String>, InferredSpan)> {
        let carrier = lowercased_headers(&self.headers);
        let is_async = carrier
            .get("x-amz-invocation-type")
            .is_some_and(|v| v == "Event");

        let path = &self.request_context.path;
        let resource = format!(
            "{} {}",
            self.request_context.http_method,
            parameterize_api_resource(path)
        );
        let domain_name = self
            .request_context
            .domain_name
            .as_deref()
            .unwrap_or_default();
        let http_url = format!("https://{domain_name}{path}");
        let start_time_ns = Some(self.request_context.time_epoch * MS_TO_NS);

        let identity = self.request_context.identity.as_ref();
        let mut tags = HashMap::new();
        tags.insert("endpoint".to_owned(), path.clone());
        tags.insert("http.url".to_owned(), http_url);
        tags.insert(
            "http.method".to_owned(),
            self.request_context.http_method.clone(),
        );
        if let Some(proto) = &self.request_context.protocol {
            tags.insert("http.protocol".to_owned(), proto.clone());
        }
        if let Some(ip) = identity.and_then(|id| id.source_ip.as_deref()) {
            tags.insert("http.source_ip".to_owned(), ip.to_owned());
        }
        if let Some(ua) = identity.and_then(|id| id.user_agent.as_deref()) {
            tags.insert("http.user_agent".to_owned(), ua.to_owned());
        }
        tags.insert(
            "request_id".to_owned(),
            self.request_context.request_id.clone(),
        );
        tags.insert(
            "http.route".to_owned(),
            self.request_context.resource_path.clone(),
        );

        let (trigger_arn, dd_resource_key) = if !self.request_context.api_id.is_empty() {
            let region = super::aws_region();
            let partition = super::get_aws_partition_by_region(&region);
            let api_id = &self.request_context.api_id;
            let stage = &self.request_context.stage;
            (
                Some(format!(
                    "arn:{partition}:apigateway:{region}::/restapis/{api_id}/stages/{stage}"
                )),
                Some(format!(
                    "arn:{partition}:apigateway:{region}::/restapis/{api_id}"
                )),
            )
        } else {
            (None, None)
        };

        let span = InferredSpan {
            operation: "aws.apigateway",
            trigger_source: "api-gateway",
            trigger_arn,
            dd_resource_key,
            service: domain_name.to_owned(),
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
    payload
        .get("requestContext")
        .and_then(|rc| rc.get("stage"))
        .is_some()
        && payload.get("httpMethod").is_some()
        && payload.get("resource").is_some()
}

#[cfg(test)]
mod tests {
    use super::super::test_utils::load_payload;
    use super::super::url_utils::parameterize_api_resource;
    use super::*;

    fn extract(payload: &Value) -> Option<(HashMap<String, String>, InferredSpan)> {
        let event: ApiGatewayRestEvent = serde_json::from_value(payload.clone()).ok()?;
        event.extract()
    }

    #[test]
    fn parameterize_resource() {
        assert_eq!(
            parameterize_api_resource("/users/12345/friends/67890"),
            "/users/{user_id}/friends/{friend_id}"
        );
        assert_eq!(
            parameterize_api_resource("/dev/proxy_route/users/12345/friends/67890"),
            "/dev/proxy_route/users/{user_id}/friends/{friend_id}"
        );
        assert_eq!(
            parameterize_api_resource("/users/{user_id}/profile"),
            "/users/{user_id}/profile"
        );
        assert_eq!(
            parameterize_api_resource("/api/v1/users/12345/settings"),
            "/api/v1/users/{user_id}/settings"
        );
        assert_eq!(
            parameterize_api_resource("/orders/123e4567-e89b-12d3-a456-426614174000/items"),
            "/orders/{order_id}/items"
        );
    }

    #[test]
    fn matches_rest_event() {
        let event = load_payload("api_gateway_rest_event.json");
        assert!(is_match(&event));
    }

    #[test]
    fn rejects_http_v2_event() {
        let event = load_payload("api_gateway_http_event.json");
        assert!(!is_match(&event));
    }

    #[test]
    fn enrich_span() {
        let event = load_payload("api_gateway_rest_event.json");
        let (_carrier, span) = extract(&event).unwrap();

        assert_eq!(span.operation, "aws.apigateway");
        assert_eq!(span.service, "id.execute-api.us-east-1.amazonaws.com");
        assert_eq!(span.resource, "GET /my/path");
        assert_eq!(span.span_type, "web");
        assert_eq!(span.tags.get("endpoint").unwrap(), "/my/path");
        assert_eq!(
            span.tags.get("http.url").unwrap(),
            "https://id.execute-api.us-east-1.amazonaws.com/my/path"
        );
        assert_eq!(span.tags.get("http.method").unwrap(), "GET");
        assert_eq!(span.tags.get("http.protocol").unwrap(), "HTTP/1.1");
        assert_eq!(span.tags.get("http.source_ip").unwrap(), "IP");
        assert_eq!(span.tags.get("http.user_agent").unwrap(), "user-agent");
        assert_eq!(span.tags.get("http.route").unwrap(), "/path");
        assert_eq!(span.tags.get("request_id").unwrap(), "id=");
    }

    #[test]
    fn enrich_span_parameterized() {
        let event = load_payload("api_gateway_rest_event_parameterized.json");
        let (_carrier, span) = extract(&event).unwrap();

        assert_eq!(
            span.service,
            "mcwkra0ya4.execute-api.sa-east-1.amazonaws.com"
        );
        assert_eq!(span.resource, "GET /dev/user/{user_id}/id/{id}");
        assert_eq!(span.span_type, "web");
        assert_eq!(span.tags.get("endpoint").unwrap(), "/dev/user/42/id/50");
        assert_eq!(
            span.tags.get("http.url").unwrap(),
            "https://mcwkra0ya4.execute-api.sa-east-1.amazonaws.com/dev/user/42/id/50"
        );
        assert_eq!(span.tags.get("http.method").unwrap(), "GET");
        assert_eq!(span.tags.get("http.protocol").unwrap(), "HTTP/1.1");
        assert_eq!(span.tags.get("http.source_ip").unwrap(), "76.115.124.192");
        assert_eq!(span.tags.get("http.user_agent").unwrap(), "curl/8.1.2");
        assert_eq!(span.tags.get("http.route").unwrap(), "/user/{id}");
        assert_eq!(
            span.tags.get("request_id").unwrap(),
            "e16399f7-e984-463a-9931-745ba021a27f"
        );
    }
}
