// Copyright 2026-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use super::{is_async_http, HttpMetadata};
use crate::inference::get_aws_partition_by_region;
use crate::inference::SpanData as Span;
use crate::inference::{
    triggers::{lowercase_key, parameterize_api_resource, resolve_service_name, Trigger},
    MS_TO_NS,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use tracing::debug;

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct APIGatewayRestEvent {
    #[serde(deserialize_with = "lowercase_key")]
    pub headers: HashMap<String, String>,
    pub request_context: RequestContext,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RequestContext {
    pub stage: String,
    pub request_id: String,
    pub api_id: String,
    pub domain_name: String,
    #[serde(rename = "requestTimeEpoch")]
    pub time_epoch: i64,
    #[serde(rename = "httpMethod")]
    pub method: String,
    pub resource_path: String,
    pub path: String,
    pub protocol: String,
    pub identity: Identity,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub source_ip: String,
    pub user_agent: String,
}

impl APIGatewayRestEvent {
    fn http_metadata(&self) -> HttpMetadata<'_> {
        HttpMetadata {
            domain: &self.request_context.domain_name,
            path: &self.request_context.path,
            method: &self.request_context.method,
            protocol: &self.request_context.protocol,
            source_ip: &self.request_context.identity.source_ip,
            user_agent: &self.request_context.identity.user_agent,
            request_id: &self.request_context.request_id,
        }
    }
}

impl Trigger for APIGatewayRestEvent {
    fn new(payload: Value) -> Option<Self> {
        match serde_json::from_value(payload) {
            Ok(event) => Some(event),
            Err(e) => {
                debug!("Failed to deserialize APIGatewayRestEvent: {}", e);
                None
            }
        }
    }

    fn is_match(payload: &Value) -> bool {
        let stage = payload.get("requestContext").and_then(|v| v.get("stage"));
        let http_method = payload.get("httpMethod");
        let resource = payload.get("resource");
        stage.is_some() && http_method.is_some() && resource.is_some()
    }

    #[allow(clippy::cast_possible_truncation)]
    fn enrich_span(
        &self,
        span: &mut Span,
        service_mapping: &HashMap<String, String>,
        aws_service_representation_enabled: bool,
    ) {
        debug!("Enriching an Inferred Span for an API Gateway REST Event");
        let resource = format!(
            "{http_method} {path}",
            http_method = self.request_context.method,
            path = parameterize_api_resource(&self.request_context.path)
        );
        let start_time = (self.request_context.time_epoch as f64 * MS_TO_NS) as i64;

        let service_name = resolve_service_name(
            service_mapping,
            &self.request_context.api_id,
            "lambda_api_gateway",
            &self.request_context.domain_name,
            &self.request_context.domain_name,
            aws_service_representation_enabled,
        );

        span.name = "aws.apigateway".to_string();
        span.service = service_name;
        span.resource = resource;
        span.r#type = "web".to_string();
        span.start = start_time;
        span.meta.extend(self.http_metadata().span_tags());
        span.meta.insert(
            "http.route".into(),
            self.request_context.resource_path.clone(),
        );
    }

    fn get_tags(&self) -> HashMap<String, String> {
        let mut tags = self.http_metadata().trigger_tags(
            "api-gateway",
            &self.headers,
            Some(&self.request_context.identity.user_agent),
        );
        tags.insert(
            "http.route".into(),
            self.request_context.resource_path.clone(),
        );

        tags
    }

    fn get_arn(&self, region: &str, _function_name: &str) -> String {
        let partition = get_aws_partition_by_region(region);
        format!(
            "arn:{partition}:apigateway:{region}::/restapis/{api_id}/stages/{stage}",
            partition = partition,
            region = region,
            api_id = self.request_context.api_id,
            stage = self.request_context.stage
        )
    }

    fn get_dd_resource_key(&self, region: &str) -> Option<String> {
        if self.request_context.api_id.is_empty() {
            return None;
        }

        let partition = get_aws_partition_by_region(region);
        Some(format!(
            "arn:{partition}:apigateway:{region}::/restapis/{api_id}",
            partition = partition,
            region = region,
            api_id = self.request_context.api_id
        ))
    }

    fn is_async(&self) -> bool {
        is_async_http(&self.headers)
    }

    fn get_carrier(&self) -> HashMap<String, String> {
        self.headers.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference::triggers::test_utils::read_json_file;

    #[test]
    fn test_parameterize_resource() {
        // Test case with numeric IDs
        assert_eq!(
            parameterize_api_resource("/users/12345/friends/67890"),
            "/users/{user_id}/friends/{friend_id}"
        );

        assert_eq!(
            parameterize_api_resource("/dev/proxy_route/users/12345/friends/67890"),
            "/dev/proxy_route/users/{user_id}/friends/{friend_id}"
        );

        // Test case with already parameterized path
        assert_eq!(
            parameterize_api_resource("/users/{user_id}/profile"),
            "/users/{user_id}/profile"
        );

        // Test case with mixed segments
        assert_eq!(
            parameterize_api_resource("/api/v1/users/12345/settings"),
            "/api/v1/users/{user_id}/settings"
        );

        // Test case with UUIDs
        assert_eq!(
            parameterize_api_resource("/orders/123e4567-e89b-12d3-a456-426614174000/items"),
            "/orders/{order_id}/items"
        );
    }

    #[test]
    fn test_new() {
        let json = read_json_file("api_gateway_rest_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let result = APIGatewayRestEvent::new(payload)
            .expect("Failed to deserialize into APIGatewayRestEvent");

        let expected = APIGatewayRestEvent {
            headers: HashMap::from([
                ("header1".to_string(), "value1".to_string()),
                ("header2".to_string(), "value2".to_string()),
            ]),
            request_context: RequestContext {
                stage: "$default".to_string(),
                request_id: "id=".to_string(),
                api_id: "id".to_string(),
                domain_name: "id.execute-api.us-east-1.amazonaws.com".to_string(),
                time_epoch: 1_583_349_317_135,
                method: "GET".to_string(),
                path: "/my/path".to_string(),
                protocol: "HTTP/1.1".to_string(),
                resource_path: "/path".to_string(),
                identity: Identity {
                    source_ip: "IP".to_string(),
                    user_agent: "user-agent".to_string(),
                },
            },
        };

        assert_eq!(result, expected);
    }

    #[test]
    fn test_is_match() {
        let json = read_json_file("api_gateway_rest_event.json");
        let payload =
            serde_json::from_str(&json).expect("Failed to deserialize APIGatewayRestEvent");

        assert!(APIGatewayRestEvent::is_match(&payload));
    }

    #[test]
    fn test_is_not_match() {
        let json = read_json_file("api_gateway_http_event.json");
        let payload =
            serde_json::from_str(&json).expect("Failed to deserialize APIGatewayRestEvent");
        assert!(!APIGatewayRestEvent::is_match(&payload));
    }

    #[test]
    fn test_enrich_span() {
        let json = read_json_file("api_gateway_rest_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event =
            APIGatewayRestEvent::new(payload).expect("Failed to deserialize APIGatewayRestEvent");
        let mut span = Span::default();
        let service_mapping = HashMap::new();
        event.enrich_span(&mut span, &service_mapping, true);
        assert_eq!(span.name, "aws.apigateway");
        assert_eq!(span.service, "id.execute-api.us-east-1.amazonaws.com");
        assert_eq!(span.resource, "GET /my/path");
        assert_eq!(span.r#type, "web");

        assert_eq!(
            span.meta,
            HashMap::from([
                ("endpoint".to_string(), "/my/path".to_string()),
                (
                    "http.url".to_string(),
                    "https://id.execute-api.us-east-1.amazonaws.com/my/path".to_string()
                ),
                ("http.method".to_string(), "GET".to_string()),
                ("http.protocol".to_string(), "HTTP/1.1".to_string()),
                ("http.source_ip".to_string(), "IP".to_string()),
                ("http.user_agent".to_string(), "user-agent".to_string()),
                ("http.route".to_string(), "/path".to_string()),
                ("request_id".to_string(), "id=".to_string()),
            ])
        );
    }

    #[test]
    fn test_get_tags() {
        let json = read_json_file("api_gateway_rest_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event =
            APIGatewayRestEvent::new(payload).expect("Failed to deserialize APIGatewayRestEvent");
        let tags = event.get_tags();

        let expected = HashMap::from([
            (
                "http.url".to_string(),
                "https://id.execute-api.us-east-1.amazonaws.com/my/path".to_string(),
            ),
            ("http.url_details.path".to_string(), "/my/path".to_string()),
            ("http.method".to_string(), "GET".to_string()),
            ("http.route".to_string(), "/path".to_string()),
            ("http.user_agent".to_string(), "user-agent".to_string()),
            (
                "function_trigger.event_source".to_string(),
                "api-gateway".to_string(),
            ),
        ]);

        assert_eq!(tags, expected);
    }

    #[test]
    fn test_enrich_parameterized_span() {
        let json = read_json_file("api_gateway_rest_event_parameterized.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event =
            APIGatewayRestEvent::new(payload).expect("Failed to deserialize APIGatewayRestEvent");
        let mut span = Span::default();
        let service_mapping = HashMap::new();
        event.enrich_span(&mut span, &service_mapping, true);
        assert_eq!(span.name, "aws.apigateway");
        assert_eq!(
            span.service,
            "mcwkra0ya4.execute-api.sa-east-1.amazonaws.com"
        );
        assert_eq!(span.resource, "GET /dev/user/{user_id}/id/{id}");
        assert_eq!(span.r#type, "web");
        let expected = HashMap::from([
            ("endpoint".to_string(), "/dev/user/42/id/50".to_string()),
            (
                "http.url".to_string(),
                "https://mcwkra0ya4.execute-api.sa-east-1.amazonaws.com/dev/user/42/id/50"
                    .to_string(),
            ),
            ("http.method".to_string(), "GET".to_string()),
            ("http.protocol".to_string(), "HTTP/1.1".to_string()),
            ("http.source_ip".to_string(), "76.115.124.192".to_string()),
            ("http.user_agent".to_string(), "curl/8.1.2".to_string()),
            ("http.route".to_string(), "/user/{id}".to_string()),
            (
                "request_id".to_string(),
                "e16399f7-e984-463a-9931-745ba021a27f".to_string(),
            ),
        ]);
        assert_eq!(span.meta, expected);
    }

    #[test]
    fn test_get_tags_parameterized() {
        let json = read_json_file("api_gateway_rest_event_parameterized.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event =
            APIGatewayRestEvent::new(payload).expect("Failed to deserialize APIGatewayRestEvent");
        let tags = event.get_tags();

        assert_eq!(
            tags,
            HashMap::from([
                (
                    "http.url".to_string(),
                    "https://mcwkra0ya4.execute-api.sa-east-1.amazonaws.com/dev/user/42/id/50"
                        .to_string(),
                ),
                (
                    "http.url_details.path".to_string(),
                    "/dev/user/42/id/50".to_string(),
                ),
                ("http.method".to_string(), "GET".to_string()),
                ("http.route".to_string(), "/user/{id}".to_string()),
                ("http.user_agent".to_string(), "curl/8.1.2".to_string()),
                (
                    "function_trigger.event_source".to_string(),
                    "api-gateway".to_string()
                ),
            ])
        );
    }

    #[test]
    fn test_get_arn() {
        let json = read_json_file("api_gateway_rest_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event =
            APIGatewayRestEvent::new(payload).expect("Failed to deserialize APIGatewayRestEvent");
        assert_eq!(
            event.get_arn("us-east-1", ""),
            "arn:aws:apigateway:us-east-1::/restapis/id/stages/$default"
        );
    }

    #[test]
    fn test_get_dd_resource_key() {
        let json = read_json_file("api_gateway_rest_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event =
            APIGatewayRestEvent::new(payload).expect("Failed to deserialize APIGatewayRestEvent");
        assert_eq!(
            event.get_dd_resource_key("us-east-1"),
            Some("arn:aws:apigateway:us-east-1::/restapis/id".to_string())
        );
    }
}
