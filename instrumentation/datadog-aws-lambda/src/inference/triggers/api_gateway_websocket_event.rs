// Copyright 2026-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use crate::inference::SpanData as Span;
use crate::{
    inference::get_aws_partition_by_region,
    inference::{
        triggers::{lowercase_key, Trigger},
        MS_TO_NS,
    },
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use tracing::debug;

use super::{http_trigger_tags, http_url, resolve_service_name};

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct APIGatewayWebSocketEvent {
    #[serde(deserialize_with = "lowercase_key", default)]
    pub headers: HashMap<String, String>,
    pub request_context: RequestContext,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RequestContext {
    pub route_key: String,
    pub domain_name: String,
    #[serde(rename = "requestTimeEpoch")]
    pub time_epoch: i64,
    pub request_id: String,
    pub api_id: String,
    pub stage: String,
    pub connection_id: String,
    pub event_type: String,
    pub message_direction: String,
}

impl Trigger for APIGatewayWebSocketEvent {
    fn new(payload: Value) -> Option<Self> {
        match serde_json::from_value(payload) {
            Ok(event) => Some(event),
            Err(e) => {
                debug!("Failed to deserialize APIGatewayWebSocketEvent: {}", e);
                None
            }
        }
    }

    fn is_match(payload: &Value) -> bool {
        let message_direction = payload
            .get("requestContext")
            .and_then(|v| v.get("messageDirection"));
        message_direction.is_some()
    }

    #[allow(clippy::cast_possible_truncation)]
    fn span_data(
        &self,
        service_mapping: &HashMap<String, String>,
        aws_service_representation_enabled: bool,
    ) -> Option<Span> {
        let mut span = Span::default();
        debug!("Enriching an Inferred Span for an API Gateway WebSocket Event");
        let resource = &self.request_context.route_key;
        let http_url = http_url(
            &self.request_context.domain_name,
            &self.request_context.route_key,
        );
        let start_time = (self.request_context.time_epoch as f64 * MS_TO_NS) as i64;

        let service_name = resolve_service_name(
            service_mapping,
            &self.request_context.api_id,
            "lambda_api_gateway",
            &self.request_context.domain_name,
            "api_gateway_websocket",
            aws_service_representation_enabled,
        );

        span.name = "aws.apigateway".to_string();
        span.service = service_name;
        span.resource.clone_from(resource);
        span.r#type = "web".to_string();
        span.start = start_time;
        span.meta.extend([
            (
                "endpoint".to_string(),
                self.request_context.route_key.clone(),
            ),
            (
                "resource_names".to_string(),
                self.request_context.route_key.clone(),
            ),
            ("http.url".to_string(), http_url),
            (
                "request_id".to_string(),
                self.request_context.request_id.clone(),
            ),
            ("apiid".to_string(), self.request_context.api_id.clone()),
            ("stage".to_string(), self.request_context.stage.clone()),
            (
                "connection_id".to_string(),
                self.request_context.connection_id.clone(),
            ),
            (
                "event_type".to_string(),
                self.request_context.event_type.clone(),
            ),
            (
                "message_direction".to_string(),
                self.request_context.message_direction.clone(),
            ),
        ]);
        Some(span)
    }

    fn get_tags(&self) -> HashMap<String, String> {
        http_trigger_tags(
            &self.request_context.domain_name,
            &self.request_context.route_key,
            "api-gateway",
            &self.headers,
        )
    }

    fn get_arn(&self, region: &str, _function_name: &str) -> String {
        let partition = get_aws_partition_by_region(region);
        format!(
            "arn:{partition}:apigateway:{region}::/apis/{api_id}/stages/{stage}",
            partition = partition,
            region = region,
            api_id = self.request_context.api_id,
            stage = self.request_context.stage
        )
    }

    fn is_async(&self) -> bool {
        // WebSocket events are always async
        true
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
    fn test_new_connect_event() {
        let json = read_json_file("api_gateway_websocket_connect_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let result = APIGatewayWebSocketEvent::new(payload)
            .expect("Failed to deserialize into APIGatewayWebSocketEvent");

        let expected = APIGatewayWebSocketEvent {
            headers: HashMap::new(),
            request_context: RequestContext {
                route_key: "hello".to_string(),
                domain_name: "85fj5nw29d.execute-api.eu-west-1.amazonaws.com".to_string(),
                time_epoch: 1_666_633_666_203,
                request_id: "ahVmYGOMmjQFhyg=".to_string(),
                api_id: "85fj5nw29d".to_string(),
                stage: "dev".to_string(),
                connection_id: "ahVWscZqmjQCI1w=".to_string(),
                event_type: "MESSAGE".to_string(),
                message_direction: "IN".to_string(),
            },
        };

        assert_eq!(result, expected);
    }

    #[test]
    fn test_new_message_event() {
        let json = read_json_file("api_gateway_websocket_message_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let result = APIGatewayWebSocketEvent::new(payload)
            .expect("Failed to deserialize into APIGatewayWebSocketEvent");

        let expected = APIGatewayWebSocketEvent {
            headers: HashMap::new(),
            request_context: RequestContext {
                route_key: "hello".to_string(),
                domain_name: "85fj5nw29d.execute-api.eu-west-1.amazonaws.com".to_string(),
                time_epoch: 1_666_633_666_203,
                request_id: "ahVmYGOMmjQFhyg=".to_string(),
                api_id: "85fj5nw29d".to_string(),
                stage: "dev".to_string(),
                connection_id: "ahVWscZqmjQCI1w=".to_string(),
                event_type: "MESSAGE".to_string(),
                message_direction: "IN".to_string(),
            },
        };

        assert_eq!(result, expected);
    }

    #[test]
    fn test_new_disconnect_event() {
        let json = read_json_file("api_gateway_websocket_disconnect_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let result = APIGatewayWebSocketEvent::new(payload)
            .expect("Failed to deserialize into APIGatewayWebSocketEvent");

        let expected = APIGatewayWebSocketEvent {
            headers: HashMap::new(),
            request_context: RequestContext {
                route_key: "hello".to_string(),
                domain_name: "85fj5nw29d.execute-api.eu-west-1.amazonaws.com".to_string(),
                time_epoch: 1_666_633_666_203,
                request_id: "ahVmYGOMmjQFhyg=".to_string(),
                api_id: "85fj5nw29d".to_string(),
                stage: "production".to_string(),
                connection_id: "ahVWscZqmjQCI1w=".to_string(),
                event_type: "DISCONNECT".to_string(), /* Note: The example payload shows MESSAGE
                                                       * event type, not DISCONNECT */
                message_direction: "IN".to_string(),
            },
        };

        assert_eq!(result, expected);
    }

    #[test]
    fn test_is_match() {
        let json = read_json_file("api_gateway_websocket_connect_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        assert!(APIGatewayWebSocketEvent::is_match(&payload));
    }

    #[test]
    fn test_is_not_match() {
        let json = read_json_file("api_gateway_http_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        assert!(!APIGatewayWebSocketEvent::is_match(&payload));

        let json = read_json_file("api_gateway_proxy_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        assert!(!APIGatewayWebSocketEvent::is_match(&payload));
    }

    #[test]
    fn test_enrich_span() {
        let json = read_json_file("api_gateway_websocket_connect_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = APIGatewayWebSocketEvent::new(payload)
            .expect("Failed to deserialize APIGatewayWebSocketEvent");

        let service_mapping = HashMap::new();
        let span = event.span_data(&service_mapping, true).unwrap();

        assert_eq!(span.name, "aws.apigateway");
        assert_eq!(
            span.service,
            "85fj5nw29d.execute-api.eu-west-1.amazonaws.com"
        );
        assert_eq!(span.resource, "hello");
        assert_eq!(span.r#type, "web");
        assert_eq!(
            span.meta,
            HashMap::from([
                ("endpoint".to_string(), "hello".to_string()),
                ("resource_names".to_string(), "hello".to_string()),
                (
                    "http.url".to_string(),
                    "https://85fj5nw29d.execute-api.eu-west-1.amazonaws.comhello".to_string()
                ),
                ("request_id".to_string(), "ahVmYGOMmjQFhyg=".to_string()),
                ("apiid".to_string(), "85fj5nw29d".to_string()),
                ("stage".to_string(), "dev".to_string()),
                ("connection_id".to_string(), "ahVWscZqmjQCI1w=".to_string()),
                ("event_type".to_string(), "MESSAGE".to_string()),
                ("message_direction".to_string(), "IN".to_string()),
            ])
        );
    }

    #[test]
    fn test_get_tags() {
        let json = read_json_file("api_gateway_websocket_connect_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = APIGatewayWebSocketEvent::new(payload)
            .expect("Failed to deserialize APIGatewayWebSocketEvent");

        let tags = event.get_tags();
        let expected = HashMap::from([
            (
                "http.url".to_string(),
                "https://85fj5nw29d.execute-api.eu-west-1.amazonaws.comhello".to_string(),
            ),
            ("http.url_details.path".to_string(), "hello".to_string()),
            (
                "function_trigger.event_source".to_string(),
                "api-gateway".to_string(),
            ),
        ]);

        assert_eq!(tags, expected);
    }

    #[test]
    fn test_get_arn() {
        let json = read_json_file("api_gateway_websocket_connect_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = APIGatewayWebSocketEvent::new(payload)
            .expect("Failed to deserialize APIGatewayWebSocketEvent");

        assert_eq!(
            event.get_arn("us-east-1", ""),
            "arn:aws:apigateway:us-east-1::/apis/85fj5nw29d/stages/dev"
        );
    }
}
