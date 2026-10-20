// Copyright 2026-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::LazyLock;

use crate::inference::SpanData as Span;
use regex::Regex;
use serde::{Deserialize, Deserializer};
use serde_json::Value;

use self::alb_event::ALBEvent;
use self::api_gateway_http_event::APIGatewayHttpEvent;
use self::api_gateway_rest_event::APIGatewayRestEvent;
use self::api_gateway_websocket_event::APIGatewayWebSocketEvent;
use self::dynamodb_event::DynamoDbRecord;
use self::event_bridge_event::EventBridgeEvent;
use self::kinesis_event::KinesisRecord;
use self::lambda_function_url_event::LambdaFunctionUrlEvent;
use self::msk_event::MSKEvent;
use self::s3_event::S3Record;
use self::sns_event::SnsRecord;
use self::sqs_event::SqsRecord;
use self::step_function_event::StepFunctionEvent;

pub mod alb_event;
pub mod api_gateway_http_event;
pub mod api_gateway_rest_event;
pub mod api_gateway_websocket_event;
pub mod dynamodb_event;
pub mod event_bridge_event;
pub mod kinesis_event;
pub mod lambda_function_url_event;
pub mod msk_event;
pub mod s3_event;
pub mod sns_event;
pub mod sqs_event;
pub mod step_function_event;

pub const DATADOG_CARRIER_KEY: &str = "_datadog";
pub const FUNCTION_TRIGGER_EVENT_SOURCE_TAG: &str = "function_trigger.event_source";
pub const FUNCTION_TRIGGER_EVENT_SOURCE_ARN_TAG: &str = "function_trigger.event_source_arn";
static ULID_UUID_GUID: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r"(?x)
        (
            [0-9a-fA-F]{8}-          # UUID/GUID segment 1
            [0-9a-fA-F]{4}-          # segment 2
            [0-9a-fA-F]{4}-          # segment 3
            [0-9a-fA-F]{4}-          # segment 4
            [0-9a-fA-F]{12}          # segment 5
        )
        |
        (
            [0123456789ABCDEFGHJKMNPQRSTVWXYZ]{26}  # ULID
        )
    ",
    )
    .ok()
});

struct HttpMetadata<'a> {
    domain: &'a str,
    path: &'a str,
    method: &'a str,
    protocol: &'a str,
    source_ip: &'a str,
    user_agent: &'a str,
    request_id: &'a str,
}

impl HttpMetadata<'_> {
    fn span_tags(&self) -> HashMap<String, String> {
        HashMap::from([
            ("endpoint".into(), self.path.into()),
            ("http.url".into(), http_url(self.domain, self.path)),
            ("http.method".into(), self.method.into()),
            ("http.protocol".into(), self.protocol.into()),
            ("http.source_ip".into(), self.source_ip.into()),
            ("http.user_agent".into(), self.user_agent.into()),
            ("request_id".into(), self.request_id.into()),
        ])
    }

    fn trigger_tags(
        &self,
        source: &str,
        headers: &HashMap<String, String>,
        user_agent: Option<&str>,
    ) -> HashMap<String, String> {
        let mut tags = http_trigger_tags(self.domain, self.path, source, headers);
        tags.insert("http.method".into(), self.method.into());
        if let Some(user_agent) = user_agent {
            tags.insert("http.user_agent".into(), user_agent.into());
        }
        tags
    }
}

fn http_url(domain: &str, path: &str) -> String {
    format!("https://{domain}{path}")
}

fn http_trigger_tags(
    domain: &str,
    path: &str,
    source: &str,
    headers: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut tags = HashMap::from([
        ("http.url".into(), http_url(domain, path)),
        ("http.url_details.path".into(), path.into()),
        (FUNCTION_TRIGGER_EVENT_SOURCE_TAG.into(), source.into()),
    ]);
    if let Some(referer) = headers.get("referer") {
        tags.insert("http.referer".into(), referer.clone());
    }
    tags
}

fn is_async_http(headers: &HashMap<String, String>) -> bool {
    headers
        .get("x-amz-invocation-type")
        .is_some_and(|value| value == "Event")
}

#[must_use]
pub fn parameterize_api_resource(resource: &str) -> String {
    // curly braces are used for APIGW parameters feature
    if resource.contains('{') && resource.contains('}') {
        return resource.to_string();
    }

    let parts: Vec<&str> = resource.split('/').collect();
    let mut result = Vec::new();

    // First element is empty string due to leading slash
    result.push(String::new());

    // Process each path segment
    for (i, part) in parts.iter().enumerate().skip(1) {
        if part.is_empty() {
            continue;
        }

        // Check if this part looks like an identifier
        // Number, ULID, GUID, or UUID
        if part.chars().all(|c| c.is_ascii_digit())
            || ULID_UUID_GUID
                .as_ref()
                .is_some_and(|regex| regex.is_match(part))
        {
            // Determine the parameter name based on the previous segment
            let param_name = if i > 1 && !parts[i - 1].is_empty() {
                let singular = parts[i - 1].trim_end_matches('s');
                if singular == "id" {
                    singular.into()
                } else {
                    format!("{singular}_id")
                }
            } else {
                "id".to_string()
            };

            // Format the parameter with braces and store it in the result
            result.push(format!("{{{param_name}}}"));
        } else {
            result.push((*part).to_string());
        }
    }
    result.join("/")
}

fn resolve_service_name(
    service_mapping: &HashMap<String, String>,
    specific_identifier: &str,
    generic_identifier: &str,
    instance_name: &str,
    fallback: &str,
    aws_service_representation_enabled: bool,
) -> String {
    let default = if aws_service_representation_enabled {
        instance_name
    } else {
        fallback
    };
    service_mapping
        .get(specific_identifier)
        .or_else(|| service_mapping.get(generic_identifier))
        .map(String::as_str)
        .unwrap_or(default)
        .to_owned()
}

pub trait Trigger {
    fn new(payload: Value) -> Option<Self>
    where
        Self: Sized;
    fn is_match(payload: &Value) -> bool
    where
        Self: Sized;
    fn span_data(
        &self,
        _service_mapping: &HashMap<String, String>,
        _aws_service_representation_enabled: bool,
    ) -> Option<Span> {
        None
    }
    fn get_tags(&self) -> HashMap<String, String>;
    fn get_arn(&self, region: &str, function_name: &str) -> String;
    fn get_carrier(&self) -> HashMap<String, String>;
    fn is_async(&self) -> bool;

    fn get_dd_resource_key(&self, _region: &str) -> Option<String> {
        None
    }
}

/// An identified Lambda event source.
#[derive(Debug)]
#[must_use]
#[non_exhaustive]
pub enum IdentifiedTrigger {
    APIGatewayHttpEvent(APIGatewayHttpEvent),
    APIGatewayRestEvent(APIGatewayRestEvent),
    APIGatewayWebSocketEvent(APIGatewayWebSocketEvent),
    ALBEvent(ALBEvent),
    LambdaFunctionUrlEvent(LambdaFunctionUrlEvent),
    MSKEvent(MSKEvent),
    SqsRecord(SqsRecord),
    SnsRecord(SnsRecord),
    DynamoDbRecord(DynamoDbRecord),
    S3Record(S3Record),
    EventBridgeEvent(EventBridgeEvent),
    KinesisRecord(KinesisRecord),
    StepFunctionEvent(StepFunctionEvent),
}

impl IdentifiedTrigger {
    /// Parses the first matching event source in the order below.
    ///
    /// Returns `None` if no source matches or the first matching source fails to parse,
    /// without trying later sources.
    pub fn from_value(payload: Value) -> Option<Self> {
        if APIGatewayHttpEvent::is_match(&payload) {
            APIGatewayHttpEvent::new(payload).map(Self::APIGatewayHttpEvent)
        } else if APIGatewayRestEvent::is_match(&payload) {
            APIGatewayRestEvent::new(payload).map(Self::APIGatewayRestEvent)
        } else if APIGatewayWebSocketEvent::is_match(&payload) {
            APIGatewayWebSocketEvent::new(payload).map(Self::APIGatewayWebSocketEvent)
        } else if ALBEvent::is_match(&payload) {
            ALBEvent::new(payload).map(Self::ALBEvent)
        } else if LambdaFunctionUrlEvent::is_match(&payload) {
            LambdaFunctionUrlEvent::new(payload).map(Self::LambdaFunctionUrlEvent)
        } else if MSKEvent::is_match(&payload) {
            MSKEvent::new(payload).map(Self::MSKEvent)
        } else if SqsRecord::is_match(&payload) {
            SqsRecord::new(payload).map(Self::SqsRecord)
        } else if SnsRecord::is_match(&payload) {
            SnsRecord::new(payload).map(Self::SnsRecord)
        } else if DynamoDbRecord::is_match(&payload) {
            DynamoDbRecord::new(payload).map(Self::DynamoDbRecord)
        } else if S3Record::is_match(&payload) {
            S3Record::new(payload).map(Self::S3Record)
        } else if EventBridgeEvent::is_match(&payload) {
            EventBridgeEvent::new(payload).map(Self::EventBridgeEvent)
        } else if KinesisRecord::is_match(&payload) {
            KinesisRecord::new(payload).map(Self::KinesisRecord)
        } else if StepFunctionEvent::is_match(&payload) {
            StepFunctionEvent::new(payload).map(Self::StepFunctionEvent)
        } else {
            None
        }
    }

    /// Borrows the identified event through its shared trigger interface.
    pub fn as_trigger(&self) -> &dyn Trigger {
        match self {
            Self::APIGatewayHttpEvent(trigger) => trigger,
            Self::APIGatewayRestEvent(trigger) => trigger,
            Self::APIGatewayWebSocketEvent(trigger) => trigger,
            Self::ALBEvent(trigger) => trigger,
            Self::LambdaFunctionUrlEvent(trigger) => trigger,
            Self::MSKEvent(trigger) => trigger,
            Self::SqsRecord(trigger) => trigger,
            Self::SnsRecord(trigger) => trigger,
            Self::DynamoDbRecord(trigger) => trigger,
            Self::S3Record(trigger) => trigger,
            Self::EventBridgeEvent(trigger) => trigger,
            Self::KinesisRecord(trigger) => trigger,
            Self::StepFunctionEvent(trigger) => trigger,
        }
    }
}

/// Moves the first record of a `Records` batch out of the payload instead of copying it.
fn take_first_record(payload: &mut Value) -> Option<Value> {
    payload
        .get_mut("Records")?
        .as_array_mut()?
        .first_mut()
        .map(Value::take)
}

/// Serialize a `HashMap` with lowercase keys
pub fn lowercase_key<'de, D, V>(deserializer: D) -> Result<HashMap<String, V>, D::Error>
where
    D: Deserializer<'de>,
    V: Deserialize<'de>,
{
    let map = HashMap::<String, V>::deserialize(deserializer)?;
    Ok(map
        .into_iter()
        .map(|(key, value)| (key.to_lowercase(), value))
        .collect())
}

#[cfg(test)]
pub mod test_utils {
    use std::fs;
    use std::path::PathBuf;

    #[must_use]
    pub fn read_json_file(file_name: &str) -> String {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests/payloads");
        path.push(file_name);
        fs::read_to_string(path).expect("Failed to read file")
    }
}

#[cfg(test)]
mod tests {
    use super::test_utils::read_json_file;
    use super::*;

    #[test]
    fn overlapping_triggers_select_the_first_match() {
        let mut payload: Value =
            serde_json::from_str(&read_json_file("api_gateway_rest_event.json")).unwrap();
        payload["requestContext"]["elb"] = serde_json::json!({
            "targetGroupArn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test"
        });
        assert!(APIGatewayRestEvent::is_match(&payload));
        assert!(ALBEvent::is_match(&payload));
        assert!(ALBEvent::new(payload.clone()).is_some());

        assert!(matches!(
            IdentifiedTrigger::from_value(payload),
            Some(IdentifiedTrigger::APIGatewayRestEvent(_))
        ));
    }

    #[test]
    fn malformed_first_match_does_not_fall_back_to_a_later_trigger() {
        let mut payload: Value =
            serde_json::from_str(&read_json_file("api_gateway_rest_event.json")).unwrap();
        payload["requestContext"]["elb"] = serde_json::json!({
            "targetGroupArn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test"
        });
        payload["requestContext"]["identity"] = Value::Null;
        assert!(APIGatewayRestEvent::is_match(&payload));
        assert!(APIGatewayRestEvent::new(payload.clone()).is_none());
        assert!(ALBEvent::is_match(&payload));
        assert!(ALBEvent::new(payload.clone()).is_some());

        assert!(IdentifiedTrigger::from_value(payload).is_none());
    }

    #[test]
    fn unmatched_payloads_have_no_trigger() {
        for payload in [
            Value::Null,
            serde_json::json!({}),
            serde_json::json!({"Records": []}),
        ] {
            assert!(IdentifiedTrigger::from_value(payload).is_none());
        }
    }

    #[test]
    fn http_triggers_preserve_user_agent_sources_and_invocation_type() {
        for (fixture, user_agent_path, expected_agent) in [
            (
                "api_gateway_http_event.json",
                "/requestContext/http/userAgent",
                "header-agent",
            ),
            (
                "api_gateway_rest_event.json",
                "/requestContext/identity/userAgent",
                "context-agent",
            ),
            (
                "lambda_function_url_event.json",
                "/requestContext/http/userAgent",
                "context-agent",
            ),
        ] {
            for (invocation_type, expected_async) in [("Event", true), ("RequestResponse", false)] {
                let mut payload: Value = serde_json::from_str(&read_json_file(fixture)).unwrap();
                *payload.pointer_mut(user_agent_path).unwrap() = "context-agent".into();
                payload["headers"]["User-Agent"] = "header-agent".into();
                payload["headers"]["Referer"] = "https://example.com".into();
                payload["headers"]["X-Amz-Invocation-Type"] = invocation_type.into();
                let identified = IdentifiedTrigger::from_value(payload).unwrap();
                let trigger = identified.as_trigger();
                let span = trigger.span_data(&HashMap::new(), true).unwrap();
                assert_eq!(span.meta["http.user_agent"], "context-agent", "{fixture}");
                let tags = trigger.get_tags();
                assert_eq!(tags["http.user_agent"], expected_agent, "{fixture}");
                assert_eq!(tags["http.referer"], "https://example.com", "{fixture}");
                assert_eq!(trigger.is_async(), expected_async, "{fixture}");
            }
        }
    }

    #[test]
    fn service_names_follow_mapping_precedence_and_representation() {
        for (fixture, specific, generic, instance, fallback) in [
            (
                "api_gateway_http_event.json",
                "x02yirxc7a",
                "lambda_api_gateway",
                "x02yirxc7a.execute-api.sa-east-1.amazonaws.com",
                "x02yirxc7a.execute-api.sa-east-1.amazonaws.com",
            ),
            (
                "api_gateway_rest_event.json",
                "id",
                "lambda_api_gateway",
                "id.execute-api.us-east-1.amazonaws.com",
                "id.execute-api.us-east-1.amazonaws.com",
            ),
            (
                "api_gateway_websocket_connect_event.json",
                "85fj5nw29d",
                "lambda_api_gateway",
                "85fj5nw29d.execute-api.eu-west-1.amazonaws.com",
                "api_gateway_websocket",
            ),
            (
                "lambda_function_url_event.json",
                "a8hyhsshac",
                "lambda_url",
                "a8hyhsshac.lambda-url.eu-south-1.amazonaws.com",
                "a8hyhsshac.lambda-url.eu-south-1.amazonaws.com",
            ),
            (
                "msk_event.json",
                "demo-cluster",
                "lambda_msk",
                "demo-cluster",
                "msk",
            ),
            ("sqs_event.json", "MyQueue", "lambda_sqs", "MyQueue", "sqs"),
            (
                "sns_event.json",
                "serverlessTracingTopicPy",
                "lambda_sns",
                "serverlessTracingTopicPy",
                "sns",
            ),
            (
                "dynamodb_event.json",
                "ExampleTableWithStream",
                "lambda_dynamodb",
                "ExampleTableWithStream",
                "dynamodb",
            ),
            (
                "s3_event.json",
                "example-bucket",
                "lambda_s3",
                "example-bucket",
                "s3",
            ),
            (
                "eventbridge_event.json",
                "testBus",
                "lambda_eventbridge",
                "testBus",
                "eventbridge",
            ),
            (
                "kinesis_event.json",
                "kinesisStream",
                "lambda_kinesis",
                "kinesisStream",
                "kinesis",
            ),
        ] {
            assert_service_names(fixture, specific, generic, instance, fallback);
        }
    }

    fn assert_service_names(
        fixture: &str,
        specific: &str,
        generic: &str,
        instance: &str,
        fallback: &str,
    ) {
        let event =
            IdentifiedTrigger::from_value(serde_json::from_str(&read_json_file(fixture)).unwrap())
                .unwrap();
        let trigger = event.as_trigger();
        for enabled in [false, true] {
            for (entries, expected) in [
                (
                    vec![(specific, "specific"), (generic, "generic")],
                    "specific",
                ),
                (vec![(generic, "generic")], "generic"),
                (
                    vec![("unrelated", "other")],
                    if enabled { instance } else { fallback },
                ),
                (vec![], if enabled { instance } else { fallback }),
            ] {
                let mapping = entries
                    .into_iter()
                    .map(|(key, value)| (key.into(), value.into()))
                    .collect();
                let span = trigger.span_data(&mapping, enabled).unwrap();
                assert_eq!(span.service, expected, "{fixture}, enabled={enabled}");
            }
        }
    }

    #[test]
    fn context_only_triggers_do_not_resolve_services() {
        for fixture in ["application_load_balancer.json", "step_function_event.json"] {
            let event = IdentifiedTrigger::from_value(
                serde_json::from_str(&read_json_file(fixture)).unwrap(),
            )
            .unwrap();
            let mapping = HashMap::from([
                ("lambda_application_load_balancer".into(), "alb".into()),
                ("lambda_stepfunction".into(), "states".into()),
            ]);
            for enabled in [false, true] {
                assert!(
                    event.as_trigger().span_data(&mapping, enabled).is_none(),
                    "{fixture}"
                );
            }
        }
    }
}
