// Copyright 2026-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::LazyLock;

use crate::inference::SpanData as Span;
use regex::Regex;
use serde::{Deserialize, Deserializer};
use serde_json::Value;

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

/// Resolves the service name for a given trigger depending on
/// service mapping configuration.
pub trait ServiceNameResolver {
    /// Get the specific service name for this trigger type, it will
    /// be used as a key to resolve the service name
    fn get_specific_identifier(&self) -> String;

    /// Get the generic service mapping key for the trigger
    fn get_generic_identifier(&self) -> &'static str;
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

#[must_use]
pub fn get_default_service_name(
    instance_name: &str,
    fallback: &str,
    aws_service_representation_enabled: bool,
) -> String {
    if !aws_service_representation_enabled {
        return fallback.to_string();
    }

    instance_name.to_string()
}

pub trait Trigger: ServiceNameResolver {
    fn new(payload: Value) -> Option<Self>
    where
        Self: Sized;
    fn is_match(payload: &Value) -> bool
    where
        Self: Sized;
    fn enrich_span(
        &self,
        span: &mut Span,
        service_mapping: &HashMap<String, String>,
        aws_service_representation_enabled: bool,
    );
    fn get_tags(&self) -> HashMap<String, String>;
    fn get_arn(&self, region: &str, function_name: &str) -> String;
    fn get_carrier(&self) -> HashMap<String, String>;
    fn is_async(&self) -> bool;

    fn get_dd_resource_key(&self, _region: &str) -> Option<String> {
        None
    }

    /// Default implementation for service name resolution
    fn resolve_service_name(
        &self,
        service_mapping: &HashMap<String, String>,
        instance_name: &str,
        fallback: &str,
        aws_service_representation_enabled: bool,
    ) -> String {
        service_mapping
            .get(&self.get_specific_identifier())
            .or_else(|| service_mapping.get(self.get_generic_identifier()))
            .cloned()
            .unwrap_or_else(|| {
                get_default_service_name(
                    instance_name,
                    fallback,
                    aws_service_representation_enabled,
                )
            })
    }
}

/// A macro do define an enum for all the know trigger types.
///
/// It generates an enum with one variant for each named type.
/// The variants are specified as `<data-type> => <variant-name>`.
///
/// It also creates a `from_value` method that use the
/// [`Trigger::is_match`] and [`Trigger::new`] methods to try and parse a
/// payload; cases are matched in the order they are declared.
macro_rules! identified_triggers {
    (
        $vis:vis enum $name:ident {
            $($type:ty => $case:ident),+,
            else => $default:ident,
        }
    ) => {
        #[derive(Debug, Default)]
        #[must_use]
        #[non_exhaustive]
        $vis enum $name {
            $($case($type),)+
            #[default]
            $default,
        }
        impl $name {
            $vis fn from_value(payload: Value) -> Self {
                $(
                if <$type>::is_match(&payload) {
                    return <$type>::new(payload).map_or(Self::$default, Self::$case);
                }
                )+
                Self::$default
            }



            $vis fn as_trigger(&self) -> Option<&dyn Trigger> {
                match self {
                    $(Self::$case(trigger) => Some(trigger),)+
                    Self::$default => None,
                }
            }
        }
    };
}

identified_triggers!(
    pub enum IdentifiedTrigger {
        api_gateway_http_event::APIGatewayHttpEvent => APIGatewayHttpEvent,
        api_gateway_rest_event::APIGatewayRestEvent => APIGatewayRestEvent,
        api_gateway_websocket_event::APIGatewayWebSocketEvent => APIGatewayWebSocketEvent,
        alb_event::ALBEvent => ALBEvent,
        lambda_function_url_event::LambdaFunctionUrlEvent => LambdaFunctionUrlEvent,
        msk_event::MSKEvent => MSKEvent,
        sqs_event::SqsRecord => SqsRecord,
        sns_event::SnsRecord => SnsRecord,
        dynamodb_event::DynamoDbRecord => DynamoDbRecord,
        s3_event::S3Record => S3Record,
        event_bridge_event::EventBridgeEvent => EventBridgeEvent,
        kinesis_event::KinesisRecord => KinesisRecord,
        step_function_event::StepFunctionEvent => StepFunctionEvent,
        else => Unknown,
    }
);

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
            IdentifiedTrigger::from_value(serde_json::from_str(&read_json_file(fixture)).unwrap());
        let trigger = event.as_trigger().unwrap();
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
                let mut span = Span::default();
                trigger.enrich_span(&mut span, &mapping, enabled);
                assert_eq!(span.service, expected, "{fixture}, enabled={enabled}");
            }
        }
    }

    #[test]
    fn context_only_triggers_do_not_resolve_services() {
        for fixture in ["application_load_balancer.json", "step_function_event.json"] {
            let event = IdentifiedTrigger::from_value(
                serde_json::from_str(&read_json_file(fixture)).unwrap(),
            );
            let mapping = HashMap::from([
                ("lambda_application_load_balancer".into(), "alb".into()),
                ("lambda_stepfunction".into(), "states".into()),
            ]);
            for enabled in [false, true] {
                let mut span = Span::default();
                event
                    .as_trigger()
                    .unwrap()
                    .enrich_span(&mut span, &mapping, enabled);
                assert_eq!(span, Span::default(), "{fixture}");
            }
        }
    }
}
