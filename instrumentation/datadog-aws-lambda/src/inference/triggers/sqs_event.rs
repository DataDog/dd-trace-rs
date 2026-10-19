// Copyright 2026-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use crate::inference::get_aws_partition_by_region;
use crate::inference::SpanData as Span;
use crate::inference::{
    base64_to_string,
    triggers::{
        event_bridge_event::EventBridgeEvent,
        sns_event::{SnsEntity, SnsRecord},
        ServiceNameResolver, Trigger, DATADOG_CARRIER_KEY, FUNCTION_TRIGGER_EVENT_SOURCE_TAG,
    },
    MS_TO_NS,
};
use datadog_opentelemetry::propagation::context::{Sampling, SpanContext};
use serde::Deserialize;
use serde_json::Value;
use std::cell::OnceCell;
use std::collections::HashMap;
use tracing::debug;

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct SqsRecord {
    #[serde(rename = "receiptHandle")]
    pub receipt_handle: String,
    pub attributes: Attributes,
    #[serde(rename = "messageAttributes")]
    pub message_attributes: HashMap<String, MessageAttribute>,
    #[serde(rename = "eventSourceARN")]
    pub event_source_arn: String,
    #[serde(rename = "awsRegion")]
    pub aws_region: String,
    pub body: String,
    /// The SNS or EventBridge event delivered as the body, parsed on first use.
    #[serde(skip)]
    wrapped: OnceCell<Option<Box<SqsWrappedEvent>>>,
}

/// An SNS notification or EventBridge event delivered as the body of an SQS message.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum SqsWrappedEvent {
    Sns(SnsRecord),
    EventBridge(EventBridgeEvent),
}

impl SqsWrappedEvent {
    fn parse(body: &str) -> Option<Self> {
        if let Ok(sns) = serde_json::from_str::<SnsEntity>(body) {
            return Some(Self::Sns(SnsRecord::from_entity(sns)));
        }
        serde_json::from_str(body).ok().map(Self::EventBridge)
    }

    pub(crate) fn as_trigger(&self) -> &dyn Trigger {
        match self {
            Self::Sns(record) => record,
            Self::EventBridge(event) => event,
        }
    }
}

impl SqsRecord {
    pub(crate) fn wrapped_event(&self) -> Option<&SqsWrappedEvent> {
        self.wrapped
            .get_or_init(|| SqsWrappedEvent::parse(&self.body).map(Box::new))
            .as_deref()
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct MessageAttribute {
    #[serde(rename = "stringValue")]
    pub string_value: Option<String>,
    #[serde(rename = "binaryValue")]
    pub binary_value: Option<String>,
    #[serde(rename = "dataType")]
    pub data_type: String,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct Attributes {
    #[serde(rename = "ApproximateReceiveCount")]
    pub approximate_receive_count: String,
    #[serde(rename = "SentTimestamp")]
    pub sent_timestamp: String,
    #[serde(rename = "SenderId")]
    pub sender_id: String,
    #[serde(rename = "AWSTraceHeader")]
    pub aws_trace_header: Option<String>,
}

impl Trigger for SqsRecord {
    fn new(mut payload: Value) -> Option<Self> {
        match serde_json::from_value::<SqsRecord>(super::take_first_record(&mut payload)?) {
            Ok(record) => Some(record),
            Err(e) => {
                debug!("Failed to deserialize SQS Record: {e}");
                None
            }
        }
    }

    fn is_match(payload: &Value) -> bool {
        if let Some(first_record) = payload
            .get("Records")
            .and_then(Value::as_array)
            .and_then(|r| r.first())
        {
            first_record
                .get("eventSource")
                .and_then(Value::as_str)
                .is_some_and(|s| s == "aws:sqs")
        } else {
            false
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    fn enrich_span(
        &self,
        span: &mut Span,
        service_mapping: &HashMap<String, String>,
        aws_service_representation_enabled: bool,
    ) {
        debug!("Enriching an Inferred Span for an SQS Event");
        let resource = self.get_specific_identifier();
        let start_time = (self
            .attributes
            .sent_timestamp
            .parse::<i64>()
            .unwrap_or_default() as f64
            * MS_TO_NS) as i64;

        let service_name = self.resolve_service_name(
            service_mapping,
            &self.get_specific_identifier(),
            "sqs",
            aws_service_representation_enabled,
        );

        span.name = "aws.sqs".to_string();
        span.service.clone_from(&service_name);
        span.resource = resource;
        span.r#type = "web".to_string();
        span.start = start_time;
        span.meta.extend(HashMap::from([
            ("operation_name".to_string(), "aws.sqs".to_string()),
            ("receipt_handle".to_string(), self.receipt_handle.clone()),
            (
                "retry_count".to_string(),
                self.attributes.approximate_receive_count.clone(),
            ),
            ("sender_id".to_string(), self.attributes.sender_id.clone()),
            ("source_arn".to_string(), self.event_source_arn.clone()),
            ("aws_region".to_string(), self.aws_region.clone()),
        ]));
    }

    fn get_tags(&self) -> HashMap<String, String> {
        HashMap::from([
            (
                "retry_count".to_string(),
                self.attributes.approximate_receive_count.clone(),
            ),
            ("sender_id".to_string(), self.attributes.sender_id.clone()),
            ("source_arn".to_string(), self.event_source_arn.clone()),
            ("aws_region".to_string(), self.aws_region.clone()),
            (
                FUNCTION_TRIGGER_EVENT_SOURCE_TAG.to_string(),
                "sqs".to_string(),
            ),
        ])
    }

    fn get_arn(&self, region: &str, _function_name: &str) -> String {
        if let [_, _, _, _, account, queue_name] = self
            .event_source_arn
            .split(':')
            .collect::<Vec<&str>>()
            .as_slice()
        {
            format!(
                "arn:{}:sqs:{}:{}:{}",
                get_aws_partition_by_region(region),
                region,
                account,
                queue_name
            )
        } else {
            String::new()
        }
    }

    fn get_carrier(&self) -> HashMap<String, String> {
        let carrier = HashMap::new();

        if let Some(ma) = self.message_attributes.get(DATADOG_CARRIER_KEY) {
            // dataType may carry a custom label suffix, e.g. "String.foo" or "Binary.foo".
            if ma.data_type.starts_with("String") {
                if let Some(string_value) = &ma.string_value {
                    return serde_json::from_str(string_value).unwrap_or_default();
                }
            } else if ma.data_type.starts_with("Binary") {
                if let Some(carrier) = ma
                    .binary_value
                    .as_deref()
                    .and_then(|value| base64_to_string(value).ok())
                {
                    return serde_json::from_str(&carrier).unwrap_or_default();
                }
            } else {
                debug!(
                    "Unsupported dataType in SQS message attribute: {}",
                    ma.data_type
                );
            }
        }

        // Check for an SNS or EventBridge event sent through SQS
        if let Some(wrapped) = self.wrapped_event() {
            return wrapped.as_trigger().get_carrier();
        }

        // TODO: AWSTraceHeader
        carrier
    }

    fn is_async(&self) -> bool {
        true
    }
}

impl ServiceNameResolver for SqsRecord {
    fn get_specific_identifier(&self) -> String {
        self.event_source_arn
            .split(':')
            .next_back()
            .unwrap_or_default()
            .to_string()
    }

    fn get_generic_identifier(&self) -> &'static str {
        "lambda_sqs"
    }
}

// extractTraceContextfromAWSTraceHeader extracts trace context from the
// AWSTraceHeader directly. Unlike the other carriers in this file, it should
// not be passed to the tracer.Propagator, instead extracting context directly.
pub(crate) fn extract_trace_context_from_aws_trace_header(
    headers_string: Option<&str>,
) -> Option<SpanContext> {
    let value = headers_string?;
    if !value.starts_with("Root=") {
        return None;
    }

    let mut trace_id = String::new();
    let mut parent_id = String::new();
    let mut sampled = String::new();
    // `dd-trace-java` is the only tracer that plants context here, and it zeroes the high 32 bits
    // of the ID section; an AWS-generated ID has random hex there. It ignores headers without
    // that padding on extract (`XRayHttpCodec`), and so did the Go extension (`rootRegex`).
    let mut datadog_planted = false;

    for part in value.split(';') {
        if part.starts_with("Root=") {
            // `Root=1-<8 hex epoch>-<24 hex id>`: the ID section starts at 16, and the trace ID
            // Datadog uses is its low 16 hex digits.
            let id_section = part.get(16..)?;
            datadog_planted = id_section.starts_with("00000000");
            trace_id = id_section.get(8..).unwrap_or_default().to_string();
        } else if let Some(parent_part) = part.strip_prefix("Parent=") {
            parent_id = parent_part.to_string();
        } else if part.starts_with("Sampled=") && sampled.is_empty() {
            sampled = part[8..].to_string();
        }
        if !trace_id.is_empty() && !parent_id.is_empty() && !sampled.is_empty() {
            break;
        }
    }

    let trace_id = u64::from_str_radix(&trace_id, 16).ok()?;
    let parent_id = u64::from_str_radix(&parent_id, 16).ok()?;

    if trace_id == 0 || parent_id == 0 {
        debug!("awstrace_header contains empty trace or parent ID");
        return None;
    }

    // Whether `Sampled` is a decision we can act on depends on who wrote the header.
    let sampling_priority = match (datadog_planted, sampled.as_str()) {
        // A keep is safe to honor whoever wrote it: the cost is over-retention, not lost spans.
        (_, "1") => Some("1"),
        // `dd-trace-java` planted this header, so the drop is Datadog's own decision.
        (true, "0") => Some("0"),
        // X-Ray's drop, or no decision at all: X-Ray tracing is off, or `dd-trace-java` wrote the
        // header before its priority was set, so it omitted `Sampled`. Leaving the priority unset
        // lets the tracer sample; sending 0 would drop its spans on someone else's behalf.
        _ => None,
    }
    .and_then(|priority| priority.parse().ok());

    Some(SpanContext {
        // the context from AWS Header is used by Datadog only and does not contain the upper
        // 64 bits like other 128 w3c compliant trace ids
        trace_id: u128::from(trace_id),
        span_id: parent_id,
        sampling: Sampling {
            priority: sampling_priority,
            mechanism: None,
        },
        origin: None,
        tags: HashMap::new(),
        links: Vec::new(),
        ..Default::default()
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::inference::triggers::test_utils::read_json_file;

    #[test]
    fn test_new() {
        let json = read_json_file("sqs_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let result = SqsRecord::new(payload).expect("Failed to deserialize into Record");

        let message_attributes = HashMap::<String, MessageAttribute>::from([
            ("_datadog".to_string(), MessageAttribute {
                string_value: Some("{\"x-datadog-trace-id\":\"2684756524522091840\",\"x-datadog-parent-id\":\"7431398482019833808\",\"x-datadog-sampling-priority\":\"1\"}".to_string()),
                binary_value: None,
                data_type: "String".to_string(),
            })
        ]);

        let expected = SqsRecord {
            receipt_handle: "MessageReceiptHandle".to_string(),
            attributes: Attributes {
                approximate_receive_count: "1".to_string(),
                sent_timestamp: "1523232000000".to_string(),
                sender_id: "123456789012".to_string(),
                aws_trace_header: None,
            },
            message_attributes,
            event_source_arn: "arn:aws:sqs:us-east-1:123456789012:MyQueue".to_string(),
            aws_region: "us-east-1".to_string(),
            body: "Hello from SQS!".to_string(),
            wrapped: OnceCell::new(),
        };

        assert_eq!(result, expected);
    }

    #[test]
    fn test_is_match() {
        let json = read_json_file("sqs_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize SqsRecord");

        assert!(SqsRecord::is_match(&payload));
    }

    #[test]
    fn test_is_not_match() {
        let json = read_json_file("api_gateway_http_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize SqsRecord");
        assert!(!SqsRecord::is_match(&payload));
    }

    #[test]
    fn test_enrich_span() {
        let json = read_json_file("sqs_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = SqsRecord::new(payload).expect("Failed to deserialize SqsRecord");
        let mut span = Span::default();
        let service_mapping = HashMap::new();
        event.enrich_span(&mut span, &service_mapping, true);
        assert_eq!(span.name, "aws.sqs");
        assert_eq!(span.service, "MyQueue");
        assert_eq!(span.resource, "MyQueue");
        assert_eq!(span.r#type, "web");

        assert_eq!(
            span.meta,
            HashMap::from([
                ("operation_name".to_string(), "aws.sqs".to_string()),
                (
                    "receipt_handle".to_string(),
                    "MessageReceiptHandle".to_string(),
                ),
                ("retry_count".to_string(), 1.to_string()),
                ("sender_id".to_string(), "123456789012".to_string()),
                (
                    "source_arn".to_string(),
                    "arn:aws:sqs:us-east-1:123456789012:MyQueue".to_string()
                ),
                ("aws_region".to_string(), "us-east-1".to_string()),
            ])
        );
    }

    #[test]
    fn test_get_tags() {
        let json = read_json_file("sqs_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = SqsRecord::new(payload).expect("Failed to deserialize SqsRecord");
        let tags = event.get_tags();

        let expected = HashMap::from([
            ("retry_count".to_string(), 1.to_string()),
            ("sender_id".to_string(), "123456789012".to_string()),
            (
                "source_arn".to_string(),
                "arn:aws:sqs:us-east-1:123456789012:MyQueue".to_string(),
            ),
            ("aws_region".to_string(), "us-east-1".to_string()),
            (
                "function_trigger.event_source".to_string(),
                "sqs".to_string(),
            ),
        ]);

        assert_eq!(tags, expected);
    }

    #[test]
    fn test_get_arn() {
        let json = read_json_file("sqs_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = SqsRecord::new(payload).expect("Failed to deserialize SqsRecord");
        assert_eq!(
            event.get_arn("us-east-1", ""),
            "arn:aws:sqs:us-east-1:123456789012:MyQueue"
        );
    }

    #[test]
    fn test_get_carrier() {
        let json = read_json_file("sqs_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = SqsRecord::new(payload).expect("Failed to deserialize SqsRecord");
        let carrier = event.get_carrier();

        let expected = HashMap::from([
            (
                "x-datadog-trace-id".to_string(),
                "2684756524522091840".to_string(),
            ),
            (
                "x-datadog-parent-id".to_string(),
                "7431398482019833808".to_string(),
            ),
            ("x-datadog-sampling-priority".to_string(), "1".to_string()),
        ]);

        assert_eq!(carrier, expected);
    }

    #[test]
    fn test_get_carrier_binary() {
        let json = read_json_file("sqs_event_binary.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = SqsRecord::new(payload).expect("Failed to deserialize SqsRecord");
        let carrier = event.get_carrier();

        let expected = HashMap::from([
            (
                "x-datadog-trace-id".to_string(),
                "1111111111111111111".to_string(),
            ),
            (
                "x-datadog-parent-id".to_string(),
                "2222222222222222222".to_string(),
            ),
            ("x-datadog-sampling-priority".to_string(), "1".to_string()),
        ]);

        assert_eq!(carrier, expected);
    }

    #[test]
    fn test_get_carrier_binary_custom_label() {
        let json = read_json_file("sqs_event_binary_custom_label.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = SqsRecord::new(payload).expect("Failed to deserialize SqsRecord");
        let carrier = event.get_carrier();

        let expected = HashMap::from([
            (
                "x-datadog-trace-id".to_string(),
                "3333333333333333333".to_string(),
            ),
            (
                "x-datadog-parent-id".to_string(),
                "4444444444444444444".to_string(),
            ),
            ("x-datadog-sampling-priority".to_string(), "1".to_string()),
        ]);

        assert_eq!(carrier, expected);
    }

    #[test]
    fn test_get_carrier_from_sns() {
        let json = read_json_file("sns_sqs_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = SqsRecord::new(payload).expect("Failed to deserialize SqsRecord");
        let carrier = event.get_carrier();

        let expected = HashMap::from([
            (
                "x-datadog-trace-id".to_string(),
                "2776434475358637757".to_string(),
            ),
            (
                "x-datadog-parent-id".to_string(),
                "4493917105238181843".to_string(),
            ),
            ("x-datadog-sampling-priority".to_string(), "1".to_string()),
        ]);

        assert_eq!(carrier, expected);
    }

    #[test]
    fn test_get_carrier_from_sns_binary() {
        let json = read_json_file("sns_sqs_binary_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = SqsRecord::new(payload).expect("Failed to deserialize SqsRecord");
        let carrier = event.get_carrier();

        let expected = HashMap::from([
            (
                "x-datadog-trace-id".to_string(),
                "5863834085596065348".to_string(),
            ),
            (
                "x-datadog-parent-id".to_string(),
                "2752725546543693249".to_string(),
            ),
            (
                "tracestate".to_string(),
                "dd=s:1;p:2633a54ccde13dc1;t.tid:6801584a00000000;t.dm:-1".to_string(),
            ),
            (
                "traceparent".to_string(),
                "00-6801584a00000000516086086dc7ee44-2633a54ccde13dc1-01".to_string(),
            ),
            (
                "x-datadog-tags".to_string(),
                "_dd.p.dm=-1,_dd.p.tid=6801584a00000000".to_string(),
            ),
            ("x-datadog-sampling-priority".to_string(), "1".to_string()),
        ]);

        assert_eq!(carrier, expected);
    }

    #[test]
    fn test_get_carrier_from_binary_message_attribute() {
        // SNS -> SQS raw message delivery: `_datadog` is a top-level SQS Binary
        // attribute whose `binaryValue` is base64-encoded carrier JSON, and the
        // body is the raw published message (no SNS envelope).
        let json = read_json_file("sqs_binary_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = SqsRecord::new(payload).expect("Failed to deserialize SqsRecord");
        let carrier = event.get_carrier();

        assert_eq!(
            carrier.get("dd-pathway-ctx-base64").map(String::as_str),
            Some("Ev+XMfNJ31T+hcjp+Gf+hcjp+Gc="),
            "DSM pathway context must be extracted from the Binary attribute"
        );
        assert_eq!(
            carrier.get("x-datadog-trace-id").map(String::as_str),
            Some("2522563026513800488")
        );
        assert_eq!(
            carrier.get("x-datadog-parent-id").map(String::as_str),
            Some("1052921069172192507")
        );
    }

    #[test]
    fn test_get_carrier_from_eventbridge() {
        let json = read_json_file("eventbridge_sqs_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = SqsRecord::new(payload).expect("Failed to deserialize EventBridgeEvent");
        let carrier = event.get_carrier();

        let expected = HashMap::from([
            (
                "x-datadog-trace-id".to_string(),
                "7379586022458917877".to_string(),
            ),
            (
                "traceparent".to_string(),
                "00-000000000000000066698e63821a03f5-24b17e9b6476c018-01".to_string(),
            ),
            ("x-datadog-tags".to_string(), "_dd.p.dm=-0".to_string()),
            (
                "x-datadog-parent-id".to_string(),
                "2644033662113726488".to_string(),
            ),
            ("tracestate".to_string(), "dd=t.dm:-0;s:1".to_string()),
            ("x-datadog-sampling-priority".to_string(), "1".to_string()),
        ]);

        assert_eq!(carrier, expected);
    }

    #[test]
    fn extract_java_sqs_header_context() {
        let json = read_json_file("eventbridge_sqs_java_header_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = SqsRecord::new(payload).expect("Failed to deserialize EventBridgeEvent");

        assert_eq!(
            extract_trace_context_from_aws_trace_header(
                event.attributes.aws_trace_header.as_deref()
            )
            .unwrap(),
            SpanContext {
                trace_id: 130_944_522_478_755_159,
                span_id: 9_032_698_535_745_367_362,
                // This fixture's root ID has non-zero high bits, i.e. AWS generated it rather
                // than a Datadog library, so its `Sampled=0` is not propagated as a drop.
                sampling: Sampling {
                    priority: None,
                    mechanism: None,
                },
                origin: None,
                tags: HashMap::new(),
                ..Default::default()
            }
        );
    }

    #[test]
    fn aws_generated_root_id_not_sampled_leaves_priority_unset() {
        let context = extract_trace_context_from_aws_trace_header(Some(
            "Root=1-64cc2edd-112fbf1701d1355973a11d57;Parent=7d5a9776024b2d42;Sampled=0",
        ))
        .expect("failed to extract context");

        // X-Ray's decision, not Datadog's: keep the IDs, let the tracer sample.
        assert_eq!(context.sampling.priority, None);
        assert_eq!(context.trace_id, 130_944_522_478_755_159);
    }

    #[test]
    fn datadog_planted_root_id_not_sampled_drops() {
        let context = extract_trace_context_from_aws_trace_header(Some(
            "Root=1-68029e8a-0000000035578e774943fd9d;Parent=76c040bdc454a7ac;Sampled=0",
        ))
        .expect("failed to extract context");

        // Zeroed high bits mean a Datadog library wrote this, so `Sampled=0` is our own decision.
        assert_eq!(context.sampling.priority, "0".parse().ok());
    }

    #[test]
    fn datadog_planted_root_id_without_sampled_leaves_priority_unset() {
        let context = extract_trace_context_from_aws_trace_header(Some(
            "Root=1-68029e8a-0000000035578e774943fd9d;Parent=76c040bdc454a7ac",
        ))
        .expect("failed to extract context");

        // `dd-trace-java` omits `Sampled` when the priority isn't set yet, so there's no
        // decision to carry.
        assert_eq!(context.sampling.priority, None);
    }

    #[test]
    fn datadog_planted_root_id_sampled_keeps() {
        let context = extract_trace_context_from_aws_trace_header(Some(
            "Root=1-68029e8a-0000000035578e774943fd9d;Parent=76c040bdc454a7ac;Sampled=1",
        ))
        .expect("failed to extract context");

        assert_eq!(context.sampling.priority, "1".parse().ok());
    }

    #[test]
    fn truncated_root_does_not_panic() {
        assert!(extract_trace_context_from_aws_trace_header(Some("Root=1-64cc")).is_none());
    }

    #[test]
    fn aws_generated_root_id_sampled_keeps_priority() {
        let context = extract_trace_context_from_aws_trace_header(Some(
            "Root=1-64cc2edd-112fbf1701d1355973a11d57;Parent=7d5a9776024b2d42;Sampled=1",
        ))
        .expect("failed to extract context");

        assert_eq!(context.sampling.priority, "1".parse().ok());
        assert_eq!(context.trace_id, 130_944_522_478_755_159);
    }
}
