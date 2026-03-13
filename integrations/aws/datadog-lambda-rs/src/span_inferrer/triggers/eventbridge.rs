// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use super::InferredSpan;
use crate::span_inferrer::carrier::{carrier_from_json_object, CARRIER_KEY};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Deserialize)]
pub(crate) struct EventBridgeEvent {
    source: String,
    #[serde(rename = "detail-type")]
    detail_type: String,
    time: Option<String>,
    detail: Value,
}

impl EventBridgeEvent {
    pub(crate) fn extract(&self) -> Option<(HashMap<String, String>, Vec<InferredSpan>)> {
        let carrier = carrier_from_json_object(self.detail.get(CARRIER_KEY)?)?;

        let start_time_ns = carrier
            .get("x-datadog-start-time")
            .and_then(|s| s.parse::<i64>().ok())
            .map(|ms| ms * 1_000_000)
            .or_else(|| parse_iso_time(self.time.as_deref()?));

        let mut tags = HashMap::new();
        tags.insert("detail_type".to_owned(), self.detail_type.clone());

        let span = InferredSpan {
            operation: "aws.eventbridge",
            trigger_source: "eventbridge",
            trigger_arn: None,
            service: self.source.clone(),
            resource: self.detail_type.clone(),
            span_type: "web",
            start_time_ns,
            is_async: true,
            tags,
        };

        Some((carrier, vec![span]))
    }
}

/// Match EventBridge events: `detail-type` exists AND `source` is not
/// the scheduled-events source (`aws.events`).
pub(crate) fn is_match(payload: &Value) -> bool {
    payload.get("detail-type").is_some()
        && (payload.get("source").and_then(|s| s.as_str()) != Some("aws.events"))
}

/// Parse an ISO 8601 timestamp (e.g. "2024-01-15T12:00:00Z") into nanoseconds
/// since Unix epoch. Only handles the `Z` suffix format that EventBridge uses.
pub(crate) fn parse_iso_time(s: &str) -> Option<i64> {
    let s = s.strip_suffix('Z')?;
    let (date_part, time_part) = s.split_once('T')?;
    let mut date_iter = date_part.splitn(3, '-');
    let year: i64 = date_iter.next()?.parse().ok()?;
    let month: i64 = date_iter.next()?.parse().ok()?;
    let day: i64 = date_iter.next()?.parse().ok()?;

    let mut time_iter = time_part.splitn(3, ':');
    let hour: i64 = time_iter.next()?.parse().ok()?;
    let min: i64 = time_iter.next()?.parse().ok()?;
    let sec: i64 = time_iter.next()?.parse().ok()?;

    let days = days_from_civil(year, month, day);
    let secs = days * 86400 + hour * 3600 + min * 60 + sec;
    Some(secs * 1_000_000_000)
}

/// Compute days from 1970-01-01 using the civil calendar algorithm.
/// Adapted from Howard Hinnant's `days_from_civil`.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) as u64 + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe as i64 - 719468
}

#[cfg(test)]
fn extract(payload: &Value) -> Option<(HashMap<String, String>, Vec<InferredSpan>)> {
    let event: EventBridgeEvent = serde_json::from_value(payload.clone()).ok()?;
    event.extract()
}

#[cfg(test)]
mod tests {
    use super::super::test_utils::load_payload;
    use super::*;
    use serde_json::json;

    #[test]
    fn matches_eventbridge_event() {
        let event = load_payload("eventbridge_event.json");
        assert!(is_match(&event));
    }

    #[test]
    fn rejects_scheduled_event() {
        let event = json!({
            "source": "aws.events",
            "detail-type": "Scheduled Event",
            "detail": {}
        });
        assert!(!is_match(&event));
    }

    #[test]
    fn rejects_non_eventbridge() {
        let event = json!({ "Records": [] });
        assert!(!is_match(&event));
    }

    #[test]
    fn extract_carrier_and_span() {
        let event = load_payload("eventbridge_event.json");

        let (carrier, spans) = extract(&event).unwrap();
        assert_eq!(carrier.get("x-datadog-trace-id").unwrap(), "12345");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].operation, "aws.eventbridge");
        assert_eq!(spans[0].service, "my.app");
        assert_eq!(spans[0].resource, "OrderPlaced");
        assert!(spans[0].start_time_ns.is_some());
    }

    #[test]
    fn extract_with_start_time_from_carrier() {
        let event = json!({
            "source": "my.app",
            "detail-type": "OrderPlaced",
            "time": "2024-06-15T10:30:00Z",
            "detail": {
                "_datadog": {
                    "x-datadog-trace-id": "12345",
                    "x-datadog-parent-id": "67890",
                    "x-datadog-start-time": "1718444400000"
                }
            }
        });

        let (_, spans) = extract(&event).unwrap();
        assert_eq!(spans[0].start_time_ns, Some(1718444400000 * 1_000_000));
    }

    #[test]
    fn extract_without_datadog_key() {
        let event = load_payload("eventbridge_event_no_carrier.json");
        assert!(extract(&event).is_none());
    }

    #[test]
    fn parse_iso_time_basic() {
        // 2024-01-01T00:00:00Z = 1704067200 seconds
        let ns = parse_iso_time("2024-01-01T00:00:00Z").unwrap();
        assert_eq!(ns, 1704067200 * 1_000_000_000);
    }
}
