// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::sync::RwLock;

use crate::mappings::{
    get_dd_key_for_otlp_attribute, get_otel_env, get_otel_operation_name_v2, get_otel_resource_v2,
    get_otel_service, get_otel_status_code, AttributeIndices, AttributeKey, OtelSpan,
};
use crate::sampling::{SamplingData, SpanProperties};
use opentelemetry::{Key, KeyValue};

pub struct PreSampledSpan<'a> {
    pub name: &'a str,
    pub span_kind: opentelemetry::trace::SpanKind,
    pub attributes: &'a [opentelemetry::KeyValue],
    pub resource: &'a opentelemetry_sdk::Resource,
    pub span_attrs: AttributeIndices,
}

impl<'a> PreSampledSpan<'a> {
    pub fn new(
        name: &'a str,
        span_kind: opentelemetry::trace::SpanKind,
        attributes: &'a [opentelemetry::KeyValue],
        resource: &'a opentelemetry_sdk::Resource,
    ) -> Self {
        Self {
            name,
            span_kind,
            attributes,
            resource,
            span_attrs: AttributeIndices::from_attribute_slice(attributes),
        }
    }
}

impl<'a> OtelSpan<'a> for PreSampledSpan<'a> {
    fn name(&self) -> &'a str {
        self.name
    }

    fn span_kind(&self) -> opentelemetry::trace::SpanKind {
        self.span_kind.clone()
    }

    fn has_attr(&self, attr_key: AttributeKey) -> bool {
        self.span_attrs.get(attr_key).is_some()
    }

    fn get_attr_str_opt(&self, attr_key: AttributeKey) -> Option<Cow<'static, str>> {
        let idx = self.span_attrs.get(attr_key)?;
        let kv = self.attributes.get(idx)?;
        Some(Cow::Owned(kv.value.to_string()))
    }

    fn get_attr_num<T: TryFrom<i64>>(&self, attr_key: AttributeKey) -> Option<T> {
        let idx = self.span_attrs.get(attr_key)?;
        let kv = self.attributes.get(idx)?;
        let i = match kv.value {
            opentelemetry::Value::I64(i) => i,
            opentelemetry::Value::F64(i) if i == i.floor() && i < i64::MAX as f64 => i as i64,
            _ => return None,
        };
        T::try_from(i).ok()
    }

    fn attr_len(&self) -> usize {
        self.attributes.len()
    }

    fn get_res_attribute_opt(&self, attr_key: AttributeKey) -> Option<opentelemetry::Value> {
        self.resource.get(&Key::from_static_str(attr_key.key()))
    }

    fn res_len(&self) -> usize {
        self.resource.len()
    }
}

impl SpanProperties for PreSampledSpan<'_> {
    type Attribute = opentelemetry::KeyValue;
    type AttributesIter<'b>
        = std::slice::Iter<'b, opentelemetry::KeyValue>
    where
        Self: 'b;

    fn operation_name(&self) -> Cow<'_, str> {
        get_otel_operation_name_v2(self)
    }

    fn service(&self) -> Cow<'_, str> {
        get_otel_service(self)
    }

    fn env(&self) -> Cow<'_, str> {
        get_otel_env(self)
    }

    fn resource(&self) -> Cow<'_, str> {
        get_otel_resource_v2(self)
    }

    fn status_code(&self) -> Option<u32> {
        get_otel_status_code(self)
    }

    fn attributes(&self) -> Self::AttributesIter<'_> {
        self.attributes.iter()
    }

    fn get_alternate_key<'b>(&self, key: &'b str) -> Option<Cow<'b, str>> {
        let mapped = get_dd_key_for_otlp_attribute(key);
        // If the mapping returned an empty string or the same key, there's no alternate
        if mapped.is_empty() || mapped.as_ref() == key {
            None
        } else {
            Some(mapped)
        }
    }
}

impl crate::sampling::AttributeLike for opentelemetry::KeyValue {
    type Value = opentelemetry::Value;

    fn key(&self) -> &str {
        self.key.as_str()
    }

    fn value(&self) -> &Self::Value {
        &self.value
    }
}

impl crate::sampling::ValueLike for opentelemetry::Value {
    fn extract_float(&self) -> Option<f64> {
        crate::sampling::utils::extract_float_value(self)
    }

    fn extract_string(&self) -> Option<Cow<'_, str>> {
        crate::sampling::utils::extract_string_value(self)
    }
}

/// OpenTelemetry Sampling Data implementation.
///
/// Provides the necessary data for making sampling decisions on OpenTelemetry spans.
/// This struct contains references to span metadata including the trace ID, span name,
/// span kind, attributes, and resource information.
pub struct OtelSamplingData<'a> {
    is_parent_sampled: Option<bool>,
    trace_id: &'a opentelemetry::trace::TraceId,
    name: &'a str,
    span_kind: opentelemetry::trace::SpanKind,
    attributes: &'a [KeyValue],
    resource: &'a RwLock<opentelemetry_sdk::Resource>,
}

impl<'a> OtelSamplingData<'a> {
    /// Creates a new OpenTelemetry sampling data instance.
    ///
    /// # Arguments
    ///
    /// * `is_parent_sampled` - Whether the parent span was sampled, if known
    /// * `trace_id` - The trace ID for this span
    /// * `name` - The span name
    /// * `span_kind` - The kind of span (e.g., Server, Client)
    /// * `attributes` - The span's attributes
    /// * `resource` - The OpenTelemetry resource containing service metadata
    pub fn new(
        is_parent_sampled: Option<bool>,
        trace_id: &'a opentelemetry::trace::TraceId,
        name: &'a str,
        span_kind: opentelemetry::trace::SpanKind,
        attributes: &'a [KeyValue],
        resource: &'a RwLock<opentelemetry_sdk::Resource>,
    ) -> Self {
        Self {
            is_parent_sampled,
            trace_id,
            name,
            span_kind,
            attributes,
            resource,
        }
    }
}

impl SamplingData for OtelSamplingData<'_> {
    type TraceId = opentelemetry::trace::TraceId;
    type Properties<'b>
        = PreSampledSpan<'b>
    where
        Self: 'b;

    fn is_parent_sampled(&self) -> Option<bool> {
        self.is_parent_sampled
    }
    fn trace_id(&self) -> &Self::TraceId {
        self.trace_id
    }

    fn with_span_properties<S, T, F>(&self, s: &S, f: F) -> T
    where
        F: for<'b> Fn(&S, &PreSampledSpan<'b>) -> T,
    {
        let resource_guard = self.resource.read().unwrap();
        let span = PreSampledSpan::new(
            self.name,
            self.span_kind.clone(),
            self.attributes,
            &resource_guard,
        );
        f(s, &span)
    }
}

impl crate::sampling::TraceIdLike for opentelemetry::trace::TraceId {
    type Item = opentelemetry::trace::TraceId;

    fn to_u128(&self) -> u128 {
        u128::from_be_bytes(self.to_bytes())
    }

    fn inner(&self) -> &Self::Item {
        self
    }
}

/// Factory for creating OpenTelemetry KeyValue attributes.
pub struct OtelAttributeFactory;

impl crate::sampling::AttributeFactory for OtelAttributeFactory {
    type Attribute = opentelemetry::KeyValue;

    fn create_i64(&self, key: &'static str, value: i64) -> Self::Attribute {
        opentelemetry::KeyValue::new(key, value)
    }

    fn create_f64(&self, key: &'static str, value: f64) -> Self::Attribute {
        opentelemetry::KeyValue::new(key, value)
    }

    fn create_string(&self, key: &'static str, value: Cow<'static, str>) -> Self::Attribute {
        opentelemetry::KeyValue::new(key, value)
    }
}

/// Converts a Datadog sampling priority to an OpenTelemetry sampling decision.
///
/// # Arguments
///
/// * `priority` - The Datadog sampling priority
///
/// # Returns
///
/// The corresponding OpenTelemetry sampling decision:
/// - `RecordAndSample` if the priority indicates the trace should be kept
/// - `RecordOnly` if the priority indicates the trace should be dropped
pub(crate) fn priority_to_otel_decision(
    priority: crate::core::sampling::SamplingPriority,
) -> opentelemetry::trace::SamplingDecision {
    if priority.is_keep() {
        opentelemetry::trace::SamplingDecision::RecordAndSample
    } else {
        opentelemetry::trace::SamplingDecision::RecordOnly
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mappings::get_otel_operation_name_v2;
    use opentelemetry::trace::SpanKind;
    use opentelemetry::{Key, KeyValue, Value};
    use opentelemetry_semantic_conventions::attribute::{
        DB_SYSTEM_NAME, HTTP_REQUEST_METHOD, MESSAGING_OPERATION_TYPE, MESSAGING_SYSTEM,
    };
    use opentelemetry_semantic_conventions::trace::{
        HTTP_RESPONSE_STATUS_CODE, NETWORK_PROTOCOL_NAME,
    };

    fn create_empty_resource() -> opentelemetry_sdk::Resource {
        opentelemetry_sdk::Resource::builder_empty().build()
    }

    #[test]
    fn test_operation_name_http_client() {
        let attrs = vec![KeyValue::new(
            Key::from_static_str(HTTP_REQUEST_METHOD),
            Value::String("GET".into()),
        )];
        let resource = create_empty_resource();
        let span = PreSampledSpan::new("", SpanKind::Client, &attrs, &resource);

        let op_name = span.operation_name();
        assert_eq!(op_name, "http.client.request");

        // Also verify using get_otel_operation_name_v2
        let op_name_v2 = get_otel_operation_name_v2(&span);
        assert_eq!(op_name_v2, "http.client.request");
    }

    #[test]
    fn test_operation_name_http_server() {
        let attrs = vec![KeyValue::new(
            Key::from_static_str(HTTP_REQUEST_METHOD),
            Value::String("POST".into()),
        )];
        let resource = create_empty_resource();
        let span = PreSampledSpan::new("", SpanKind::Server, &attrs, &resource);

        let op_name = span.operation_name();
        assert_eq!(op_name, "http.server.request");

        let op_name_v2 = get_otel_operation_name_v2(&span);
        assert_eq!(op_name_v2, "http.server.request");
    }

    #[test]
    fn test_operation_name_database() {
        let attrs = vec![KeyValue::new(
            Key::from_static_str(DB_SYSTEM_NAME),
            Value::String("postgresql".into()),
        )];
        let resource = create_empty_resource();
        let span = PreSampledSpan::new("", SpanKind::Client, &attrs, &resource);

        let op_name = span.operation_name();
        assert_eq!(op_name, "postgresql.query");

        let op_name_v2 = get_otel_operation_name_v2(&span);
        assert_eq!(op_name_v2, "postgresql.query");
    }

    #[test]
    fn test_operation_name_messaging() {
        let attrs = vec![
            KeyValue::new(
                Key::from_static_str(MESSAGING_SYSTEM),
                Value::String("kafka".into()),
            ),
            KeyValue::new(
                Key::from_static_str(MESSAGING_OPERATION_TYPE),
                Value::String("process".into()),
            ),
        ];
        let resource = create_empty_resource();
        let span = PreSampledSpan::new("", SpanKind::Consumer, &attrs, &resource);

        let op_name = span.operation_name();
        assert_eq!(op_name, "kafka.process");

        let op_name_v2 = get_otel_operation_name_v2(&span);
        assert_eq!(op_name_v2, "kafka.process");
    }

    #[test]
    fn test_operation_name_generic_server_with_protocol() {
        let attrs = vec![KeyValue::new(
            Key::from_static_str(NETWORK_PROTOCOL_NAME),
            Value::String("http".into()),
        )];
        let resource = create_empty_resource();
        let span = PreSampledSpan::new("", SpanKind::Server, &attrs, &resource);

        let op_name = span.operation_name();
        assert_eq!(op_name, "http.server.request");

        let op_name_v2 = get_otel_operation_name_v2(&span);
        assert_eq!(op_name_v2, "http.server.request");
    }

    #[test]
    fn test_operation_name_internal_fallback() {
        let attrs = vec![KeyValue::new("custom.tag", "value")];
        let resource = create_empty_resource();
        let span = PreSampledSpan::new("", SpanKind::Internal, &attrs, &resource);

        let op_name = span.operation_name();
        assert_eq!(op_name, "internal");

        let op_name_v2 = get_otel_operation_name_v2(&span);
        assert_eq!(op_name_v2, "internal");
    }

    #[test]
    fn test_service_from_resource() {
        use opentelemetry_semantic_conventions::resource::SERVICE_NAME;

        let resource = opentelemetry_sdk::Resource::builder_empty()
            .with_attributes(vec![KeyValue::new(SERVICE_NAME, "my-service")])
            .build();
        let attrs = vec![];
        let span = PreSampledSpan::new("test", SpanKind::Server, &attrs, &resource);

        assert_eq!(span.service(), "my-service");
    }

    #[test]
    fn test_env_from_attributes() {
        let attrs = vec![KeyValue::new("datadog.env", "production")];
        let resource = create_empty_resource();
        let span = PreSampledSpan::new("test", SpanKind::Server, &attrs, &resource);

        assert_eq!(span.env(), "production");
    }

    #[test]
    fn test_env_empty_when_not_present() {
        let attrs = vec![];
        let resource = create_empty_resource();
        let span = PreSampledSpan::new("test", SpanKind::Server, &attrs, &resource);

        assert_eq!(span.env(), "");
    }

    #[test]
    fn test_status_code_from_attributes() {
        let attrs = vec![KeyValue::new(
            Key::from_static_str(HTTP_RESPONSE_STATUS_CODE),
            Value::I64(404),
        )];
        let resource = create_empty_resource();
        let span = PreSampledSpan::new("test", SpanKind::Server, &attrs, &resource);

        assert_eq!(span.status_code(), Some(404));
    }

    #[test]
    fn test_status_code_none_when_not_present() {
        let attrs = vec![];
        let resource = create_empty_resource();
        let span = PreSampledSpan::new("test", SpanKind::Server, &attrs, &resource);

        assert_eq!(span.status_code(), None);
    }

    #[test]
    fn test_attributes_iteration() {
        let attrs = vec![
            KeyValue::new("key1", "value1"),
            KeyValue::new("key2", Value::I64(42)),
        ];
        let resource = create_empty_resource();
        let span = PreSampledSpan::new("test", SpanKind::Server, &attrs, &resource);

        let collected: Vec<_> = span.attributes().collect();
        assert_eq!(collected.len(), 2);
        assert_eq!(collected[0].key.as_str(), "key1");
        assert_eq!(collected[1].key.as_str(), "key2");
    }

    #[test]
    fn test_get_alternate_key_http_status() {
        let attrs = vec![];
        let resource = create_empty_resource();
        let span = PreSampledSpan::new("test", SpanKind::Server, &attrs, &resource);

        // Test HTTP status code mapping
        let alternate = span.get_alternate_key("http.response.status_code");
        assert_eq!(alternate, Some("http.status_code".into()));
    }

    #[test]
    fn test_get_alternate_key_http_method() {
        let attrs = vec![];
        let resource = create_empty_resource();
        let span = PreSampledSpan::new("test", SpanKind::Server, &attrs, &resource);

        // Test HTTP method mapping
        let alternate = span.get_alternate_key("http.request.method");
        assert_eq!(alternate, Some("http.method".into()));
    }

    #[test]
    fn test_get_alternate_key_no_mapping() {
        let attrs = vec![];
        let resource = create_empty_resource();
        let span = PreSampledSpan::new("test", SpanKind::Server, &attrs, &resource);

        // Test key with no mapping
        let alternate = span.get_alternate_key("custom.attribute");
        assert_eq!(alternate, None);
    }

    #[test]
    fn test_attribute_key_mapping_comprehensive() {
        // Test that OTel attribute keys are correctly mapped to Datadog keys
        let attrs = vec![];
        let resource = create_empty_resource();
        let span = PreSampledSpan::new("test", SpanKind::Server, &attrs, &resource);

        // HTTP attribute mappings (OTel -> DD)
        assert_eq!(
            span.get_alternate_key("http.response.status_code"),
            Some("http.status_code".into())
        );
        assert_eq!(
            span.get_alternate_key("http.request.method"),
            Some("http.method".into())
        );
        assert_eq!(span.get_alternate_key("url.full"), Some("http.url".into()));
        assert_eq!(
            span.get_alternate_key("user_agent.original"),
            Some("http.useragent".into())
        );
        assert_eq!(
            span.get_alternate_key("server.address"),
            Some("http.server_name".into())
        );
        assert_eq!(
            span.get_alternate_key("client.address"),
            Some("http.client_ip".into())
        );

        // Keys without mappings (same in both OTel and DD) should return None
        assert_eq!(span.get_alternate_key("custom.tag"), None);
        assert_eq!(span.get_alternate_key("application.name"), None);
        assert_eq!(span.get_alternate_key("http.route"), None); // Maps to itself

        // Datadog convention keys map to empty string (filtered out), which get_alternate_key
        // returns as None
        assert_eq!(span.get_alternate_key("service.name"), None);
        assert_eq!(span.get_alternate_key("operation.name"), None);
        assert_eq!(span.get_alternate_key("datadog.custom"), None);
    }

    #[test]
    fn test_otel_to_datadog_attribute_mapping_in_span() {
        // Test that a span with OTel attribute names can be queried using DD keys via
        // get_alternate_key
        let otel_attrs = vec![
            KeyValue::new("http.response.status_code", Value::I64(500)),
            KeyValue::new("http.request.method", "POST"),
            KeyValue::new("url.full", "https://example.com/api"),
        ];
        let resource = create_empty_resource();
        let span = PreSampledSpan::new("test-span", SpanKind::Client, &otel_attrs, &resource);

        // Verify the OTel attributes are present
        let attrs: Vec<_> = span.attributes().collect();
        assert_eq!(attrs.len(), 3);

        // Verify we can find the DD equivalent keys for these OTel attributes
        assert_eq!(
            span.get_alternate_key("http.response.status_code"),
            Some("http.status_code".into())
        );
        assert_eq!(
            span.get_alternate_key("http.request.method"),
            Some("http.method".into())
        );
        assert_eq!(span.get_alternate_key("url.full"), Some("http.url".into()));

        // Verify the actual attributes can be found by their original keys
        let status_code_attr = attrs
            .iter()
            .find(|a| a.key.as_str() == "http.response.status_code");
        assert!(status_code_attr.is_some());

        let method_attr = attrs
            .iter()
            .find(|a| a.key.as_str() == "http.request.method");
        assert!(method_attr.is_some());
    }

    #[test]
    fn test_multiple_attribute_mappings() {
        // Test that a span with multiple OTel attributes correctly maps them all to DD keys
        let mixed_attrs = vec![
            KeyValue::new("http.response.status_code", Value::I64(503)),
            KeyValue::new("http.request.method", "POST"),
            KeyValue::new("url.full", "https://example.com/api/v1/resource"),
        ];
        let resource = create_empty_resource();
        let span = PreSampledSpan::new("test-span", SpanKind::Client, &mixed_attrs, &resource);

        // Verify all three OTel attributes have correct DD mappings
        assert_eq!(
            span.get_alternate_key("http.response.status_code"),
            Some("http.status_code".into())
        );
        assert_eq!(
            span.get_alternate_key("http.request.method"),
            Some("http.method".into())
        );
        assert_eq!(span.get_alternate_key("url.full"), Some("http.url".into()));

        // Verify all attributes are present
        let attrs: Vec<_> = span.attributes().collect();
        assert_eq!(attrs.len(), 3);

        // Verify each attribute can be found by its original OTel key
        assert!(attrs
            .iter()
            .any(|a| a.key.as_str() == "http.response.status_code"));
        assert!(attrs
            .iter()
            .any(|a| a.key.as_str() == "http.request.method"));
        assert!(attrs.iter().any(|a| a.key.as_str() == "url.full"));
    }

    #[test]
    fn test_mixed_direct_and_mapped_attributes() {
        // Test that spans with both OTel attributes (that have DD mappings) and
        // custom attributes (that don't have mappings) work correctly together
        let mixed_attrs = vec![
            // OTel attribute with DD mapping
            KeyValue::new("http.response.status_code", Value::I64(503)),
            // Custom attribute without mapping
            KeyValue::new("custom.tag", "custom_value"),
        ];
        let resource = create_empty_resource();
        let span = PreSampledSpan::new("test-span", SpanKind::Client, &mixed_attrs, &resource);

        // OTel attribute should have alternate DD key
        assert_eq!(
            span.get_alternate_key("http.response.status_code"),
            Some("http.status_code".into())
        );

        // Custom attribute should not have alternate key
        assert_eq!(span.get_alternate_key("custom.tag"), None);

        // Both attributes should be present and accessible
        let attrs: Vec<_> = span.attributes().collect();
        assert_eq!(attrs.len(), 2);

        assert!(attrs
            .iter()
            .any(|a| a.key.as_str() == "http.response.status_code"));
        assert!(attrs.iter().any(|a| a.key.as_str() == "custom.tag"));

        // Verify the status code is accessible
        assert_eq!(span.status_code(), Some(503));
    }
}
