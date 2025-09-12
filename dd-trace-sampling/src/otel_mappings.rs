// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;

use datadog_opentelemetry_mappings::{AttributeIndices, AttributeKey, OtelSpan};
use opentelemetry::Key;

pub(crate) struct PreSampledSpan<'a> {
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
            span_attrs: datadog_opentelemetry_mappings::AttributeIndices::from_attribute_slice(
                attributes,
            ),
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
