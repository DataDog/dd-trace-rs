// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use opentelemetry::KeyValue;
use opentelemetry_semantic_conventions as semconv;

macro_rules! token_count {
    () => {
        0
    };
    ($first:tt $($rest:tt)*) => {
        1 + token_count!($($rest)*)
    };
}

macro_rules! match_key {
    (find $val:expr => { $($key:expr),+ $(,)? }) => {
        $(
            if $val == $key.key {
                return Some($key)
            }
        )*
        return None
    }
}

macro_rules! attribute_key {
    (@ $($idx:tt)*) => {
        const NUMBER_OF_ATTRIBUTES: usize = token_count!($($idx)*);
    };
    ($string_lit:expr => $key_name:ident $(, $string_lit_rest:expr => $key_name_rest:ident)* , @ $($idx:tt)*) => {
        pub const $key_name: AttributeKey = AttributeKey {
            idx: token_count!($($idx)*),
            key: $string_lit,
        };
        attribute_key!($($string_lit_rest => $key_name_rest ,)* @ $($idx)* ,);
    };
    ($($key:expr => $key_name:ident),* $(,)?) => {
        attribute_key!($($key => $key_name ,)* @);
        fn get_attribute_idx(key: &str) -> Option<AttributeKey> {
            match_key!(
                find key => {
                    $(
                        $key_name,
                    )*
                }
            );
        }
    };
}

attribute_key! {
    "datadog.service" => DATADOG_SERVICE,
    "datadog.name" => DATADOG_NAME,
    "datadog.env" => DATADOG_ENV,
    "datadog.resource" => DATADOG_RESOURCE,
    "datadog.type" => DATADOG_TYPE,
    "datadog.version" => DATADOG_VERSION,
    "datadog.http_status_code" => DATADOG_HTTP_STATUS_CODE,
    "datadog.span.kind" => DATADOG_SPAN_KIND,
    "datadog.error" => DATADOG_ERROR,
    "datadog.error.msg" => DATADOG_ERROR_MSG,
    "datadog.error.type" => DATADOG_ERROR_TYPE,
    "datadog.error.stack" => DATADOG_ERROR_STACK,
    "operation.name" => OPERATION_NAME,
    "http.request.method" => HTTP_REQUEST_METHOD,
    "http.method" => HTTP_METHOD,
    "db.system" => DB_SYSTEM,
    "db.system.name" => DB_SYSTEM_NAME,
    "messaging.system" => MESSAGING_SYSTEM,
    "messaging.operation" => MESSAGING_OPERATION,
    "messaging.operation.type" => MESSAGING_OPERATION_TYPE,
    "rpc.system" => RPC_SYSTEM,
    "rpc.service" => RPC_SERVICE,
    "faas.invoked_provider" => FAAS_INVOKED_PROVIDER,
    "faas.invoked_name" => FAAS_INVOKED_NAME,
    "faas.trigger" => FAAS_TRIGGER,
    "graphql.operation.type" => GRAPHQL_OPERATION_TYPE,
    "network.protocol.name" => NETWORK_PROTOCOL_NAME,
    "resource.name" => RESOURCE_NAME,
    "http.route" => HTTP_ROUTE,
    "messaging.destination" => MESSAGING_DESTINATION,
    "messaging.destination.name" => MESSAGING_DESTINATION_NAME,
    "rpc.method" => RPC_METHOD,
    "graphql.operation.name" => GRAPHQL_OPERATION_NAME,
    "db.statement" => DB_STATEMENT,
    "db.query.text" => DB_QUERY_TEXT,
    "span.type" => SPAN_TYPE,
    "http.response.status_code" => HTTP_RESPONSE_STATUS_CODE,
    "http.status_code" => HTTP_STATUS_CODE,
    semconv::attribute::SERVICE_NAME => SERVICE_NAME,
    semconv::attribute::SERVICE_VERSION => SERVICE_VERSION,
    "deployment.environment.name" => DEPLOYMENT_ENVIRONMENT_NAME,
    "deployment.environment" => DEPLOYMENT_ENVIRONMENT,

    "_dd.measured" => DD_MEASURED,
}

/// Contains the index of the attribute matching the corresponding key on the span

#[derive(Debug, Clone, Copy)]
pub struct AttributeKey {
    idx: usize,
    key: &'static str,
}

impl AttributeKey {
    pub(crate) fn key(&self) -> &'static str {
        self.key
    }
}

#[derive(Debug)]
pub struct AttributeIndices([u32; NUMBER_OF_ATTRIBUTES]);

impl Default for AttributeIndices {
    fn default() -> Self {
        Self([u32::MAX; NUMBER_OF_ATTRIBUTES])
    }
}

impl AttributeIndices {
    fn set(&mut self, key: AttributeKey, val: usize) {
        self.0[key.idx] = val as u32;
    }

    pub(crate) fn get(&self, key: AttributeKey) -> Option<usize> {
        let val = self.0[key.idx];
        if val == u32::MAX {
            None
        } else {
            Some(val as usize)
        }
    }
}

impl AttributeIndices {
    pub(crate) fn from_attribute_slice(attributes: &[opentelemetry::KeyValue]) -> Self {
        let mut s = Self::default();
        for (i, KeyValue { key, .. }) in attributes.iter().enumerate() {
            let Some(idx) = get_attribute_idx(key.as_str()) else {
                continue;
            };
            s.set(idx, i);
        }
        s
    }
}
