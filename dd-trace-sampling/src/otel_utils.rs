// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;

use super::{attribute_keys::*, sem_convs};

use opentelemetry::trace::SpanKind;
use opentelemetry_sdk::Resource;

/// The Span trait is used to implement utils function is a way that is generic
/// and could be ported to multiple Span models
pub trait OtelSpan {
    fn name(&self) -> Cow<'static, str>;
    fn span_kind(&self) -> SpanKind;
    fn has_attr(&self, attr_key: AttributeKey) -> bool;
    fn get_attr_str_opt(&self, attr_key: AttributeKey) -> Option<Cow<'static, str>>;
    fn get_attr_num<T: TryFrom<i64>>(&self, attr_key: AttributeKey) -> Option<T>;

    fn get_attr_str(&self, attr_key: AttributeKey) -> Cow<'static, str> {
        self.get_attr_str_opt(attr_key).unwrap_or_default()
    }
}

/// Returns the datadog operation name from the otel span
/// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/traceutil/otel_util.go#L405
pub fn get_otel_operation_name_v2(span: &impl OtelSpan) -> Cow<'static, str> {
    if let Some(name) = span.get_attr_str_opt(OPERATION_NAME) {
        return name;
    }

    let is_client = matches!(span.span_kind(), SpanKind::Client);
    let is_server = matches!(span.span_kind(), SpanKind::Server);

    // http
    if span.has_attr(HTTP_METHOD) || span.has_attr(HTTP_REQUEST_METHOD) {
        if is_client {
            return Cow::Borrowed("http.client.request");
        } else if is_server {
            return Cow::Borrowed("http.server.request");
        }
    }

    // database
    let db_system = span.get_attr_str(DB_SYSTEM);
    if !db_system.is_empty() && is_client {
        return Cow::Owned(format!("{}.query", db_system));
    }

    // messaging
    let messaging_system = span.get_attr_str(MESSAGING_SYSTEM);
    let messaging_operation = span.get_attr_str(MESSAGING_OPERATION);
    if !messaging_system.is_empty()
        && !messaging_operation.is_empty()
        && matches!(
            span.span_kind(),
            SpanKind::Client | SpanKind::Server | SpanKind::Consumer | SpanKind::Producer
        )
    {
        return Cow::Owned(format!("{}.{}", messaging_system, messaging_operation));
    }

    // RPC & AWS
    let rpc_system = span.get_attr_str(RPC_SYSTEM);
    let is_rpc = !rpc_system.is_empty();
    let is_aws = rpc_system == "aws-api";
    if is_client && is_aws {
        let rpc_service = span.get_attr_str(RPC_SERVICE);
        if !rpc_service.is_empty() {
            return Cow::Owned(format!("aws.{}.request", rpc_service));
        }
        return Cow::Borrowed("aws.client.request");
    }
    if is_client && is_rpc {
        return Cow::Owned(format!("{}.client.request", rpc_system));
    }
    if is_server && is_rpc {
        return Cow::Owned(format!("{}.server.request", rpc_system));
    }

    // FAAS client
    let faas_invoked_provider = span.get_attr_str(FAAS_INVOKED_PROVIDER);
    let faas_invoked_name = span.get_attr_str(FAAS_INVOKED_NAME);
    if is_client && !faas_invoked_provider.is_empty() && !faas_invoked_name.is_empty() {
        return Cow::Owned(format!(
            "{}.{}.invoke",
            faas_invoked_provider, faas_invoked_name
        ));
    }

    // FAAS server
    let faas_trigger = span.get_attr_str(FAAS_TRIGGER);
    if !faas_trigger.is_empty() && is_server {
        return Cow::Owned(format!("{}.invoke", faas_trigger));
    }

    // GraphQL
    if !span.get_attr_str(GRAPHQL_OPERATION_TYPE).is_empty() {
        return Cow::Borrowed("graphql.server.request");
    }

    // Generic HTTP server/client
    let protocol = span.get_attr_str(NETWORK_PROTOCOL_NAME);
    if is_server {
        if !protocol.is_empty() {
            return Cow::Owned(format!("{}.server.request", protocol));
        }
        return Cow::Borrowed("server.request");
    } else if is_client {
        if !protocol.is_empty() {
            return Cow::Owned(format!("{}.client.request", protocol));
        }
        return Cow::Borrowed("client.request");
    }

    // if nothing matches, checking for generic http server/client

    // Fallback in span kind
    Cow::Borrowed(match span.span_kind() {
        SpanKind::Client => "Client",
        SpanKind::Server => "Server",
        SpanKind::Producer => "Producer",
        SpanKind::Consumer => "Consumer",
        SpanKind::Internal => "Internal",
    })
}

/// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/traceutil/otel_util.go#L332
pub fn get_otel_resource_v2(span: &impl OtelSpan, res: &Resource) -> Cow<'static, str> {
    let m = get_res_span_attributes(span, res, &[RESOURCE_NAME]);
    if !m.is_empty() {
        return m;
    }

    let mut m = get_res_span_attributes(span, res, &[HTTP_REQUEST_METHOD, HTTP_METHOD]);
    if !m.is_empty() {
        if m == "_OTHER" {
            m = Cow::Borrowed("HTTP");
        }
        if matches!(span.span_kind(), SpanKind::Server) {
            let route = get_res_span_attributes(span, res, &[HTTP_ROUTE]);
            if !route.is_empty() {
                return Cow::Owned(format!("{} {}", m, route));
            }
        }
        return m;
    }

    let messaging_operation = get_res_span_attributes(span, res, &[MESSAGING_OPERATION]);
    if !messaging_operation.is_empty() {
        let mut res_name = messaging_operation;
        let messaging_destination = get_res_span_attributes(
            span,
            res,
            &[MESSAGING_DESTINATION, MESSAGING_DESTINATION_NAME],
        );
        if !messaging_destination.is_empty() {
            res_name = Cow::Owned(format!("{} {}", res_name, messaging_destination));
        }
        return res_name;
    }

    let rpc_method = get_res_span_attributes(span, res, &[RPC_METHOD]);
    if !rpc_method.is_empty() {
        let mut res_name = rpc_method;
        let rpc_service = get_res_span_attributes(span, res, &[RPC_SERVICE]);
        if !rpc_service.is_empty() {
            res_name = Cow::Owned(format!("{} {}", res_name, rpc_service));
        }
        return res_name;
    }

    let graphql_operation_type = get_res_span_attributes(span, res, &[GRAPHQL_OPERATION_TYPE]);
    if !graphql_operation_type.is_empty() {
        let mut res_name = graphql_operation_type;
        let graphql_operation_name = get_res_span_attributes(span, res, &[GRAPHQL_OPERATION_NAME]);
        if !graphql_operation_name.is_empty() {
            res_name = Cow::Owned(format!("{} {}", res_name, graphql_operation_name));
        }
        return res_name;
    }

    let db_system = get_res_span_attributes(span, res, &[DB_SYSTEM]);
    if !db_system.is_empty() {
        let db_statement = get_res_span_attributes(span, res, &[DB_STATEMENT]);
        if !db_statement.is_empty() {
            return db_statement;
        }
        let db_query = get_res_span_attributes(span, res, &[DB_QUERY_TEXT]);
        if !db_query.is_empty() {
            return db_query;
        }
    }
    span.name()
}

// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/traceutil/otel_util.go#L571
pub fn get_otel_status_code(span: &impl OtelSpan) -> u32 {
    if let Some(code) = span.get_attr_num(HTTP_RESPONSE_STATUS_CODE) {
        return code;
    }
    if let Some(code) = span.get_attr_num(HTTP_STATUS_CODE) {
        return code;
    }
    0
}

const SPAN_TYPE_SQL: &str = "sql";
const SPAN_TYPE_CASSANDRA: &str = "cassandra";
const SPAN_TYPE_REDIS: &str = "redis";
const SPAN_TYPE_MEMCACHED: &str = "memcached";
const SPAN_TYPE_MONGODB: &str = "mongodb";
const SPAN_TYPE_ELASTICSEARCH: &str = "elasticsearch";
const SPAN_TYPE_OPENSEARCH: &str = "opensearch";
const SPAN_TYPE_DB: &str = "db";

macro_rules! db_mapping {
    (match $val:expr => {
        $($otel_db_type:expr => $dd_db_type:expr),* $(,)?
    }) => {
        (|| {
            $(
                if $val == $otel_db_type {
                    return Some($dd_db_type);
                }
            )*
            None
        })()
    };
}

// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/traceutil/otel_util.go#L118
fn check_db_type(db_type: &str) -> &'static str {
    let span_type = db_mapping!(match db_type => {
       sem_convs::ATTRIBUTE_DB_SYSTEM_OTHER_SQL  => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_MSSQL => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_MYSQL => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_ORACLE => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_DB2 => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_POSTGRESQL => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_REDSHIFT => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_CLOUDSCAPE => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_HSQLDB => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_MAXDB => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_INGRES => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_FIRSTSQL => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_EDB => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_CACHE => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_FIREBIRD => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_DERBY => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_INFORMIX => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_MARIADB => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_SQLITE => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_SYBASE => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_TERADATA => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_VERTICA => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_H2 => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_COLDFUSION => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_COCKROACHDB => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_PROGRESS => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_HANADB => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_ADABAS => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_FILEMAKER => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_INSTANTDB => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_INTERBASE => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_NETEZZA => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_PERVASIVE => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_POINTBASE => SPAN_TYPE_SQL,
        sem_convs::ATTRIBUTE_DB_SYSTEM_CLICKHOUSE => SPAN_TYPE_SQL,

        // Cassandra db types
        sem_convs::ATTRIBUTE_DB_SYSTEM_CASSANDRA => SPAN_TYPE_CASSANDRA,

        // Redis db types
        sem_convs::ATTRIBUTE_DB_SYSTEM_REDIS => SPAN_TYPE_REDIS,

        // Memcached db types
        sem_convs::ATTRIBUTE_DB_SYSTEM_MEMCACHED => SPAN_TYPE_MEMCACHED,

        // Mongodb db types
        sem_convs::ATTRIBUTE_DB_SYSTEM_MONGODB => SPAN_TYPE_MONGODB,

        // Elasticsearch db types
        sem_convs::ATTRIBUTE_DB_SYSTEM_ELASTICSEARCH => SPAN_TYPE_ELASTICSEARCH,

        // Opensearch db types
        sem_convs::ATTRIBUTE_DB_SYSTEM_OPENSEARCH => SPAN_TYPE_OPENSEARCH,

        // Generic db types
        sem_convs::ATTRIBUTE_DB_SYSTEM_HIVE => SPAN_TYPE_DB,
        sem_convs::ATTRIBUTE_DB_SYSTEM_HBASE => SPAN_TYPE_DB,
        sem_convs::ATTRIBUTE_DB_SYSTEM_NEO4J => SPAN_TYPE_DB,
        sem_convs::ATTRIBUTE_DB_SYSTEM_COUCHBASE => SPAN_TYPE_DB,
        sem_convs::ATTRIBUTE_DB_SYSTEM_COUCHDB => SPAN_TYPE_DB,
        sem_convs::ATTRIBUTE_DB_SYSTEM_COSMOSDB => SPAN_TYPE_DB,
        sem_convs::ATTRIBUTE_DB_SYSTEM_DYNAMODB => SPAN_TYPE_DB,
        sem_convs::ATTRIBUTE_DB_SYSTEM_GEODE => SPAN_TYPE_DB,
    });
    span_type.unwrap_or(SPAN_TYPE_DB)
}

// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/traceutil/otel_util.go#L250
pub fn get_otel_span_type(span: &impl OtelSpan, res: &Resource) -> Cow<'static, str> {
    let typ = get_res_span_attributes(span, res, &[SPAN_TYPE]);
    if !typ.is_empty() {
        return typ;
    }
    match span.span_kind() {
        SpanKind::Server => Cow::Borrowed("web"),
        SpanKind::Client => {
            let db = get_res_span_attributes(span, res, &[DB_SYSTEM]);
            if db.is_empty() {
                Cow::Borrowed("http")
            } else {
                Cow::Borrowed(check_db_type(&db))
            }
        }
        _ => Cow::Borrowed("custom"),
    }
}

/// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/traceutil/otel_util.go#L605
pub fn get_otel_env(res: &Resource) -> Cow<'static, str> {
    get_res_attributes(res, &[DEPLOYMENT_ENVIRONMENT_NAME, DEPLOYMENT_ENVIRONMENT])
}

pub const DEFAULT_OTLP_SERVICE_NAME: &str = "otlpresourcenoservicename";

/// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/traceutil/otel_util.go#L272
pub fn get_otel_service(res: &Resource) -> Cow<'static, str> {
    let service = res.get(&opentelemetry::Key::from_static_str(
        sem_convs::ATTRIBUTE_SERVICE_NAME,
    ));
    if let Some(service) = service {
        if !service.as_str().is_empty() {
            return Cow::Owned(service.to_string());
        }
    }
    Cow::Borrowed(DEFAULT_OTLP_SERVICE_NAME)
}

// https://github.com/DataDog/opentelemetry-mapping-go/blob/67e66831012599082cc42cf877ea340266d95bb4/pkg/otlp/attributes/attributes.go#L175
fn http_mappings(k: &str) -> Option<&'static str> {
    match k {
        sem_convs::ATTRIBUTE_CLIENT_ADDRESS => Some("http.client_ip"),
        sem_convs::ATTRIBUTE_HTTP_RESPONSE_BODY_SIZE => Some("http.response.content_length"),
        sem_convs::ATTRIBUTE_HTTP_RESPONSE_STATUS_CODE => Some("http.status_code"),
        sem_convs::ATTRIBUTE_HTTP_REQUEST_BODY_SIZE => Some("http.request.content_length"),
        "http.request.header.referrer" => Some("http.referrer"),
        sem_convs::ATTRIBUTE_HTTP_REQUEST_METHOD => Some("http.method"),
        sem_convs::ATTRIBUTE_HTTP_ROUTE => Some("http.route"),
        sem_convs::ATTRIBUTE_NETWORK_PROTOCOL_VERSION => Some("http.version"),
        sem_convs::ATTRIBUTE_SERVER_ADDRESS => Some("http.server_name"),
        sem_convs::ATTRIBUTE_URL_FULL => Some("http.url"),
        sem_convs::ATTRIBUTE_USER_AGENT_ORIGINAL => Some("http.useragent"),
        _ => None,
    }
}

fn is_datadog_convention_key(k: &str) -> bool {
    matches!(
        k,
        "service.name" | "operation.name" | "resource.name" | "span.type"
    ) || k.starts_with("datadog.")
}

pub fn get_dd_key_for_otlp_attribute(k: &str) -> Cow<'static, str> {
    if let Some(mapped_key) = http_mappings(k) {
        return Cow::Borrowed(mapped_key);
    }
    if let Some(suffix) = k.strip_prefix("http.request.header.") {
        return Cow::Owned(format!("http.request.headers.{}", suffix));
    }
    if is_datadog_convention_key(k) {
        return Cow::Borrowed("");
    }
    Cow::Owned(k.to_owned())
}

fn get_res_span_attributes(
    span: &impl OtelSpan,
    res: &Resource,
    attributes: &[AttributeKey],
) -> Cow<'static, str> {
    for &attr_key in attributes {
        let res_attr = get_res_attribute(res, &attr_key);
        if !res_attr.is_empty() {
            return res_attr;
        }
        if let Some(attr) = span.get_attr_str_opt(attr_key) {
            return attr;
        }
    }
    Cow::Borrowed("")
}

fn get_res_attributes(res: &Resource, attributes: &[AttributeKey]) -> Cow<'static, str> {
    for &attr_key in attributes {
        let res_attr = get_res_attribute(res, &attr_key);
        if !res_attr.is_empty() {
            return res_attr;
        }
    }
    Cow::Borrowed("")
}

fn get_res_attribute(res: &Resource, attr: &AttributeKey) -> Cow<'static, str> {
    let Some(value) = res.get(&opentelemetry::Key::from_static_str(attr.key())) else {
        return Cow::Borrowed("");
    };
    Cow::Owned(value.to_string())
}
