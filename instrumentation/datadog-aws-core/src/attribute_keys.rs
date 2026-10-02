// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Attribute-key constants shared by the AWS instrumentation crates.

/// Message or event payload key that carries Datadog trace propagation data.
pub const DATADOG_ATTRIBUTE_KEY: &str = "_datadog";
/// Trace propagation payload key for the producer span start time.
pub const START_TIME_KEY: &str = "x-datadog-start-time";
/// Trace propagation payload key for the producer span resource name.
pub const DATADOG_RESOURCE_NAME_KEY: &str = "x-datadog-resource-name";

/// Span attribute key for the Datadog operation name.
pub const OPERATION_NAME: &str = "operation.name";
/// Span attribute key for the Datadog resource name.
pub const RESOURCE_NAME: &str = "resource.name";
/// Span attribute key for the OpenTelemetry span kind.
pub const SPAN_KIND: &str = "span.kind";
/// Span attribute key for the HTTP request method.
pub const HTTP_METHOD: &str = "http.method";
/// Span attribute key for the HTTP request URL.
pub const HTTP_URL: &str = "http.url";
/// Span attribute key for the HTTP response status code.
pub const HTTP_STATUS_CODE: &str = "http.status_code";

/// Span attribute key for the AWS service name.
pub const AWS_SERVICE: &str = "aws.service";
/// Span attribute key for the AWS operation name.
pub const AWS_OPERATION: &str = "aws.operation";
/// Span attribute key for the AWS region.
pub const AWS_REGION: &str = "aws.region";
/// Span attribute key for the AWS partition.
pub const AWS_PARTITION: &str = "aws.partition";
/// Span attribute key for the AWS SDK user agent.
pub const AWS_AGENT: &str = "aws.agent";
/// Span attribute key for the AWS request ID.
pub const AWS_REQUEST_ID: &str = "aws.request_id";

/// Span attribute key for the messaging system name.
pub const MESSAGING_SYSTEM: &str = "messaging.system";
/// Span attribute key for the number of messages in a batch operation.
pub const MESSAGING_BATCH_MESSAGE_COUNT: &str = "messaging.batch.message_count";

/// Span attribute key for the cloud resource identifier.
pub const CLOUD_RESOURCE_ID: &str = "cloud.resource_id";
/// AWS SDK request field key for SQS queue names.
pub const QUEUE_NAME: &str = "queuename";

/// AWS SDK request field key for SNS topic names.
pub const TOPIC_NAME: &str = "topicname";
/// AWS SDK request field key for SNS publish target names.
pub const TARGET_NAME: &str = "targetname";

/// AWS SDK request field key for EventBridge rule names.
pub const RULE_NAME: &str = "rulename";
