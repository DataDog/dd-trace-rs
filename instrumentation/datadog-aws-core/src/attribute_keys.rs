// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

// Trace propagation payload keys.
pub const DATADOG_ATTRIBUTE_KEY: &str = "_datadog";
pub const START_TIME_KEY: &str = "x-datadog-start-time";
pub const DATADOG_RESOURCE_NAME_KEY: &str = "x-datadog-resource-name";

// Common span attributes.
pub const OPERATION_NAME: &str = "operation.name";
pub const RESOURCE_NAME: &str = "resource.name";
pub const SPAN_KIND: &str = "span.kind";
pub const HTTP_METHOD: &str = "http.method";
pub const HTTP_URL: &str = "http.url";
pub const HTTP_STATUS_CODE: &str = "http.status_code";

// Generic aws.sdk span attributes.
pub const AWS_SERVICE: &str = "aws.service";
pub const AWS_OPERATION: &str = "aws.operation";
pub const AWS_REGION: &str = "aws.region";
pub const AWS_PARTITION: &str = "aws.partition";
pub const AWS_AGENT: &str = "aws.agent";
pub const AWS_REQUEST_ID: &str = "aws.request_id";

// SQS aws.sdk span attributes.
pub const CLOUD_RESOURCE_ID: &str = "cloud.resource_id";
pub const QUEUE_NAME: &str = "queuename";
pub const MESSAGING_SYSTEM: &str = "messaging.system";

// SNS aws.sdk span attributes.
pub const TOPIC_NAME: &str = "topicname";
pub const TARGET_NAME: &str = "targetname";

// EventBridge aws.sdk span attributes.
pub const RULE_NAME: &str = "rulename";
