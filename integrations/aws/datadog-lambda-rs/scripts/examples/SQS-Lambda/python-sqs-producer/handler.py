# Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
# SPDX-License-Identifier: Apache-2.0

"""Minimal SQS producer — sends a message to SQS when invoked directly.

ddtrace auto-instruments the boto3 SQS call and injects trace context
into the _datadog message attribute, which the downstream Rust consumer
picks up via the Datadog Lambda extension.
"""

import json
import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sqs = boto3.client("sqs")
QUEUE_URL = os.environ["QUEUE_URL"]


def handler(event, context):
    body = event.get("body", "hello from Python SQS producer")
    logger.info("Sending message to SQS: %s", body)

    response = sqs.send_message(QueueUrl=QUEUE_URL, MessageBody=body)
    message_id = response.get("MessageId", "unknown")
    logger.info("Sent messageId=%s", message_id)

    return {"statusCode": 200, "body": json.dumps({"message_id": message_id})}
