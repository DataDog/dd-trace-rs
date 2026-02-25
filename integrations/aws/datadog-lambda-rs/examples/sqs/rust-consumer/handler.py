# Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
# SPDX-License-Identifier: Apache-2.0

"""SQS producer — sends a message to SQS.

ddtrace auto-instruments the boto3 call and injects trace context into
the _datadog message attribute.
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
    response = sqs.send_message(QueueUrl=QUEUE_URL, MessageBody=body)
    message_id = response.get("MessageId", "unknown")
    logger.info("Sent messageId=%s", message_id)
    return {"statusCode": 200, "body": json.dumps({"message_id": message_id})}
