# Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
# SPDX-License-Identifier: Apache-2.0

"""SNS producer — publishes a message to an SNS topic.

ddtrace auto-instruments the boto3 call and injects trace context into
the _datadog message attribute.
"""

import json
import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sns = boto3.client("sns")
TOPIC_ARN = os.environ["TOPIC_ARN"]


def handler(event, context):
    message = event.get("message", "hello from Python SNS producer")
    response = sns.publish(TopicArn=TOPIC_ARN, Message=message)
    message_id = response.get("MessageId", "unknown")
    logger.info("Published messageId=%s", message_id)
    return {"statusCode": 200, "body": json.dumps({"message_id": message_id})}
