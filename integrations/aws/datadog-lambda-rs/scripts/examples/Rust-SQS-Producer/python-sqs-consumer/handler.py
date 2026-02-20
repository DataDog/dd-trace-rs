# Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
# SPDX-License-Identifier: Apache-2.0

"""Minimal SQS consumer — ddtrace auto-extracts trace context from _datadog."""

import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event, context):
    records = event.get("Records", [])
    logger.info("Received %d SQS record(s)", len(records))

    for i, record in enumerate(records):
        body = record.get("body", "")
        message_id = record.get("messageId", "unknown")
        logger.info("[%d] messageId=%s body=%s", i, message_id, body)

    return {"statusCode": 200, "body": json.dumps({"records_processed": len(records)})}
