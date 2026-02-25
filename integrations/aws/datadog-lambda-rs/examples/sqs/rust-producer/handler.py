# Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
# SPDX-License-Identifier: Apache-2.0

"""SQS consumer — processes messages from SQS.

ddtrace auto-extracts trace context from the _datadog message attribute.
"""

import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event, context):
    records = event.get("Records", [])
    logger.info("Received %d SQS record(s)", len(records))
    for i, record in enumerate(records):
        logger.info("[%d] messageId=%s body=%s", i, record.get("messageId"), record.get("body"))
    return {"statusCode": 200, "body": json.dumps({"records_processed": len(records)})}
