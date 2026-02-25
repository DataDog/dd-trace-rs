# Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
# SPDX-License-Identifier: Apache-2.0

"""SNS consumer — processes messages delivered directly by SNS.

ddtrace auto-extracts trace context from the _datadog MessageAttribute.
"""

import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event, context):
    records = event.get("Records", [])
    logger.info("Received %d SNS record(s)", len(records))
    for i, record in enumerate(records):
        sns_msg = record.get("Sns", {})
        logger.info("[%d] MessageId=%s Message=%s", i, sns_msg.get("MessageId"), sns_msg.get("Message"))
    return {"statusCode": 200, "body": json.dumps({"records_processed": len(records)})}
