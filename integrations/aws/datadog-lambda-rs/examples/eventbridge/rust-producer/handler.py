# Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
# SPDX-License-Identifier: Apache-2.0

"""EventBridge consumer — processes events delivered by an EventBridge rule.

ddtrace auto-extracts trace context from the _datadog key in the event detail.
"""

import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event, context):
    source = event.get("source", "unknown")
    detail_type = event.get("detail-type", "unknown")
    detail = event.get("detail", {})
    logger.info("Received event: source=%s detail-type=%s detail=%s", source, detail_type, json.dumps(detail))
    return {"statusCode": 200, "body": json.dumps({"source": source, "detail_type": detail_type})}
