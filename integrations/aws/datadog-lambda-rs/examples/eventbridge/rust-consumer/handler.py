# Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
# SPDX-License-Identifier: Apache-2.0

"""EventBridge producer — puts an event on an EventBridge bus.

ddtrace auto-instruments the boto3 call and injects trace context into
the _datadog key in the event detail.
"""

import json
import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

events = boto3.client("events")
EVENT_BUS_NAME = os.environ["EVENT_BUS_NAME"]


def handler(event, context):
    detail = event.get("detail", {"message": "hello from Python EventBridge producer"})
    response = events.put_events(
        Entries=[
            {
                "EventBusName": EVENT_BUS_NAME,
                "Source": "datadog-lambda-rs.example",
                "DetailType": "ExampleEvent",
                "Detail": json.dumps(detail),
            }
        ]
    )
    logger.info("PutEvents response: %s", json.dumps(response, default=str))
    return {"statusCode": 200, "body": json.dumps({"failed_count": response["FailedEntryCount"]})}
