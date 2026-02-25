#!/usr/bin/env node
// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

import * as cdk from "aws-cdk-lib";
import { DatadogLambdaExamplesStack } from "../lib/examples-stack";

const app = new cdk.App();
new DatadogLambdaExamplesStack(app, "DatadogLambdaExamplesStack", {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT ?? process.env.AWS_ACCOUNT_ID,
    region:
      process.env.CDK_DEFAULT_REGION ??
      process.env.AWS_REGION ??
      process.env.AWS_DEFAULT_REGION ??
      "us-east-1",
  },
});
