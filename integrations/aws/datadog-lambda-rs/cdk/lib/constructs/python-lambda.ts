// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

import * as path from "path";
import { Duration, Stack, Tags } from "aws-cdk-lib";
import * as lambda from "aws-cdk-lib/aws-lambda";
import { Construct } from "constructs";

export interface PythonLambdaProps {
  functionName: string;
  handlerDir: string;
  environment?: Record<string, string>;
  extensionVersion?: number;
  pythonLayerVersion?: number;
}

export class PythonLambda extends Construct {
  public readonly fn: lambda.Function;

  constructor(scope: Construct, id: string, props: PythonLambdaProps) {
    super(scope, id);

    const extVersion = props.extensionVersion ?? 92;
    const pyVersion = props.pythonLayerVersion ?? 122;
    const region = Stack.of(this).region;

    this.fn = new lambda.Function(this, "Function", {
      functionName: props.functionName,
      runtime: lambda.Runtime.PYTHON_3_12,
      architecture: lambda.Architecture.ARM_64,
      handler: "datadog_lambda.handler.handler",
      code: lambda.Code.fromAsset(
        path.join(__dirname, "../../../examples", props.handlerDir)
      ),
      timeout: Duration.seconds(30),
      memorySize: 256,
      environment: {
        DD_LAMBDA_HANDLER: "handler.handler",
        DD_TRACE_ENABLED: "true",
        DD_COLD_START_TRACING: "true",
        DD_TRACE_SAMPLING_RULES: '[{"sample_rate":1.0}]',
        ...props.environment,
      },
      layers: [
        lambda.LayerVersion.fromLayerVersionArn(
          this,
          "DatadogExtension",
          `arn:aws:lambda:${region}:464622532012:layer:Datadog-Extension-ARM:${extVersion}`
        ),
        lambda.LayerVersion.fromLayerVersionArn(
          this,
          "DatadogPython",
          `arn:aws:lambda:${region}:464622532012:layer:Datadog-Python312-ARM:${pyVersion}`
        ),
      ],
    });

    const service = props.environment?.DD_SERVICE ?? props.functionName;
    const env = props.environment?.DD_ENV ?? "dev";
    Tags.of(this.fn).add("service", service);
    Tags.of(this.fn).add("env", env);
  }
}
