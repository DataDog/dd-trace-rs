// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

import * as path from "path";
import { Duration, Stack, Tags } from "aws-cdk-lib";
import * as lambda from "aws-cdk-lib/aws-lambda";
import { Construct } from "constructs";

export interface RustLambdaProps {
  exampleName: string;
  environment?: Record<string, string>;
  extensionVersion?: number;
}

export class RustLambda extends Construct {
  public readonly fn: lambda.Function;

  constructor(scope: Construct, id: string, props: RustLambdaProps) {
    super(scope, id);

    const extVersion = props.extensionVersion ?? 92;

    this.fn = new lambda.Function(this, "Function", {
      functionName: props.exampleName,
      runtime: lambda.Runtime.PROVIDED_AL2023,
      architecture: lambda.Architecture.ARM_64,
      handler: "bootstrap",
      code: lambda.Code.fromAsset(
        path.join(__dirname, "../../rust-binaries", `${props.exampleName}.zip`)
      ),
      timeout: Duration.seconds(30),
      memorySize: 256,
      environment: {
        DD_TRACE_ENABLED: "true",
        ...props.environment,
      },
      layers: [
        lambda.LayerVersion.fromLayerVersionArn(
          this,
          "DatadogExtension",
          `arn:aws:lambda:${Stack.of(this).region}:464622532012:layer:Datadog-Extension-ARM:${extVersion}`
        ),
      ],
    });

    const service = props.environment?.DD_SERVICE ?? props.exampleName;
    const env = props.environment?.DD_ENV ?? "dev";
    Tags.of(this.fn).add("service", service);
    Tags.of(this.fn).add("env", env);
  }
}
