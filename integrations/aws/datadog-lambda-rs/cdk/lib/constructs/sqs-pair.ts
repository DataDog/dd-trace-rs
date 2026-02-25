// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

import { Duration, RemovalPolicy } from "aws-cdk-lib";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as sqs from "aws-cdk-lib/aws-sqs";
import * as lambdaEventSources from "aws-cdk-lib/aws-lambda-event-sources";
import { Construct } from "constructs";

export interface SqsPairProps {
  prefix: string;
  producer: lambda.Function;
  consumer: lambda.Function;
}

export class SqsPair extends Construct {
  public readonly queue: sqs.Queue;

  constructor(scope: Construct, id: string, props: SqsPairProps) {
    super(scope, id);

    this.queue = new sqs.Queue(this, "Queue", {
      queueName: `${props.prefix}-queue`,
      visibilityTimeout: Duration.seconds(60),
      removalPolicy: RemovalPolicy.DESTROY,
    });

    this.queue.grantSendMessages(props.producer);
    props.producer.addEnvironment("QUEUE_URL", this.queue.queueUrl);

    props.consumer.addEventSource(
      new lambdaEventSources.SqsEventSource(this.queue, { batchSize: 1 })
    );
  }
}
