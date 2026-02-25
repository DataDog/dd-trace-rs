// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

import * as lambda from "aws-cdk-lib/aws-lambda";
import * as sns from "aws-cdk-lib/aws-sns";
import * as snsSubscriptions from "aws-cdk-lib/aws-sns-subscriptions";
import { Construct } from "constructs";

export interface SnsPairProps {
  prefix: string;
  publisher: lambda.Function;
  consumer: lambda.Function;
}

export class SnsPair extends Construct {
  public readonly topic: sns.Topic;

  constructor(scope: Construct, id: string, props: SnsPairProps) {
    super(scope, id);

    this.topic = new sns.Topic(this, "Topic", {
      topicName: `${props.prefix}-topic`,
    });

    this.topic.grantPublish(props.publisher);
    props.publisher.addEnvironment("TOPIC_ARN", this.topic.topicArn);

    this.topic.addSubscription(
      new snsSubscriptions.LambdaSubscription(props.consumer)
    );
  }
}
