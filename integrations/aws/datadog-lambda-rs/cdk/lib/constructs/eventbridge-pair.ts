// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

import { RemovalPolicy } from "aws-cdk-lib";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as events from "aws-cdk-lib/aws-events";
import * as targets from "aws-cdk-lib/aws-events-targets";
import { Construct } from "constructs";

export interface EventBridgePairProps {
  prefix: string;
  producer: lambda.Function;
  consumer: lambda.Function;
}

export class EventBridgePair extends Construct {
  public readonly bus: events.EventBus;

  constructor(scope: Construct, id: string, props: EventBridgePairProps) {
    super(scope, id);

    this.bus = new events.EventBus(this, "Bus", {
      eventBusName: `${props.prefix}-bus`,
    });
    this.bus.applyRemovalPolicy(RemovalPolicy.DESTROY);

    this.bus.grantPutEventsTo(props.producer);
    props.producer.addEnvironment("EVENT_BUS_NAME", this.bus.eventBusName);

    new events.Rule(this, "Rule", {
      eventBus: this.bus,
      ruleName: `${props.prefix}-rule`,
      eventPattern: {
        source: ["datadog-lambda-rs.example"],
      },
      targets: [new targets.LambdaFunction(props.consumer)],
    });
  }
}
