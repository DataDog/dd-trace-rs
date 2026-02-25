// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

import { Stack, StackProps } from "aws-cdk-lib";
import { Construct } from "constructs";
import { RustLambda } from "./constructs/rust-lambda";
import { PythonLambda } from "./constructs/python-lambda";
import { SqsPair } from "./constructs/sqs-pair";
import { SnsPair } from "./constructs/sns-pair";
import { EventBridgePair } from "./constructs/eventbridge-pair";

export class DatadogLambdaExamplesStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const ddApiKey = process.env.DD_API_KEY;
    if (!ddApiKey) {
      throw new Error("DD_API_KEY environment variable is required");
    }
    const ddEnv = process.env.DD_ENV ?? "dev";

    const commonEnv = {
      DD_API_KEY: ddApiKey,
      DD_ENV: ddEnv,
      DD_LOG_LEVEL: "debug",
    };

    // SQS: Rust → SQS → Python
    const sqsRustProducer = new RustLambda(this, "SqsRustProducer", {
      exampleName: "sqs-producer",
      environment: { ...commonEnv, DD_SERVICE: "sqs-producer" },
    });
    const sqsPythonConsumer = new PythonLambda(this, "SqsPythonConsumer", {
      functionName: "sqs-python-consumer",
      handlerDir: "sqs/rust-producer",
      environment: { ...commonEnv, DD_SERVICE: "sqs-python-consumer" },
    });
    new SqsPair(this, "SqsProducerPair", {
      prefix: "sqs-producer",
      producer: sqsRustProducer.fn,
      consumer: sqsPythonConsumer.fn,
    });

    // SQS: Python → SQS → Rust
    const sqsPythonProducer = new PythonLambda(this, "SqsPythonProducer", {
      functionName: "sqs-python-producer",
      handlerDir: "sqs/rust-consumer",
      environment: { ...commonEnv, DD_SERVICE: "sqs-python-producer" },
    });
    const sqsRustConsumer = new RustLambda(this, "SqsRustConsumer", {
      exampleName: "sqs-consumer",
      environment: { ...commonEnv, DD_SERVICE: "sqs-consumer" },
    });
    new SqsPair(this, "SqsConsumerPair", {
      prefix: "sqs-consumer",
      producer: sqsPythonProducer.fn,
      consumer: sqsRustConsumer.fn,
    });

    // SNS: Rust → SNS → Python
    const snsRustProducer = new RustLambda(this, "SnsRustProducer", {
      exampleName: "sns-producer",
      environment: { ...commonEnv, DD_SERVICE: "sns-producer" },
    });
    const snsPythonConsumer = new PythonLambda(this, "SnsPythonConsumer", {
      functionName: "sns-python-consumer",
      handlerDir: "sns/rust-producer",
      environment: { ...commonEnv, DD_SERVICE: "sns-python-consumer" },
    });
    new SnsPair(this, "SnsProducerPair", {
      prefix: "sns-producer",
      publisher: snsRustProducer.fn,
      consumer: snsPythonConsumer.fn,
    });

    // SNS: Python → SNS → Rust
    const snsPythonProducer = new PythonLambda(this, "SnsPythonProducer", {
      functionName: "sns-python-producer",
      handlerDir: "sns/rust-consumer",
      environment: { ...commonEnv, DD_SERVICE: "sns-python-producer" },
    });
    const snsRustConsumer = new RustLambda(this, "SnsRustConsumer", {
      exampleName: "sns-consumer",
      environment: { ...commonEnv, DD_SERVICE: "sns-consumer" },
    });
    new SnsPair(this, "SnsConsumerPair", {
      prefix: "sns-consumer",
      publisher: snsPythonProducer.fn,
      consumer: snsRustConsumer.fn,
    });

    // EventBridge: Rust → EventBridge → Python
    const ebRustProducer = new RustLambda(this, "EbRustProducer", {
      exampleName: "eventbridge-producer",
      environment: { ...commonEnv, DD_SERVICE: "eventbridge-producer" },
    });
    const ebPythonConsumer = new PythonLambda(this, "EbPythonConsumer", {
      functionName: "eventbridge-python-consumer",
      handlerDir: "eventbridge/rust-producer",
      environment: { ...commonEnv, DD_SERVICE: "eventbridge-python-consumer" },
    });
    new EventBridgePair(this, "EbProducerPair", {
      prefix: "eventbridge-producer",
      producer: ebRustProducer.fn,
      consumer: ebPythonConsumer.fn,
    });

    // EventBridge: Python → EventBridge → Rust
    const ebPythonProducer = new PythonLambda(this, "EbPythonProducer", {
      functionName: "eventbridge-python-producer",
      handlerDir: "eventbridge/rust-consumer",
      environment: { ...commonEnv, DD_SERVICE: "eventbridge-python-producer" },
    });
    const ebRustConsumer = new RustLambda(this, "EbRustConsumer", {
      exampleName: "eventbridge-consumer",
      environment: { ...commonEnv, DD_SERVICE: "eventbridge-consumer" },
    });
    new EventBridgePair(this, "EbConsumerPair", {
      prefix: "eventbridge-consumer",
      producer: ebPythonProducer.fn,
      consumer: ebRustConsumer.fn,
    });
  }
}
