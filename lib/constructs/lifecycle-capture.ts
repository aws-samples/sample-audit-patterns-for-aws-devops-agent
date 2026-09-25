import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as logs from 'aws-cdk-lib/aws-logs';

/**
 * Layer 1 - Lifecycle capture (zero code): all aidevops events -> Logs.
 *
 * An EventBridge rule matches every event on source `aws.aidevops` and
 * forwards it to a CloudWatch Log Group, giving a complete, low-cost record
 * of agent lifecycle activity with no Lambda in the path.
 */
export class LifecycleCapture extends Construct {
  public readonly logGroup: logs.LogGroup;

  constructor(scope: Construct, id: string) {
    super(scope, id);

    this.logGroup = new logs.LogGroup(this, 'LifecycleLogGroup', {
      logGroupName: '/devops-agent/aidevops-lifecycle',
      retention: logs.RetentionDays.THREE_MONTHS,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    new events.Rule(this, 'LifecycleRule', {
      description: 'Capture all AWS DevOps Agent lifecycle events to CloudWatch Logs',
      eventPattern: { source: ['aws.aidevops'] },
      targets: [new targets.CloudWatchLogGroup(this.logGroup)],
    });
  }
}
