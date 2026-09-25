import { Construct } from 'constructs';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as sns from 'aws-cdk-lib/aws-sns';

export interface ControlPlaneAlertingProps {
  /** Topic notified when a mutating control-plane call is observed. */
  readonly alertTopic: sns.ITopic;
}

/**
 * Layer 4 - Control-plane alerting: mutating aidevops API calls -> SNS.
 * Requires CloudTrail management events on the default bus (default when
 * an org/account trail is enabled).
 *
 * The topic is injected rather than owned: the operator subscribes to ONE
 * topic and receives both control-plane changes (this layer) and audit-pipeline
 * failures (the journal DLQ alarm).
 */
export class ControlPlaneAlerting extends Construct {
  constructor(scope: Construct, id: string, props: ControlPlaneAlertingProps) {
    super(scope, id);

    const { alertTopic } = props;

    new events.Rule(this, 'ControlPlaneRule', {
      description: 'Alert on mutating DevOps Agent control-plane API calls',
      // NOTE: DevOps Agent CloudTrail events are published under source
      // `aws.aidevops` (the service's own event source), NOT `aws.cloudtrail`.
      // This was verified against a live agent space — mutating API calls
      // (e.g., DeleteAgentSpace) appear on the default bus with this source
      // when an account/org CloudTrail is enabled.
      eventPattern: {
        source: ['aws.aidevops'],
        detailType: ['AWS API Call via CloudTrail'],
        detail: {
          eventSource: ['aidevops.amazonaws.com'],
          eventName: [
            'DeleteAgentSpace', 'DisassociateService', 'DisableOperatorApp',
            'UpdateAssociation', 'DeleteTrigger', 'DeletePrivateConnection',
            // An operator approving an elevated action is a control-plane
            // mutation: the service mints a scoped STS session and the agent
            // then acts with it. Without this, the only record is after the
            // fact in CloudTrail (see correlate/correlate_agent.py).
            'UpdateApprovalAction',
          ],
        },
      },
      targets: [new targets.SnsTopic(alertTopic)],
    });
  }
}
