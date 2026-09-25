import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as subscriptions from 'aws-cdk-lib/aws-sns-subscriptions';
import { LifecycleCapture } from './constructs/lifecycle-capture';
import { JournalArchival } from './constructs/journal-archival';
import { RecommendationsSnapshot } from './constructs/recommendations-snapshot';
import { ControlPlaneAlerting } from './constructs/control-plane-alerting';
import { AuditQueryLayer } from './constructs/audit-query-layer';

export interface DevOpsAgentAuditTrailStackProps extends cdk.StackProps {
  /** The DevOps Agent Agent Space ID to audit. */
  readonly agentSpaceId: string;
  /** How often to poll recommendations. Default: rate(1 day). */
  readonly recommendationPollSchedule?: string;
  /** The immutable archive bucket (owned by the stateful ArchiveStack). */
  readonly archiveBucket: s3.IBucket;
  /**
   * Optional email address subscribed to the alert topic. Without a
   * subscription the alarms and the control-plane tripwire fire into a topic
   * nobody receives, so supplying this at deploy time is strongly recommended.
   * AWS sends a confirmation email that must be accepted.
   */
  readonly alertEmail?: string;
  /**
   * Explicit acknowledgement that the alert topic is intentionally left without
   * a subscription (e.g. the operator wires their own subscription out of band).
   * Deploying with neither `alertEmail` nor this flag fails synth: an
   * unsubscribed topic silently disables both the control-plane tripwire and the
   * journal DLQ alarm, so the omission must be a deliberate choice, not an
   * accident.
   */
  readonly acknowledgeNoAlerting?: boolean;
}

/**
 * Captures the operational trail of AWS DevOps Agent across four surfaces:
 *   Layer 1 - Lifecycle events      -> CloudWatch Logs (zero code)
 *   Layer 2 - Journal (findings)    -> Lambda -> S3, on terminal events
 *   Layer 3 - Recommendations       -> scheduled Lambda poll -> S3 (versioned)
 *   Layer 4 - Control-plane changes -> SNS alert
 *
 * DevOps Agent event source is `aws.aidevops`; CloudTrail source is
 * `aidevops.amazonaws.com`. Events land on the default bus in the hosting
 * account/Region, so deploy this stack there.
 *
 * Each layer is modeled as its own Construct (best practice: model with
 * constructs, deploy with stacks); this stack is a thin, stateless composer
 * that wires the layers to the archive bucket owned by the ArchiveStack.
 */
export class DevOpsAgentAuditTrailStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: DevOpsAgentAuditTrailStackProps) {
    super(scope, id, props);

    const { agentSpaceId } = props;
    const pollSchedule = props.recommendationPollSchedule ?? 'rate(1 day)';
    const archiveBucket = props.archiveBucket;

    // Reported here rather than thrown in bin/app.ts so that app-level commands
    // which do not need this value (cdk bootstrap / doctor / context) still
    // work. A synth-time error still fails `cdk synth` and `cdk deploy`.
    if (!agentSpaceId) {
      cdk.Annotations.of(this).addError(
        'Missing required context "agentSpaceId". Deploy with: ' +
          'cdk deploy -c agentSpaceId=<your-agent-space-id>',
      );
    }

    // ---------------------------------------------------------------------
    // One alert topic for the whole audit trail. Both the control-plane
    // tripwire (someone changed the agent) and the pipeline-health alarm (a
    // terminal event failed to archive) publish here, so the operator has a
    // single subscription to manage.
    // ---------------------------------------------------------------------
    // Encrypted with the AWS managed key for SNS. Alert payloads name the agent
    // space and the principal that changed it, so they are audit content too.
    const alertTopic = new sns.Topic(this, 'ControlPlaneAlertTopic', {
      displayName: 'DevOps Agent audit trail alerts',
      masterKey: kms.Alias.fromAliasName(this, 'SnsManagedKey', 'alias/aws/sns'),
    });

    if (props.alertEmail) {
      alertTopic.addSubscription(new subscriptions.EmailSubscription(props.alertEmail));
    } else if (!props.acknowledgeNoAlerting) {
      // An unsubscribed alert topic silently disables both the
      // control-plane tripwire and the journal DLQ alarm — the whole detective
      // story fires into a topic nobody receives. Refuse to synth unless the
      // operator either supplies a subscription or explicitly acknowledges the
      // gap. Reported as a synth-time error (not thrown) for the same reason as
      // agentSpaceId above: app-level commands must still evaluate the app.
      cdk.Annotations.of(this).addError(
        'No alert subscription configured. The control-plane tripwire and the ' +
          'journal DLQ alarm would notify nobody. Supply an email with ' +
          '-c alertEmail=<you@example.com>, or acknowledge the gap explicitly ' +
          'with -c acknowledgeNoAlerting=true (e.g. if you subscribe to the ' +
          'topic out of band).',
      );
    }

    // ---------------------------------------------------------------------
    // Each audit layer is modeled as its own construct
    // ---------------------------------------------------------------------
    const lifecycle = new LifecycleCapture(this, 'LifecycleCapture');

    const journal = new JournalArchival(this, 'JournalArchival', {
      archiveBucket,
      agentSpaceId,
      alertTopic,
    });

    new RecommendationsSnapshot(this, 'RecommendationsSnapshot', {
      archiveBucket,
      agentSpaceId,
      pollSchedule,
    });

    new ControlPlaneAlerting(this, 'ControlPlaneAlerting', { alertTopic });

    // ---------------------------------------------------------------------
    // Layer 5: Query layer — Glue catalog + Athena workgroup for auditing
    // ---------------------------------------------------------------------
    const queryLayer = new AuditQueryLayer(this, 'AuditQueryLayer', {
      archiveBucket,
      agentSpaceId,
    });

    // ---------------------------------------------------------------------
    // Outputs
    // ---------------------------------------------------------------------
    new cdk.CfnOutput(this, 'LifecycleLogGroupName', { value: lifecycle.logGroup.logGroupName });
    new cdk.CfnOutput(this, 'ControlPlaneAlertTopicArn', { value: alertTopic.topicArn });
    new cdk.CfnOutput(this, 'JournalDlqUrl', { value: journal.dlq.queueUrl });
    new cdk.CfnOutput(this, 'AlertSubscriptionConfigured', {
      value: props.alertEmail ? 'yes' : 'NO - subscribe to the topic manually',
    });
    new cdk.CfnOutput(this, 'AuditQueryWorkgroup', { value: queryLayer.workgroup.name! });
    new cdk.CfnOutput(this, 'AuditQueryResultsBucket', { value: queryLayer.resultsBucket.bucketName });
  }
}
