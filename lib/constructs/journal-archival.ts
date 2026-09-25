import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cwActions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as path from 'path';
import { makeAssetOptions } from '../bundling';

export interface JournalArchivalProps {
  /** Immutable archive bucket that journals are written into. */
  readonly archiveBucket: s3.IBucket;
  /**
   * Agent Space whose journals this layer archives. Used both to scope the
   * IAM grant to that agent space's ARN and to filter the EventBridge rule,
   * so the two always agree about which space is in scope.
   */
  readonly agentSpaceId: string;
  /**
   * Topic notified when the DLQ alarm fires. An alarm with no action is only
   * visible to someone already looking at CloudWatch — and a terminal event
   * that failed to archive is a permanent loss of the behavior record, because
   * terminal events are never re-emitted. So this is wired, not optional.
   */
  readonly alertTopic: sns.ITopic;
}

/**
 * Layer 2 - Journal archival: terminal events -> Lambda -> S3.
 *
 * When an investigation or mitigation reaches a terminal state, an
 * EventBridge rule invokes a Lambda that pages the DevOps Agent journal and
 * writes it into the immutable archive. Failed invocations land in a DLQ,
 * and a CloudWatch alarm fires on any message there — a terminal event that
 * did not archive is a permanent behavior-record loss risk.
 */
export class JournalArchival extends Construct {
  public readonly dlq: sqs.Queue;
  public readonly dlqAlarm: cloudwatch.Alarm;

  constructor(scope: Construct, id: string, props: JournalArchivalProps) {
    super(scope, id);

    const { archiveBucket, agentSpaceId, alertTopic } = props;

    // Both `aidevops:ListJournalRecords` and `aidevops:GetBacklogTask` take
    // `agentspace` as a REQUIRED resource type, so they can be scoped rather
    // than granted on "*".
    // https://docs.aws.amazon.com/service-authorization/latest/reference/list_devops-agent.html
    const agentSpaceArn = cdk.Stack.of(this).formatArn({
      service: 'aidevops',
      resource: 'agentspace',
      resourceName: agentSpaceId,
      arnFormat: cdk.ArnFormat.SLASH_RESOURCE_NAME,
    });

    // Encrypted at rest as well as in transit: a failed message carries the
    // journal event that could not be archived, which is audit content.
    // SQS-managed SSE needs no key policy and costs nothing.
    this.dlq = new sqs.Queue(this, 'JournalArchiverDlq', {
      retentionPeriod: cdk.Duration.days(14),
      enforceSSL: true,
      encryption: sqs.QueueEncryption.SQS_MANAGED,
    });

    const logGroup = new logs.LogGroup(this, 'JournalArchiverLogGroup', {
      retention: logs.RetentionDays.THREE_MONTHS,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const journalFn = new lambda.Function(this, 'JournalArchiver', {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'handler.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '..', '..', 'lambda', 'journal-archiver'),
        makeAssetOptions(path.join(__dirname, '..', '..', 'lambda', 'journal-archiver'))),
      timeout: cdk.Duration.minutes(2), // absorb journal pagination
      memorySize: 256,
      environment: { ARCHIVE_BUCKET: archiveBucket.bucketName },
      logGroup,
      description: 'Archives the DevOps Agent journal to S3 when an investigation reaches a terminal state.',
    });

    archiveBucket.grantPut(journalFn, 'journals/*');
    journalFn.addToRolePolicy(new iam.PolicyStatement({
      // NOTE: the IAM action namespace is `aidevops:`, NOT `devops-agent:`
      // (the latter is only the AWS CLI service name). These differ.
      actions: ['aidevops:ListJournalRecords', 'aidevops:GetBacklogTask'],
      resources: [agentSpaceArn],
    }));

    new events.Rule(this, 'TerminalEventRule', {
      description: 'Invoke journal archiver on terminal investigation/mitigation events',
      eventPattern: {
        source: ['aws.aidevops'],
        detailType: [
          'Investigation Completed', 'Investigation Failed',
          'Investigation Timed Out', 'Investigation Cancelled',
          'Mitigation Completed', 'Mitigation Failed',
          'Mitigation Timed Out', 'Mitigation Cancelled',
        ],
        // Scoped to the SAME agent space as the IAM grant above. Without this
        // filter, an account running several agent spaces would deliver events
        // the policy forbids: every such invocation would fail on AccessDenied,
        // land in the DLQ and raise the alarm. Keeping rule and policy in
        // agreement means a DLQ message signals a real fault, not a
        // misconfiguration. Layer 1 still logs lifecycle events from every
        // space — it needs no IAM.
        detail: { metadata: { agent_space_id: [agentSpaceId] } },
      },
      targets: [new targets.LambdaFunction(journalFn, {
        deadLetterQueue: this.dlq,
        retryAttempts: 2,
      })],
    });

    this.dlqAlarm = new cloudwatch.Alarm(this, 'JournalDlqAlarm', {
      alarmDescription: 'A journal-archive terminal event failed and landed in the DLQ (permanent behavior-record loss risk).',
      metric: this.dlq.metricApproximateNumberOfMessagesVisible({ period: cdk.Duration.minutes(5) }),
      threshold: 1,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    this.dlqAlarm.addAlarmAction(new cwActions.SnsAction(alertTopic));
  }
}
