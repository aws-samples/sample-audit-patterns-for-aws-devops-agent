import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as scheduler from 'aws-cdk-lib/aws-scheduler';
import * as path from 'path';
import { makeAssetOptions } from '../bundling';

export interface RecommendationsSnapshotProps {
  /** Immutable archive bucket that recommendation snapshots are written into. */
  readonly archiveBucket: s3.IBucket;
  /** The DevOps Agent Agent Space ID to poll. */
  readonly agentSpaceId: string;
  /** Schedule expression for the poll (e.g. rate(1 day)). */
  readonly pollSchedule: string;
}

/**
 * Layer 3 - Recommendations snapshot: scheduled poll -> S3 (versioned).
 * Recommendations have NO EventBridge event, so we poll on a schedule.
 */
export class RecommendationsSnapshot extends Construct {
  constructor(scope: Construct, id: string, props: RecommendationsSnapshotProps) {
    super(scope, id);

    const { archiveBucket, agentSpaceId, pollSchedule } = props;

    const logGroup = new logs.LogGroup(this, 'RecommendationsPollLogGroup', {
      retention: logs.RetentionDays.THREE_MONTHS,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const recsFn = new lambda.Function(this, 'RecommendationsPoll', {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'handler.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '..', '..', 'lambda', 'recommendations-poll'),
        makeAssetOptions(path.join(__dirname, '..', '..', 'lambda', 'recommendations-poll'))),
      timeout: cdk.Duration.minutes(2),
      memorySize: 256,
      environment: {
        ARCHIVE_BUCKET: archiveBucket.bucketName,
        AGENT_SPACE_ID: agentSpaceId,
      },
      logGroup,
      description: 'Polls DevOps Agent recommendations and snapshots each version to S3.',
    });

    // Put + read (NOT delete): the poller HEADs the existing object to compare
    // content (ETag) before writing, so it only creates a new locked version
    // when the snapshot actually changed. grantRead adds GetObject (which
    // covers HeadObject); grantPut adds PutObject. Deliberately no DeleteObject
    // grant — nothing should delete from a tamper-evident audit archive.
    archiveBucket.grantPut(recsFn, 'recommendations/*');
    archiveBucket.grantRead(recsFn, 'recommendations/*');
    // Goals are snapshotted alongside the recommendations: a recommendation has
    // no field saying whether it is still current, and the owning goal's
    // lastSuccessfulTaskId is the only discriminator.
    archiveBucket.grantPut(recsFn, 'goals/*');
    archiveBucket.grantRead(recsFn, 'goals/*');
    recsFn.addToRolePolicy(new iam.PolicyStatement({
      // Both actions take `agentspace` as a required resource type, so scope
      // them to the space this poller reads.
      // https://docs.aws.amazon.com/service-authorization/latest/reference/list_devops-agent.html
      actions: ['aidevops:ListRecommendations', 'aidevops:ListGoals'],
      resources: [
        cdk.Stack.of(this).formatArn({
          service: 'aidevops',
          resource: 'agentspace',
          resourceName: agentSpaceId,
          arnFormat: cdk.ArnFormat.SLASH_RESOURCE_NAME,
        }),
      ],
    }));

    new scheduler.CfnSchedule(this, 'RecommendationsSchedule', {
      flexibleTimeWindow: { mode: 'OFF' },
      scheduleExpression: pollSchedule,
      description: 'Daily poll of DevOps Agent recommendations',
      target: {
        arn: recsFn.functionArn,
        roleArn: this.schedulerRoleFor(recsFn).roleArn,
      },
    });
  }

  /** Role that EventBridge Scheduler assumes to invoke a Lambda target. */
  private schedulerRoleFor(fn: lambda.Function): iam.Role {
    // Condition on the calling account so a schedule in someone else's account
    // cannot assume this role (confused deputy).
    // https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html
    const role = new iam.Role(this, `SchedulerRole${fn.node.id}`, {
      assumedBy: new iam.ServicePrincipal('scheduler.amazonaws.com', {
        conditions: {
          StringEquals: { 'aws:SourceAccount': cdk.Stack.of(this).account },
        },
      }),
      description: 'Allows EventBridge Scheduler to invoke the recommendations poll function',
    });
    fn.grantInvoke(role);
    return role;
  }
}
