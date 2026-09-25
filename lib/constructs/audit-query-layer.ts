import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as glue from 'aws-cdk-lib/aws-glue';
import * as athena from 'aws-cdk-lib/aws-athena';
import * as s3 from 'aws-cdk-lib/aws-s3';

export interface AuditQueryLayerProps {
  /** The archive bucket containing journals and recommendations. */
  readonly archiveBucket: s3.IBucket;
  /** Agent Space ID — used for partition projection enum values. */
  readonly agentSpaceId: string;
}

/**
 * Layer 5 — Query layer: Glue Data Catalog + Athena workgroup for auditing.
 *
 * Overlays three tables on the existing S3 archive (no new Lambdas, no crawlers):
 *   1. journals  — Hive-partitioned by space + date, using partition projection
 *   2. recommendations — flat table over the recommendations/ prefix
 *   3. goals — flat table over the goals/ prefix; joins to recommendations to
 *      tell current advice from superseded
 *
 * Plus an Athena workgroup with a dedicated (non-Object-Locked) results bucket,
 * a byte-scan cost guard, and CloudWatch metrics.
 *
 * Deploy note: the archive bucket has Object Lock + default retention. Athena
 * query results must be deletable, so results go to their own bucket.
 */
export class AuditQueryLayer extends Construct {
  public readonly database: glue.CfnDatabase;
  public readonly workgroup: athena.CfnWorkGroup;
  public readonly resultsBucket: s3.Bucket;

  constructor(scope: Construct, id: string, props: AuditQueryLayerProps) {
    super(scope, id);

    const { archiveBucket, agentSpaceId } = props;

    // -----------------------------------------------------------------
    // Athena results bucket — separate from the archive because the
    // archive bucket's Object Lock + default retention would prevent
    // Athena from managing its own result objects.
    // -----------------------------------------------------------------
    this.resultsBucket = new s3.Bucket(this, 'QueryResultsBucket', {
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
      lifecycleRules: [{ expiration: cdk.Duration.days(7) }],
    });

    // -----------------------------------------------------------------
    // Glue Data Catalog database
    // -----------------------------------------------------------------
    this.database = new glue.CfnDatabase(this, 'AuditDatabase', {
      catalogId: cdk.Aws.ACCOUNT_ID,
      databaseInput: {
        name: 'devops_agent_audit',
        description:
          'AWS DevOps Agent audit trail — journals and recommendations archive',
      },
    });

    // -----------------------------------------------------------------
    // Journals table — Hive-partitioned with partition projection
    //
    // S3 key pattern: journals/space={id}/dt={YYYY-MM-DD}/{execution}.json
    // Partition projection means zero maintenance: no crawler, no
    // MSCK REPAIR TABLE. Athena generates partitions on the fly.
    // -----------------------------------------------------------------
    new glue.CfnTable(this, 'JournalsTable', {
      catalogId: cdk.Aws.ACCOUNT_ID,
      databaseName: this.database.ref,
      tableInput: {
        name: 'journals',
        description:
          'Agent investigation journals archived on terminal events',
        tableType: 'EXTERNAL_TABLE',
        parameters: {
          'projection.enabled': 'true',
          'projection.space.type': 'enum',
          'projection.space.values': agentSpaceId,
          'projection.dt.type': 'date',
          'projection.dt.format': 'yyyy-MM-dd',
          'projection.dt.range': '2026-01-01,NOW',
          'projection.dt.interval': '1',
          'projection.dt.interval.unit': 'DAYS',
          'storage.location.template': `s3://${archiveBucket.bucketName}/journals/space=\${space}/dt=\${dt}/`,
          'classification': 'json',
        },
        storageDescriptor: {
          location: `s3://${archiveBucket.bucketName}/journals/`,
          inputFormat: 'org.apache.hadoop.mapred.TextInputFormat',
          outputFormat:
            'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat',
          serdeInfo: {
            serializationLibrary: 'org.openx.data.jsonserde.JsonSerDe',
            parameters: { 'ignore.malformed.json': 'true' },
          },
          columns: [
            { name: 'agent_space_id', type: 'string' },
            { name: 'execution_id', type: 'string' },
            { name: 'task_id', type: 'string' },
            { name: 'status', type: 'string' },
            { name: 'detail_type', type: 'string' },
            { name: 'event_time', type: 'string' },
            { name: 'summary_record_id', type: 'string' },
            { name: 'record_count', type: 'int' },
            {
              name: 'task',
              type: 'struct<taskId:string,title:string,description:string,taskType:string,priority:string,status:string,createdAt:string,updatedAt:string>',
            },
            {
              name: 'journal_records',
              type: 'array<struct<recordId:string,content:string,createdAt:string,recordType:string>>',
            },
          ],
        },
        partitionKeys: [
          { name: 'space', type: 'string' },
          { name: 'dt', type: 'string' },
        ],
      },
    });

    // -----------------------------------------------------------------
    // Recommendations table — flat, prefix-scanned
    //
    // S3 key pattern: recommendations/{id}/v{version}.json
    // NOT Hive-style, so no partition projection. Volume is low
    // (tens/hundreds of objects) — Athena recurses subdirectories by
    // default, which is sufficient.
    // -----------------------------------------------------------------
    new glue.CfnTable(this, 'RecommendationsTable', {
      catalogId: cdk.Aws.ACCOUNT_ID,
      databaseName: this.database.ref,
      tableInput: {
        name: 'recommendations',
        description: 'Agent recommendations versioned snapshots',
        tableType: 'EXTERNAL_TABLE',
        parameters: { classification: 'json' },
        storageDescriptor: {
          location: `s3://${archiveBucket.bucketName}/recommendations/`,
          inputFormat: 'org.apache.hadoop.mapred.TextInputFormat',
          outputFormat:
            'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat',
          serdeInfo: {
            serializationLibrary: 'org.openx.data.jsonserde.JsonSerDe',
            parameters: { 'ignore.malformed.json': 'true' },
          },
          columns: [
            { name: 'recommendationid', type: 'string' },
            { name: 'taskid', type: 'string' },
            { name: 'goalid', type: 'string' },
            { name: 'title', type: 'string' },
            { name: 'status', type: 'string' },
            { name: 'priority', type: 'string' },
            { name: 'rankposition', type: 'int' },
            { name: 'version', type: 'int' },
            { name: 'createdat', type: 'string' },
            { name: 'updatedat', type: 'string' },
            // content.summary is double-encoded JSON — leave as string;
            // auditors use json_extract_scalar() to query inside it
            { name: 'content', type: 'struct<summary:string>' },
          ],
        },
      },
    });

    // -----------------------------------------------------------------
    // Goals table — flat, prefix-scanned
    //
    // S3 key pattern: goals/{goalId}/v{version}.json
    //
    // Exists for exactly one join. Every evaluation run re-creates the advice it
    // still believes in under new recommendationIds and leaves the previous
    // run's records behind, so `recommendations` mixes current advice with
    // superseded advice and carries no field distinguishing them. The goal's
    // lastSuccessfulTaskId does:
    //
    //   SELECT r.recommendationid, r.title
    //   FROM recommendations r JOIN goals g ON r.goalid = g.goalid
    //   WHERE r.taskid = g.lastsuccessfultaskid
    //
    // Note this join cannot rescue recommendations with a null goalid (a
    // different producer writes those) — see the README limitation.
    // -----------------------------------------------------------------
    new glue.CfnTable(this, 'GoalsTable', {
      catalogId: cdk.Aws.ACCOUNT_ID,
      databaseName: this.database.ref,
      tableInput: {
        name: 'goals',
        description:
          'Agent goal snapshots — lastSuccessfulTaskId tells current advice from superseded',
        tableType: 'EXTERNAL_TABLE',
        parameters: { classification: 'json' },
        storageDescriptor: {
          location: `s3://${archiveBucket.bucketName}/goals/`,
          inputFormat: 'org.apache.hadoop.mapred.TextInputFormat',
          outputFormat:
            'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat',
          serdeInfo: {
            serializationLibrary: 'org.openx.data.jsonserde.JsonSerDe',
            parameters: { 'ignore.malformed.json': 'true' },
          },
          columns: [
            { name: 'goalid', type: 'string' },
            { name: 'title', type: 'string' },
            { name: 'status', type: 'string' },
            { name: 'goaltype', type: 'string' },
            { name: 'lasttaskid', type: 'string' },
            // The discriminator. Null on a goal whose first evaluation has not
            // succeeded yet — which is a real audit answer, not missing data.
            { name: 'lastsuccessfultaskid', type: 'string' },
            { name: 'lastevaluatedat', type: 'string' },
            { name: 'version', type: 'int' },
            { name: 'createdat', type: 'string' },
            { name: 'updatedat', type: 'string' },
            {
              name: 'evaluationschedule',
              type: 'struct<state:string,expression:string>',
            },
          ],
        },
      },
    });

    // -----------------------------------------------------------------
    // Athena workgroup — cost-guarded, encrypted results
    // -----------------------------------------------------------------
    this.workgroup = new athena.CfnWorkGroup(this, 'AuditWorkgroup', {
      name: 'devops-agent-audit',
      description: 'Workgroup for DevOps Agent audit trail queries',
      state: 'ENABLED',
      workGroupConfiguration: {
        resultConfiguration: {
          outputLocation: `s3://${this.resultsBucket.bucketName}/`,
          encryptionConfiguration: { encryptionOption: 'SSE_S3' },
        },
        bytesScannedCutoffPerQuery: 10 * 1024 * 1024 * 1024, // 10 GB guard
        enforceWorkGroupConfiguration: true,
        publishCloudWatchMetricsEnabled: true,
      },
    });
  }
}
