import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';

export interface ArchiveStackProps extends cdk.StackProps {
  /**
   * Object Lock retention mode for the archive bucket.
   *   - GOVERNANCE (default): objects are protected, but a principal holding
   *     `s3:BypassGovernanceRetention` can still delete/shorten them. Safe,
   *     reversible, good for most audit needs.
   *   - COMPLIANCE: NO principal (not even the account root) can delete or
   *     shorten a locked object until its retention expires. Truly immutable
   *     and IRREVERSIBLE for the retention window. Choose deliberately.
   * Default: GOVERNANCE.
   */
  readonly objectLockMode?: 'GOVERNANCE' | 'COMPLIANCE';
  /**
   * Default retention applied to every new journal/recommendation object,
   * in days. Applies going forward to new objects only. Default: 365.
   */
  readonly objectLockRetentionDays?: number;
  /**
   * How long to keep S3 server access logs for the archive bucket, in days.
   * Default: 365.
   */
  readonly accessLogRetentionDays?: number;
}

/**
 * Stateful stack: owns the immutable archive bucket for journals and
 * recommendations. Split out from the pipeline stack so the stateless audit
 * plumbing can be redeployed or destroyed without ever touching the archive.
 *
 * Termination protection is forced on: this stack holds tamper-evident audit
 * data under Object Lock and must never be casually deleted.
 */
export class ArchiveStack extends cdk.Stack {
  public readonly archiveBucket: s3.Bucket;

  constructor(scope: Construct, id: string, props: ArchiveStackProps = {}) {
    super(scope, id, { ...props, terminationProtection: true });

    const lockMode = props.objectLockMode ?? 'GOVERNANCE';
    const lockRetentionDays = props.objectLockRetentionDays ?? 365;
    const accessLogRetentionDays = props.accessLogRetentionDays ?? 365;

    // ---------------------------------------------------------------------
    // Access-log destination for the archive bucket.
    //
    // This is a SEPARATE bucket by necessity, not preference: S3 refuses to
    // deliver server access logs to a destination that has Object Lock enabled
    // or a default retention period — and the archive bucket has both. The
    // destination must also use SSE-S3; with SSE-KMS the log objects may be
    // written under a key the reader cannot use.
    // https://docs.aws.amazon.com/AmazonS3/latest/userguide/troubleshooting-server-access-logging.html
    //
    // Why bother: the archive is tamper-evident for WRITES, but without access
    // logging there is no record of who READ the agent's journals. For an audit
    // archive, reads are part of the audit story.
    // ---------------------------------------------------------------------
    const accessLogsBucket = new s3.Bucket(this, 'AccessLogsBucket', {
      encryption: s3.BucketEncryption.S3_MANAGED, // SSE-KMS is not supported for log delivery
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      // Deliberately NO Object Lock and no default retention — either one
      // silently blocks log delivery.
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      lifecycleRules: [{ expiration: cdk.Duration.days(accessLogRetentionDays) }],
    });

    // ---------------------------------------------------------------------
    // Shared: immutable archive bucket for journals and recommendations
    // ---------------------------------------------------------------------
    // Object Lock is ENFORCED here, not merely enabled: a default retention
    // rule locks every new object for `lockRetentionDays`. Enabling the
    // feature alone (objectLockEnabled) leaves objects deletable — the
    // default retention is what actually makes the archive tamper-evident.
    this.archiveBucket = new s3.Bucket(this, 'ArchiveBucket', {
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      versioned: true,
      objectLockEnabled: true,
      objectLockDefaultRetention:
        lockMode === 'COMPLIANCE'
          ? s3.ObjectLockRetention.compliance(cdk.Duration.days(lockRetentionDays))
          : s3.ObjectLockRetention.governance(cdk.Duration.days(lockRetentionDays)),
      enforceSSL: true,
      serverAccessLogsBucket: accessLogsBucket,
      serverAccessLogsPrefix: 'archive-access/',
      removalPolicy: cdk.RemovalPolicy.RETAIN, // never auto-delete an audit archive
      lifecycleRules: [
        { transitions: [{ storageClass: s3.StorageClass.INFREQUENT_ACCESS, transitionAfter: cdk.Duration.days(90) }] },
      ],
    });

    new cdk.CfnOutput(this, 'ArchiveBucketName', { value: this.archiveBucket.bucketName });
    new cdk.CfnOutput(this, 'AccessLogsBucketName', { value: accessLogsBucket.bucketName });
  }
}
