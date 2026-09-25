import { describe, it, expect } from 'vitest';
import * as cdk from 'aws-cdk-lib';
import { Template, Match, Annotations } from 'aws-cdk-lib/assertions';
import * as fs from 'fs';
import * as path from 'path';
import { ArchiveStack } from '../lib/archive-stack';
import { DevOpsAgentAuditTrailStack } from '../lib/devops-agent-audit-trail-stack';

// Skip Lambda asset bundling during tests — the build environment has no
// Docker and no outbound network for pip3. We're testing infrastructure only.
process.env.SKIP_BUNDLING = '1';

// Construct apps with the SAME feature flags the CLI uses at deploy time.
// A bare `new cdk.App()` carries no context, so flag-dependent behaviour (e.g.
// @aws-cdk/aws-s3:serverAccessLogsUseBucketPolicy, which is what makes the S3
// log-delivery grant a bucket policy rather than an ineffective ACL) would be
// absent in tests and present in production — the tests would assert a
// template nobody deploys.
const cdkContext = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', 'cdk.json'), 'utf8'),
).context;
const newApp = () => new cdk.App({ context: cdkContext });

describe('DevOpsAgentAuditTrailStack', () => {
  const app = newApp();
  const archive = new ArchiveStack(app, 'TestArchiveStack');
  const stack = new DevOpsAgentAuditTrailStack(app, 'TestStack', {
    agentSpaceId: 'test-agent-space-id',
    archiveBucket: archive.archiveBucket,
    acknowledgeNoAlerting: true,
  });
  const template = Template.fromStack(stack);
  const archiveTemplate = Template.fromStack(archive);

  describe('Layer 1 — Lifecycle capture', () => {
    it('creates a CloudWatch log group with RETAIN policy', () => {
      template.hasResource('AWS::Logs::LogGroup', {
        Properties: { LogGroupName: '/devops-agent/aidevops-lifecycle' },
        DeletionPolicy: 'Retain',
      });
    });

    it('creates an EventBridge rule matching source aws.aidevops', () => {
      template.hasResourceProperties('AWS::Events::Rule', {
        EventPattern: {
          source: ['aws.aidevops'],
        },
      });
    });
  });

  describe('Layer 2 — Journal archival', () => {
    it('creates a Lambda function for journal archiving', () => {
      template.hasResourceProperties('AWS::Lambda::Function', {
        Handler: 'handler.handler',
        Runtime: 'python3.12',
        Timeout: 120,
        MemorySize: 256,
      });
    });

    it('creates an EventBridge rule for terminal events only', () => {
      template.hasResourceProperties('AWS::Events::Rule', {
        EventPattern: {
          source: ['aws.aidevops'],
          'detail-type': [
            'Investigation Completed', 'Investigation Failed',
            'Investigation Timed Out', 'Investigation Cancelled',
            'Mitigation Completed', 'Mitigation Failed',
            'Mitigation Timed Out', 'Mitigation Cancelled',
          ],
        },
      });
    });

    it('filters terminal events to the configured agent space', () => {
      // Must match the IAM scope. If the rule were broader than the policy, an
      // account with several agent spaces would deliver events the policy
      // forbids — each failing to AccessDenied, filling the DLQ and firing the
      // alarm for a misconfiguration rather than a real fault.
      template.hasResourceProperties('AWS::Events::Rule', {
        EventPattern: Match.objectLike({
          detail: { metadata: { agent_space_id: ['test-agent-space-id'] } },
        }),
      });
    });

    it('creates a DLQ for the journal archiver', () => {
      template.hasResourceProperties('AWS::SQS::Queue', {});
      template.resourceCountIs('AWS::SQS::Queue', 1);
    });

    it('encrypts the journal DLQ at rest', () => {
      // A failed message carries the journal event that could not be
      // archived, so the DLQ holds audit content too.
      template.hasResourceProperties('AWS::SQS::Queue', {
        SqsManagedSseEnabled: true,
      });
    });

    it('alarms on a non-empty journal DLQ (threshold 1)', () => {
      template.hasResourceProperties('AWS::CloudWatch::Alarm', {
        MetricName: 'ApproximateNumberOfMessagesVisible',
        Namespace: 'AWS/SQS',
        Threshold: 1,
        ComparisonOperator: 'GreaterThanOrEqualToThreshold',
        EvaluationPeriods: 1,
      });
    });

    it('wires the DLQ alarm to the alert topic (an alarm with no action notifies nobody)', () => {
      template.hasResourceProperties('AWS::CloudWatch::Alarm', {
        MetricName: 'ApproximateNumberOfMessagesVisible',
        AlarmActions: Match.arrayWith([Match.objectLike({ Ref: Match.anyValue() })]),
      });
    });
  });

  describe('Layer 3 — Recommendations poll', () => {
    it('creates an EventBridge Scheduler for recommendations polling', () => {
      template.hasResourceProperties('AWS::Scheduler::Schedule', {
        ScheduleExpression: 'rate(1 day)',
        FlexibleTimeWindow: { Mode: 'OFF' },
      });
    });
  });

  describe('Layer 4 — Control-plane alerting', () => {
    it('creates a single shared SNS topic for all audit alerts', () => {
      template.resourceCountIs('AWS::SNS::Topic', 1);
    });

    it('creates no subscription when no alertEmail is supplied', () => {
      template.resourceCountIs('AWS::SNS::Subscription', 0);
    });

    it('creates a rule matching CloudTrail mutating events', () => {
      template.hasResourceProperties('AWS::Events::Rule', {
        EventPattern: {
          source: ['aws.aidevops'],
          'detail-type': ['AWS API Call via CloudTrail'],
          detail: {
            eventSource: ['aidevops.amazonaws.com'],
            eventName: [
              'DeleteAgentSpace', 'DisassociateService', 'DisableOperatorApp',
              'UpdateAssociation', 'DeleteTrigger', 'DeletePrivateConnection',
              'UpdateApprovalAction',
            ],
          },
        },
      });
    });
  });

  describe('ArchiveStack — S3 Archive Bucket', () => {
    it('is a termination-protected stack', () => {
      expect(archive.terminationProtection).toBe(true);
    });

    it('creates a versioned bucket with Object Lock', () => {
      archiveTemplate.hasResourceProperties('AWS::S3::Bucket', {
        VersioningConfiguration: { Status: 'Enabled' },
        ObjectLockEnabled: true,
        BucketEncryption: {
          ServerSideEncryptionConfiguration: [
            { ServerSideEncryptionByDefault: { SSEAlgorithm: 'AES256' } },
          ],
        },
      });
    });

    it('enforces Object Lock with a default retention rule (not just enabled)', () => {
      // Enabling Object Lock alone leaves objects deletable; the default
      // retention is what actually makes the archive tamper-evident.
      archiveTemplate.hasResourceProperties('AWS::S3::Bucket', {
        ObjectLockConfiguration: {
          ObjectLockEnabled: 'Enabled',
          Rule: {
            DefaultRetention: { Mode: 'GOVERNANCE', Days: 365 },
          },
        },
      });
    });

    it('grants the S3 log delivery service write access via bucket policy', () => {
      // Without @aws-cdk/aws-s3:serverAccessLogsUseBucketPolicy, CDK falls back
      // to an ACL grant — ineffective on bucket-owner-enforced buckets — and
      // log delivery fails silently. This asserts the policy grant exists.
      archiveTemplate.hasResourceProperties('AWS::S3::BucketPolicy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Effect: 'Allow',
              Action: 's3:PutObject',
              Principal: { Service: 'logging.s3.amazonaws.com' },
            }),
          ]),
        },
      });
    });

    it('bucket has RETAIN deletion policy', () => {
      archiveTemplate.hasResource('AWS::S3::Bucket', {
        DeletionPolicy: 'Retain',
      });
    });

    it('blocks all public access', () => {
      archiveTemplate.hasResourceProperties('AWS::S3::Bucket', {
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: true,
          BlockPublicPolicy: true,
          IgnorePublicAcls: true,
          RestrictPublicBuckets: true,
        },
      });
    });

    it('archive bucket logical ID is stable (guards stateful-resource replacement)', () => {
      const buckets = archiveTemplate.findResources('AWS::S3::Bucket');
      const ids = Object.keys(buckets);
      // Archive bucket + its access-log destination.
      expect(ids).toHaveLength(2);
      expect(ids).toContain('ArchiveBucket9DECBF5D');
    });

    it('sends archive bucket server access logs to a separate bucket', () => {
      archiveTemplate.hasResourceProperties('AWS::S3::Bucket', {
        ObjectLockEnabled: true,
        LoggingConfiguration: {
          DestinationBucketName: Match.anyValue(),
          LogFilePrefix: 'archive-access/',
        },
      });
    });

    it('access-log destination has no Object Lock and uses SSE-S3', () => {
      // Both are hard requirements: Object Lock (or a default retention rule)
      // blocks log delivery outright, and SSE-KMS yields log objects encrypted
      // under a key the reader may not be able to use.
      const buckets = Object.entries(archiveTemplate.findResources('AWS::S3::Bucket'));
      const logsBucket = buckets.find(([id]) => id.startsWith('AccessLogsBucket'));
      expect(logsBucket).toBeDefined();
      const props: any = logsBucket![1].Properties;
      expect(props.ObjectLockEnabled).toBeUndefined();
      expect(props.ObjectLockConfiguration).toBeUndefined();
      expect(props.BucketEncryption.ServerSideEncryptionConfiguration[0]
        .ServerSideEncryptionByDefault.SSEAlgorithm).toBe('AES256');
    });
  });

  describe('IAM permissions', () => {
    it('grants journal archiver aidevops:ListJournalRecords and GetBacklogTask', () => {
      // @aws-cdk/aws-iam:minimizePolicies (set in cdk.json) sorts actions, so
      // assert membership rather than source order. Resources are scoped to the
      // agent space ARN — both actions take `agentspace` as a required resource
      // type, so "*" would be needlessly broad.
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Action: Match.arrayWith([
                'aidevops:GetBacklogTask',
                'aidevops:ListJournalRecords',
              ]),
              Effect: 'Allow',
              Resource: Match.not('*'),
            }),
          ]),
        },
      });
    });

    it('scopes both aidevops grants to the agent space ARN, never "*"', () => {
      const policies = template.findResources('AWS::IAM::Policy');
      const aidevopsStatements = Object.values(policies).flatMap((p: any) =>
        p.Properties.PolicyDocument.Statement.filter((s: any) => {
          const actions = Array.isArray(s.Action) ? s.Action : [s.Action];
          return actions.some((a: string) => String(a).startsWith('aidevops:'));
        }),
      );
      expect(aidevopsStatements.length).toBe(2);
      for (const s of aidevopsStatements) {
        expect(s.Resource).not.toBe('*');
        expect(JSON.stringify(s.Resource)).toContain('agentspace/');
      }
    });

    it('grants recommendations poll aidevops:ListRecommendations', () => {
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Action: Match.arrayWith(['aidevops:ListRecommendations']),
              Effect: 'Allow',
            }),
          ]),
        },
      });
    });

    it('grants recommendations poll aidevops:ListGoals, for current-vs-superseded', () => {
      // A recommendation carries no field saying whether it is still live. The
      // goal's lastSuccessfulTaskId is the only discriminator, so the poll needs
      // ListGoals or the archive is complete but undecodable on that point.
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Action: Match.arrayWith(['aidevops:ListGoals']),
              Effect: 'Allow',
            }),
          ]),
        },
      });
    });

    it('scopes the recommendations poll S3 grants to the goals/ prefix', () => {
      // Prefix scope only. The no-delete guarantee is asserted by the sibling test
      // below, which collects actions across every policy in the template.
      const policies = template.findResources('AWS::IAM::Policy');
      const resources = JSON.stringify(
        Object.values(policies).flatMap((p: any) =>
          p.Properties.PolicyDocument.Statement.map((s: any) => s.Resource),
        ),
      );
      expect(resources).toContain('goals/*');
    });

    it('grants recommendations poll S3 read (for the pre-write ETag check) but NOT delete', () => {
      // The poller HEADs/GETs existing snapshots to skip unchanged writes, so
      // it needs read. It must never delete from a tamper-evident archive.
      const policies = template.findResources('AWS::IAM::Policy');
      const actions = Object.values(policies).flatMap((p: any) =>
        p.Properties.PolicyDocument.Statement.flatMap((s: any) =>
          Array.isArray(s.Action) ? s.Action : [s.Action],
        ),
      );
      // grantRead emits `s3:GetObject*` (wildcard), not the bare action, so
      // match by prefix rather than an exact string.
      expect(actions.some((a: string) => /^s3:GetObject/.test(a))).toBe(true);
      expect(actions.some((a: string) => /^s3:DeleteObject/.test(a))).toBe(false);
    });
  });

  describe('Log retention', () => {
    it('creates explicit log groups with bounded retention (90 days) and RETAIN', () => {
      template.hasResourceProperties('AWS::Logs::LogGroup', { RetentionInDays: 90 });
      const groups = template.findResources('AWS::Logs::LogGroup');
      expect(Object.keys(groups).length).toBeGreaterThanOrEqual(3);
    });
  });
});

describe('Missing agentSpaceId', () => {
  // Reported as a synth-time error rather than thrown during app construction:
  // `cdk bootstrap`, `cdk doctor`, and `cdk context` all evaluate the app, so a
  // constructor throw makes those commands unusable without a value they do not
  // need. A synth-time error still blocks `cdk synth` and `cdk deploy`.
  it('reports a synth-time error instead of throwing at construction', () => {
    const app4 = newApp();
    const archive4 = new ArchiveStack(app4, 'NoCtxArchiveStack');
    const stack4 = new DevOpsAgentAuditTrailStack(app4, 'NoCtxTestStack', {
      agentSpaceId: '',
      archiveBucket: archive4.archiveBucket,
      acknowledgeNoAlerting: true,
    });
    Annotations.fromStack(stack4).hasError(
      '*',
      Match.stringLikeRegexp('Missing required context "agentSpaceId"'),
    );
  });

  it('reports no such error when the id is supplied', () => {
    const app5 = newApp();
    const archive5 = new ArchiveStack(app5, 'CtxArchiveStack');
    const stack5 = new DevOpsAgentAuditTrailStack(app5, 'CtxTestStack', {
      agentSpaceId: 'test-agent-space-id',
      archiveBucket: archive5.archiveBucket,
    });
    Annotations.fromStack(stack5).hasNoError('*', Match.stringLikeRegexp('agentSpaceId'));
  });
});

describe('Alert subscription', () => {
  it('subscribes the supplied email to the alert topic', () => {
    const app2 = newApp();
    const archive2 = new ArchiveStack(app2, 'SubArchiveStack');
    const stack2 = new DevOpsAgentAuditTrailStack(app2, 'SubTestStack', {
      agentSpaceId: 'test-agent-space-id',
      archiveBucket: archive2.archiveBucket,
      alertEmail: 'oncall@example.com',
    });
    Template.fromStack(stack2).hasResourceProperties('AWS::SNS::Subscription', {
      Protocol: 'email',
      Endpoint: 'oncall@example.com',
    });
  });
});

describe('Alerting enforcement', () => {
  // An unsubscribed alert topic silently disables the control-plane tripwire
  // and the journal DLQ alarm. Deploying with neither a subscription nor an
  // explicit acknowledgement must fail synth.
  it('reports a synth-time error when neither alertEmail nor acknowledgeNoAlerting is set', () => {
    const appA = newApp();
    const archiveA = new ArchiveStack(appA, 'NoAlertArchiveStack');
    const stackA = new DevOpsAgentAuditTrailStack(appA, 'NoAlertTestStack', {
      agentSpaceId: 'test-agent-space-id',
      archiveBucket: archiveA.archiveBucket,
    });
    Annotations.fromStack(stackA).hasError(
      '*',
      Match.stringLikeRegexp('No alert subscription configured'),
    );
  });

  it('does NOT error when an alertEmail is supplied', () => {
    const appB = newApp();
    const archiveB = new ArchiveStack(appB, 'EmailArchiveStack');
    const stackB = new DevOpsAgentAuditTrailStack(appB, 'EmailTestStack', {
      agentSpaceId: 'test-agent-space-id',
      archiveBucket: archiveB.archiveBucket,
      alertEmail: 'oncall@example.com',
    });
    Annotations.fromStack(stackB).hasNoError(
      '*',
      Match.stringLikeRegexp('No alert subscription configured'),
    );
  });

  it('does NOT error when the operator explicitly acknowledges no alerting', () => {
    const appC = newApp();
    const archiveC = new ArchiveStack(appC, 'AckArchiveStack');
    const stackC = new DevOpsAgentAuditTrailStack(appC, 'AckTestStack', {
      agentSpaceId: 'test-agent-space-id',
      archiveBucket: archiveC.archiveBucket,
      acknowledgeNoAlerting: true,
    });
    Annotations.fromStack(stackC).hasNoError(
      '*',
      Match.stringLikeRegexp('No alert subscription configured'),
    );
  });

  it('creates no SNS subscription when alerting is acknowledged-absent', () => {
    const appD = newApp();
    const archiveD = new ArchiveStack(appD, 'AckNoSubArchiveStack');
    const stackD = new DevOpsAgentAuditTrailStack(appD, 'AckNoSubTestStack', {
      agentSpaceId: 'test-agent-space-id',
      archiveBucket: archiveD.archiveBucket,
      acknowledgeNoAlerting: true,
    });
    Template.fromStack(stackD).resourceCountIs('AWS::SNS::Subscription', 0);
  });
});

describe('Placeholder bundling isolation', () => {
  // Regression guard. The SKIP_BUNDLING escape hatch writes a stub handler.py.
  // If that stub shares an asset hash with a real bundle, CDK reuses the staged
  // directory and a later `cdk deploy` silently ships the stub — no synth or
  // deploy error, only a runtime ImportError. Pinning a distinct custom hash
  // keeps the two artifacts in separate cdk.out/asset.<hash>/ directories.
  it('gives each skipped-bundle placeholder its own asset key', () => {
    const app3 = newApp();
    const archive3 = new ArchiveStack(app3, 'HashArchiveStack');
    const stack3 = new DevOpsAgentAuditTrailStack(app3, 'HashTestStack', {
      agentSpaceId: 'test-agent-space-id',
      archiveBucket: archive3.archiveBucket,
      acknowledgeNoAlerting: true,
    });
    const assets = Object.values(
      Template.fromStack(stack3).findResources('AWS::Lambda::Function'),
    )
      .map((fn: any) => fn.Properties.Code?.S3Key)
      .filter(Boolean);

    expect(assets.length).toBeGreaterThanOrEqual(2);
    // Distinct per asset directory, so the two Python functions never collapse
    // onto one staged artifact.
    expect(new Set(assets).size).toBe(assets.length);
  });

  it('exposes assetHash only while bundling is skipped', async () => {
    const { makeAssetOptions } = await import('../lib/bundling');
    expect(makeAssetOptions('/tmp/journal-archiver').assetHash)
      .toBe('skip-bundling-placeholder-journal-archiver');

    const saved = process.env.SKIP_BUNDLING;
    delete process.env.SKIP_BUNDLING;
    try {
      expect(makeAssetOptions('/tmp/journal-archiver').assetHash).toBeUndefined();
    } finally {
      process.env.SKIP_BUNDLING = saved;
    }
  });
});

describe('Layer 5 — Audit query layer', () => {
  const app = new cdk.App();
  const archive = new ArchiveStack(app, 'QLTestArchiveStack');
  const stack = new DevOpsAgentAuditTrailStack(app, 'QLTestStack', {
    agentSpaceId: 'test-agent-space-id',
    archiveBucket: archive.archiveBucket,
    acknowledgeNoAlerting: true,
  });
  const template = Template.fromStack(stack);

  it('creates a Glue database named devops_agent_audit', () => {
    template.hasResourceProperties('AWS::Glue::Database', {
      DatabaseInput: {
        Name: 'devops_agent_audit',
      },
    });
  });

  it('creates a journals table with partition projection enabled', () => {
    template.hasResourceProperties('AWS::Glue::Table', {
      TableInput: {
        Name: 'journals',
        TableType: 'EXTERNAL_TABLE',
        Parameters: Match.objectLike({
          'projection.enabled': 'true',
          'projection.space.type': 'enum',
          'projection.space.values': 'test-agent-space-id',
          'projection.dt.type': 'date',
          'projection.dt.format': 'yyyy-MM-dd',
        }),
      },
    });
  });

  it('creates a recommendations table over the recommendations/ prefix', () => {
    template.hasResourceProperties('AWS::Glue::Table', {
      TableInput: {
        Name: 'recommendations',
        TableType: 'EXTERNAL_TABLE',
      },
    });
  });

  it('creates a goals table carrying lastSuccessfulTaskId, so the join is possible', () => {
    // The point of this table is one join: recommendations.taskid =
    // goals.lastsuccessfultaskid tells an auditor which advice is still live.
    template.hasResourceProperties('AWS::Glue::Table', {
      TableInput: Match.objectLike({
        Name: 'goals',
        TableType: 'EXTERNAL_TABLE',
        StorageDescriptor: Match.objectLike({
          Columns: Match.arrayWith([
            Match.objectLike({ Name: 'goalid', Type: 'string' }),
            Match.objectLike({ Name: 'lastsuccessfultaskid', Type: 'string' }),
          ]),
        }),
      }),
    });
  });

  it('points the goals table at the goals/ prefix, not recommendations/', () => {
    const tables = template.findResources('AWS::Glue::Table');
    const goals = Object.values(tables).find(
      (t: any) => t.Properties.TableInput.Name === 'goals',
    ) as any;
    expect(JSON.stringify(goals.Properties.TableInput.StorageDescriptor.Location))
      .toContain('/goals/');
  });

  it('creates an Athena workgroup with SSE-S3 encryption and byte-scan limit', () => {
    template.hasResourceProperties('AWS::Athena::WorkGroup', {
      Name: 'devops-agent-audit',
      State: 'ENABLED',
      WorkGroupConfiguration: {
        ResultConfiguration: {
          EncryptionConfiguration: { EncryptionOption: 'SSE_S3' },
        },
        BytesScannedCutoffPerQuery: 10737418240,
        EnforceWorkGroupConfiguration: true,
        PublishCloudWatchMetricsEnabled: true,
      },
    });
  });

  it('creates a separate results bucket (archive bucket has Object Lock)', () => {
    // The archive bucket's Object Lock + default retention blocks Athena from
    // managing result objects. Verify the query layer has its own bucket.
    const buckets = template.findResources('AWS::S3::Bucket');
    expect(Object.keys(buckets).length).toBeGreaterThanOrEqual(1);
    // Results bucket should have a 7-day lifecycle expiry
    template.hasResourceProperties('AWS::S3::Bucket', {
      LifecycleConfiguration: {
        Rules: Match.arrayWith([
          Match.objectLike({
            ExpirationInDays: 7,
            Status: 'Enabled',
          }),
        ]),
      },
    });
  });
});
