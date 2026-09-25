#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { ArchiveStack } from '../lib/archive-stack';
import { DevOpsAgentAuditTrailStack } from '../lib/devops-agent-audit-trail-stack';

const app = new cdk.App();

// SKIP_BUNDLING exists for the test suite (no Docker/network in CI), where the
// stack is constructed directly from lib/. It must NEVER reach a real synth or
// deploy: it writes a placeholder handler, and once a placeholder is uploaded to
// the CDK assets bucket it is cached under that asset hash — CloudFormation then
// sees no diff on later deploys and the stub sticks. Fail loudly here instead.
if (process.env.SKIP_BUNDLING) {
  throw new Error(
    'SKIP_BUNDLING is set. It is for the test suite only — synthesizing or ' +
      'deploying with it would ship placeholder Lambda code. Unset it and retry.',
  );
}

// The Agent Space to audit. Pass via context:
//   cdk deploy -c agentSpaceId=<id>
// Region/account resolve from your CLI/CDK environment.
//
// Deliberately NOT a hard throw here: `cdk bootstrap`, `cdk doctor`, and
// `cdk context` all evaluate this app, so throwing during construction makes
// those commands unusable without a value they do not need. The stack reports
// the missing value as a synth-time error instead, which still blocks synth
// and deploy.
const agentSpaceId = app.node.tryGetContext('agentSpaceId');

// Object Lock enforcement (optional). Mode is IRREVERSIBLE once set on the
// bucket, so default to the safe/reversible GOVERNANCE mode.
//   cdk deploy -c objectLockMode=COMPLIANCE -c objectLockRetentionDays=2555
const objectLockMode = app.node.tryGetContext('objectLockMode');
if (objectLockMode && objectLockMode !== 'GOVERNANCE' && objectLockMode !== 'COMPLIANCE') {
  throw new Error(`Invalid objectLockMode "${objectLockMode}". Use GOVERNANCE or COMPLIANCE.`);
}
const retentionCtx = app.node.tryGetContext('objectLockRetentionDays');
const objectLockRetentionDays = retentionCtx !== undefined ? Number(retentionCtx) : undefined;
if (objectLockRetentionDays !== undefined && (!Number.isInteger(objectLockRetentionDays) || objectLockRetentionDays < 1)) {
  throw new Error(`Invalid objectLockRetentionDays "${retentionCtx}". Use a positive integer number of days.`);
}

const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION,
};

// Optional email subscribed to the alert topic (control-plane changes + the
// journal DLQ alarm). Without it, alerts fire into a topic nobody receives.
//   cdk deploy -c alertEmail=you@example.com
const alertEmail = app.node.tryGetContext('alertEmail');
if (alertEmail !== undefined && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(String(alertEmail))) {
  throw new Error(`Invalid alertEmail "${alertEmail}". Provide a single email address.`);
}

// Explicit acknowledgement that the alert topic is deliberately left without a
// subscription. Without either alertEmail or this flag, the stack fails synth.
// Accepts the CDK context convention of `true`.
//   cdk deploy -c acknowledgeNoAlerting=true
const acknowledgeNoAlertingCtx = app.node.tryGetContext('acknowledgeNoAlerting');
const acknowledgeNoAlerting =
  acknowledgeNoAlertingCtx === true || acknowledgeNoAlertingCtx === 'true';

// Stateful stack: owns the immutable archive bucket. Deployed first so the
// pipeline stack can reference the bucket. Termination-protected.
const archive = new ArchiveStack(app, 'DevOpsAgentAuditArchiveStack', {
  objectLockMode,
  objectLockRetentionDays,
  env,
  description: 'Stateful archive bucket (Object Lock) for the AWS DevOps Agent audit trail.',
});

// Stateless stack: the audit plumbing. Redeployable/destroyable without
// touching the archive.
new DevOpsAgentAuditTrailStack(app, 'DevOpsAgentAuditTrailStack', {
  agentSpaceId,
  archiveBucket: archive.archiveBucket,
  alertEmail,
  acknowledgeNoAlerting,
  env,
  description:
    'Audit trail for AWS DevOps Agent: journal archival, recommendations snapshot, lifecycle capture, and control-plane alerting.',
});
