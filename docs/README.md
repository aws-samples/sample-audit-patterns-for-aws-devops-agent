# Diagrams

## Audit Trail for AWS DevOps Agent.png

Architecture diagram drawn with the official AWS Architecture Icons. It shows both flows:

- **Always-on capture (the two CDK stacks)** — the five layers that continuously record agent activity, writing to the Object-Lock archive bucket owned by the stateful `DevOpsAgentAuditArchiveStack`:
  - Layer 1: lifecycle events → EventBridge → CloudWatch Logs
  - Layer 2: terminal events → EventBridge → Lambda (`journal-archiver`) → S3, with a DLQ and alarm on the rule's target
  - Layer 3: EventBridge Scheduler → Lambda (`recommendations-poll`) → S3
  - Layer 4: CloudTrail → EventBridge rule (`source: aws.aidevops`, `eventSource: aidevops.amazonaws.com`) → SNS
  - Layer 5: Glue Data Catalog + Athena workgroup over the archive
- **On-demand correlation** — two independent CLIs drive the loop from the agent's own archived output:
  - `correlate.py` (human-made changes, heuristic): forward, an archived recommendation → the resource it names → the AWS Config change → the CloudTrail write event (who/when); backward, an archived finding → prior recommendations naming the same resource → the last CloudTrail change to it. AWS Config resolves the resource, its history, and compliance state; CloudTrail supplies attribution.
  - `correlate_agent.py` (agent-made changes, deterministic): joins each executed call to the approval that authorized it, on the approval id carried in the session name. Reads CloudTrail only.

Note that Layer 4 alerts via an **EventBridge rule** matching CloudTrail events, not by wiring CloudTrail to SNS directly. DevOps Agent CloudTrail events arrive under `source: aws.aidevops`, not `aws.cloudtrail` — see `lib/constructs/control-plane-alerting.ts`.
