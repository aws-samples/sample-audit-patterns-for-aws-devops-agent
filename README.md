# Audit patterns for AWS DevOps Agent

A CDK (TypeScript) app that captures the operational trail of [AWS DevOps Agent](https://docs.aws.amazon.com/devopsagent/) so you can audit what the agent investigated, what it concluded, what it recommended, and who changed its configuration.

> **Sample code.** This project is published as an educational sample to accompany a blog post. It is **not** intended for production use as-is, and it is provided without support or warranty. Review it against your own security, compliance, and operational requirements, and perform your own security testing, before deploying it to any environment you care about. See [LICENSE](LICENSE).

It deploys five layers:

| Layer | Captures | Mechanism |
|---|---|---|
| **1. Lifecycle** | Every investigation/mitigation state change | EventBridge rule (`source: aws.aidevops`) → CloudWatch Logs |
| **2. Journal** | Per-incident reasoning + findings, including approved mitigations | EventBridge (terminal events) → Lambda → S3 |
| **3. Recommendations** | Cross-incident prevention advice, versioned (proactive), plus the goal snapshot that dates it | EventBridge Scheduler → Lambda poll → S3 |
| **4. Control plane** | Mutating changes to the agent itself | EventBridge (CloudTrail `aidevops.amazonaws.com`) → SNS |
| **5. Query** | SQL over the archived journals, recommendations, and goals | Glue Data Catalog tables + Athena workgroup |

> **Why not just CloudTrail?** CloudTrail records who *invoked* the agent, but not the metric/log reads the agent performs while investigating. The behavioral record lives in the **agent journal**, retrieved via API. This stack captures it.

## Architecture

![Five capture layers for AWS DevOps Agent: lifecycle events to CloudWatch Logs, terminal events to a Lambda that archives journals to S3 with a dead-letter queue, a scheduled poll for recommendations, control-plane mutations to an SNS topic via an EventBridge rule, and a Glue/Athena query layer. Two operator CLIs read the trail.](docs/Audit%20Trail%20for%20AWS%20DevOps%20Agent.png)

```
  aws.aidevops (lifecycle) ─┬─▶ EventBridge rule ─▶ CloudWatch Logs        (Layer 1)
                            └─▶ EventBridge rule ─▶ Lambda ─▶ S3           (Layer 2, terminal events)
                                                   └─▶ SQS DLQ ─▶ alarm ─▶ SNS
  EventBridge Scheduler ──────▶ Lambda ─▶ list-recommendations ─▶ S3       (Layer 3, daily poll)
                                       └▶ list-goals ───────────▶ S3       (Layer 3, same poll)
  CloudTrail aidevops.* ──────▶ EventBridge rule ─▶ SNS                    (Layer 4, mutations)
  S3 archive ─────────────────▶ Glue Data Catalog ─▶ Athena workgroup      (Layer 5, SQL)
```

The journal, recommendations, and goals land in one versioned, Object-Lock S3 bucket (`journals/…`, `recommendations/…`, `goals/…`), owned by a separate stateful stack (see [Deploy](#deploy)).

> **Decide who can read the archive.** Journals hold more than metadata: they carry the agent's reasoning, its tool output, and an inventory of the account resources it enumerated while investigating. Treat the archive as sensitive. This sample ships no reader role. The Lambda grants it does create are scoped per prefix, but operators, Athena users, and the `correlate/` CLIs read the archive with whatever their own IAM already allows, which in practice is the whole bucket. Decide deliberately who needs that, and consider adding a least-privilege read role that separates `journals/` from `recommendations/` and `goals/`.

## Prerequisites

- An existing DevOps Agent **Agent Space** (note its ID and hosting Region).
- AWS CDK v2 and Node.js 22.12+ (the test toolchain requires it; older 22.x fails to load rolldown's native binding).
- Credentials for the account/Region hosting the Agent Space.
- An organization or account **CloudTrail** enabled (required for Layer 4).
- Either **Docker** or a local **pip3** for Lambda bundling (the app prefers local pip3, falls back to Docker). Bundling installs a recent `boto3` so the `devops-agent` client is present regardless of the Lambda runtime's SDK version.

## Deploy

The app synthesizes **two stacks**:

- **`DevOpsAgentAuditArchiveStack`** — stateful. Owns the versioned, Object-Lock archive bucket and has **termination protection** enabled. Object Lock default retention is `GOVERNANCE`/365 days (see below to change it).
- **`DevOpsAgentAuditTrailStack`** — stateless. The audit plumbing (the capture and query layers). It references the archive bucket and can be redeployed or destroyed without touching the archive.

```bash
npm install
npx cdk bootstrap          # first time in the account/Region
npx cdk deploy --all -c agentSpaceId=<your-agent-space-id> -c alertEmail=you@example.com
```

`alertEmail` subscribes an address to the stack's alert topic, which carries **both** control-plane changes (Layer 4) and audit-pipeline failures (the journal DLQ alarm). It is **required**: an unsubscribed topic silently disables both, so `cdk synth` and `cdk deploy` fail unless you either supply an address or explicitly acknowledge the gap with `-c acknowledgeNoAlerting=true`. Use that acknowledgement only if you subscribe to the topic out of band. AWS sends a confirmation email you must accept. The `AlertSubscriptionConfigured` stack output tells you whether a subscription was created.

Optional: change the recommendations poll cadence (default `rate(1 day)`):

```bash
npx cdk deploy --all -c agentSpaceId=<id> -c recommendationPollSchedule="rate(12 hours)"
```

Optional: set the archive bucket's Object Lock default retention. Mode is **IRREVERSIBLE** once set, so it defaults to the safe/reversible `GOVERNANCE`:

```bash
npx cdk deploy --all -c agentSpaceId=<id> \
  -c objectLockMode=COMPLIANCE -c objectLockRetentionDays=2555
```

If you deployed with `-c acknowledgeNoAlerting=true`, subscribe to the alert SNS topic yourself (ARN is in the stack outputs) — otherwise control-plane changes and DLQ alarms go unreceived.

## Verify

The pipeline captures investigations as they happen. For testing, you don't have
to wait for an alarm — you can trigger an on-demand investigation:

```bash
aws devops-agent create-backlog-task \
  --agent-space-id <your-agent-space-id> \
  --task-type INVESTIGATION \
  --priority LOW \
  --title "audit-trail verification" \
  --description "Investigate recent CloudWatch alarm state changes in this account over the last 24 hours."
```

The investigation typically completes within the hour; when it reaches a terminal
state, Layer 2 archives the journal automatically. Then confirm capture:

```bash
# Lifecycle events (Layer 1)
aws logs filter-log-events --log-group-name /devops-agent/aidevops-lifecycle \
  --query 'events[].message' --output text

# Journal archive (Layer 2)
aws s3 ls s3://<ArchiveBucketName>/journals/ --recursive

# Recommendations (Layer 3) — after a poll runs, or invoke the function manually
aws s3 ls s3://<ArchiveBucketName>/recommendations/ --recursive

# Goals (Layer 3, same poll) — lastSuccessfulTaskId is what dates the advice
aws s3 ls s3://<ArchiveBucketName>/goals/ --recursive
```

## Sample integrations: correlate a change back to its cause

The archive is more than storage — it is queryable evidence. [`correlate/`](correlate/)
ships **two independent CLIs**, one per kind of change. They share no code, so
adapt or delete either without touching the other.

### Human-made changes — [`correlate.py`](correlate/README.md)

Pivots on a resource the agent named and correlates it to the real change plus
its compliance state. Heuristic by necessity: for a human change there is no id
linking intent to API call, so it matches on resource identity + time window.

```bash
cd correlate && pip install -r requirements.txt

# Forward: did anyone act on a recommendation? Config change + CloudTrail attribution.
python correlate.py --archive-bucket <ArchiveBucketName> \
  --recommendation <recommendationId> --window-hours 24

# Backward: is a new finding a consequence of a prior recommendation on the same
# resource? Ends with the last CloudTrail write event (who changed it, and when).
python correlate.py --archive-bucket <ArchiveBucketName> \
  --finding <executionId> --check-prior-recommendations
```

Both modes also read the provenance a recommendation carries about itself, which the resource-identity heuristic cannot reach. `affected_incidents` names the investigations behind the advice by backlog task id — the same id an archived journal stores as `task_id` — so that hop is an exact join rather than a time-window guess, and references with no journal in the archive are reported as such instead of dropped. Advice the agent re-created on later runs is collapsed into one entry by its provenance group, with the other `recommendationId`s named and the range of runs it spans, so week-over-week repetition of one finding stops reading as several independent findings.

### Agent-made changes — [`correlate_agent.py`](correlate/README-agent.md)

Pivots on the agent's approval identity. **Deterministic**: when an operator
approves an elevated action, the service stamps the approval id into the STS
session it mints, so the executed call carries that id in its own principal ARN.
Correlation is an id join, not a time-window guess.

```bash
# What has the agent been approved to do, and did the calls match?
python correlate_agent.py --window-hours 24

# Who approved the change to this resource?
python correlate_agent.py --resource-id sg-0abc1234 --window-hours 48

# One approval, plus the scoped-down credential it minted
python correlate_agent.py --approval-id <approvalId> --session-policy
```

It also checks each executed call against the arguments pinned in the approval,
so you can see whether what ran matched what the operator was shown. That check
is one-way containment, not a byte-for-byte diff — the README explains why.

Both are read-only. `correlate.py` needs CloudTrail + AWS Config; `correlate_agent.py`
needs only `cloudtrail:LookupEvents`.

## Notes and limitations

- **Regional / per-account.** DevOps Agent events land on the default bus in the Agent Space's hosting account and Region. Deploy this stack there. To centralize across accounts, forward each default bus to a central bus (standard cross-account EventBridge).
- **Recommendations are polled, not evented.** There is no EventBridge event for recommendations; they are generated on the goal cadence, so Layer 3 polls the API and keys S3 objects on `recommendationId` + `version` so status changes are preserved rather than overwritten. `recommendationId` is not stable across evaluation runs — each run creates new records, so one piece of advice repeated over time appears under several ids.
- **The API returns superseded recommendations, so Layer 3 snapshots the goal too.** Each evaluation run creates new records and leaves the previous run's behind, so `ListRecommendations` mixes current with superseded advice and no field on a recommendation says which it is. The only discriminator is the owning goal's `lastSuccessfulTaskId`, so the poll snapshots goals alongside recommendations and Layer 5 exposes them as a `goals` table. Joining the two sorts the archive out: `SELECT r.recommendationid, r.title FROM recommendations r JOIN goals g ON r.goalid = g.goalid WHERE r.taskid = g.lastsuccessfultaskid`. Note that the `recommendations` table is one row per snapshot, so a recommendation with two versions appears twice — add a version filter if you want one row per recommendation. The join also cannot rescue a recommendation with a null `goalid`: a different producer writes those, and they stay archived and queryable but cannot be dated against a goal.
- **IAM actions use the `aidevops:` prefix**, not `devops-agent:` — the latter is only the AWS CLI/SDK service name. The Lambda policies are scoped to the configured Agent Space ARN (`arn:aws:aidevops:<region>:<account>:agentspace/<id>`), since `ListJournalRecords`, `GetBacklogTask`, `ListRecommendations`, and `ListGoals` all take `agentspace` as a required resource type.
- **The agent's action boundary is its IAM role.** This stack observes; it does not gate the agent. Control the agent's capabilities through its execution-role policy.

## Cleanup

Destroy only the stateless pipeline stack — this leaves the archive untouched:

```bash
npx cdk destroy DevOpsAgentAuditTrailStack
```

The S3 archive bucket and CloudWatch log groups use `RETAIN`, so even destroying the pipeline stack leaves the audit record in place.

`DevOpsAgentAuditArchiveStack` has **termination protection** enabled and must be handled deliberately. To remove the archive you must first disable termination protection, then destroy the stack — and the bucket itself still uses `RETAIN` (and may hold Object-Lock–protected objects that cannot be deleted until their retention expires), so it is not removed automatically. Do this only when you are certain you no longer need the audit data.

## License

MIT-0. See [LICENSE](LICENSE).
