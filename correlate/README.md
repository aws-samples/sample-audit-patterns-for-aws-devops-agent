# correlate — DevOps Agent finding-to-change correlator

> **Two engines live here.** This one (`correlate.py`) pivots on a **resource** and
> correlates heuristically — use it for human-made changes, or when all you have is
> a resource id. Its sibling
> [`correlate_agent.py`](README-agent.md) pivots on the agent's **approval identity**
> and correlates deterministically — use it for changes the agent made through the
> approval flow. They share no code, so take either or both.

Given a resource identified by the DevOps Agent (via the journal or a recommendation), this CLI tool closes the loop by finding:

1. The **canonical identity** of the resource (via AWS Config `select-resource-config`)
2. The **configuration-item history** — what Config recorded as the before/after state
3. The **compliance state** — which Config rules evaluated the resource, and whether it's currently COMPLIANT or NON_COMPLIANT
4. The **correlated CloudTrail write event** — who changed what, when, from where

## Why not just scan CloudTrail?

In a production account, hundreds of changes happen concurrently. Scanning the whole window yields noise. Instead we **pivot on the specific resource the agent named** — the agent's output is the index into the change history.

## The extensibility seam: per-resource-type strategies

CloudTrail does not index resources uniformly, so correlation needs a small
registry that declares *how* each type is indexed. This is the one extension
point — **to support a new resource type, add an entry to `RESOURCE_STRATEGIES`
in `correlate.py`. There is no other code to change.**

Three lookup modes:

| Mode | Meaning | Example types |
|---|---|---|
| `"name"` | The short name/id IS the CloudTrail `ResourceName` | S3 (bucket name), Lambda (function name), EC2 security group |
| `"arn"` | CloudTrail indexes the **full ARN**, not the short name; the tool builds the ARN from `arn_template` | RDS DB instance, RDS cluster |
| `None` | Type is **not** indexed by `ResourceName`; scan by `ResourceType`, then confirm the id matches one of the strategy's declared `id_in_request` keys in `requestParameters` | (fallback for unindexed types) |

A strategy can also set `scan_fallback: true`: the primary `name`/`arn` lookup
runs first, and only if it returns zero events does the tool re-run the
`ResourceType` scan+filter path. This hedges against regional or historical
gaps in CloudTrail's `ResourceName` index.

Scan paths use **precise key matching**, not a substring scan of the whole
payload: the resource id must be the value (or a list element) of one of the
keys in `id_in_request`. This avoids false positives where the id appears
inside an unrelated field — the matcher picks up
`AuthorizeSecurityGroupIngress` (id under `groupId`) and ignores generic
`CreateTags` noise (id nested under `resourcesSet`).

| Resource Type | Mode | Notes |
|---|---|---|
| `AWS::S3::Bucket` | `name` | Bucket name indexes cleanly |
| `AWS::Lambda::Function` | `name` | Function name works (may include AssumeRole noise) |
| `AWS::RDS::DBInstance` | `arn` | `arn:aws:rds:{region}:{account}:db:{name}` — the DB identifier and DbiResourceId do **not** index; only the full ARN does |
| `AWS::RDS::DBCluster` | `arn` | `arn:aws:rds:{region}:{account}:cluster:{name}` |
| `AWS::EC2::SecurityGroup` | `name` + `scan_fallback` | SG id as `ResourceName`, with the `groupId` scan as a fallback |

### Adding a new type

```python
RESOURCE_STRATEGIES["AWS::DynamoDB::Table"] = {
    "lookup": "name",                 # or "arn" with an arn_template, or None
    "id_in_request": ["tableName"],   # keys that carry the id in requestParameters
}
```

The RDS case is why the registry exists: "just use the resource name as
ResourceName" (which works for S3 and Lambda) silently returns zero events for
RDS, because CloudTrail only indexes RDS by full ARN.

## Usage

```bash
pip install -r requirements.txt

# Correlate a specific resource
python correlate.py \
  --resource-id amzn-s3-demo-bucket \
  --resource-type AWS::S3::Bucket \
  --window-hours 2

# Use resource name instead of ID
python correlate.py \
  --resource-name my-function \
  --resource-type AWS::Lambda::Function \
  --window-hours 24

# RDS — pass the DB identifier; the tool resolves it and builds the ARN
python correlate.py \
  --resource-name example-mariadb \
  --resource-type AWS::RDS::DBInstance \
  --window-hours 1

# Center on a specific incident time
python correlate.py \
  --resource-id sg-0abc1234 \
  --resource-type AWS::EC2::SecurityGroup \
  --incident-time 2026-07-01T14:00:00Z \
  --window-hours 4
```

## Archive-aware modes (drive the tool from the agent's own output)

These modes read the S3 audit archive so you pass a recommendation or finding
id instead of a resource. Requires `--archive-bucket <ArchiveBucketName>` (from
the CDK stack outputs).

    # Forward: recommendation -> real change -> who applied it
    python correlate.py --archive-bucket $BUCKET --recommendation rec-abc123 --window-hours 24

    # Backward: is this finding a consequence of a prior recommendation?
    python correlate.py --archive-bucket $BUCKET --finding exe-def456 --check-prior-recommendations

The two loop-closing modes (`--recommendation`, and `--finding
--check-prior-recommendations`) print a formatted text summary. The backward view
closes the loop with identity: it ends with the last CloudTrail write event on the
resource (event, principal, source IP, time), so you see who applied the change
without a second forward command. Because of that attribution step,
`--check-prior-recommendations` is no longer S3-only: it also calls AWS Config and
CloudTrail (read-only), so the credentials need those permissions too. `--finding`
*without* `--check-prior-recommendations` instead runs the resource through the
standard correlation and emits the raw correlation JSON (same shape as the
`--resource-id` path).

### How the resource is extracted (heuristic)

The tool pulls resource identifiers from the archived recommendation/finding by
(1) checking structured fields (`resourceId`, `resourceArn`, ...) and
(2) regex-scanning text for EC2-style ids (`sg-`, `i-`, ...) and ARNs — including
text buried in double-encoded JSON (`content.summary` / journal record `content`).
Refs with an inferrable Config type sort first, so the primary correlation target
is the most-correlatable id found. This is heuristic by design — consistent with
the correlation itself being heuristic (resource identity + time window, not a
guaranteed causal link). If a resource cannot be extracted, the tool says so and
you fall back to `--resource-id`.

## Output

JSON with four sections:
- `resolved` — canonical resource identity from Config
- `config_history` — configuration-item captures in the window
- `compliance` — all Config rules evaluating this resource and their current state
- `correlated_changes` — CloudTrail write events touching the resource in the window

Each entry in `correlated_changes` includes an `agentInitiated` boolean. When `true`,
the call was made by AWS DevOps Agent rather than directly by a human operator —
detected via `invokedBy: aidevops.amazonaws.com` in the CloudTrail event's
`userIdentity`. The formatted output modes display this as an "Actor" line when
present.

Note the flag means "the agent made this call," not "the agent acted unapproved."
Elevated actions are always operator-approved, and an approved call still carries
`aidevops.amazonaws.com`, so it sets this flag too. To see the approving operator
and whether the executed call matched what they were shown, use `correlate_agent.py`.

## Limitations

- Config's `relatedEvents` field (the old deterministic CloudTrail link) is no longer populated. Correlation is heuristic: resource identity + time window.
- Config capture lag is minutes — this is retrospective audit, not real-time alerting.
- Some resource types expose identity only in CloudTrail `requestParameters`. Common ones are handled; uncommon services may need an added strategy entry.
