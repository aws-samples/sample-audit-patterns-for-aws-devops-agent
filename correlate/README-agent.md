# correlate_agent — approval-to-change correlator for agent actions

Given an elevated action the DevOps Agent performed, this CLI recovers the human
approval that authorized it, and checks the executed call against what the
operator was actually shown.

This is the agent-driven counterpart to [`correlate.py`](README.md). **They are
separate engines on purpose** — see [Which one do I want?](#which-one-do-i-want).

## Why this one is deterministic

`correlate.py` has to guess: it pivots on a resource and a time window, because
for a human-made change there is no id linking the intent to the API call.

Agent actions are different. When an operator approves an elevated action, the
service stamps the approval's identity into the credential it mints:

```
aidevops:UpdateApprovalAction     responseElements.approvalId = <approvalId>
                                  requestParameters.finalPattern.argumentPins
                                        |
sts:AssumeRole                    externalId      = <approvalId>
                                  roleSessionName = op.system.apr.<approvalId-head>
                                  requestParameters.policy = scoped session policy
                                        |
<the actual API call>             userIdentity.arn = .../op.system.apr.<head>
                                  sessionContext.sourceIdentity
```

The executed call carries the approval id **inside its own principal ARN**. So
the correlation is an id join, not a heuristic: given a write you can recover the
exact approval, and given an approval you can recover the exact write. No time
window, no resource matching, no ambiguity when two changes touch one resource
in the same minute.

## Which one do I want?

|  | `correlate.py` | `correlate_agent.py` |
|---|---|---|
| Pivots on | a resource the agent named | the agent's approval identity |
| Correlation | heuristic (resource + time window) | deterministic (join on approval id) |
| Answers | "who changed this resource?" | "who approved this action, and did it match?" |
| Covers | human changes, agent-initiated changes | approval-gated agent actions (all of them) |
| Needs | CloudTrail + AWS Config | CloudTrail only |

They share no code. Take one without the other, extend either freely, and
neither can break the other. If you only care about one story, delete the other
file and its tests.

Not sure? If you have a **resource id**, start with `correlate.py`. If you have
an **approval id**, or you want to audit what the agent has been permitted to do,
start here.

## Usage

```bash
pip install -r requirements.txt

# Everything the agent was approved to do in the last 24h
python correlate_agent.py --window-hours 24

# One specific approval, with the scoped credential it minted
python correlate_agent.py --approval-id 019f0000-1111-7222-8333-444455556666 --session-policy

# "Who approved the change to this security group?"
python correlate_agent.py --resource-id sg-0abc1234 --window-hours 48

# Include the reads the approved session made, not just the writes
python correlate_agent.py --window-hours 6 --include-reads

# Raw JSON for piping into jq or a report
python correlate_agent.py --window-hours 24 --json
```

Read-only. Needs `cloudtrail:LookupEvents`.

## Output

```
Approval:       019f0000-1111-7222-8333-444455556666
  Decision:     APPROVED (recorded APPROVED)
  Approved by:  arn:aws:sts::...:assumed-role/DevOpsAgentRole-AgentSpace-.../alice
  At:           2026-08-02T21:32:32Z  from 203.0.113.10
  Single use:   True   expires 2026-08-02T22:32:32Z
  Approved call: use_aws -> ec2:ModifySecurityGroupRules
    GroupId = sg-0123456789abcdef0
    SecurityGroupRules = [{"SecurityGroupRule":{"CidrIpv4":"0.0.0.0/0","FromPort":443,...
  Session role: DevOpsAgentActionsRole-AgentSpace-...
  Credential:   900s, expires 2026-08-02T21:47:33Z
  Scoped to:    ec2:ModifySecurityGroupRules, app-integrations:TagResource (+35 more), (+ service-call passthrough)

  Executed:     ec2:ModifySecurityGroupRules  at 2026-08-02T21:32:34Z
    Principal:  arn:aws:sts::...:assumed-role/DevOpsAgentActionsRole-.../op.system.apr.019f0000-1111-72
    Via:        aidevops.amazonaws.com
    Approved values honored: PASS

  Correlation:  OK approval 019f0000-... -> session -> 1 call(s), joined on approval id
```

Two things in there are worth knowing about.

### The approval pins the call before it happens

`finalPattern.argumentPins` records the exact operation, region, and arguments
the operator was shown. The tool checks the executed call against those pins and
reports `PASS` or `MISMATCH`.

**This check is containment, one-way.** It confirms every approved value is
present in the executed call, which is what catches a call that targeted
something other than what was displayed. It does *not* prove the call carried
nothing extra, and it is not a byte-for-byte diff — the approval and the
CloudTrail event describe the same call in different shapes (the approval pins a
flat `GroupId` and a JSON-*string* rule list; EC2 logs a nested
`ModifySecurityGroupRulesRequest` with an extra positional `tag`). Comparing
structures would report a spurious mismatch on every call, so the tool compares
scalar leaf values instead. Read `PASS` as "the approved values were honored".

### The credential is scoped to the one approved action

The `AssumeRole` passes an inline session policy allowing just the approved
operation, region-pinned, for 900 seconds. The actions role may be broad; the
session handed to the agent is not.

One honest caveat: that policy also carries an `Action: "*"` statement gated on
`aws:ViaAWSService: true`. It is a service-call passthrough, not a usable grant,
and the summary labels it as such rather than listing it as if the operator had
approved wildcard access.

## Failed approvals are shown, not hidden

An approval whose response carries no `approvalId` never minted a credential, so
no call can exist. Those appear as `NOT RECORDED`:

```
Approval attempt: 2026-08-02T21:28:53Z  NOT RECORDED
  Note:         approval not recorded (no approvalId in response) — no credential
                was minted, so no call can exist
```

Keeping them is deliberate. A run of these next to one success is exactly what an
operator retrying a broken approval looks like, and dropping them would make the
trail read as if the successful attempt were the only one. It also distinguishes
two states a naive tool conflates:

- **NOT RECORDED** — the approval never took effect. Nothing could have run.
- **recorded, but no call found** — the approval succeeded and nothing ran. The
  agent errored, or the resume was lost. Worth investigating.

## Performance note

The tool starts from `UpdateApprovalAction`, which is low-volume even in a busy
account, and follows indexed lookups from there. It resolves `AssumeRole` events
only when needed, and indexes them **once per run** rather than once per
approval — `AssumeRole` is among the highest-volume events in any active account,
and rescanning it per approval turns a ten-approval window into minutes. There is
a regression test covering that.

## Limitations

- **Approval-gated actions only.** Every elevated action the agent takes is
  operator-approved, so this covers all agent writes rather than a subset. Should
  a path ever execute without an approval, there would be no approval record to
  join to; use `correlate.py` for that case, where the `agentInitiated` flag
  detects agent-made calls without needing an approval.
- **CloudTrail lookup is ~15 minutes behind live** and retains 90 days. For older
  or bulk analysis, query the CloudTrail S3 data with Athena using the same join
  keys (`externalId`, `roleSessionName`).
- **The session-name convention is observed, not contractual.** `op.system.apr.`
  and the head length come from live events. The tool derives a candidate name
  first and falls back to the authoritative `externalId` join if that finds
  nothing, so a change in the convention degrades to a slower correct answer
  rather than a wrong one.
