#!/usr/bin/env python3
"""Correlate an AWS DevOps Agent *elevated action* to the human approval that
authorized it.

This is the agent-driven counterpart to `correlate.py`. The two are deliberately
separate engines because they pivot on different things and offer different
guarantees:

    correlate.py        pivots on a RESOURCE the agent named, and correlates
                        heuristically (resource identity + time window). Use it
                        for human-made changes, or when all you have is a
                        resource id.

    correlate_agent.py  pivots on the AGENT'S OWN APPROVAL IDENTITY, and
                        correlates DETERMINISTICALLY (an id join). Use it for
                        changes the agent made through the approval flow.

Pick whichever matches your question; they share no code, so you can take one
without the other, and extending one cannot break the other.

Why this one is deterministic
-----------------------------
When an operator approves an elevated action, the service mints a short-lived,
scoped-down credential and stamps the approval's identity into the STS session:

    aidevops:UpdateApprovalAction   responseElements.approvalId = <approvalId>
                                    requestParameters.finalPattern.argumentPins
                                             |
    sts:AssumeRole                  externalId       = <approvalId>
                                    roleSessionName  = <prefix><approvalId-head>
                                    requestParameters.policy = scoped session policy
                                             |
    <the actual API call>           userIdentity.arn = .../<roleSessionName>
                                    userIdentity.sessionContext.sourceIdentity

So the executed call carries the approval id inside its own principal ARN. No
time-window guessing and no resource matching: given a write event you can
recover the exact approval, and given an approval you can recover the exact
write. That is a stronger primitive than anything available for human changes,
where `correlate.py`'s heuristics are the best you can do.

What this proves, and what it does not
--------------------------------------
The approval record pins the intended call in `finalPattern.argumentPins`, so
the tool can check the executed call against what was approved. That check is
**containment, one-way**: it confirms every approved value is present in the
executed call. It does not prove the executed call added nothing beyond the
pinned arguments, and it is not a byte-for-byte diff — the approval and the
CloudTrail event use different argument shapes for the same call (see
`_pins_satisfied`). Treat a PASS as "the approved values were honored", not as
"the call was provably identical".

Limitations
-----------
    - Approval-gated actions only. Every elevated action the agent takes is
      operator-approved, so in practice this covers all agent writes. Should a
      path ever execute without an approval, there would be no approval record
      to join to; use `correlate.py` for that case (its `agentInitiated` flag
      detects agent-made calls without needing an approval).
    - CloudTrail lookup is ~15 minutes behind live and retains 90 days. For
      older or bulk analysis, query the CloudTrail S3 data with Athena using the
      same join keys.
    - The session-name prefix (`op.system.apr.`) and the head-truncation length
      are observed, not contractual. The tool derives a candidate name and, if
      that finds nothing, discovers the real one by indexing AssumeRole events on
      `externalId` — so a change in either does not silently return "no writes".
    - Both engines read CloudTrail; this one does not need AWS Config, so it
      works on resource types Config does not track.
"""
import argparse
import json
import sys
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError


# The approval event. This is the one indexed lookup that starts everything:
# it is cheap, it is low-volume even in a busy account, and every elevated
# action must produce one.
APPROVAL_EVENT_NAME = "UpdateApprovalAction"
AGENT_SERVICE_PRINCIPAL = "aidevops.amazonaws.com"

# Observed session-name prefix for an approval-minted session, and the number of
# approvalId characters retained after it. Both are derived from live events,
# NOT from a documented contract, which is why `resolve_session_name` treats a
# miss as "go ask the AssumeRole event" rather than "no writes exist".
SESSION_NAME_PREFIX = "op.system.apr."
SESSION_ID_HEAD_LEN = 16

# Pins that are metadata about the call rather than arguments to it, and so are
# checked against the event's own envelope instead of its requestParameters.
_ENVELOPE_PINS = {"operation", "region"}


def _cloudtrail(region):
    return boto3.client("cloudtrail", region_name=region)


# ---------------------------------------------------------------------------
# Step 1 — enumerate approvals.
# ---------------------------------------------------------------------------

def find_approvals(ct, window, approval_id=None):
    """Return the approval decisions recorded in the window, newest first.

    Each entry carries the decision, who made it, and the argument pins that
    constrain what the agent was then allowed to run.

    An approval whose `responseElements` is absent is a FAILED attempt: the
    console recorded the click but the service returned no approvalId, so no
    credential was ever minted and no write can exist. Those are kept and
    flagged (`recorded=False`) rather than dropped — a run of them next to one
    success is exactly what an operator retrying a broken approval looks like,
    and hiding it would misrepresent the trail.
    """
    approvals = []
    for ce in _lookup(ct, [{"AttributeKey": "EventName",
                            "AttributeValue": APPROVAL_EVENT_NAME}], window):
        rp = ce.get("requestParameters") or {}
        re_ = ce.get("responseElements") or {}
        recorded_id = re_.get("approvalId")
        if approval_id and recorded_id != approval_id:
            continue
        pattern = rp.get("finalPattern") or {}
        identity = ce.get("userIdentity") or {}
        approvals.append({
            "approvalId": recorded_id,
            "recorded": bool(recorded_id),
            "decision": rp.get("action"),
            "status": re_.get("status"),
            "singleUse": rp.get("singleUse"),
            "expiresAt": _epoch_to_iso(re_.get("expiresAt")),
            "approvedAt": ce.get("eventTime"),
            "approvedBy": identity.get("arn", ""),
            "sourceIP": ce.get("sourceIPAddress", ""),
            "userAgent": ce.get("userAgent", ""),
            "tool": pattern.get("tool"),
            "argumentPins": pattern.get("argumentPins") or {},
            "agentSpace": _first_arn_of_type(ce.get("resources"), "AgentSpace"),
        })
    approvals.sort(key=lambda a: a["approvedAt"] or "", reverse=True)
    return approvals


# ---------------------------------------------------------------------------
# Step 2 — resolve the approval to the STS session it minted.
# ---------------------------------------------------------------------------

def derive_session_name(approval_id):
    """Best-guess session name for an approval, from the observed convention."""
    return f"{SESSION_NAME_PREFIX}{approval_id[:SESSION_ID_HEAD_LEN]}"


def index_approval_sessions(ct, window):
    """Index every approval-minted STS session in the window by approval id.

    ONE pass over the window's AssumeRole events, not one pass per approval.
    That distinction matters: `AssumeRole` is among the highest-volume events in
    any active account (every service-linked role, every console refresh), so
    scanning it per approval turns a 10-approval window into ten full scans and
    the tool takes minutes. Callers build this once and look up by id.

    Keyed on `externalId`, which carries the FULL approvalId — the session name
    carries only a head, so the id is the safe join key and cannot alias between
    two approvals. Also captures the scoped session policy, which is the part an
    auditor actually wants: it shows how narrow the credential was.
    """
    index = {}
    for ce in _lookup(ct, [{"AttributeKey": "EventName", "AttributeValue": "AssumeRole"}], window):
        rp = ce.get("requestParameters") or {}
        external_id = rp.get("externalId")
        if not external_id or not rp.get("roleSessionName", "").startswith(SESSION_NAME_PREFIX):
            continue
        re_ = ce.get("responseElements") or {}
        index[external_id] = {
            "sessionName": rp.get("roleSessionName"),
            "roleArn": rp.get("roleArn"),
            "durationSeconds": rp.get("durationSeconds"),
            "sessionPolicy": _parse_policy(rp.get("policy")),
            "assumedAt": ce.get("eventTime"),
            "credentialExpires": ((re_.get("credentials") or {}).get("expiration")),
        }
    return index


# ---------------------------------------------------------------------------
# Step 3 — find what that session actually did.
# ---------------------------------------------------------------------------

def find_session_calls(ct, session_name, window):
    """Every call made by an approval-minted session, oldest first.

    CloudTrail indexes sessions by Username, so this is a single indexed lookup
    rather than a scan. Read-only calls are kept: a session that read before it
    wrote is part of the record, and callers filter if they only want mutations.
    """
    calls = []
    for ce in _lookup(ct, [{"AttributeKey": "Username", "AttributeValue": session_name}], window):
        identity = ce.get("userIdentity") or {}
        session_ctx = identity.get("sessionContext") or {}
        calls.append({
            "eventTime": ce.get("eventTime"),
            "eventName": ce.get("eventName"),
            "eventSource": ce.get("eventSource"),
            "operation": _operation_of(ce),
            "eventId": ce.get("eventID"),
            "region": ce.get("awsRegion"),
            "readOnly": ce.get("readOnly"),
            "errorCode": ce.get("errorCode"),
            "principal": identity.get("arn", ""),
            "sourceIdentity": session_ctx.get("sourceIdentity"),
            "invokedBy": identity.get("invokedBy", ""),
            "requestParameters": ce.get("requestParameters") or {},
        })
    calls.sort(key=lambda c: c["eventTime"] or "")
    return calls


# ---------------------------------------------------------------------------
# Step 4 — check the executed call against what was approved.
# ---------------------------------------------------------------------------

def _leaf_values(value, depth=0):
    """Every scalar leaf in a value, unwrapping strings that are themselves JSON.

    The approval pins some arguments as JSON STRINGS (a pinned
    `SecurityGroupRules` arrives as `'[{"SecurityGroupRule": {...}}]'`), so a
    plain equality test against the event's parsed requestParameters always
    fails. Comparing leaf sets sidesteps the shape difference.
    """
    if depth > 8:
        return set()
    out = set()
    if isinstance(value, str):
        s = value.strip()
        if s and s[0] in "{[":
            try:
                return _leaf_values(json.loads(s), depth + 1)
            except (ValueError, TypeError):
                pass
        out.add(s)
    elif isinstance(value, bool):
        out.add(str(value).lower())
    elif isinstance(value, (int, float)):
        out.add(str(value))
    elif isinstance(value, dict):
        for v in value.values():
            out |= _leaf_values(v, depth + 1)
    elif isinstance(value, list):
        for v in value:
            out |= _leaf_values(v, depth + 1)
    return out


def _pins_satisfied(pins, call):
    """Check each approved pin against the executed call.

    The approval and the CloudTrail event describe the same call in DIFFERENT
    shapes, so this is not a diff. For the security-group case the approval pins
    a flat `GroupId` plus a JSON-string rule list, while EC2 logs a nested
    `ModifySecurityGroupRulesRequest` that also carries fields the approval never
    mentioned (a positional `tag`). Comparing structures would report a spurious
    mismatch on every call.

    So: `operation` and `region` are checked against the event's envelope, and
    every other pin is checked by leaf-value containment — each scalar the
    operator approved must appear somewhere in the executed request.

    This direction is the one that matters for an approval gate: it catches a
    call that targeted something other than what was shown to the operator. It
    does NOT prove the call carried nothing extra, so `verified` is reported as
    a containment result and named accordingly.
    """
    actual_leaves = _leaf_values(call.get("requestParameters") or {})
    checks = []
    for key, pinned in sorted(pins.items()):
        if key == "operation":
            ok = pinned == call.get("operation")
            checks.append({"pin": key, "approved": pinned,
                           "executed": call.get("operation"), "match": ok})
        elif key == "region":
            ok = pinned == call.get("region")
            checks.append({"pin": key, "approved": pinned,
                           "executed": call.get("region"), "match": ok})
        else:
            wanted = _leaf_values(pinned)
            missing = sorted(wanted - actual_leaves)
            checks.append({"pin": key, "approved": pinned,
                           "missing": missing, "match": not missing})
    return checks


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------

def correlate_agent_actions(region, window_hours, approval_id=None, resource_id=None,
                            writes_only=True, include_session_policy=False,
                            end_time=None):
    """Join approvals to the calls they authorized.

    Walks approval -> session -> calls -> pin check for each approval in the
    window. `resource_id` filters to approvals or calls that mention the id, so
    an operator asking "who approved the change to sg-abc" gets only that.
    """
    ct = _cloudtrail(region)
    end = _parse_time(end_time) if end_time else datetime.now(timezone.utc)
    window = (end - timedelta(hours=window_hours), end)

    approvals = find_approvals(ct, window, approval_id=approval_id)

    # Build the session index at most once, and only when it is actually needed:
    # either the caller asked for session policies, or a derived session name
    # found no calls and we need the authoritative name. Deferred because the
    # AssumeRole scan is the single most expensive call this tool makes.
    session_index = None

    def _sessions():
        nonlocal session_index
        if session_index is None:
            session_index = index_approval_sessions(ct, window)
        return session_index

    if include_session_policy and any(a["recorded"] for a in approvals):
        _sessions()

    results = []
    for approval in approvals:
        entry = dict(approval)
        entry["calls"] = []
        entry["session"] = None

        if not approval["recorded"]:
            # No approvalId means no credential was minted. Say so explicitly
            # rather than reporting an empty call list, which reads like a
            # successful approval that happened to do nothing.
            entry["note"] = ("approval not recorded (no approvalId in response) — "
                             "no credential was minted, so no call can exist")
            results.append(entry)
            continue

        session_name = derive_session_name(approval["approvalId"])
        detail = (session_index or {}).get(approval["approvalId"])
        calls = find_session_calls(ct, session_name, window)

        if not calls:
            # The derived name found nothing. Either the convention changed, or
            # the approval genuinely never ran. Consult the authoritative index
            # before concluding the latter.
            detail = _sessions().get(approval["approvalId"]) or detail
            if detail and detail.get("sessionName") and detail["sessionName"] != session_name:
                session_name = detail["sessionName"]
                calls = find_session_calls(ct, session_name, window)

        if writes_only:
            calls = [c for c in calls if c.get("readOnly") is False]

        for call in calls:
            call["approvalChecks"] = _pins_satisfied(approval["argumentPins"], call)
            call["approvedValuesHonored"] = all(c["match"] for c in call["approvalChecks"])
            call["viaAgentService"] = AGENT_SERVICE_PRINCIPAL in (call.get("invokedBy") or "")

        entry["sessionName"] = session_name
        entry["session"] = detail
        entry["calls"] = calls
        results.append(entry)

    if resource_id:
        results = [r for r in results if _mentions(r, resource_id)]
    return {"region": region, "window": [str(window[0]), str(window[1])],
            "approvals": results}


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def format_agent_correlation(result):
    """Render the approval-to-change chain as a readable audit summary."""
    approvals = result.get("approvals") or []
    if not approvals:
        return ("No agent approval activity found in "
                f"{result['window'][0]} .. {result['window'][1]}")

    lines = []
    for approval in approvals:
        lines.append("=" * 72)
        if not approval.get("recorded"):
            lines.append(f"Approval attempt: {approval.get('approvedAt')}  NOT RECORDED")
            lines.append(f"  Clicked by:   {approval.get('approvedBy')}")
            lines.append(f"  Note:         {approval.get('note')}")
            lines.append("")
            continue

        lines.append(f"Approval:       {approval['approvalId']}")
        lines.append(f"  Decision:     {approval.get('decision')} "
                     f"(recorded {approval.get('status')})")
        lines.append(f"  Approved by:  {approval.get('approvedBy')}")
        lines.append(f"  At:           {approval.get('approvedAt')}  from {approval.get('sourceIP')}")
        if approval.get("singleUse") is not None:
            lines.append(f"  Single use:   {approval.get('singleUse')}   "
                         f"expires {approval.get('expiresAt')}")
        pins = approval.get("argumentPins") or {}
        if pins:
            lines.append(f"  Approved call: {approval.get('tool')} -> {pins.get('operation', '(unpinned)')}")
            for key in sorted(pins):
                if key in _ENVELOPE_PINS:
                    continue
                lines.append(f"    {key} = {_truncate(pins[key])}")

        session = approval.get("session") or {}
        if session:
            lines.append(f"  Session role: {_short_arn(session.get('roleArn'))}")
            lines.append(f"  Credential:   {session.get('durationSeconds')}s, "
                         f"expires {session.get('credentialExpires')}")
            policy = session.get("sessionPolicy")
            if policy:
                lines.append("  Scoped to:    " + ", ".join(_policy_actions(policy)))
        lines.append(f"  Session name: {approval.get('sessionName')}")
        lines.append("")

        calls = approval.get("calls") or []
        if not calls:
            lines.append("  Executed:     nothing (approval recorded but no matching call found)")
            lines.append("")
            continue

        for call in calls:
            lines.append(f"  Executed:     {call.get('operation')}  at {call.get('eventTime')}")
            lines.append(f"    Principal:  {call.get('principal')}")
            lines.append(f"    Via:        {call.get('invokedBy') or '(direct)'}")
            if call.get("errorCode"):
                lines.append(f"    Error:      {call['errorCode']}")
            verdict = "PASS" if call.get("approvedValuesHonored") else "MISMATCH"
            lines.append(f"    Approved values honored: {verdict}")
            for check in call.get("approvalChecks") or []:
                if check["match"]:
                    continue
                if "missing" in check:
                    lines.append(f"      ! {check['pin']}: approved values absent "
                                 f"from executed call: {check['missing']}")
                else:
                    lines.append(f"      ! {check['pin']}: approved {check['approved']!r} "
                                 f"but executed {check['executed']!r}")
            lines.append("")
        lines.append(f"  Correlation:  OK approval {approval['approvalId']} "
                     f"-> session -> {len(calls)} call(s), joined on approval id")
        lines.append("")
    return "\n".join(lines).rstrip()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _lookup(ct, attrs, window):
    """Paginate lookup_events and yield each event's parsed CloudTrailEvent."""
    start, end = window
    token = None
    while True:
        kwargs = {"LookupAttributes": attrs, "StartTime": start,
                  "EndTime": end, "MaxResults": 50}
        if token:
            kwargs["NextToken"] = token
        resp = ct.lookup_events(**kwargs)
        for e in resp.get("Events", []):
            yield json.loads(e["CloudTrailEvent"])
        token = resp.get("NextToken")
        if not token:
            return


def _operation_of(ce):
    """`service:Operation`, matching the form the approval pins."""
    source = (ce.get("eventSource") or "").split(".")[0]
    name = ce.get("eventName") or ""
    return f"{source}:{name}" if source else name


def _mentions(entry, needle):
    return needle in json.dumps(entry, default=str)


def _parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _epoch_to_iso(value):
    if not isinstance(value, (int, float)):
        return value
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def _parse_policy(value):
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return None


def _policy_actions(policy):
    """Summarize a session policy's actions, keeping it short but honest.

    A statement gated on `aws:ViaAWSService` is a service-call passthrough, not
    a grant the agent can use directly, so it is labeled rather than listed as
    if it were a broad permission the operator granted.
    """
    out = []
    for stmt in policy.get("Statement", []):
        actions = stmt.get("Action")
        actions = [actions] if isinstance(actions, str) else (actions or [])
        cond = json.dumps(stmt.get("Condition") or {})
        if "ViaAWSService" in cond:
            out.append("(+ service-call passthrough)")
        elif len(actions) > 3:
            out.append(f"{actions[0]} (+{len(actions) - 1} more)")
        else:
            out.extend(actions)
    return out or ["(none)"]


def _first_arn_of_type(resources, type_suffix):
    for r in resources or []:
        if str(r.get("type", "")).endswith(type_suffix):
            return r.get("ARN")
    return None


def _short_arn(arn):
    return (arn or "").split("/")[-1] or arn


def _truncate(value, limit=96):
    s = value if isinstance(value, str) else json.dumps(value)
    return s if len(s) <= limit else s[:limit] + "..."


def main():
    p = argparse.ArgumentParser(
        description="Correlate a DevOps Agent elevated action to the human approval "
                    "that authorized it (deterministic join on approval id)."
    )
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--window-hours", type=float, default=24,
                   help="How far back to look (default: 24)")
    p.add_argument("--end-time", help="ISO8601 end of the window (default: now)")
    p.add_argument("--approval-id", help="Correlate only this approval id")
    p.add_argument("--resource-id",
                   help="Keep only approvals/calls mentioning this resource id")
    p.add_argument("--include-reads", action="store_true",
                   help="Include read-only calls made by the approved session")
    p.add_argument("--session-policy", action="store_true",
                   help="Resolve the AssumeRole event to show the scoped session policy")
    p.add_argument("--json", action="store_true", help="Emit raw JSON instead of a summary")
    args = p.parse_args()

    try:
        result = correlate_agent_actions(
            args.region, args.window_hours,
            approval_id=args.approval_id,
            resource_id=args.resource_id,
            writes_only=not args.include_reads,
            include_session_policy=args.session_policy,
            end_time=args.end_time,
        )
    except ClientError as e:
        print(f"AWS API call failed: {e}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(result, indent=2, default=str) if args.json
          else format_agent_correlation(result))


if __name__ == "__main__":
    main()
