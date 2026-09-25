#!/usr/bin/env python3
"""Correlate an AWS DevOps Agent finding to the actual infrastructure change and
its compliance state.

The agent tells you *what it concluded* (via the journal) and *what to fix* (via
recommendations). This tool closes the loop: given a finding's resource, it finds
the real change that touched that resource (CloudTrail) and the resource's
recorded state and compliance (AWS Config).

Why this is not a naive "scan all changes in the window":
    In a production account, hundreds of changes happen concurrently. Scanning
    the whole window yields noise. Instead we PIVOT on the specific resource the
    agent named — the agent's own output is the index into the change history.

Correlation strategy:
    1. Resolve the resource canonically via AWS Config (authoritative identity
       and change timeline). `select-resource-config` keys resources reliably;
       CloudTrail's ResourceName lookup does not, and varies by service.
    2. Pull the resource's Config configuration-item history (before/after state).
    3. Pull the resource's compliance state from Config rules, if any apply.
    4. Best-effort: find the CloudTrail write event that caused the change,
       using per-resource-type lookup strategies (see RESOURCE_STRATEGIES).

Limitations:
    - Config's `relatedEvents` field (the old deterministic CloudTrail link) is
      no longer populated. Correlation is therefore heuristic: resource identity
      + time window, not a guaranteed causal link.
    - Config capture lag is minutes; this is retrospective audit, not real-time.
    - Some resource types expose their identity only in CloudTrail
      `requestParameters`, not the indexed ResourceName. We handle the common
      ones; unusual services may need an added strategy.
"""
import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError


# ---------------------------------------------------------------------------
# Per-resource-type CloudTrail lookup strategies — the extensibility seam.
#
# To correlate a new resource type, add an entry here. There is no other code to
# change. Each entry declares HOW CloudTrail indexes that type, because it is not
# uniform (this is the whole reason the tool needs a registry):
#
#   lookup = "name"  -> the resource's name/id IS the CloudTrail ResourceName.
#                       Examples: S3 (bucket name), Lambda (function name).
#   lookup = "arn"   -> CloudTrail indexes the FULL ARN, not the short name.
#                       Example: RDS (arn:aws:rds:...:db:<name>). We build the
#                       ARN from `arn_template` using account/region/name.
#   lookup = None    -> the type is NOT indexed by ResourceName at all. Fall back
#                       to a ResourceType-scoped scan, then confirm the id appears
#                       in requestParameters.
#
# `scan_fallback = True` -> the type is normally indexed (lookup="name"/"arn") but
#                       CloudTrail's ResourceName index has regional/historical
#                       variability, so if the primary lookup returns zero events
#                       we re-run the ResourceType scan+filter path
#                       (used by EC2 security groups).
#
# `id_in_request` lists the requestParameters keys that carry the resource id, used
# to confirm scan hits (fallback or lookup=None) actually reference this resource.
# ---------------------------------------------------------------------------
RESOURCE_STRATEGIES = {
    "AWS::S3::Bucket": {
        "lookup": "name",                  # bucket name indexes cleanly
        "id_in_request": ["bucketName"],
    },
    "AWS::Lambda::Function": {
        "lookup": "name",                  # function name works, but is noisy
        "id_in_request": ["functionName", "FunctionName"],
    },
    "AWS::EC2::SecurityGroup": {
        # CloudTrail DOES index security groups by
        # ResourceName. `lookup-events AttributeKey=ResourceName,AttributeValue=<sg-id>`
        # returned all four SG mutation events directly, each with
        # Resources[].ResourceName = the sg-id. So the primary mode is "name".
        # `scan_fallback` keeps the old ResourceType scan reachable, because
        # ResourceName indexing has regional/historical variability; the scan
        # still filters on `id_in_request` (groupId top-level — CreateTags nests
        # ids under resourcesSet.items[].resourceId, which we deliberately skip).
        "lookup": "name",
        "scan_fallback": True,
        "id_in_request": ["groupId", "groupIds"],
    },
    "AWS::RDS::DBInstance": {
        # CloudTrail indexes RDS by full ARN, NOT the DB identifier or
        # DbiResourceId. requestParameters.resourceName is the ARN.
        "lookup": "arn",
        "arn_template": "arn:aws:rds:{region}:{account}:db:{name}",
        "id_in_request": ["resourceName"],
    },
    "AWS::RDS::DBCluster": {
        "lookup": "arn",
        "arn_template": "arn:aws:rds:{region}:{account}:cluster:{name}",
        "id_in_request": ["resourceName"],
    },
}

# ---------------------------------------------------------------------------
# Resource extraction — pull resource identifiers out of an archived
# recommendation or journal record so the tool can be driven by the agent's
# own output (forward/backward correlation) instead of a hand-supplied resource id.
#
# There is no structured resource field in these payloads: recommendations
# bury ids in content.summary (a JSON STRING); journal records bury them in
# content (a JSON STRING), with ARNs and sg- ids the most common. So:
# recursively unwrap double-encoded JSON, gather all text, regex-scan.
# Correlation is heuristic by design.
# ---------------------------------------------------------------------------

# Defensive: honored if a payload ever carries an explicit resource field.
_STRUCTURED_ID_KEYS = ["resourceId", "resource_id", "resourceArn", "resource_arn"]
_STRUCTURED_TYPE_KEYS = ["resourceType", "resource_type"]

# EC2-style resource-id prefixes -> AWS Config resource type.
_ID_PREFIX_TYPES = {
    "sg-": "AWS::EC2::SecurityGroup",
    "i-": "AWS::EC2::Instance",
    "vol-": "AWS::EC2::Volume",
    "subnet-": "AWS::EC2::Subnet",
    "vpc-": "AWS::EC2::VPC",
    "acl-": "AWS::EC2::NetworkAcl",
    "eni-": "AWS::EC2::NetworkInterface",
}

# ARN service segment -> AWS Config resource type (extend as needed).
_ARN_SERVICE_TYPES = {
    "s3": "AWS::S3::Bucket",
    "lambda": "AWS::Lambda::Function",
    "rds": "AWS::RDS::DBInstance",
    "ec2": "AWS::EC2::Instance",
}

_EC2_ID_RE = re.compile(r"\b(sg|i|vol|subnet|vpc|acl|eni)-[0-9a-f]{8,17}\b")
# Exclude `\` from the ARN body: content.summary is double-encoded JSON, so an
# ARN followed by an escaped quote surfaces as `...Rate\"` — stopping at the
# backslash keeps the trailing escape out of the extracted id.
_ARN_RE = re.compile(r"arn:aws:([a-z0-9-]+):[a-z0-9-]*:[0-9]*:[^\s\"'\\,]+")

# Characters allowed in a value interpolated into an AWS Config SELECT literal.
# Covers ARNs, resource ids/names, and `AWS::Service::Type`; excludes quotes,
# backslashes, and whitespace so a value cannot terminate the literal it sits in.
_CONFIG_LITERAL_RE = re.compile(r"[A-Za-z0-9:_/.+=@-]+")

# ARN services that are NEVER a correlation target — they identify the audit
# subject itself, not a changed resource. Every recommendation carries a
# top-level `agentSpaceArn`
# (arn:aws:aidevops:...:agentspace/...). Because ARNs are scanned first and
# run_recommendation_mode() uses resources[0], NOT skipping this would make the
# tool correlate the agent space instead of the affected resource. Skip it.
_ARN_SERVICE_SKIP = {"aidevops"}


def _type_for_ec2_id(resource_id):
    for prefix, rtype in _ID_PREFIX_TYPES.items():
        if resource_id.startswith(prefix):
            return rtype
    return None


def _type_for_arn(arn):
    m = _ARN_RE.match(arn)
    if not m:
        return None
    return _ARN_SERVICE_TYPES.get(m.group(1))


def _normalize_arn(arn):
    """Reduce an ARN to the correlation target. For S3 the extracted ARN often
    carries an object path (arn:aws:s3:::bucket/key/...); the Config resource is
    the bucket, so trim at the first `/` after the bucket name.
    """
    m = _ARN_RE.match(arn)
    if m and m.group(1) == "s3" and "/" in arn:
        return arn.split("/", 1)[0]
    return arn


def _gather_text(value, depth=0):
    """Recursively collect all string content from a value, unwrapping any
    string that is itself JSON (the archive double-encodes content.summary and
    journal record.content). Bounded depth guards against pathological nesting.
    """
    if depth > 6:
        return []
    out = []
    if isinstance(value, str):
        out.append(value)
        s = value.strip()
        if s and s[0] in "{[":
            try:
                out.extend(_gather_text(json.loads(s), depth + 1))
            except (ValueError, TypeError):
                pass
    elif isinstance(value, dict):
        for v in value.values():
            out.extend(_gather_text(v, depth + 1))
    elif isinstance(value, list):
        for v in value:
            out.extend(_gather_text(v, depth + 1))
    elif isinstance(value, (int, float)):
        out.append(str(value))
    return out


def extract_resources(obj):
    """Return a de-duplicated list of {resource_id, resource_type} refs found in
    an archived recommendation or journal record.

    1. Defensive: honor an explicit structured field if one is ever present.
    2. Primary: recursively unwrap double-encoded JSON, then regex-scan all text
       for ARNs and EC2-style ids (resource ids live embedded in text).

    Ordering contract: refs with an inferred Config type sort first (stable, so
    text order is preserved within each group). Callers using resources[0] get
    the most-correlatable ref rather than whichever id happened to appear first.

    resource_type may be None when it cannot be inferred; the caller can still
    pass the id to Config, which resolves the type authoritatively.
    """
    found, seen = [], set()

    def _add(rid, rtype):
        if rid and rid not in seen:
            seen.add(rid)
            found.append({"resource_id": rid, "resource_type": rtype})

    # 1. Defensive structured-field check (rare in practice). Guard on
    #    dict: journal payloads can arrive as a top-level list, which has no
    #    .get; _gather_text below still handles lists in step 2.
    if isinstance(obj, dict):
        sid = next((obj[k] for k in _STRUCTURED_ID_KEYS if isinstance(obj.get(k), str)), None)
        if sid:
            stype = next((obj[k] for k in _STRUCTURED_TYPE_KEYS if isinstance(obj.get(k), str)), None)
            if not stype:
                stype = _type_for_arn(sid) if sid.startswith("arn:") else _type_for_ec2_id(sid)
            _add(sid, stype)

    # 2. Recursively unwrap + regex-scan. ARNs first (dominant in the corpus),
    #    but skip service ARNs that identify the audit subject, not a change
    #    target (e.g. the ubiquitous agentSpaceArn) — see _ARN_SERVICE_SKIP.
    text = " ".join(_gather_text(obj))
    for m in _ARN_RE.finditer(text):
        if m.group(1) in _ARN_SERVICE_SKIP:
            continue
        rid = _normalize_arn(m.group(0).rstrip(".,;)"))
        _add(rid, _type_for_arn(rid))
    for m in _EC2_ID_RE.finditer(text):
        rid = m.group(0)
        _add(rid, _type_for_ec2_id(rid))

    # Stable sort: typed refs before untyped, preserving text order within each
    # group. Makes resources[0] the most-correlatable ref for callers.
    found.sort(key=lambda r: r["resource_type"] is None)
    return found


# Journal record types that represent the diagnosed cause / summary worth
# correlating. The service has emitted two generations of type names: newer
# journals use finding / investigation_summary / investigation_summary_md,
# earlier journals use investigation_result — handle both. We deliberately skip
# `message` (agent chatter) and `utilization` (token accounting) to avoid
# keying on incidental ids.
_FINDING_RECORD_TYPES = {
    "investigation_result",
    "finding", "investigation_summary", "investigation_summary_md",
}

# Cause records name the specific broken resource; summaries recap the whole
# investigation and often lead with context (VPC) before cause (SG). Scan
# causes first so resources[0] is the diagnosed resource rather than a
# context id the summary happened to mention first.
_RECORD_TYPE_PRIORITY = {"investigation_result": 0, "finding": 0,
                         "investigation_summary": 1, "investigation_summary_md": 1}


def extract_resources_from_journal(payload):
    """Extract resource refs from a journal payload's result/summary records.

    Scans only the diagnosed-cause record types (see _FINDING_RECORD_TYPES),
    not every message/utilization record, to avoid keying on incidental ids the
    agent merely looked at. Eligible records are visited in SEMANTIC priority
    order (cause records before summaries, see _RECORD_TYPE_PRIORITY) rather than
    payload order, so the first-seen id is the diagnosed resource even when a
    summary that leads with context precedes the cause record. `extract_resources`
    unwraps each record's double-encoded `content`. De-duplicated across records,
    then re-sorted typed-first so the aggregate keeps the same
    most-correlatable-ref-first contract each per-record call already honors
    (typed refs still sort ahead of untyped, so resources[0] is the
    most-correlatable diagnosed ref, not merely the first-seen one).
    """
    eligible = [r for r in payload.get("journal_records", [])
                if r.get("recordType") in _FINDING_RECORD_TYPES]
    # Stable sort by priority: same-priority records keep payload order.
    eligible.sort(key=lambda r: _RECORD_TYPE_PRIORITY.get(r.get("recordType"), 0))
    found, seen = [], set()
    for record in eligible:
        for ref in extract_resources(record):
            if ref["resource_id"] not in seen:
                seen.add(ref["resource_id"])
                found.append(ref)
    found.sort(key=lambda r: r["resource_type"] is None)
    return found


def extract_incident_refs(rec):
    """Return the incident provenance a recommendation carries about itself.

    Two fields inside `content.summary` name the investigations behind the advice,
    and neither is reachable by the resource-identity heuristic:

      affected_incidents  {incident id: timestamp} — the incident id is a backlog
                          task id, which is what an archived journal stores as
                          `task_id`, so this is an exact join, not a time window.
      provenance          content_producing_execution_ids carries a stable cluster
                          id (`<hash>-pi-groupN`). It survives across evaluation
                          runs even though recommendationId does not, so it is the
                          only way to recognize repeated advice as one thread.

    Absent fields are normal — a large share of recommendations carry neither — and
    report as empty. Data that is PRESENT but the wrong shape reports a `malformed`
    reason instead — an empty result must mean "no references", never "we could not
    read them".
    """
    refs = {"incidents": {}, "provenance_group": None,
            "production_method": None, "malformed": None}
    summary = (rec.get("content") or {}).get("summary") if isinstance(rec, dict) else None
    if summary is None:
        return refs
    if isinstance(summary, str):
        try:
            summary = json.loads(summary)
        except (ValueError, TypeError):
            refs["malformed"] = "content.summary is not parseable JSON"
            return refs
    if not isinstance(summary, dict):
        refs["malformed"] = "content.summary is not an object"
        return refs

    incidents = summary.get("affected_incidents")
    if isinstance(incidents, dict):
        refs["incidents"] = {k: v for k, v in incidents.items() if isinstance(k, str)}
    elif incidents is not None:
        refs["malformed"] = (f"affected_incidents is {type(incidents).__name__}, "
                             f"expected an id->timestamp object")

    prov = summary.get("provenance")
    if isinstance(prov, dict):
        ids = prov.get("content_producing_execution_ids")
        if isinstance(ids, list) and ids and isinstance(ids[0], str):
            refs["provenance_group"] = ids[0]
        method = prov.get("production_method")
        if isinstance(method, str):
            refs["production_method"] = method
    return refs


def group_by_provenance(recs):
    """Collapse recommendations that are the same advice into one entry each.

    Every evaluation run re-CREATEs the advice it still believes in under a NEW
    recommendationId, so week-over-week repetition of a single finding shows up in
    the archive as several distinct ids. Reporting them one-per-id reads as several
    independent findings. `provenance.content_producing_execution_ids` is stable
    across runs, so it is the key that puts them back together.

    Two timestamps, and they mean different things: `createdAt` is identical across
    the whole group (when the advice was first authored, preserved on every re-
    creation), while `updatedAt` moves each time a run supersedes a record. So the
    group's span is first_created -> last_updated, and the number of evaluation runs
    it survived is the count of distinct `taskId`s.

    Recommendations with no provenance are keyed on their own id, so they stay
    one entry each.
    """
    grouped = {}
    for rec in recs:
        refs = extract_incident_refs(rec)
        key = refs["provenance_group"] or f"\0{rec.get('recommendationId')}"
        g = grouped.setdefault(key, {
            "provenance_group": refs["provenance_group"],
            "recommendation_ids": set(), "run_task_ids": set(),
            "first_created": None, "last_updated": None,
            "latest": None, "incidents": {}, "malformed": refs["malformed"],
            "production_methods": set(),
        })
        if refs["malformed"] and not g["malformed"]:
            g["malformed"] = refs["malformed"]
        if rec.get("recommendationId"):
            g["recommendation_ids"].add(rec["recommendationId"])
        if rec.get("taskId"):
            g["run_task_ids"].add(rec["taskId"])
        if refs["production_method"]:
            g["production_methods"].add(refs["production_method"])
        g["incidents"].update(refs["incidents"])
        created, updated = str(rec.get("createdAt") or ""), str(rec.get("updatedAt") or "")
        if created and (g["first_created"] is None or created < g["first_created"]):
            g["first_created"] = created
        if updated and (g["last_updated"] is None or updated > g["last_updated"]):
            g["last_updated"] = updated
        # Newest record in the group supplies the title/status we report. Version
        # breaks the tie when updatedAt is absent or equal.
        rank = (updated, rec.get("version") or 0)
        if g["latest"] is None or rank >= g["_rank"]:
            g["latest"], g["_rank"] = rec, rank

    out = []
    for g in grouped.values():
        g.pop("_rank", None)
        g["recommendation_ids"] = sorted(g["recommendation_ids"])
        g["run_task_ids"] = sorted(g["run_task_ids"])
        g["production_methods"] = sorted(g["production_methods"])
        out.append(g)
    out.sort(key=lambda g: (g["first_created"] or "", g["recommendation_ids"]))
    return out


def format_recommendation_correlation(versions, correlation, journal_index=None):
    """Render the forward correlation: recommendation -> Config
    change -> CloudTrail attribution.

    With `journal_index`, also names the investigations that produced the advice
    (see extract_incident_refs). Optional so callers that only want the
    resource-identity correlation stay unchanged. It is a callable returning the
    index, not the index itself — see journal_index_provider.
    """
    latest = versions[-1]
    first = versions[0]
    lines = []
    rec_id = latest.get("recommendationId")
    if rec_id:
        lines.append(f"Recommendation: {rec_id}")
    lines.append(f"Title:          {latest.get('title', '(no title)')}")
    if len(versions) > 1:
        lines.append(f"Status:         {first.get('status')} -> {latest.get('status')} "
                     f"(v{latest.get('version')})")
    else:
        lines.append(f"Status:         {latest.get('status')} (v{latest.get('version')})")
    lines.append("")

    if journal_index is not None:
        # A recommendation's versions may span provenance states: early versions
        # carry no provenance while a later version gains a group id, which splits
        # them across two groups. Merge incidents from all groups rather than
        # picking [0], which may be the no-provenance group with no incidents.
        groups = group_by_provenance(versions)
        merged = {"incidents": {}, "malformed": None, "provenance_group": None}
        for g in groups:
            merged["incidents"].update(g.get("incidents") or {})
            if g.get("malformed") and not merged["malformed"]:
                merged["malformed"] = g["malformed"]
            if g.get("provenance_group") and not merged["provenance_group"]:
                merged["provenance_group"] = g["provenance_group"]
        trace = format_incident_trace(merged, journal_index, indent="  ")
        if trace:
            lines.extend(trace)
            lines.append("")

    resolved = correlation.get("resolved") or {}
    history = correlation.get("config_history") or []
    if resolved and history:
        lines.append("Config change detected:")
        lines.append(f"  Resource:     {resolved.get('resourceType')} / {resolved.get('resourceId')}")
        lines.append(f"  Changed:      {history[0].get('captureTime')}")
        lines.append("")
    else:
        lines.append("Config change detected: none in window")
        lines.append("")

    changes = correlation.get("correlated_changes") or []
    if changes:
        c = changes[0]
        lines.append("CloudTrail attribution:")
        lines.append(f"  Event:        {c.get('eventName')}")
        lines.append(f"  Principal:    {c.get('actor')}")
        lines.append(f"  Source IP:    {c.get('sourceIP')}")
        lines.append(f"  Time:         {c.get('eventTime')}")
        if c.get("agentInitiated"):
            lines.append("  Actor:        AWS DevOps Agent (agent-initiated)")
        lines.append("")
        lines.append("Correlation:    OK Recommendation -> Config change -> CloudTrail event aligned")
    else:
        lines.append("CloudTrail attribution: no write event found in window")
    return "\n".join(lines)


def format_incident_trace(group, journal_index, indent="    "):
    """Render the investigations behind one group of advice, oldest first.

    Reports incidents that resolve to an archived journal AND those that do not.
    An unresolved reference is a fact about the archive's coverage (the advice is
    older than the pipeline, or was carried forward from a run before it), not a
    fact about the advice — so it is labelled, never dropped.

    Three outcomes, kept distinct on purpose: resolved to a journal, looked up and
    genuinely absent, or never looked up because no `journal_index` was given. The
    last must not borrow the second's wording — an auditor reading "not in this
    archive" would take it as a checked fact about capture.
    """
    lines = []
    if group.get("malformed"):
        lines.append(f"{indent}! Provenance could not be read: {group['malformed']}")
    incidents = group.get("incidents") or {}
    if not incidents:
        # Nothing to join, so do not pay for the archive scan. Many archived
        # recommendations carry no incident refs at all; for those the index is
        # pure cost. This guard is why `journal_index` is a callable.
        return lines
    resolved = resolve_incidents(incidents, journal_index() if journal_index else {})
    if not resolved:
        return lines
    lines.append(f"{indent}Produced by investigation(s):")
    for r in resolved:
        lines.append(f"{indent}  {r['incident_id']} ({r['incident_time']})")
        if r["execution_id"]:
            lines.append(f"{indent}    -> journal {r['execution_id']}")
        elif journal_index:
            lines.append(f"{indent}    -> not in this archive "
                         f"(referenced, but no journal was captured for it)")
        else:
            # Without an index nothing was read, so "not in this archive" would
            # assert coverage no read supports. Same rule as the malformed case
            # above: an unchecked claim must never render as a checked one.
            lines.append(f"{indent}    -> not resolved "
                         f"(no archive index was consulted)")
    return lines


def format_backward_correlation(finding_ref, prior_recommendations, correlation=None,
                                journal_index=None):
    """Render the backward correlation: is this finding a
    consequence of a prior recommendation touching the same resource?

    Closes the audit loop with identity: appends the last CloudTrail write event
    on this resource (who/when) so the operator sees attribution here rather than
    needing a second forward command. `correlation` is optional so existing
    callers/tests without it stay valid; the attribution block is useful whether
    or not prior recommendations were found.

    Prior recommendations are collapsed by provenance group (see
    group_by_provenance) so advice the agent re-created on every evaluation run is
    one entry rather than N competing findings, and each entry names the
    investigations it came from. `journal_index` is optional: without it the
    incident ids are still reported, just not resolved to journals. It is a
    callable returning the index, not the index itself — see
    journal_index_provider — so groups with no incident refs cost no archive reads.
    """
    lines = [f"Resource:       {finding_ref.get('resource_type')} / {finding_ref.get('resource_id')}", ""]
    if not prior_recommendations:
        lines.append("No prior recommendations reference this resource.")
    else:
        lines.append("Prior recommendations referencing this resource:")
        groups = group_by_provenance(prior_recommendations)
        for g in groups:
            rec = g["latest"]
            lines.append(f"  {rec.get('recommendationId')} "
                         f"(v{rec.get('version')}, {rec.get('status')}):")
            lines.append(f"    \"{rec.get('title', '(no title)')}\"")
            others = [r for r in g["recommendation_ids"]
                      if r != rec.get("recommendationId")]
            if others:
                runs = len(g["run_task_ids"]) or len(g["recommendation_ids"])
                method = "/".join(g["production_methods"]) or "re-created"
                lines.append(f"    Same advice across {runs} evaluation runs ({method}); "
                             f"also archived as: {', '.join(others)}")
                lines.append(f"    First authored {g['first_created']} -> "
                             f"last touched {g['last_updated']}")
            lines.extend(format_incident_trace(g, journal_index))
        lines.append("")
        ids = ", ".join(g["latest"].get("recommendationId", "") for g in groups)
        lines.append(f"! This finding may be a consequence of recommendation(s): {ids}")

    changes = (correlation or {}).get("correlated_changes") or []
    lines.append("")
    if changes:
        c = changes[0]
        lines.append("Last change to this resource (CloudTrail):")
        lines.append(f"  Event:        {c.get('eventName')}")
        lines.append(f"  Principal:    {c.get('actor')}")
        lines.append(f"  Source IP:    {c.get('sourceIP')}")
        lines.append(f"  Time:         {c.get('eventTime')}")
        if c.get("agentInitiated"):
            lines.append("  Actor:        AWS DevOps Agent (agent-initiated)")
    else:
        lines.append("No write event found for this resource in the window.")
    return "\n".join(lines)


def run_recommendation_mode(s3, bucket, recommendation_id, region, window_hours, incident_time):
    versions = load_recommendation(s3, bucket, recommendation_id)
    if not versions:
        return f"No archived recommendation found for id {recommendation_id} in s3://{bucket}/recommendations/"
    resources = []
    for v in versions:
        resources = extract_resources(v)
        if resources:
            break
    if not resources:
        return (f"Recommendation {recommendation_id} archived, but no resource id could be "
                f"extracted from it (title/summary). Correlate manually with --resource-id.")
    ref = resources[0]
    correlation = correlate(region, ref["resource_id"], None, ref["resource_type"],
                            incident_time, window_hours)
    return format_recommendation_correlation(versions, correlation,
                                             journal_index=journal_index_provider(s3, bucket))


def run_finding_mode(s3, bucket, execution_id, region, window_hours, incident_time,
                     check_prior_recommendations):
    payload = load_finding(s3, bucket, execution_id)
    if payload is None:
        return f"No archived journal found for execution id {execution_id} in s3://{bucket}/journals/"
    resources = extract_resources_from_journal(payload)
    if not resources:
        return (f"Journal {execution_id} archived, but no resource id could be extracted "
                f"from its finding records.")
    ref = resources[0]
    if check_prior_recommendations:
        priors = find_prior_recommendations(s3, bucket, ref["resource_id"])
        correlation = correlate(region, ref["resource_id"], None, ref["resource_type"],
                                incident_time, window_hours)
        return format_backward_correlation(ref, priors, correlation=correlation,
                                           journal_index=journal_index_provider(s3, bucket))
    correlation = correlate(region, ref["resource_id"], None, ref["resource_type"],
                            incident_time, window_hours)
    return json.dumps(correlation, indent=2, default=str)


# Only these event categories represent changes worth correlating.
WRITE_ONLY = True


def _config(region):
    return boto3.client("config", region_name=region)


def _cloudtrail(region):
    return boto3.client("cloudtrail", region_name=region)


def _s3(region):
    return boto3.client("s3", region_name=region)


def load_recommendation(s3, bucket, recommendation_id):
    """Load all archived versions of a recommendation, sorted ascending by version.

    Reads recommendations/<id>/v*.json. Returns [] if none exist.
    """
    prefix = f"recommendations/{recommendation_id}/"
    versions = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        for item in page.get("Contents", []):
            body = s3.get_object(Bucket=bucket, Key=item["Key"])["Body"].read()
            versions.append(json.loads(body))
    versions.sort(key=lambda r: r.get("version") or 0)
    return versions


def find_prior_recommendations(s3, bucket, resource_id):
    """Find archived recommendations that reference resource_id.

    Groups by recommendationId and reports the LATEST version's status (status is
    an opaque string — real values seen include PROPOSED and UPDATE_IN_PROGRESS),
    so a multi-version progression is summarized by where it landed.

    recommendationId is NOT stable across the goal's evaluation runs: each run
    creates new records with new ids, so one piece of advice repeated week over
    week appears here as several distinct recommendationIds. Grouping by id
    reports snapshots, not one lifecycle. The agent does compare new advice
    against the recommendations currently attached to the goal — what it does
    not do is compare against the full history archived here.
    """
    latest = {}  # recommendationId -> recommendation dict (highest version seen)
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix="recommendations/"):
        for item in page.get("Contents", []):
            rec = json.loads(s3.get_object(Bucket=bucket, Key=item["Key"])["Body"].read())
            if not any(r["resource_id"] == resource_id for r in extract_resources(rec)):
                continue
            rid = rec.get("recommendationId")
            if rid not in latest or (rec.get("version") or 0) >= (latest[rid].get("version") or 0):
                latest[rid] = rec
    return sorted(latest.values(), key=lambda r: r.get("recommendationId", ""))


def journal_task_index(s3, bucket):
    """Map backlog task id -> execution id for every archived journal.

    A recommendation names its originating investigations by backlog task id
    (`affected_incidents`), which the archived journal stores as `task_id`. That
    id is unrelated to the execution id, so the join has to read each payload.
    One scan of the prefix, reused for every incident on the recommendation.
    """
    index = {}
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix="journals/"):
        for item in page.get("Contents", []):
            payload = json.loads(s3.get_object(Bucket=bucket, Key=item["Key"])["Body"].read())
            task = payload.get("task_id")
            if isinstance(task, str) and task:
                index[task] = payload.get("execution_id")
    return index


def journal_index_provider(s3, bucket):
    """Defer `journal_task_index` until something actually needs resolving.

    The scan is one LIST plus one GetObject per archived journal, and the two
    callers cannot know in advance whether the advice they are rendering names any
    investigations — most of it does not. Returning a thunk moves that decision to
    the one place that knows (format_incident_trace) and caches the result, so a
    finding with several provenance groups still scans the archive once.
    """
    cached = {}
    def get():
        if "index" not in cached:
            cached["index"] = journal_task_index(s3, bucket)
        return cached["index"]
    return get


def resolve_incidents(incidents, journal_index):
    """Join `affected_incidents` against the journal archive, oldest first.

    `execution_id` is None when the incident is referenced but no journal for it
    is in the archive. That is expected, not a gap in capture: recommendations are
    carried forward across runs, so advice can outlive — or predate — the archive
    itself. Reporting the reference either way is the point; silently dropping it
    would let an auditor believe the recommendation had no origin.
    """
    resolved = [{"incident_id": iid,
                 "incident_time": incidents[iid],
                 "execution_id": journal_index.get(iid)}
                for iid in incidents]
    resolved.sort(key=lambda r: (str(r["incident_time"]), r["incident_id"]))
    return resolved


def load_finding(s3, bucket, execution_id):
    """Load an archived journal payload by execution id.

    Journal keys are journals/space=<id>/dt=<date>/<executionId>.json; the space
    and date are not required from the caller — we scan the journals/ prefix and
    match the <executionId>.json leaf. Returns the payload dict, or None.
    """
    leaf = f"/{execution_id}.json"
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix="journals/"):
        for item in page.get("Contents", []):
            if item["Key"].endswith(leaf):
                body = s3.get_object(Bucket=bucket, Key=item["Key"])["Body"].read()
                return json.loads(body)
    return None


def _config_literal(value, field):
    """Validate a value before it is interpolated into a Config SELECT literal.

    Config's SELECT dialect has no parameter binding, so the WHERE clause has to
    be built by string concatenation. Resource ids extracted from the archive are
    already constrained by _ARN_RE / _EC2_ID_RE, but --resource-id/-name/-type
    come straight from the operator, so validate every value against an allowlist
    of identifier characters rather than trusting the caller. Anything carrying a
    quote, backslash, or whitespace is rejected instead of escaped.
    """
    if not _CONFIG_LITERAL_RE.fullmatch(value):
        raise ValueError(
            f"invalid {field} {value!r}: expected only letters, digits, and : _ / . - + = @"
        )
    return value


def resolve_resource(cfg, resource_id=None, resource_name=None, resource_type=None):
    """Resolve a resource canonically via Config. Returns the CI summary or None."""
    where = []
    if resource_id:
        where.append(f"resourceId = '{_config_literal(resource_id, 'resource id')}'")
    if resource_name:
        where.append(f"resourceName = '{_config_literal(resource_name, 'resource name')}'")
    if resource_type:
        where.append(f"resourceType = '{_config_literal(resource_type, 'resource type')}'")
    if not where:
        return None
    expr = (
        "SELECT resourceId, resourceName, resourceType, "
        "configurationItemCaptureTime, awsRegion, accountId "
        "WHERE " + " AND ".join(where)
    )
    resp = cfg.select_resource_config(Expression=expr)
    results = [json.loads(r) for r in resp.get("Results", [])]
    return results[0] if results else None


def config_history(cfg, resource_type, resource_id, window_start=None):
    """Configuration-item history for the resource (before/after states)."""
    kwargs = {"resourceType": resource_type, "resourceId": resource_id, "limit": 20}
    if window_start:
        kwargs["laterTime"] = datetime.now(timezone.utc)
        kwargs["earlierTime"] = window_start
    resp = cfg.get_resource_config_history(**kwargs)
    return resp.get("configurationItems", [])


def compliance_state(cfg, resource_type, resource_id):
    """Config-rule compliance for the resource, if any rules evaluate it."""
    try:
        resp = cfg.get_compliance_details_by_resource(
            ResourceType=resource_type, ResourceId=resource_id
        )
        return [
            {
                "rule": r["EvaluationResultIdentifier"]["EvaluationResultQualifier"].get(
                    "ConfigRuleName"
                ),
                "compliance": r.get("ComplianceType"),
                "recordedAt": str(r.get("ResultRecordedTime", "")),
            }
            for r in resp.get("EvaluationResults", [])
        ]
    except Exception as e:  # noqa: BLE001 - best-effort
        return [{"error": str(e)}]


def _resource_matches(params, id_keys, resource_id):
    """Whether resource_id appears in any of the strategy's declared request-param keys.

    Precise key-based matching (not a substring scan of the whole payload): the
    resource id must be the value — or an element of a list value — of one of the
    keys the strategy declares in `id_in_request`. This avoids false positives
    where the id happens to appear inside an unrelated field (a tag, a longer ARN).
    """
    for key in id_keys:
        val = params.get(key)
        if val == resource_id:
            return True
        if isinstance(val, list) and resource_id in val:
            return True
    return False


def _scan_events(ct, attrs, window, id_keys=None, resource_id=None):
    """Paginate lookup_events over `attrs`, normalize each write event, and (when
    `id_keys` is given) keep only events whose requestParameters reference
    `resource_id` under one of those keys. Returns the tool's event shape.
    """
    start, end = window
    events, token = [], None
    while True:
        kwargs = {
            "LookupAttributes": attrs,
            "StartTime": start,
            "EndTime": end,
            "MaxResults": 50,
        }
        if token:
            kwargs["NextToken"] = token
        resp = ct.lookup_events(**kwargs)
        for e in resp.get("Events", []):
            ce = json.loads(e["CloudTrailEvent"])
            if WRITE_ONLY and ce.get("readOnly") is not False:
                continue
            # Scan paths (lookup=None or scan fallback) confirm the resource id
            # appears in one of the strategy's declared requestParameters keys.
            if id_keys is not None:
                params = ce.get("requestParameters") or {}
                if not _resource_matches(params, id_keys, resource_id):
                    continue
            identity = ce.get("userIdentity", {})
            invoked_by = identity.get("invokedBy", "")
            source_ip = ce.get("sourceIPAddress", "")
            agent_initiated = (
                "aidevops.amazonaws.com" in invoked_by
                or "aidevops.amazonaws.com" in source_ip
            )
            events.append(
                {
                    "eventTime": str(e["EventTime"]),
                    "eventName": e["EventName"],
                    "eventId": e["EventId"],
                    "actor": identity.get("arn", ""),
                    "sourceIP": source_ip,
                    "agentInitiated": agent_initiated,
                }
            )
        token = resp.get("NextToken")
        if not token:
            break
    return events


def correlated_changes(ct, resource_type, resource_id, resource_name, window, account=None, region=None):
    """Best-effort CloudTrail change events for the resource within the window.

    Dispatches on the resource type's declared lookup mode (see RESOURCE_STRATEGIES):
    "name" indexes on the short name, "arn" builds and indexes on the full ARN, and
    None scans by ResourceType then filters on requestParameters.

    When a strategy sets `scan_fallback` and the primary ResourceName/ARN lookup
    returns zero events, we re-run the ResourceType scan+filter path — CloudTrail's
    ResourceName index has regional/historical gaps.
    """
    strategy = RESOURCE_STRATEGIES.get(resource_type, {"lookup": "name"})
    lookup = strategy["lookup"]

    if lookup == "name":
        key = resource_name or resource_id
        attrs = [{"AttributeKey": "ResourceName", "AttributeValue": key}]
    elif lookup == "arn":
        # CloudTrail indexes this type by full ARN (e.g. RDS).
        key = strategy["arn_template"].format(
            region=region or "", account=account or "", name=resource_name or resource_id
        )
        attrs = [{"AttributeKey": "ResourceName", "AttributeValue": key}]
    else:
        # No clean index: scan by ResourceType, filtered on requestParameters.
        attrs = [{"AttributeKey": "ResourceType", "AttributeValue": resource_type}]

    if lookup is None:
        return _scan_events(
            ct, attrs, window, strategy.get("id_in_request", []), resource_id
        )

    events = _scan_events(ct, attrs, window)
    if events or not strategy.get("scan_fallback"):
        return events

    # Primary lookup found nothing and the strategy allows a fallback: scan by
    # ResourceType and confirm the id via the declared requestParameters keys.
    scan_attrs = [{"AttributeKey": "ResourceType", "AttributeValue": resource_type}]
    return _scan_events(
        ct, scan_attrs, window, strategy.get("id_in_request", []), resource_id
    )


def correlate(region, resource_id, resource_name, resource_type, incident_time, window_hours):
    cfg, ct = _config(region), _cloudtrail(region)

    resolved = resolve_resource(cfg, resource_id, resource_name, resource_type)
    if not resolved:
        print(
            f"No Config record for resource "
            f"(id={resource_id} name={resource_name} type={resource_type}). "
            f"Config may not track this type, or the resource does not exist.",
            file=sys.stderr,
        )
        return {"resolved": None}

    rtype = resolved["resourceType"]
    rid = resolved["resourceId"]
    rname = resolved.get("resourceName")

    center = (
        datetime.fromisoformat(incident_time.replace("Z", "+00:00"))
        if incident_time
        else datetime.now(timezone.utc)
    )
    window = (center - timedelta(hours=window_hours), center + timedelta(hours=window_hours))

    return {
        "resolved": resolved,
        "window": [str(window[0]), str(window[1])],
        "config_history": [
            {
                "captureTime": str(ci.get("configurationItemCaptureTime")),
                "status": ci.get("configurationItemStatus"),
            }
            for ci in config_history(cfg, rtype, rid, window[0])
        ],
        "compliance": compliance_state(cfg, rtype, rid),
        "correlated_changes": correlated_changes(
            ct, rtype, rid, rname, window,
            account=resolved.get("accountId"), region=resolved.get("awsRegion") or region,
        ),
    }


def main():
    p = argparse.ArgumentParser(
        description="Correlate a DevOps Agent finding's resource to the real change + compliance state."
    )
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--resource-id", help="Resource id from the agent finding (e.g. a bucket name, sg-..., function name)")
    p.add_argument("--resource-name", help="Resource name if different from id")
    p.add_argument("--resource-type", help="AWS Config resource type, e.g. AWS::S3::Bucket")
    p.add_argument("--incident-time", help="ISO8601 incident time to center the window on (default: now)")
    p.add_argument("--window-hours", type=int, default=24, help="Correlation window half-width in hours")
    p.add_argument("--archive-bucket", help="S3 audit archive bucket (required for --recommendation/--finding)")
    p.add_argument("--recommendation", help="Archived recommendation id to correlate (forward correlation)")
    p.add_argument("--finding", help="Archived journal execution id to correlate (backward correlation)")
    p.add_argument("--check-prior-recommendations", action="store_true",
                   help="With --finding: report prior recommendations referencing the same resource")
    args = p.parse_args()

    if args.recommendation or args.finding:
        if not args.archive_bucket:
            p.error("--archive-bucket is required with --recommendation/--finding")
        s3 = _s3(args.region)
        try:
            if args.recommendation:
                print(run_recommendation_mode(s3, args.archive_bucket, args.recommendation,
                                              args.region, args.window_hours, args.incident_time))
            else:
                print(run_finding_mode(s3, args.archive_bucket, args.finding, args.region,
                                       args.window_hours, args.incident_time,
                                       args.check_prior_recommendations))
        except json.JSONDecodeError as e:
            print(f"Archive read failed: corrupt JSON in s3://{args.archive_bucket} ({e})",
                  file=sys.stderr)
            sys.exit(1)
        except ClientError as e:
            # Source-agnostic: this wrapper spans the archive-read (S3) AND the
            # downstream correlate() calls (CloudTrail/Config), so a ClientError
            # may originate from any of them — don't mislabel it as an S3 failure.
            print(f"AWS API call failed: {e}", file=sys.stderr)
            sys.exit(1)
        return

    if not (args.resource_id or args.resource_name):
        p.error("provide at least --resource-id or --resource-name")

    result = correlate(
        args.region,
        args.resource_id,
        args.resource_name,
        args.resource_type,
        args.incident_time,
        args.window_hours,
    )
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
