import json
from datetime import datetime, timezone

import correlate


def _rec(summary_obj, **top):
    """Build a recommendation in the real shape: content.summary is a JSON string."""
    return {"content": {"summary": json.dumps(summary_obj)}, **top}


def test_extracts_sg_id_from_double_encoded_summary():
    rec = _rec(
        {"overview": "The egress rule on sg-0123456789abcdef0 is too broad.",
         "next_steps": "Tighten it."},
        title="[HIGH] Fix egress on sg-0123456789abcdef0",
    )
    resources = correlate.extract_resources(rec)
    assert {"resource_id": "sg-0123456789abcdef0",
            "resource_type": "AWS::EC2::SecurityGroup"} in resources


def test_extracts_arn_and_maps_service_to_type():
    rec = _rec({"background": "Enable versioning on arn:aws:s3:::my-audit-bucket now."})
    resources = correlate.extract_resources(rec)
    assert {"resource_id": "arn:aws:s3:::my-audit-bucket",
            "resource_type": "AWS::S3::Bucket"} in resources


def test_extracts_from_plain_dict_without_content_wrapper():
    # Journal records / already-parsed objects: scan string values directly.
    obj = {"type": "investigation_result",
           "text": "The alarm fired for arn:aws:rds:us-east-1:111122223333:db:example-mariadb"}
    resources = correlate.extract_resources(obj)
    ids = [r["resource_id"] for r in resources]
    assert "arn:aws:rds:us-east-1:111122223333:db:example-mariadb" in ids


def test_returns_empty_when_no_resource_found():
    assert correlate.extract_resources(_rec({"overview": "no identifiers here"})) == []


def test_deduplicates_repeated_ids():
    rec = _rec({"overview": "sg-0123456789abcdef0 again sg-0123456789abcdef0",
                "next_steps": "and once more sg-0123456789abcdef0"})
    ids = [r["resource_id"] for r in correlate.extract_resources(rec)]
    assert ids.count("sg-0123456789abcdef0") == 1


def test_defensive_structured_field_still_honored_if_present():
    # Not seen in the real corpus, but cheap forward-compat: a structured id wins.
    rec = {"resourceId": "sg-11112222333344445", "resourceType": "AWS::EC2::SecurityGroup"}
    resources = correlate.extract_resources(rec)
    assert {"resource_id": "sg-11112222333344445",
            "resource_type": "AWS::EC2::SecurityGroup"} in resources


def test_arn_from_double_encoded_text_has_no_trailing_escape():
    # In double-encoded JSON an ARN followed by an escaped quote surfaces as
    # `...Rate\"` in the gathered text; the regex must not keep the backslash.
    rec = _rec({"overview": json.dumps(
        {"alarm": "arn:aws:cloudwatch:us-east-1:111122223333:alarm:StorefrontAPI-5xxErrorRate"})})
    ids = [r["resource_id"] for r in correlate.extract_resources(rec)]
    assert "arn:aws:cloudwatch:us-east-1:111122223333:alarm:StorefrontAPI-5xxErrorRate" in ids
    assert not any(i.endswith("\\") for i in ids)


def test_s3_object_path_arn_trims_to_bucket():
    # S3 ARNs can carry an object path. The correlation
    # target is the bucket, so trim at the first `/` after the bucket name.
    rec = _rec({"background":
                "Fix arn:aws:s3:::example-account-archive/individual/111122223333 "
                "and arn:aws:s3:::example-account-archive/system/111122223333."})
    resources = correlate.extract_resources(rec)
    assert {"resource_id": "arn:aws:s3:::example-account-archive",
            "resource_type": "AWS::S3::Bucket"} in resources
    # Two object paths in the same bucket collapse to one entry after trimming.
    buckets = [r for r in resources if r["resource_id"].startswith("arn:aws:s3:::")]
    assert len(buckets) == 1


def test_typed_refs_sort_before_untyped():
    # An IAM role ARN (type None) appears in the text BEFORE an S3 ARN (typed).
    # resources[0] must be the S3 bucket — the most-correlatable ref.
    rec = _rec({"overview":
                "Role arn:aws:iam::111122223333:role/SomeRole then bucket "
                "arn:aws:s3:::my-audit-bucket needs versioning."})
    resources = correlate.extract_resources(rec)
    assert resources[0] == {"resource_id": "arn:aws:s3:::my-audit-bucket",
                            "resource_type": "AWS::S3::Bucket"}


def test_non_dict_top_level_input_does_not_crash():
    # Journal payloads can arrive as a top-level list; step 1's structured-field
    # check must not call .get on a list.
    resources = correlate.extract_resources([{"text": "sg-0123456789abcdef0"}])
    ids = [r["resource_id"] for r in resources]
    assert "sg-0123456789abcdef0" in ids


def test_agent_space_arn_is_not_extracted_as_a_target():
    # VALIDATED 2026-07-22: every rec carries a top-level agentSpaceArn. It
    # identifies the audit subject, not a changed resource, so it must NOT be
    # returned (else run_recommendation_mode would correlate the agent space).
    rec = _rec(
        {"overview": "Tighten egress on sg-0123456789abcdef0."},
        agentSpaceArn="arn:aws:aidevops:us-east-1:111122223333:agentspace/abc-123",
    )
    ids = [r["resource_id"] for r in correlate.extract_resources(rec)]
    assert "sg-0123456789abcdef0" in ids
    assert not any(i.startswith("arn:aws:aidevops:") for i in ids)


# ---------------------------------------------------------------------------
# Security-group CloudTrail lookup strategy.
# ---------------------------------------------------------------------------


def test_sg_strategy_prefers_resource_name_lookup():
    strat = correlate.RESOURCE_STRATEGIES["AWS::EC2::SecurityGroup"]
    # CORRECTED 2026-07-22: SG is indexed by ResourceName, so the primary mode
    # is "name" (direct lookup), not None (scan-only).
    assert strat["lookup"] == "name"


def test_sg_strategy_retains_scan_fallback_and_precise_match_keys():
    strat = correlate.RESOURCE_STRATEGIES["AWS::EC2::SecurityGroup"]
    assert strat.get("scan_fallback") is True
    assert "groupId" in strat["id_in_request"]


def _ct_event(event_name, request_params, event_id="e-1"):
    return {
        "EventTime": datetime(2026, 7, 22, 12, 0, 0, tzinfo=timezone.utc),
        "EventName": event_name,
        "EventId": event_id,
        "CloudTrailEvent": json.dumps(
            {
                "readOnly": False,
                "requestParameters": request_params,
                "userIdentity": {"arn": "arn:aws:iam::111122223333:role/DevOps"},
                "sourceIPAddress": "10.0.0.1",
            }
        ),
    }


class _FakeCT:
    """Minimal CloudTrail stand-in: returns canned events keyed on the lookup
    attribute (ResourceName vs ResourceType) and records every call."""

    def __init__(self, by_name=None, by_type=None):
        self._by_name = by_name or []
        self._by_type = by_type or []
        self.calls = []

    def lookup_events(self, **kwargs):
        attr = kwargs["LookupAttributes"][0]
        self.calls.append(attr)
        if attr["AttributeKey"] == "ResourceName":
            events = self._by_name
        elif attr["AttributeKey"] == "ResourceType":
            events = self._by_type
        else:
            events = []
        return {"Events": events}


_SG_WINDOW = (
    datetime(2026, 7, 22, 0, 0, 0, tzinfo=timezone.utc),
    datetime(2026, 7, 23, 0, 0, 0, tzinfo=timezone.utc),
)


def test_sg_falls_back_to_type_scan_when_name_lookup_empty():
    # ResourceName lookup returns nothing; the type scan surfaces a matching
    # mutation event (groupId in requestParameters).
    scan_event = _ct_event("AuthorizeSecurityGroupIngress",
                           {"groupId": "sg-0123456789abcdef0"})
    ct = _FakeCT(by_name=[], by_type=[scan_event])
    events = correlate.correlated_changes(
        ct, "AWS::EC2::SecurityGroup", "sg-0123456789abcdef0", None, _SG_WINDOW
    )
    assert [e["eventName"] for e in events] == ["AuthorizeSecurityGroupIngress"]
    assert [c["AttributeKey"] for c in ct.calls] == ["ResourceName", "ResourceType"]


def test_sg_uses_name_lookup_and_skips_scan_when_name_returns_events():
    name_event = _ct_event("RevokeSecurityGroupEgress",
                          {"groupId": "sg-0123456789abcdef0"})
    ct = _FakeCT(by_name=[name_event], by_type=[])
    events = correlate.correlated_changes(
        ct, "AWS::EC2::SecurityGroup", "sg-0123456789abcdef0", None, _SG_WINDOW
    )
    assert [e["eventName"] for e in events] == ["RevokeSecurityGroupEgress"]
    # The scan must never run once the ResourceName lookup yields events.
    assert [c["AttributeKey"] for c in ct.calls] == ["ResourceName"]


def test_sg_fallback_still_filters_on_declared_request_keys():
    # A type-scan hit whose id lives only in an unmatched key (CreateTags nests
    # under resourcesSet, deliberately NOT in id_in_request) must be dropped.
    unrelated = _ct_event(
        "CreateTags",
        {"resourcesSet": {"items": [{"resourceId": "sg-0123456789abcdef0"}]}},
    )
    ct = _FakeCT(by_name=[], by_type=[unrelated])
    events = correlate.correlated_changes(
        ct, "AWS::EC2::SecurityGroup", "sg-0123456789abcdef0", None, _SG_WINDOW
    )
    assert events == []


def test_agent_initiated_flag_set_when_invoked_by_aidevops():
    event = {
        "EventTime": datetime(2026, 7, 22, 12, 0, 0, tzinfo=timezone.utc),
        "EventName": "AuthorizeSecurityGroupEgress",
        "EventId": "e-agent",
        "CloudTrailEvent": json.dumps({
            "readOnly": False,
            "requestParameters": {"groupId": "sg-0123456789abcdef0"},
            "userIdentity": {
                "arn": "arn:aws:sts::111122223333:assumed-role/DevOpsAgentMitigationRole/session",
                "invokedBy": "aidevops.amazonaws.com",
            },
            "sourceIPAddress": "aidevops.amazonaws.com",
        }),
    }
    ct = _FakeCT(by_name=[event])
    events = correlate.correlated_changes(
        ct, "AWS::EC2::SecurityGroup", "sg-0123456789abcdef0", None, _SG_WINDOW
    )
    assert len(events) == 1
    assert events[0]["agentInitiated"] is True


def test_agent_initiated_flag_false_for_human_changes():
    event = _ct_event("AuthorizeSecurityGroupEgress",
                      {"groupId": "sg-0123456789abcdef0"})
    ct = _FakeCT(by_name=[event])
    events = correlate.correlated_changes(
        ct, "AWS::EC2::SecurityGroup", "sg-0123456789abcdef0", None, _SG_WINDOW
    )
    assert len(events) == 1
    assert events[0]["agentInitiated"] is False


# ---------------------------------------------------------------------------
# S3 archive readers (Tasks 2–5).
# ---------------------------------------------------------------------------


class FakeS3:
    """Minimal duck-typed S3 client for archive-read tests."""
    def __init__(self, objects):
        self._objects = objects  # {key: dict-body}

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        objects = self._objects

        class _P:
            def paginate(self, Bucket, Prefix):
                keys = sorted(k for k in objects if k.startswith(Prefix))
                yield {"Contents": [{"Key": k} for k in keys]}
        return _P()

    def get_object(self, Bucket, Key):
        import io, json
        return {"Body": io.BytesIO(json.dumps(self._objects[Key]).encode())}


def test_load_recommendation_returns_versions_sorted():
    s3 = FakeS3({
        "recommendations/rec-abc123/v1.json": {"recommendationId": "rec-abc123", "version": 1, "status": "PROPOSED"},
        "recommendations/rec-abc123/v2.json": {"recommendationId": "rec-abc123", "version": 2, "status": "ACCEPTED"},
    })
    versions = correlate.load_recommendation(s3, "bucket", "rec-abc123")
    assert [v["version"] for v in versions] == [1, 2]
    assert versions[-1]["status"] == "ACCEPTED"


def test_load_recommendation_missing_returns_empty():
    assert correlate.load_recommendation(FakeS3({}), "bucket", "rec-nope") == []


def test_load_finding_locates_journal_by_execution_id():
    s3 = FakeS3({
        "journals/space=as-1/dt=2026-07-10/exe-def456.json": {
            "execution_id": "exe-def456",
            "journal_records": [{"recordType": "finding", "summary": "sg-0123456789abcdef0 too broad"}],
        },
    })
    payload = correlate.load_finding(s3, "bucket", "exe-def456")
    assert payload["execution_id"] == "exe-def456"
    assert payload["journal_records"][0]["recordType"] == "finding"


def test_load_finding_missing_returns_none():
    assert correlate.load_finding(FakeS3({}), "bucket", "exe-nope") is None


def test_extract_resources_from_journal_scans_result_records():
    payload = {
        "journal_records": [
            {"recordType": "message",
             "content": json.dumps({"role": "assistant", "content": "thinking..."})},
            {"recordType": "investigation_result",
             "content": json.dumps({"type": "investigation_result",
                                    "text": "root cause: sg-0123456789abcdef0 egress too broad"})},
            {"recordType": "utilization",
             "content": json.dumps({"tokens": 1234})},
        ]
    }
    resources = correlate.extract_resources_from_journal(payload)
    ids = [r["resource_id"] for r in resources]
    assert "sg-0123456789abcdef0" in ids
    assert resources[0]["resource_type"] == "AWS::EC2::SecurityGroup"


def test_extract_resources_from_journal_empty_when_no_result_ids():
    payload = {"journal_records": [
        {"recordType": "message", "content": json.dumps({"content": "no ids here"})},
        {"recordType": "utilization", "content": json.dumps({"tokens": 10})},
    ]}
    assert correlate.extract_resources_from_journal(payload) == []


def test_extract_resources_from_journal_prefers_cause_over_summary():
    # Observed journal shape: a summary record appears BEFORE the
    # cause finding in payload order, and its text leads with context (vpc-)
    # before the causal resource (sg-). The finding record names the sg first.
    # Scanning by payload order would make resources[0] the VPC; semantic
    # priority (cause records first) must make it the diagnosed SG.
    payload = {"journal_records": [
        {"recordType": "investigation_summary",
         "content": json.dumps({"type": "investigation_summary",
                                "text": "Context: vpc-0123456789abcdef0 spans the tier. "
                                        "The blocked path involves sg-0123456789abcdef0."})},
        {"recordType": "finding",
         "content": json.dumps({"type": "finding",
                                "text": "cause-sg-egress-blocked-443: sg-0123456789abcdef0 "
                                        "egress rule blocks 443 to vpc-0123456789abcdef0."})},
    ]}
    resources = correlate.extract_resources_from_journal(payload)
    assert resources[0]["resource_id"] == "sg-0123456789abcdef0"


def test_extract_resources_from_journal_summary_only_still_extracts():
    # Priority ordering must not drop summaries when no cause record exists.
    payload = {"journal_records": [
        {"recordType": "investigation_summary_md",
         "content": json.dumps({"type": "investigation_summary_md",
                                "text": "Summary: sg-0123456789abcdef0 egress too broad."})},
    ]}
    ids = [r["resource_id"] for r in correlate.extract_resources_from_journal(payload)]
    assert "sg-0123456789abcdef0" in ids


def test_find_prior_recommendations_matches_resource():
    s3 = FakeS3({
        "recommendations/rec-abc123/v1.json": {
            "recommendationId": "rec-abc123", "version": 1, "status": "PROPOSED",
            "title": "Authorize egress on sg-0123456789abcdef0 to 10.0.2.0/24:3306"},
        "recommendations/rec-abc123/v2.json": {
            "recommendationId": "rec-abc123", "version": 2, "status": "UPDATE_IN_PROGRESS",
            "title": "Authorize egress on sg-0123456789abcdef0 to 10.0.2.0/24:3306"},
        "recommendations/rec-zzz999/v1.json": {
            "recommendationId": "rec-zzz999", "version": 1, "status": "PROPOSED",
            "title": "Unrelated recommendation about arn:aws:s3:::some-bucket"},
    })
    matches = correlate.find_prior_recommendations(s3, "bucket", "sg-0123456789abcdef0")
    assert len(matches) == 1
    assert matches[0]["recommendationId"] == "rec-abc123"
    # latest version wins for status reporting (real-world status value)
    assert matches[0]["version"] == 2
    assert matches[0]["status"] == "UPDATE_IN_PROGRESS"


def test_find_prior_recommendations_none_returns_empty():
    assert correlate.find_prior_recommendations(FakeS3({}), "bucket", "sg-x") == []


# ---------------------------------------------------------------------------
# Human-readable formatters (Task 6).
# ---------------------------------------------------------------------------


def test_format_recommendation_correlation_shows_status_progression():
    versions = [
        {"recommendationId": "rec-abc123", "version": 1, "status": "PROPOSED",
         "title": "[HIGH] Authorize egress on sg-0123456789abcdef0 to 10.0.2.0/24:3306"},
        {"recommendationId": "rec-abc123", "version": 2, "status": "ACCEPTED",
         "title": "[HIGH] Authorize egress on sg-0123456789abcdef0 to 10.0.2.0/24:3306"},
    ]
    correlation = {
        "resolved": {"resourceType": "AWS::EC2::SecurityGroup", "resourceId": "sg-0123456789abcdef0"},
        "config_history": [{"captureTime": "2026-07-10T14:32:18Z", "status": "OK"}],
        "correlated_changes": [{"eventName": "AuthorizeSecurityGroupEgress",
                                "actor": "arn:aws:iam::111122223333:user/jsmith",
                                "sourceIP": "10.1.44.7", "eventTime": "2026-07-10T14:32:16Z"}],
    }
    out = correlate.format_recommendation_correlation(versions, correlation)
    assert "PROPOSED" in out and "ACCEPTED" in out
    assert "sg-0123456789abcdef0" in out
    assert "AuthorizeSecurityGroupEgress" in out
    assert "arn:aws:iam::111122223333:user/jsmith" in out


def test_format_backward_correlation_warns_on_prior_recs():
    finding_ref = {"resource_id": "sg-0123456789abcdef0", "resource_type": "AWS::EC2::SecurityGroup"}
    priors = [{"recommendationId": "rec-abc123", "version": 2, "status": "ACCEPTED",
               "title": "Authorize egress on sg-0123456789abcdef0 to 10.0.2.0/24:3306"}]
    out = correlate.format_backward_correlation(finding_ref, priors)
    assert "rec-abc123" in out
    assert "consequence" in out.lower()


def test_format_backward_correlation_clean_when_no_priors():
    finding_ref = {"resource_id": "sg-x", "resource_type": "AWS::EC2::SecurityGroup"}
    out = correlate.format_backward_correlation(finding_ref, [])
    assert "No prior recommendations" in out


# ---------------------------------------------------------------------------
# CLI modes (Task 7).
# ---------------------------------------------------------------------------


def test_run_recommendation_mode_uses_extracted_resource(monkeypatch):
    s3 = FakeS3({
        "recommendations/rec-abc123/v1.json": {"recommendationId": "rec-abc123", "version": 1,
            "status": "PROPOSED", "title": "egress on sg-0123456789abcdef0"},
    })
    captured = {}

    def fake_correlate(region, resource_id, resource_name, resource_type, incident_time, window_hours):
        captured["resource_id"] = resource_id
        return {"resolved": {"resourceType": "AWS::EC2::SecurityGroup", "resourceId": resource_id},
                "config_history": [], "correlated_changes": []}

    monkeypatch.setattr(correlate, "correlate", fake_correlate)
    out = correlate.run_recommendation_mode(s3, "bucket", "rec-abc123",
                                            region="us-east-1", window_hours=24, incident_time=None)
    assert captured["resource_id"] == "sg-0123456789abcdef0"
    assert "rec-abc123" in out


def test_run_recommendation_mode_no_resource_extracted():
    s3 = FakeS3({
        "recommendations/rec-noids/v1.json": {"recommendationId": "rec-noids", "version": 1,
            "status": "PROPOSED", "title": "no identifiers in this recommendation at all"},
    })
    out = correlate.run_recommendation_mode(s3, "bucket", "rec-noids",
                                            region="us-east-1", window_hours=24, incident_time=None)
    assert "no resource id could be" in out
    assert "rec-noids" in out


def test_run_finding_mode_check_prior_recommendations_warns(monkeypatch):
    s3 = FakeS3({
        "journals/space=as-1/dt=2026-07-10/exe-def456.json": {
            "execution_id": "exe-def456",
            "journal_records": [
                {"recordType": "investigation_result",
                 "content": json.dumps({"type": "investigation_result",
                                        "text": "root cause: sg-0123456789abcdef0 egress too broad"})},
            ],
        },
        "recommendations/rec-abc123/v1.json": {
            "recommendationId": "rec-abc123", "version": 1, "status": "ACCEPTED",
            "title": "Authorize egress on sg-0123456789abcdef0 to 10.0.2.0/24:3306"},
    })
    # The check-prior branch now also calls correlate() for attribution; stub it
    # (no changes) so this test stays offline and focused on the warning.
    monkeypatch.setattr(correlate, "correlate",
                        lambda *a, **k: {"resolved": None, "correlated_changes": []})
    out = correlate.run_finding_mode(s3, "bucket", "exe-def456", region="us-east-1",
                                     window_hours=24, incident_time=None,
                                     check_prior_recommendations=True)
    assert "rec-abc123" in out
    assert "consequence" in out.lower()


def test_run_recommendation_mode_surfaces_corrupt_json():
    import io

    class _BadS3(FakeS3):
        def get_object(self, Bucket, Key):
            return {"Body": io.BytesIO(b"{not valid json")}

    s3 = _BadS3({"recommendations/rec-bad/v1.json": {}})
    try:
        correlate.run_recommendation_mode(s3, "bucket", "rec-bad",
                                          region="us-east-1", window_hours=24, incident_time=None)
        assert False, "expected JSONDecodeError to propagate from the reader"
    except json.JSONDecodeError:
        pass


def test_main_translates_client_error_to_clean_message(monkeypatch, capsys):
    # A ClientError from a mode runner (may originate in S3 OR the downstream
    # CloudTrail/Config calls) must surface as a source-agnostic one-liner and
    # exit(1) — not a raw traceback, and not mislabeled as an S3 failure.
    from botocore.exceptions import ClientError

    def boom(*a, **k):
        raise ClientError({"Error": {"Code": "ThrottlingException",
                                     "Message": "Rate exceeded"}}, "LookupEvents")

    monkeypatch.setattr(correlate, "_s3", lambda region: object())
    monkeypatch.setattr(correlate, "run_recommendation_mode", boom)
    monkeypatch.setattr(
        "sys.argv",
        ["correlate.py", "--recommendation", "rec-x", "--archive-bucket", "audit-bucket"],
    )
    try:
        correlate.main()
        assert False, "expected SystemExit"
    except SystemExit as e:
        assert e.code == 1
    err = capsys.readouterr().err
    assert "AWS API call failed" in err
    assert "Rate exceeded" in err
    # Must NOT mislabel a non-S3 failure as an archive/S3 read problem.
    assert "Archive read failed" not in err


# ---------------------------------------------------------------------------
# Backward correlation now closes the loop with CloudTrail attribution.
# ---------------------------------------------------------------------------


def test_format_backward_correlation_appends_attribution():
    finding_ref = {"resource_id": "sg-0123456789abcdef0", "resource_type": "AWS::EC2::SecurityGroup"}
    priors = [{"recommendationId": "rec-abc123", "version": 2, "status": "ACCEPTED",
               "title": "Authorize egress on sg-0123456789abcdef0 to 10.0.2.0/24:3306"}]
    correlation = {
        "resolved": {"resourceType": "AWS::EC2::SecurityGroup", "resourceId": "sg-0123456789abcdef0"},
        "correlated_changes": [{"eventName": "AuthorizeSecurityGroupEgress",
                                "actor": "arn:aws:iam::111122223333:user/jsmith",
                                "sourceIP": "10.1.44.7", "eventTime": "2026-07-10T14:32:16Z"}],
    }
    out = correlate.format_backward_correlation(finding_ref, priors, correlation=correlation)
    assert "rec-abc123" in out
    assert "consequence" in out.lower()
    assert "Last change to this resource" in out
    assert "AuthorizeSecurityGroupEgress" in out
    assert "arn:aws:iam::111122223333:user/jsmith" in out


def test_format_backward_correlation_attribution_none_is_graceful():
    finding_ref = {"resource_id": "sg-x", "resource_type": "AWS::EC2::SecurityGroup"}
    # No priors AND no correlation: must not crash, and must state no write event.
    out = correlate.format_backward_correlation(finding_ref, [], correlation=None)
    assert "No prior recommendations" in out
    assert "No write event found" in out


def test_run_finding_mode_check_prior_includes_attribution(monkeypatch):
    s3 = FakeS3({
        "journals/space=as-1/dt=2026-07-10/exe-def456.json": {
            "execution_id": "exe-def456",
            "journal_records": [
                {"recordType": "investigation_result",
                 "content": json.dumps({"type": "investigation_result",
                                        "text": "root cause: sg-0123456789abcdef0 egress too broad"})},
            ],
        },
        "recommendations/rec-abc123/v1.json": {
            "recommendationId": "rec-abc123", "version": 1, "status": "ACCEPTED",
            "title": "Authorize egress on sg-0123456789abcdef0 to 10.0.2.0/24:3306"},
    })
    captured = {}

    def fake_correlate(region, resource_id, resource_name, resource_type, incident_time, window_hours):
        captured["resource_id"] = resource_id
        return {"resolved": {"resourceType": resource_type, "resourceId": resource_id},
                "correlated_changes": [{"eventName": "AuthorizeSecurityGroupEgress",
                                        "actor": "arn:aws:iam::111122223333:user/jsmith",
                                        "sourceIP": "10.1.44.7", "eventTime": "2026-07-10T14:32:16Z"}]}

    monkeypatch.setattr(correlate, "correlate", fake_correlate)
    out = correlate.run_finding_mode(s3, "bucket", "exe-def456", region="us-east-1",
                                     window_hours=24, incident_time=None,
                                     check_prior_recommendations=True)
    assert captured["resource_id"] == "sg-0123456789abcdef0"
    assert "rec-abc123" in out
    assert "AuthorizeSecurityGroupEgress" in out
    assert "arn:aws:iam::111122223333:user/jsmith" in out


# ---------------------------------------------------------------------------
# Incident provenance: which investigations produced this advice.
#
# A recommendation's `content.summary` carries two identity fields the resource
# heuristic cannot see: `affected_incidents` (incident id -> timestamp) and
# `provenance.content_producing_execution_ids` (a stable cluster id, `…-pi-groupN`).
# Shapes below match what the API returns.
# ---------------------------------------------------------------------------


def _rec_with_provenance(rid, version, incidents, group, method="carried_forward", **top):
    summary = {"overview": "Tighten the egress rule on sg-0123456789abcdef0.",
               "affected_incidents": incidents,
               "provenance": {"content_producing_execution_ids": [group],
                              "production_method": method}}
    return _rec(summary, recommendationId=rid, version=version, **top)


def test_extract_incident_refs_reads_affected_incidents_and_group():
    rec = _rec_with_provenance(
        "rec-aaaa1111", 2,
        {"bbbbbbbb-5555-6666-7777-888888888888": "2026-07-02T18:09:08.809000+00:00"},
        "0123456789abcdef0123456789abcdef-pi-group1")
    refs = correlate.extract_incident_refs(rec)
    assert refs["incidents"] == {
        "bbbbbbbb-5555-6666-7777-888888888888": "2026-07-02T18:09:08.809000+00:00"}
    assert refs["provenance_group"] == "0123456789abcdef0123456789abcdef-pi-group1"
    assert refs["production_method"] == "carried_forward"
    assert refs["malformed"] is None


def test_extract_incident_refs_absent_fields_are_empty_not_an_error():
    # Many archived objects carry neither field. That is normal, not malformed.
    refs = correlate.extract_incident_refs(_rec({"overview": "no provenance here"}))
    assert refs["incidents"] == {}
    assert refs["provenance_group"] is None
    assert refs["malformed"] is None


def test_extract_incident_refs_flags_unparseable_summary():
    # content.summary is a JSON string. If it is not parseable we must say so,
    # not silently report "no incidents" — that reads as a proven negative.
    rec = {"recommendationId": "rec-bad", "content": {"summary": "{not json"}}
    refs = correlate.extract_incident_refs(rec)
    assert refs["malformed"]
    assert "summary" in refs["malformed"]


def test_extract_incident_refs_flags_wrong_typed_affected_incidents():
    # A list instead of the documented id->timestamp map: flag it, don't crash
    # and don't report a clean empty.
    rec = _rec({"affected_incidents": ["bbbbbbbb-5555-6666-7777-888888888888"]},
               recommendationId="rec-listy")
    refs = correlate.extract_incident_refs(rec)
    assert refs["incidents"] == {}
    assert refs["malformed"]
    assert "affected_incidents" in refs["malformed"]


def _journal(execution_id, task_id, dt="2026-07-23"):
    return (f"journals/space=as-1/dt={dt}/{execution_id}.json",
            {"execution_id": execution_id, "task_id": task_id, "journal_records": []})


def test_journal_task_index_maps_incident_id_to_execution_id():
    # Live shape: the recommendation's incident id is the journal's `task_id`,
    # which is NOT a substring of the execution id — the join has to go through
    # the payload, not the object key.
    key, body = _journal("exe-ops1-11111111-2222-3333-4444-555555555555",
                         "aaaaaaaa-1111-2222-3333-444444444444")
    index = correlate.journal_task_index(FakeS3({key: body}), "bucket")
    assert index == {"aaaaaaaa-1111-2222-3333-444444444444":
                     "exe-ops1-11111111-2222-3333-4444-555555555555"}


def test_journal_task_index_skips_journals_with_no_task_id():
    key = "journals/space=as-1/dt=2026-07-23/exe-notask.json"
    index = correlate.journal_task_index(
        FakeS3({key: {"execution_id": "exe-notask", "journal_records": []}}), "bucket")
    assert index == {}


def test_resolve_incidents_separates_archived_from_unarchived():
    # Recommendations outlive the archive's start date: advice generated before
    # the pipeline was deployed references incidents no journal was captured for.
    # Those must be reported as referenced-but-unarchived, and must not stop the
    # resolvable ones from resolving.
    index = {"aaaaaaaa-1111-2222-3333-444444444444":
             "exe-ops1-11111111-2222-3333-4444-555555555555"}
    incidents = {"aaaaaaaa-1111-2222-3333-444444444444": "2026-07-23T22:13:11+00:00",
                 "bbbbbbbb-5555-6666-7777-888888888888": "2026-07-02T18:09:08+00:00"}
    resolved = correlate.resolve_incidents(incidents, index)
    assert resolved == [
        {"incident_id": "bbbbbbbb-5555-6666-7777-888888888888",
         "incident_time": "2026-07-02T18:09:08+00:00", "execution_id": None},
        {"incident_id": "aaaaaaaa-1111-2222-3333-444444444444",
         "incident_time": "2026-07-23T22:13:11+00:00",
         "execution_id": "exe-ops1-11111111-2222-3333-4444-555555555555"},
    ]


def test_resolve_incidents_orders_oldest_first_for_a_readable_timeline():
    index = {}
    incidents = {"inc-b": "2026-07-20T00:00:00+00:00", "inc-a": "2026-07-02T00:00:00+00:00"}
    assert [r["incident_id"] for r in correlate.resolve_incidents(incidents, index)] \
        == ["inc-a", "inc-b"]


def test_group_by_provenance_collapses_advice_repeated_across_runs():
    # Live shape (group fe7380c2…-pi-group1): one piece of advice re-created by
    # five weekly evaluation runs. Five recommendationIds, five taskIds, one
    # createdAt. Reporting five entries would read as five separate findings.
    incidents = {"bbbbbbbb-5555-6666-7777-888888888888": "2026-07-02T18:09:08+00:00"}
    group = "0123456789abcdef0123456789abcdef-pi-group1"
    recs = [
        _rec_with_provenance("rec-aaaa1111", 2, incidents, group, status="UPDATE_IN_PROGRESS",
                             taskId="task2222", createdAt="2026-07-02 22:09:01.237000+00:00",
                             updatedAt="2026-08-01 15:17:15.329000+00:00"),
        _rec_with_provenance("rec-bbbb2222", 2, incidents, group, status="UPDATE_IN_PROGRESS",
                             taskId="task3333", createdAt="2026-07-02 22:09:01.237000+00:00",
                             updatedAt="2026-07-09 21:37:53.698000+00:00"),
        _rec_with_provenance("rec-cccc3333", 1, incidents, group, status="PROPOSED",
                             taskId="task1111", createdAt="2026-07-02 22:09:01.237000+00:00",
                             updatedAt="2026-07-02 22:09:01.237000+00:00"),
    ]
    groups = correlate.group_by_provenance(recs)
    assert len(groups) == 1
    g = groups[0]
    assert g["provenance_group"] == group
    assert g["recommendation_ids"] == ["rec-aaaa1111", "rec-bbbb2222", "rec-cccc3333"]
    assert g["run_task_ids"] == ["task1111", "task2222", "task3333"]
    assert g["first_created"] == "2026-07-02 22:09:01.237000+00:00"
    assert g["last_updated"] == "2026-08-01 15:17:15.329000+00:00"
    assert g["incidents"] == incidents
    assert g["latest"]["recommendationId"] == "rec-aaaa1111"  # newest updatedAt


def test_group_by_provenance_keeps_ungrouped_recommendations_separate():
    # No provenance field: each recommendation is its own entry, as before.
    recs = [_rec({"overview": "advice a"}, recommendationId="rec-a", version=1),
            _rec({"overview": "advice b"}, recommendationId="rec-b", version=1)]
    groups = correlate.group_by_provenance(recs)
    assert [g["recommendation_ids"] for g in groups] == [["rec-a"], ["rec-b"]]
    assert all(g["provenance_group"] is None for g in groups)


def test_group_by_provenance_carries_the_malformed_reason_forward():
    recs = [{"recommendationId": "rec-bad", "version": 1, "content": {"summary": "{not json"}}]
    groups = correlate.group_by_provenance(recs)
    assert len(groups) == 1
    assert groups[0]["malformed"]


def test_format_backward_correlation_collapses_a_group_and_names_the_other_ids():
    ref = {"resource_id": "sg-0123456789abcdef0", "resource_type": "AWS::EC2::SecurityGroup"}
    group = "0123456789abcdef0123456789abcdef-pi-group1"
    incidents = {"bbbbbbbb-5555-6666-7777-888888888888": "2026-07-02T18:09:08+00:00"}
    priors = [
        _rec_with_provenance("rec-aaaa1111", 2, incidents, group, status="UPDATE_IN_PROGRESS",
                             taskId="task2222", title="Authorize egress on sg-0123456789abcdef0",
                             createdAt="2026-07-02 22:09:01+00:00",
                             updatedAt="2026-08-01 15:17:15+00:00"),
        _rec_with_provenance("rec-bbbb2222", 2, incidents, group, status="UPDATE_IN_PROGRESS",
                             taskId="task3333", title="Authorize egress on sg-0123456789abcdef0",
                             createdAt="2026-07-02 22:09:01+00:00",
                             updatedAt="2026-07-09 21:37:53+00:00"),
    ]
    out = correlate.format_backward_correlation(ref, priors)
    # One headline entry, not two competing findings.
    assert out.count("Authorize egress on sg-0123456789abcdef0") == 1
    assert "2 evaluation runs" in out
    assert "rec-bbbb2222" in out       # the other id is still named, for audit
    assert "2026-08-01 15:17:15+00:00" in out


def test_format_backward_correlation_resolves_and_reports_unarchived_incidents():
    ref = {"resource_id": "sg-0123456789abcdef0", "resource_type": "AWS::EC2::SecurityGroup"}
    incidents = {"aaaaaaaa-1111-2222-3333-444444444444": "2026-07-23T22:13:11+00:00",
                 "bbbbbbbb-5555-6666-7777-888888888888": "2026-07-02T18:09:08+00:00"}
    priors = [_rec_with_provenance("rec-abc123", 1, incidents, "grp-1", status="PROPOSED",
                                   title="Authorize egress")]
    index = {"aaaaaaaa-1111-2222-3333-444444444444":
             "exe-ops1-11111111-2222-3333-4444-555555555555"}
    out = correlate.format_backward_correlation(ref, priors, journal_index=lambda: index)
    assert "exe-ops1-11111111-2222-3333-4444-555555555555" in out
    # The unresolvable one is still reported, and labelled as an archive gap
    # rather than dropped — dropping it would read as "this advice had no origin".
    assert "bbbbbbbb-5555-6666-7777-888888888888" in out
    assert "not in this archive" in out


def test_incidents_are_not_called_unarchived_when_no_index_was_consulted():
    # Criterion: the renderer must never assert a fact it did not check. With no
    # index, nothing was looked up, so "not in this archive" would be a claim about
    # the archive's coverage that no read supports. The reference is still named.
    ref = {"resource_id": "sg-0123456789abcdef0", "resource_type": "AWS::EC2::SecurityGroup"}
    incidents = {"bbbbbbbb-5555-6666-7777-888888888888": "2026-07-02T18:09:08+00:00"}
    priors = [_rec_with_provenance("rec-abc123", 1, incidents, "grp-1", status="PROPOSED",
                                   title="Authorize egress")]
    out = correlate.format_backward_correlation(ref, priors)
    assert "bbbbbbbb-5555-6666-7777-888888888888" in out
    assert "not in this archive" not in out
    assert "no archive index was consulted" in out


def test_format_backward_correlation_still_reports_recs_with_no_incident_refs():
    # Resource-identity-only recommendations must keep reporting exactly as they
    # did before incident provenance existed.
    ref = {"resource_id": "sg-0123456789abcdef0", "resource_type": "AWS::EC2::SecurityGroup"}
    priors = [{"recommendationId": "rec-plain", "version": 1, "status": "PROPOSED",
               "title": "Authorize egress on sg-0123456789abcdef0"}]
    out = correlate.format_backward_correlation(ref, priors)
    assert "rec-plain" in out
    assert "consequence" in out.lower()
    assert "Produced by investigation" not in out
    assert "not in this archive" not in out


def test_format_backward_correlation_flags_malformed_provenance():
    ref = {"resource_id": "sg-0123456789abcdef0", "resource_type": "AWS::EC2::SecurityGroup"}
    priors = [{"recommendationId": "rec-bad", "version": 1, "status": "PROPOSED",
               "title": "Authorize egress", "content": {"summary": "{not json"}}]
    out = correlate.format_backward_correlation(ref, priors)
    assert "rec-bad" in out
    assert "could not be read" in out.lower() or "unreadable" in out.lower()


def test_format_recommendation_correlation_traces_producing_investigations():
    # Criterion 1 on the forward path: from a recommendation, name the
    # investigations that produced it and resolve them to archived journals.
    incidents = {"aaaaaaaa-1111-2222-3333-444444444444": "2026-07-23T22:13:11+00:00"}
    versions = [_rec_with_provenance("rec-dddd4444", 1, incidents,
                                     "fedcba9876543210fedcba9876543210-pi-group1",
                                     method="generated", status="PROPOSED",
                                     title="Authorize egress on sg-0123456789abcdef0",
                                     taskId="task1111")]
    correlation = {"resolved": {}, "config_history": [], "correlated_changes": []}
    index = {"aaaaaaaa-1111-2222-3333-444444444444":
             "exe-ops1-11111111-2222-3333-4444-555555555555"}
    out = correlate.format_recommendation_correlation(versions, correlation,
                                                      journal_index=lambda: index)
    assert "Produced by investigation" in out
    assert "exe-ops1-11111111-2222-3333-4444-555555555555" in out


def test_forward_trace_uses_incidents_from_all_groups_when_provenance_varies():
    # Criterion: when v1 has no provenance and v2 gains a provenance group,
    # group_by_provenance returns two groups. The forward trace must still render
    # the incidents from v2's group, not silently drop them because [0] is the
    # no-provenance version.
    incidents = {"aaaaaaaa-1111-2222-3333-444444444444": "2026-07-23T22:13:11+00:00"}
    v1 = {"recommendationId": "rec-abc", "version": 1, "status": "PROPOSED",
          "title": "Authorize egress", "createdAt": "2026-07-01", "updatedAt": "2026-07-01"}
    v2 = _rec_with_provenance("rec-abc", 2, incidents, "grp-1", method="generated",
                              status="ACCEPTED", title="Authorize egress",
                              createdAt="2026-07-01", updatedAt="2026-08-01")
    correlation = {"resolved": {}, "config_history": [], "correlated_changes": []}
    index = {"aaaaaaaa-1111-2222-3333-444444444444":
             "exe-ops1-11111111-2222-3333-4444-555555555555"}
    out = correlate.format_recommendation_correlation(
        [v1, v2], correlation, journal_index=lambda: index)
    assert "Produced by investigation" in out
    assert "exe-ops1-11111111-2222-3333-4444-555555555555" in out


def test_group_by_provenance_handles_null_version_without_crashing():
    # The API can return "version": null for a recommendation. When two recs
    # share a provenance group and have the same updatedAt, the tie-breaker
    # compares versions. `None >= 0` raises TypeError.
    s = json.dumps({"overview": "test",
                    "affected_incidents": {"inc-1": "2026-07-02T18:09:08+00:00"},
                    "provenance": {"content_producing_execution_ids": ["grp-1"],
                                   "production_method": "carried_forward"}})
    rec1 = {"recommendationId": "rec-aaa", "version": None, "updatedAt": "2026-08-01",
            "content": {"summary": s}}
    rec2 = {"recommendationId": "rec-bbb", "version": 2, "updatedAt": "2026-08-01",
            "content": {"summary": s}}
    groups = correlate.group_by_provenance([rec1, rec2])
    assert len(groups) == 1
    # The versioned rec wins the tie-break.
    assert groups[0]["latest"]["recommendationId"] == "rec-bbb"


def test_format_recommendation_correlation_without_index_is_unchanged():
    versions = [{"recommendationId": "rec-plain", "version": 1, "status": "PROPOSED",
                 "title": "Authorize egress"}]
    out = correlate.format_recommendation_correlation(
        versions, {"resolved": {}, "config_history": [], "correlated_changes": []})
    assert "Produced by investigation" not in out


def test_run_finding_mode_resolves_incident_provenance_end_to_end(monkeypatch):
    # The whole Change B path: journal -> resource -> prior advice -> the
    # investigations behind that advice, one of which is not archived.
    jkey, jbody = _journal("exe-ops1-11111111-2222-3333-4444-555555555555",
                           "aaaaaaaa-1111-2222-3333-444444444444")
    jbody["journal_records"] = [
        {"recordType": "finding",
         "content": json.dumps({"type": "finding",
                                "text": "cause: sg-0123456789abcdef0 egress too broad"})}]
    incidents = {"aaaaaaaa-1111-2222-3333-444444444444": "2026-07-23T22:13:11+00:00",
                 "bbbbbbbb-5555-6666-7777-888888888888": "2026-07-02T18:09:08+00:00"}
    s3 = FakeS3({
        jkey: jbody,
        "recommendations/rec-abc123/v1.json": _rec_with_provenance(
            "rec-abc123", 1, incidents, "grp-1", status="PROPOSED",
            title="Authorize egress on sg-0123456789abcdef0"),
    })
    monkeypatch.setattr(correlate, "correlate",
                        lambda *a, **k: {"resolved": None, "correlated_changes": []})
    out = correlate.run_finding_mode(
        s3, "bucket", "exe-ops1-11111111-2222-3333-4444-555555555555",
        region="us-east-1", window_hours=24, incident_time=None,
        check_prior_recommendations=True)
    assert "exe-ops1-11111111-2222-3333-4444-555555555555" in out
    assert "bbbbbbbb-5555-6666-7777-888888888888" in out
    assert "not in this archive" in out


def test_run_recommendation_mode_resolves_incident_provenance_end_to_end(monkeypatch):
    jkey, jbody = _journal("exe-ops1-11111111-2222-3333-4444-555555555555",
                           "aaaaaaaa-1111-2222-3333-444444444444")
    s3 = FakeS3({
        jkey: jbody,
        "recommendations/rec-abc123/v1.json": _rec_with_provenance(
            "rec-abc123", 1, {"aaaaaaaa-1111-2222-3333-444444444444": "2026-07-23T22:13:11+00:00"},
            "grp-1", status="PROPOSED", title="Authorize egress on sg-0123456789abcdef0"),
    })
    monkeypatch.setattr(correlate, "correlate",
                        lambda *a, **k: {"resolved": {}, "config_history": [],
                                         "correlated_changes": []})
    out = correlate.run_recommendation_mode(s3, "bucket", "rec-abc123", region="us-east-1",
                                           window_hours=24, incident_time=None)
    assert "exe-ops1-11111111-2222-3333-4444-555555555555" in out


class CountingS3(FakeS3):
    """FakeS3 that records archive reads, so a test can assert none happened.

    The behavior under test is the absence of I/O — a full scan of journals/ costs
    one LIST plus one GetObject per object, and doing it when there is nothing to
    resolve is pure waste. Counting is the only way to observe that from outside.
    """
    def __init__(self, objects):
        super().__init__(objects)
        self.list_calls = 0
        self.get_calls = 0

    def get_paginator(self, name):
        self.list_calls += 1
        return super().get_paginator(name)

    def get_object(self, Bucket, Key):
        self.get_calls += 1
        return super().get_object(Bucket=Bucket, Key=Key)


def _journal_archive():
    return {
        "journals/space=as-1/dt=2026-07-23/exe-ops1-11111111-2222-3333-4444-555555555555.json": {
            "execution_id": "exe-ops1-11111111-2222-3333-4444-555555555555",
            "task_id": "aaaaaaaa-1111-2222-3333-444444444444",
        },
        "journals/space=as-1/dt=2026-07-02/exe-ops1-99999999-8888-7777-6666-555555555555.json": {
            "execution_id": "exe-ops1-99999999-8888-7777-6666-555555555555",
            "task_id": "bbbbbbbb-5555-6666-7777-888888888888",
        },
    }


def test_journal_index_provider_does_not_touch_the_archive_until_called():
    # Building the provider must be free. The scan is what costs.
    s3 = CountingS3(_journal_archive())
    correlate.journal_index_provider(s3, "bucket")
    assert (s3.list_calls, s3.get_calls) == (0, 0)


def test_journal_index_provider_scans_once_when_called_repeatedly():
    s3 = CountingS3(_journal_archive())
    provider = correlate.journal_index_provider(s3, "bucket")
    first = provider()
    second = provider()
    assert first == second
    assert first["aaaaaaaa-1111-2222-3333-444444444444"] == \
        "exe-ops1-11111111-2222-3333-4444-555555555555"
    assert s3.list_calls == 1
    assert s3.get_calls == 2   # one per journal, once — not twice


def test_journal_index_provider_caches_an_empty_archive_too():
    # A genuinely empty archive still resolves to "scanned", so repeated calls
    # must not re-LIST looking for something that is not there.
    s3 = CountingS3({})
    provider = correlate.journal_index_provider(s3, "bucket")
    assert provider() == {}
    assert provider() == {}
    assert s3.list_calls == 1


def test_recommendation_with_no_incidents_never_reads_the_journal_archive():
    # Criterion: advice that names no investigations costs nothing to render.
    s3 = CountingS3(_journal_archive())
    versions = [{"recommendationId": "rec-plain", "version": 1, "status": "PROPOSED",
                 "title": "Authorize egress on sg-0123456789abcdef0"}]
    correlation = {"resolved": {}, "config_history": [], "correlated_changes": []}
    out = correlate.format_recommendation_correlation(
        versions, correlation, journal_index=correlate.journal_index_provider(s3, "bucket"))
    assert "rec-plain" in out
    assert "Produced by investigation" not in out
    assert (s3.list_calls, s3.get_calls) == (0, 0)


def test_finding_with_no_incident_refs_never_reads_the_journal_archive():
    s3 = CountingS3(_journal_archive())
    ref = {"resource_id": "sg-0123456789abcdef0", "resource_type": "AWS::EC2::SecurityGroup"}
    priors = [{"recommendationId": "rec-plain", "version": 1, "status": "PROPOSED",
               "title": "Authorize egress on sg-0123456789abcdef0"}]
    out = correlate.format_backward_correlation(
        ref, priors, journal_index=correlate.journal_index_provider(s3, "bucket"))
    assert "rec-plain" in out
    assert (s3.list_calls, s3.get_calls) == (0, 0)


def test_several_provenance_groups_share_one_archive_scan():
    # Criterion: the archive is scanned once per invocation, not once per group.
    s3 = CountingS3(_journal_archive())
    ref = {"resource_id": "sg-0123456789abcdef0", "resource_type": "AWS::EC2::SecurityGroup"}
    priors = [
        _rec_with_provenance("rec-aaaa1111", 1,
                             {"aaaaaaaa-1111-2222-3333-444444444444": "2026-07-23T22:13:11+00:00"},
                             "grp-1", title="Authorize egress", taskId="task1111"),
        _rec_with_provenance("rec-bbbb2222", 1,
                             {"bbbbbbbb-5555-6666-7777-888888888888": "2026-07-02T18:09:08+00:00"},
                             "grp-2", title="Restrict ingress", taskId="task2222"),
    ]
    out = correlate.format_backward_correlation(
        ref, priors, journal_index=correlate.journal_index_provider(s3, "bucket"))
    assert "exe-ops1-11111111-2222-3333-4444-555555555555" in out
    assert "exe-ops1-99999999-8888-7777-6666-555555555555" in out
    assert s3.list_calls == 1
