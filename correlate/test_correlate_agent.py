import json
from datetime import datetime, timezone

import correlate_agent


# Shapes captured from a live approval, with identifiers replaced by
# placeholders. The shapes are what matter: the approval pins a JSON *string*
# rule list while EC2 logs a nested request object, which is the whole reason
# the pin check compares leaf values.
APPROVAL_ID = "019f0000-1111-7222-8333-444455556666"
SESSION_NAME = "op.system.apr.019f0000-1111-72"
OPERATOR_ARN = ("arn:aws:sts::123456789012:assumed-role/"
                "DevOpsAgentRole-AgentSpace-EXAMPLE1/AROAEXAMPLE-alice")
AGENT_SESSION_ARN = ("arn:aws:sts::123456789012:assumed-role/"
                     f"DevOpsAgentActionsRole-AgentSpace-EXAMPLE2/{SESSION_NAME}")

PINNED_RULES = json.dumps([{
    "SecurityGroupRule": {"CidrIpv4": "0.0.0.0/0", "FromPort": 443,
                          "IpProtocol": "tcp", "ToPort": 443},
    "SecurityGroupRuleId": "sgr-0d28445c956a5d8ac",
}])

EXECUTED_PARAMS = {
    "ModifySecurityGroupRulesRequest": {
        "SecurityGroupRule": {
            "SecurityGroupRuleId": "sgr-0d28445c956a5d8ac",
            "tag": 1,
            "SecurityGroupRule": {"CidrIpv4": "0.0.0.0/0", "FromPort": 443,
                                  "ToPort": 443, "IpProtocol": "tcp"},
        },
        "GroupId": "sg-0123456789abcdef0",
    }
}


def _approval_event(approval_id=APPROVAL_ID, action="APPROVED", pins=None,
                    recorded=True, event_time="2026-08-02T21:32:32Z"):
    response = ({"approvalId": approval_id, "status": action,
                 "expiresAt": 1785709952.005613} if recorded else None)
    return {
        "eventName": "UpdateApprovalAction",
        "eventSource": "aidevops.amazonaws.com",
        "eventTime": event_time,
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.10",
        "userAgent": "Mozilla/5.0",
        "userIdentity": {"arn": OPERATOR_ARN},
        "requestParameters": {
            "action": action,
            "singleUse": True,
            "finalPattern": {"tool": "use_aws", "argumentPins": pins if pins is not None else {
                "operation": "ec2:ModifySecurityGroupRules",
                "region": "us-east-1",
                "GroupId": "sg-0123456789abcdef0",
                "SecurityGroupRules": PINNED_RULES,
            }},
        },
        "responseElements": response,
        "resources": [{"type": "AWS::AIDevOps::AgentSpace",
                       "ARN": "arn:aws:aidevops:us-east-1:123456789012:agentspace/space-1"}],
    }


def _assume_role_event(approval_id=APPROVAL_ID, session_name=SESSION_NAME):
    return {
        "eventName": "AssumeRole",
        "eventSource": "sts.amazonaws.com",
        "eventTime": "2026-08-02T21:32:33Z",
        "requestParameters": {
            "roleArn": ("arn:aws:iam::123456789012:role/service-role/"
                        "DevOpsAgentActionsRole-AgentSpace-EXAMPLE2"),
            "roleSessionName": session_name,
            "externalId": approval_id,
            "durationSeconds": 900,
            "policy": json.dumps({"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Action": "ec2:ModifySecurityGroupRules", "Resource": "*"},
                {"Effect": "Allow", "Action": ["a:Tag", "b:Tag", "c:Tag", "d:Tag"], "Resource": "*"},
                {"Effect": "Allow", "Action": "*", "Resource": "*",
                 "Condition": {"Bool": {"aws:ViaAWSService": "true"}}},
            ]}),
        },
        "responseElements": {"credentials": {"expiration": "2026-08-02T21:47:33Z"}},
    }


def _write_event(params=None, operation=("ec2", "ModifySecurityGroupRules"),
                 region="us-east-1", read_only=False, error_code=None):
    source, name = operation
    return {
        "eventName": name,
        "eventSource": f"{source}.amazonaws.com",
        "eventTime": "2026-08-02T21:32:34Z",
        "eventID": "evt-1",
        "awsRegion": region,
        "readOnly": read_only,
        "errorCode": error_code,
        "userIdentity": {
            "arn": AGENT_SESSION_ARN,
            "invokedBy": "aidevops.amazonaws.com",
            "sessionContext": {"sourceIdentity": SESSION_NAME},
        },
        "requestParameters": EXECUTED_PARAMS if params is None else params,
    }


class FakeCT:
    """CloudTrail stub that answers per-lookup-attribute, like the real index.

    Records every lookup so tests can assert on HOW MANY scans happened, not
    just the output — the AssumeRole scan is the tool's expensive call and the
    per-approval-rescan regression is invisible in results alone.
    """

    def __init__(self, by_event_name=None, by_username=None):
        self.by_event_name = by_event_name or {}
        self.by_username = by_username or {}
        self.lookups = []

    def lookup_events(self, **kwargs):
        attr = kwargs["LookupAttributes"][0]
        key, value = attr["AttributeKey"], attr["AttributeValue"]
        self.lookups.append((key, value))
        events = (self.by_event_name if key == "EventName" else self.by_username).get(value, [])
        return {"Events": [{"CloudTrailEvent": json.dumps(e)} for e in events]}

    def scan_count(self, key, value):
        return sum(1 for k, v in self.lookups if k == key and v == value)


WINDOW = (datetime(2026, 8, 2, 21, 0, tzinfo=timezone.utc),
          datetime(2026, 8, 2, 22, 0, tzinfo=timezone.utc))


# --- approval enumeration ---------------------------------------------------

def test_find_approvals_extracts_decision_and_pins():
    ct = FakeCT(by_event_name={"UpdateApprovalAction": [_approval_event()]})
    approvals = correlate_agent.find_approvals(ct, WINDOW)
    assert len(approvals) == 1
    a = approvals[0]
    assert a["approvalId"] == APPROVAL_ID
    assert a["decision"] == "APPROVED"
    assert a["approvedBy"] == OPERATOR_ARN
    assert a["argumentPins"]["GroupId"] == "sg-0123456789abcdef0"
    assert a["recorded"] is True


def test_find_approvals_flags_unrecorded_attempt_rather_than_dropping_it():
    # A click that produced no approvalId minted no credential. Keeping it is
    # deliberate: a run of these beside one success is the visible signature of
    # an operator retrying a broken approval.
    ct = FakeCT(by_event_name={"UpdateApprovalAction": [_approval_event(recorded=False)]})
    approvals = correlate_agent.find_approvals(ct, WINDOW)
    assert len(approvals) == 1
    assert approvals[0]["recorded"] is False
    assert approvals[0]["approvalId"] is None


def test_find_approvals_filters_to_requested_id():
    other = _approval_event(approval_id="019f0000-0000-7000-8000-000000000000",
                            event_time="2026-08-02T21:10:00Z")
    ct = FakeCT(by_event_name={"UpdateApprovalAction": [_approval_event(), other]})
    approvals = correlate_agent.find_approvals(ct, WINDOW, approval_id=APPROVAL_ID)
    assert [a["approvalId"] for a in approvals] == [APPROVAL_ID]


def test_find_approvals_sorts_newest_first():
    older = _approval_event(approval_id="019f0000-0000-7000-8000-000000000000",
                            event_time="2026-08-02T21:05:00Z")
    ct = FakeCT(by_event_name={"UpdateApprovalAction": [older, _approval_event()]})
    times = [a["approvedAt"] for a in correlate_agent.find_approvals(ct, WINDOW)]
    assert times == sorted(times, reverse=True)


def test_expires_at_epoch_is_rendered_as_iso():
    ct = FakeCT(by_event_name={"UpdateApprovalAction": [_approval_event()]})
    expires = correlate_agent.find_approvals(ct, WINDOW)[0]["expiresAt"]
    assert expires.startswith("2026-08-02T22:32:32")


# --- session resolution -----------------------------------------------------

def test_derive_session_name_matches_observed_convention():
    assert correlate_agent.derive_session_name(APPROVAL_ID) == SESSION_NAME


def test_index_approval_sessions_keys_on_external_id():
    ct = FakeCT(by_event_name={"AssumeRole": [_assume_role_event()]})
    index = correlate_agent.index_approval_sessions(ct, WINDOW)
    assert index[APPROVAL_ID]["sessionName"] == SESSION_NAME
    assert index[APPROVAL_ID]["durationSeconds"] == 900


def test_index_approval_sessions_ignores_unrelated_assume_roles():
    # An account is full of AssumeRole events; only approval-minted sessions
    # carry both an externalId and the approval session-name prefix.
    noise = {
        "eventName": "AssumeRole",
        "eventTime": "2026-08-02T21:31:00Z",
        "requestParameters": {"roleArn": "arn:aws:iam::1:role/other",
                              "roleSessionName": "some-ci-job"},
        "responseElements": {},
    }
    ct = FakeCT(by_event_name={"AssumeRole": [noise, _assume_role_event()]})
    index = correlate_agent.index_approval_sessions(ct, WINDOW)
    assert list(index) == [APPROVAL_ID]


def test_session_policy_summary_labels_via_aws_service_passthrough():
    # The wide `Action: *` statement is gated on aws:ViaAWSService. Listing it as
    # a plain grant would misrepresent the credential's real scope.
    ct = FakeCT(by_event_name={"AssumeRole": [_assume_role_event()]})
    policy = correlate_agent.index_approval_sessions(ct, WINDOW)[APPROVAL_ID]["sessionPolicy"]
    actions = correlate_agent._policy_actions(policy)
    assert "ec2:ModifySecurityGroupRules" in actions
    assert "(+ service-call passthrough)" in actions
    assert "*" not in actions


# --- session calls ----------------------------------------------------------

def test_find_session_calls_normalizes_operation_to_service_colon_name():
    ct = FakeCT(by_username={SESSION_NAME: [_write_event()]})
    calls = correlate_agent.find_session_calls(ct, SESSION_NAME, WINDOW)
    assert calls[0]["operation"] == "ec2:ModifySecurityGroupRules"
    assert calls[0]["sourceIdentity"] == SESSION_NAME


# --- pin checking -----------------------------------------------------------

def test_pins_satisfied_passes_despite_shape_difference():
    # The approval pins a JSON-string rule list; EC2 logs a nested object with an
    # extra positional `tag`. Structural equality would fail here; containment
    # of approved leaf values is the correct check.
    pins = {"operation": "ec2:ModifySecurityGroupRules", "region": "us-east-1",
            "GroupId": "sg-0123456789abcdef0", "SecurityGroupRules": PINNED_RULES}
    call = correlate_agent.find_session_calls(
        FakeCT(by_username={SESSION_NAME: [_write_event()]}), SESSION_NAME, WINDOW)[0]
    checks = correlate_agent._pins_satisfied(pins, call)
    assert all(c["match"] for c in checks)


def test_pins_satisfied_catches_wrong_target_resource():
    # The security property that matters: a call that targeted something other
    # than what the operator was shown must be reported.
    pins = {"operation": "ec2:ModifySecurityGroupRules", "region": "us-east-1",
            "GroupId": "sg-DIFFERENT", "SecurityGroupRules": PINNED_RULES}
    call = correlate_agent.find_session_calls(
        FakeCT(by_username={SESSION_NAME: [_write_event()]}), SESSION_NAME, WINDOW)[0]
    checks = {c["pin"]: c for c in correlate_agent._pins_satisfied(pins, call)}
    assert checks["GroupId"]["match"] is False
    assert checks["GroupId"]["missing"] == ["sg-DIFFERENT"]


def test_pins_satisfied_catches_wrong_port():
    # Approved 443, executed 80 — the exact substitution an approval gate exists
    # to prevent.
    approved_443 = json.dumps([{"SecurityGroupRule": {
        "CidrIpv4": "0.0.0.0/0", "FromPort": 443, "IpProtocol": "tcp", "ToPort": 443}}])
    executed_80 = {"ModifySecurityGroupRulesRequest": {
        "GroupId": "sg-0123456789abcdef0",
        "SecurityGroupRule": {"SecurityGroupRule": {
            "CidrIpv4": "0.0.0.0/0", "FromPort": 80, "ToPort": 80, "IpProtocol": "tcp"}}}}
    call = correlate_agent.find_session_calls(
        FakeCT(by_username={SESSION_NAME: [_write_event(params=executed_80)]}),
        SESSION_NAME, WINDOW)[0]
    checks = {c["pin"]: c for c in
              correlate_agent._pins_satisfied({"SecurityGroupRules": approved_443}, call)}
    assert checks["SecurityGroupRules"]["match"] is False
    assert "443" in checks["SecurityGroupRules"]["missing"]


def test_pins_satisfied_catches_wrong_operation():
    pins = {"operation": "ec2:ModifySecurityGroupRules"}
    call = correlate_agent.find_session_calls(
        FakeCT(by_username={SESSION_NAME: [
            _write_event(operation=("ec2", "AuthorizeSecurityGroupIngress"))]}),
        SESSION_NAME, WINDOW)[0]
    check = correlate_agent._pins_satisfied(pins, call)[0]
    assert check["match"] is False
    assert check["executed"] == "ec2:AuthorizeSecurityGroupIngress"


def test_pins_satisfied_catches_wrong_region():
    pins = {"region": "us-east-1"}
    call = correlate_agent.find_session_calls(
        FakeCT(by_username={SESSION_NAME: [_write_event(region="eu-west-1")]}),
        SESSION_NAME, WINDOW)[0]
    check = correlate_agent._pins_satisfied(pins, call)[0]
    assert check["match"] is False
    assert check["executed"] == "eu-west-1"


def test_boolean_pin_compares_case_insensitively_against_json():
    # JSON booleans are lowercase; a naive str() would make True != "true".
    assert correlate_agent._leaf_values(True) == {"true"}
    assert correlate_agent._leaf_values({"x": True}) == {"true"}


# --- end-to-end correlation -------------------------------------------------

def test_correlate_joins_approval_to_executed_call():
    ct = FakeCT(
        by_event_name={"UpdateApprovalAction": [_approval_event()],
                       "AssumeRole": [_assume_role_event()]},
        by_username={SESSION_NAME: [_write_event()]},
    )
    out = _run(ct)
    approval = out["approvals"][0]
    assert approval["approvalId"] == APPROVAL_ID
    assert len(approval["calls"]) == 1
    call = approval["calls"][0]
    assert call["operation"] == "ec2:ModifySecurityGroupRules"
    assert call["approvedValuesHonored"] is True
    assert call["viaAgentService"] is True


def test_unrecorded_approval_reports_why_no_call_exists():
    ct = FakeCT(by_event_name={"UpdateApprovalAction": [_approval_event(recorded=False)]})
    approval = _run(ct)["approvals"][0]
    assert approval["calls"] == []
    assert "no credential was minted" in approval["note"]


def test_recorded_approval_with_no_call_is_distinguished_from_unrecorded():
    # Approval succeeded but nothing ran — a real state (the agent errored, or
    # the resume was dropped). Must NOT be reported as "not recorded".
    ct = FakeCT(by_event_name={"UpdateApprovalAction": [_approval_event()],
                               "AssumeRole": []})
    approval = _run(ct)["approvals"][0]
    assert approval["recorded"] is True
    assert approval["calls"] == []
    assert "note" not in approval


def test_writes_only_filters_reads_by_default():
    ct = FakeCT(
        by_event_name={"UpdateApprovalAction": [_approval_event()], "AssumeRole": []},
        by_username={SESSION_NAME: [_write_event(read_only=True), _write_event()]},
    )
    assert len(_run(ct)["approvals"][0]["calls"]) == 1
    assert len(_run(ct, writes_only=False)["approvals"][0]["calls"]) == 2


def test_failed_call_retains_error_code():
    ct = FakeCT(
        by_event_name={"UpdateApprovalAction": [_approval_event()], "AssumeRole": []},
        by_username={SESSION_NAME: [_write_event(error_code="UnauthorizedOperation")]},
    )
    assert _run(ct)["approvals"][0]["calls"][0]["errorCode"] == "UnauthorizedOperation"


def test_assume_role_index_is_built_once_not_once_per_approval():
    # Regression guard. The AssumeRole scan is this tool's most expensive call;
    # rebuilding it per approval turned a 10-approval window into minutes.
    approvals = [_approval_event(approval_id=f"019f0000-1111-7222-8333-444455{i:06d}",
                                 event_time=f"2026-08-02T21:{i:02d}:00Z")
                 for i in range(5)]
    ct = FakeCT(by_event_name={"UpdateApprovalAction": approvals, "AssumeRole": []})
    _run(ct)
    assert ct.scan_count("EventName", "AssumeRole") == 1


def test_session_discovered_from_assume_role_when_convention_changes():
    # If the session-name convention shifts, the derived name finds nothing. The
    # tool must fall back to the authoritative externalId join rather than
    # silently reporting that the approval never ran.
    actual = "op.system.apr.CHANGED-FORMAT"
    ct = FakeCT(
        by_event_name={"UpdateApprovalAction": [_approval_event()],
                       "AssumeRole": [_assume_role_event(session_name=actual)]},
        by_username={actual: [_write_event()]},
    )
    approval = _run(ct)["approvals"][0]
    assert approval["sessionName"] == actual
    assert len(approval["calls"]) == 1


def test_resource_filter_keeps_only_matching_approvals():
    other = _approval_event(
        approval_id="019f0000-0000-7000-8000-000000000000",
        event_time="2026-08-02T21:05:00Z",
        pins={"operation": "ec2:ModifySecurityGroupRules", "GroupId": "sg-unrelated"},
    )
    ct = FakeCT(by_event_name={"UpdateApprovalAction": [_approval_event(), other],
                               "AssumeRole": []})
    out = _run(ct, resource_id="sg-0123456789abcdef0")
    assert [a["approvalId"] for a in out["approvals"]] == [APPROVAL_ID]


# --- formatting -------------------------------------------------------------

def test_format_shows_approval_then_execution_chain():
    ct = FakeCT(
        by_event_name={"UpdateApprovalAction": [_approval_event()],
                       "AssumeRole": [_assume_role_event()]},
        by_username={SESSION_NAME: [_write_event()]},
    )
    text = correlate_agent.format_agent_correlation(_run(ct, include_session_policy=True))
    assert APPROVAL_ID in text
    assert "Approved values honored: PASS" in text
    assert "ec2:ModifySecurityGroupRules" in text
    assert "joined on approval id" in text


def test_format_flags_mismatch_with_the_offending_pin():
    pins = {"operation": "ec2:ModifySecurityGroupRules", "GroupId": "sg-NOTTHISONE"}
    ct = FakeCT(
        by_event_name={"UpdateApprovalAction": [_approval_event(pins=pins)], "AssumeRole": []},
        by_username={SESSION_NAME: [_write_event()]},
    )
    text = correlate_agent.format_agent_correlation(_run(ct))
    assert "MISMATCH" in text
    assert "sg-NOTTHISONE" in text


def test_format_empty_window_says_so():
    text = correlate_agent.format_agent_correlation(
        {"window": ["2026-08-02T21:00:00Z", "2026-08-02T22:00:00Z"], "approvals": []})
    assert "No agent approval activity" in text


def test_format_unrecorded_attempt_does_not_claim_an_approval_id():
    ct = FakeCT(by_event_name={"UpdateApprovalAction": [_approval_event(recorded=False)]})
    text = correlate_agent.format_agent_correlation(_run(ct))
    assert "NOT RECORDED" in text
    assert "Approval:       None" not in text


# --- helper -----------------------------------------------------------------

def _run(ct, **kwargs):
    """Drive correlate_agent_actions against a FakeCT by patching the client."""
    real = correlate_agent._cloudtrail
    correlate_agent._cloudtrail = lambda region: ct
    try:
        return correlate_agent.correlate_agent_actions(
            "us-east-1", 1, end_time="2026-08-02T22:00:00Z", **kwargs)
    finally:
        correlate_agent._cloudtrail = real
