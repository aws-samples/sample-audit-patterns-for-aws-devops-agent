"""Tests for the Layer 2 journal archiver.

The behaviours that matter here are the ones a template test cannot see:
pagination is actually followed, redelivery does not write a second
Object-Locked version, and task enrichment failing does not cost us the
journal.
"""
import json

import pytest

from conftest import BUCKET, FakeAgent, FakeS3, client_error


def event(execution="exe-1", space="space-1234", task="task-9",
          time="2026-08-02T21:32:32Z", status="COMPLETED",
          detail_type="Investigation Completed"):
    detail = {
        "metadata": {"agent_space_id": space, "execution_id": execution},
        "data": {"status": status, "summary_record_id": "rec-sum-1"},
    }
    if task is not None:
        detail["metadata"]["task_id"] = task
    return {"detail": detail, "detail-type": detail_type, "time": time}


def body_of(put) -> dict:
    return json.loads(put["Body"].decode("utf-8"))


def test_archives_journal_to_a_key_derived_from_space_date_and_execution(
        load_journal_archiver):
    agent = FakeAgent(journal_pages=[{"records": [{"id": "r1"}, {"id": "r2"}]}])
    module, s3, _ = load_journal_archiver(agent=agent)

    result = module.handler(event(), None)

    assert s3.put_keys == ["journals/space=space-1234/dt=2026-08-02/exe-1.json"]
    assert result == {"archived": s3.put_keys[0], "records": 2}
    put = s3.puts[0]
    assert put["Bucket"] == BUCKET
    assert put["ContentType"] == "application/json"
    assert body_of(put)["record_count"] == 2


def test_follows_next_token_until_exhausted_and_archives_every_page(
        load_journal_archiver):
    # A single call is not guaranteed to return the whole journal. If the
    # handler stopped at page one it would silently archive a partial record.
    agent = FakeAgent(journal_pages=[
        {"records": [{"id": "r1"}], "nextToken": "t1"},
        {"records": [{"id": "r2"}], "nextToken": "t2"},
        {"records": [{"id": "r3"}]},
    ])
    module, s3, _ = load_journal_archiver(agent=agent)

    result = module.handler(event(), None)

    assert result["records"] == 3
    assert [r["id"] for r in body_of(s3.puts[0])["journal_records"]] == ["r1", "r2", "r3"]
    # The token from each page must be sent back on the next call.
    assert [r.get("nextToken") for r in agent.journal_requests] == [None, "t1", "t2"]


def test_conditional_put_prevents_a_second_locked_version_on_redelivery(
        load_journal_archiver):
    # EventBridge is at-least-once and the bucket is versioned + Object-Locked,
    # so an unconditional put would create a new, un-prunable version per
    # redelivery. IfNoneMatch='*' is what makes the write a no-op instead.
    module, s3, _ = load_journal_archiver()

    module.handler(event(), None)

    assert s3.puts[0]["IfNoneMatch"] == "*"


def test_precondition_failed_is_the_redelivery_success_path_not_an_error(
        load_journal_archiver):
    # Raising here would send an event to the DLQ even though the archive is
    # intact, which turns a healthy redelivery into a false alarm.
    def already_exists(**_):
        raise client_error("PreconditionFailed", "PutObject")

    agent = FakeAgent(journal_pages=[{"records": [{"id": "r1"}]}])
    module, s3, _ = load_journal_archiver(s3=FakeS3(put=already_exists), agent=agent)

    result = module.handler(event(), None)

    assert result == {"archived": s3.put_keys[0], "records": 1,
                     "already_archived": True}


def test_other_s3_errors_raise_so_the_event_reaches_the_dlq(load_journal_archiver):
    def denied(**_):
        raise client_error("AccessDenied", "PutObject")

    module, _, _ = load_journal_archiver(s3=FakeS3(put=denied))

    with pytest.raises(Exception) as excinfo:
        module.handler(event(), None)
    assert "AccessDenied" in str(excinfo.value)


def test_journal_fetch_failure_raises_before_any_write(load_journal_archiver):
    agent = FakeAgent(list_error=client_error("ThrottlingException",
                                              "ListJournalRecords"))
    module, s3, _ = load_journal_archiver(agent=agent)

    with pytest.raises(Exception):
        module.handler(event(), None)
    assert s3.puts == []


def test_task_enrichment_failure_does_not_cost_us_the_journal(load_journal_archiver):
    # Task metadata is supplementary; the journal is the audit record. A failure
    # enriching the former must not lose the latter.
    agent = FakeAgent(journal_pages=[{"records": [{"id": "r1"}]}],
                      task=client_error("ResourceNotFoundException",
                                        "GetBacklogTask"))
    module, s3, _ = load_journal_archiver(agent=agent)

    result = module.handler(event(), None)

    assert result["records"] == 1
    assert body_of(s3.puts[0])["task"] == {}


def test_task_detail_is_included_when_enrichment_succeeds(load_journal_archiver):
    agent = FakeAgent(journal_pages=[{"records": []}],
                      task={"title": "audit-trail verification",
                            "taskType": "INVESTIGATION"})
    module, s3, _ = load_journal_archiver(agent=agent)

    module.handler(event(task="task-9"), None)

    assert body_of(s3.puts[0])["task"]["title"] == "audit-trail verification"
    assert agent.task_requests == [{"agentSpaceId": "space-1234", "taskId": "task-9"}]


def test_no_task_lookup_when_the_event_carries_no_task_id(load_journal_archiver):
    module, s3, agent = load_journal_archiver()

    module.handler(event(task=None), None)

    assert agent.task_requests == []
    assert body_of(s3.puts[0])["task_id"] is None


def test_payload_carries_the_event_envelope_for_audit(load_journal_archiver):
    agent = FakeAgent(journal_pages=[{"records": [{"id": "r1"}]}])
    module, s3, _ = load_journal_archiver(agent=agent)

    module.handler(event(status="FAILED", detail_type="Investigation Failed"), None)

    payload = body_of(s3.puts[0])
    assert payload["status"] == "FAILED"
    assert payload["detail_type"] == "Investigation Failed"
    assert payload["event_time"] == "2026-08-02T21:32:32Z"
    assert payload["summary_record_id"] == "rec-sum-1"


def test_non_serializable_record_values_do_not_break_the_write(
        load_journal_archiver):
    # The API returns datetimes; json.dumps(default=str) is what keeps those
    # from raising mid-archive.
    from datetime import datetime, timezone
    agent = FakeAgent(journal_pages=[
        {"records": [{"createdAt": datetime(2026, 8, 2, tzinfo=timezone.utc)}]},
    ])
    module, s3, _ = load_journal_archiver(agent=agent)

    module.handler(event(), None)

    assert "2026-08-02" in body_of(s3.puts[0])["journal_records"][0]["createdAt"]
