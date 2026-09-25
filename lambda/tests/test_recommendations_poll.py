"""Tests for the Layer 3 recommendations poll.

The interesting behaviour is the write gate. The bucket is versioned and
Object-Locked, so an unconditional daily put would create a new retention-locked
version even when nothing changed. These tests pin the three outcomes: new,
unchanged (skip), and changed-without-a-version-bump (must still write).
"""
import hashlib
import json

import pytest

from conftest import BUCKET, SPACE, FakeAgent, FakeS3, client_error


def rec(rid="rec-1", version=1, **extra):
    return {"recommendationId": rid, "version": version, **extra}


def etag_for(recommendation) -> dict:
    """A head_object response whose ETag matches this recommendation's body."""
    body = json.dumps(recommendation, default=str).encode("utf-8")
    digest = hashlib.md5(body, usedforsecurity=False).hexdigest()
    return {"ETag": f'"{digest}"'}


def test_writes_a_new_snapshot_keyed_on_id_and_version(load_recommendations_poll):
    agent = FakeAgent(recommendation_pages=[{"recommendations": [rec("rec-a", 3)]}])
    module, s3, _ = load_recommendations_poll(agent=agent)

    result = module.handler({}, None)

    assert s3.put_keys == ["recommendations/rec-a/v3.json"]
    assert s3.puts[0]["Bucket"] == BUCKET
    assert result == {"recommendations_seen": 1, "snapshots_written": 1,
                     "snapshots_skipped": 0, "errors": 0,
                     "goals_seen": 0, "goal_snapshots_written": 0,
                     "goal_snapshots_skipped": 0, "goal_errors": 0}


def test_versions_are_kept_as_history_not_overwritten(load_recommendations_poll):
    # A status change bumps the version; each must land on its own key or the
    # earlier state is lost.
    agent = FakeAgent(recommendation_pages=[
        {"recommendations": [rec("rec-a", 1), rec("rec-a", 2)]},
    ])
    module, s3, _ = load_recommendations_poll(agent=agent)

    module.handler({}, None)

    assert s3.put_keys == ["recommendations/rec-a/v1.json",
                          "recommendations/rec-a/v2.json"]


def test_missing_version_defaults_to_v1(load_recommendations_poll):
    agent = FakeAgent(recommendation_pages=[
        {"recommendations": [{"recommendationId": "rec-a"}]},
    ])
    module, s3, _ = load_recommendations_poll(agent=agent)

    module.handler({}, None)

    assert s3.put_keys == ["recommendations/rec-a/v1.json"]


def test_identical_content_is_skipped_so_no_new_locked_version_is_created(
        load_recommendations_poll):
    existing = rec("rec-a", 1, title="unchanged")
    agent = FakeAgent(recommendation_pages=[{"recommendations": [existing]}])
    module, s3, _ = load_recommendations_poll(
        s3=FakeS3(head=etag_for(existing)), agent=agent)

    result = module.handler({}, None)

    assert s3.puts == []
    assert result["snapshots_skipped"] == 1
    assert result["snapshots_written"] == 0


def test_content_changing_without_a_version_bump_still_writes(
        load_recommendations_poll):
    # A plain skip-if-exists would silently miss this. The ETag comparison is
    # what catches it.
    stored = rec("rec-a", 1, title="old text")
    incoming = rec("rec-a", 1, title="new text")
    agent = FakeAgent(recommendation_pages=[{"recommendations": [incoming]}])
    module, s3, _ = load_recommendations_poll(
        s3=FakeS3(head=etag_for(stored)), agent=agent)

    result = module.handler({}, None)

    assert s3.put_keys == ["recommendations/rec-a/v1.json"]
    assert result["snapshots_written"] == 1


def test_inconclusive_head_writes_rather_than_risking_a_lost_snapshot(
        load_recommendations_poll):
    # Never skip a snapshot because the existence check failed for a reason
    # other than "not found".
    def denied(**_):
        raise client_error("AccessDenied", "HeadObject")

    agent = FakeAgent(recommendation_pages=[{"recommendations": [rec()]}])
    module, s3, _ = load_recommendations_poll(s3=FakeS3(head=denied), agent=agent)

    result = module.handler({}, None)

    assert result["snapshots_written"] == 1


def test_follows_next_token_across_pages(load_recommendations_poll):
    agent = FakeAgent(recommendation_pages=[
        {"recommendations": [rec("rec-a")], "nextToken": "t1"},
        {"recommendations": [rec("rec-b")]},
    ])
    module, s3, _ = load_recommendations_poll(agent=agent)

    result = module.handler({}, None)

    assert result["recommendations_seen"] == 2
    assert [r.get("nextToken") for r in agent.recommendation_requests] == [None, "t1"]
    assert [r["agentSpaceId"] for r in agent.recommendation_requests] == [SPACE, SPACE]


def test_one_failed_write_does_not_abort_the_rest_of_the_poll(
        load_recommendations_poll):
    def fail_second(**kwargs):
        if kwargs["Key"].startswith("recommendations/rec-b/"):
            raise client_error("SlowDown", "PutObject")
        return {}

    agent = FakeAgent(recommendation_pages=[
        {"recommendations": [rec("rec-a"), rec("rec-b"), rec("rec-c")]},
    ])
    module, s3, _ = load_recommendations_poll(s3=FakeS3(put=fail_second), agent=agent)

    result = module.handler({}, None)

    assert result == {"recommendations_seen": 3, "snapshots_written": 2,
                      "snapshots_skipped": 0, "errors": 1,
                      "goals_seen": 0, "goal_snapshots_written": 0,
                      "goal_snapshots_skipped": 0, "goal_errors": 0}


def test_raises_when_every_attempted_write_failed(load_recommendations_poll):
    # A systematic problem (bad policy, wrong bucket) must surface, not be
    # swallowed as a quiet no-op poll.
    def always_fail(**_):
        raise client_error("AccessDenied", "PutObject")

    agent = FakeAgent(recommendation_pages=[
        {"recommendations": [rec("rec-a"), rec("rec-b")]},
    ])
    module, _, _ = load_recommendations_poll(s3=FakeS3(put=always_fail), agent=agent)

    with pytest.raises(RuntimeError, match="All 2 S3 writes failed"):
        module.handler({}, None)


def test_all_unchanged_is_success_not_a_failure(load_recommendations_poll):
    existing = rec("rec-a", 1)
    agent = FakeAgent(recommendation_pages=[{"recommendations": [existing]}])
    module, _, _ = load_recommendations_poll(
        s3=FakeS3(head=etag_for(existing)), agent=agent)

    result = module.handler({}, None)  # must not raise

    assert result["snapshots_written"] == 0
    assert result["errors"] == 0


def test_a_skip_does_not_mask_a_systematic_write_failure(load_recommendations_poll):
    # written == 0 with errors > 0 must still raise even when some recs were
    # skipped, or a broken policy looks like a quiet day.
    unchanged = rec("rec-a", 1)

    def head(**kwargs):
        if kwargs["Key"].startswith("recommendations/rec-a/"):
            return etag_for(unchanged)
        raise client_error("404", "HeadObject")

    def always_fail(**_):
        raise client_error("AccessDenied", "PutObject")

    agent = FakeAgent(recommendation_pages=[
        {"recommendations": [unchanged, rec("rec-b")]},
    ])
    module, _, _ = load_recommendations_poll(
        s3=FakeS3(head=head, put=always_fail), agent=agent)

    with pytest.raises(RuntimeError, match="All 1 S3 writes failed"):
        module.handler({}, None)


def test_list_failure_raises_and_writes_nothing(load_recommendations_poll):
    agent = FakeAgent(list_error=client_error("ThrottlingException",
                                              "ListRecommendations"))
    module, s3, _ = load_recommendations_poll(agent=agent)

    with pytest.raises(Exception):
        module.handler({}, None)
    assert s3.puts == []


def test_empty_result_set_is_a_clean_no_op(load_recommendations_poll):
    module, s3, _ = load_recommendations_poll(
        agent=FakeAgent(recommendation_pages=[{"recommendations": []}]))

    result = module.handler({}, None)

    assert s3.puts == []
    assert result == {"recommendations_seen": 0, "snapshots_written": 0,
                      "snapshots_skipped": 0, "errors": 0,
                      "goals_seen": 0, "goal_snapshots_written": 0,
                      "goal_snapshots_skipped": 0, "goal_errors": 0}


def test_non_serializable_values_do_not_break_the_write(load_recommendations_poll):
    from datetime import datetime, timezone
    agent = FakeAgent(recommendation_pages=[
        {"recommendations": [rec(createdAt=datetime(2026, 8, 2, tzinfo=timezone.utc))]},
    ])
    module, s3, _ = load_recommendations_poll(agent=agent)

    module.handler({}, None)

    body = json.loads(s3.puts[0]["Body"].decode("utf-8"))
    assert "2026-08-02" in body["createdAt"]


# ---------------------------------------------------------------------------
# Goal snapshots.
#
# `ListRecommendations` mixes the current run's advice with superseded records
# from earlier runs and there is no field on a recommendation that says which is
# which. The only discriminator is the goal's `lastSuccessfulTaskId`, so the poll
# snapshots the goals too — otherwise the archive is unreadable on this point.
# Shape below is the live `ListGoals` response.
# ---------------------------------------------------------------------------


def goal(gid="goal-abc12345", version=1, last_successful="task1111", **extra):
    g = {"goalId": gid, "version": version, "status": "ACTIVE",
         "lastTaskId": last_successful, **extra}
    if last_successful is not None:
        g["lastSuccessfulTaskId"] = last_successful
    return g


def test_snapshots_the_goal_so_current_advice_can_be_told_from_superseded(
        load_recommendations_poll):
    agent = FakeAgent(recommendation_pages=[{"recommendations": [rec("rec-a", 1)]}],
                      goal_pages=[{"goals": [goal()]}])
    module, s3, _ = load_recommendations_poll(agent=agent)

    result = module.handler({}, None)

    assert "goals/goal-abc12345/v1.json" in s3.put_keys
    body = json.loads(next(p["Body"] for p in s3.puts
                           if p["Key"] == "goals/goal-abc12345/v1.json").decode("utf-8"))
    assert body["lastSuccessfulTaskId"] == "task1111"
    assert result["goals_seen"] == 1
    assert result["goal_snapshots_written"] == 1
    assert result["goal_errors"] == 0


def test_unchanged_goal_writes_no_new_locked_version(load_recommendations_poll):
    # Same gate as the recommendations: the bucket is versioned + Object-Locked,
    # and the goal changes weekly at most, so a daily poll must not re-write it.
    existing = goal()
    agent = FakeAgent(recommendation_pages=[{"recommendations": []}],
                      goal_pages=[{"goals": [existing]}])
    module, s3, _ = load_recommendations_poll(
        s3=FakeS3(head=etag_for(existing)), agent=agent)

    result = module.handler({}, None)

    assert s3.puts == []
    assert result["goal_snapshots_written"] == 0
    assert result["goal_snapshots_skipped"] == 1


def test_goal_with_no_successful_run_is_still_recorded(load_recommendations_poll):
    # A goal whose first evaluation has not succeeded has no current run. Record
    # it anyway: "no successful run yet" is the audit answer, and omitting the
    # goal would leave an auditor unable to tell that from "goal not polled".
    agent = FakeAgent(recommendation_pages=[{"recommendations": []}],
                      goal_pages=[{"goals": [goal(last_successful=None)]}])
    module, s3, _ = load_recommendations_poll(agent=agent)

    result = module.handler({}, None)

    body = json.loads(s3.puts[0]["Body"].decode("utf-8"))
    assert "lastSuccessfulTaskId" not in body
    assert result["goal_snapshots_written"] == 1


def test_goal_listing_failure_does_not_lose_the_recommendation_snapshots(
        load_recommendations_poll):
    # Goals are a decoding aid, not the record itself. Losing them must never
    # cost us the advice — but it must be reported, not swallowed.
    agent = FakeAgent(recommendation_pages=[{"recommendations": [rec("rec-a", 1)]}],
                      goal_error=client_error("AccessDeniedException", "ListGoals"))
    module, s3, _ = load_recommendations_poll(agent=agent)

    result = module.handler({}, None)

    assert s3.put_keys == ["recommendations/rec-a/v1.json"]
    assert result["snapshots_written"] == 1
    assert result["goals_seen"] == 0
    assert result["goal_errors"] == 1


def test_goal_pagination_is_followed(load_recommendations_poll):
    agent = FakeAgent(recommendation_pages=[{"recommendations": []}],
                      goal_pages=[{"goals": [goal("goal-a")], "nextToken": "g1"},
                                  {"goals": [goal("goal-b")]}])
    module, s3, _ = load_recommendations_poll(agent=agent)

    result = module.handler({}, None)

    assert result["goals_seen"] == 2
    assert [r.get("nextToken") for r in agent.goal_requests] == [None, "g1"]
    assert [r["agentSpaceId"] for r in agent.goal_requests] == [SPACE, SPACE]


def test_a_failed_goal_write_is_reported_without_failing_the_poll(
        load_recommendations_poll):
    def fail_goals(**kwargs):
        if kwargs["Key"].startswith("goals/"):
            raise client_error("AccessDenied", "PutObject")
        return {}

    agent = FakeAgent(recommendation_pages=[{"recommendations": [rec("rec-a", 1)]}],
                      goal_pages=[{"goals": [goal()]}])
    module, _, _ = load_recommendations_poll(s3=FakeS3(put=fail_goals), agent=agent)

    result = module.handler({}, None)  # must not raise: the advice was archived

    assert result["snapshots_written"] == 1
    assert result["goal_snapshots_written"] == 0
    assert result["goal_errors"] == 1
