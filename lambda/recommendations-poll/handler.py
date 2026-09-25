"""Snapshot AWS DevOps Agent recommendations to S3 on a schedule.

Recommendations are the agent's proactive (cross-incident) output. They are
generated on the goal's evaluation cadence and have NO EventBridge event, so
this function is invoked by EventBridge Scheduler and polls the API.

Each recommendation carries a status and a version. We key the S3 object on
recommendationId + version so status changes are preserved as history rather
than overwritten. recommendationId is not stable across evaluation runs: each
run creates new records and leaves the prior run's records at whatever status
they last held, so the archive accumulates snapshots per record, not one
lifecycle per piece of advice.

Because of that, `ListRecommendations` returns the current run's advice mixed
with superseded records from earlier runs, and no field on a recommendation says
which it is. The only discriminator is the owning goal's `lastSuccessfulTaskId`
compared against the recommendation's `taskId`, so this function also snapshots
the goals. Without them the archive is complete but undecodable on the one
question an auditor asks first: is this advice still live? Goals are keyed on
goalId + version; a goal's version rarely bumps, so run-to-run history for a
goal lives in the bucket's S3 object versions rather than in distinct keys.

Writes are content-conditional: we only put an object when it is new OR its
content actually changed since the last snapshot (compared via the object's
ETag, which is the MD5 of the body for these single-part puts). This matters
because the bucket is versioned + Object-Locked — an unconditional write on
every poll would create a NEW, retention-locked version each day even when
nothing changed (billable and un-prunable until the lock lapses). The ETag
check also catches the case the API allows: content mutating WITHOUT a version
bump, which a plain skip-if-exists would silently miss.
"""
import hashlib
import json
import logging
import os
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")
agent = boto3.client("devops-agent")
BUCKET = os.environ["ARCHIVE_BUCKET"]
SPACE = os.environ["AGENT_SPACE_ID"]


def _unchanged(key: str, body: bytes) -> bool:
    """True if an object already exists at `key` with identical content.

    S3's ETag for a single-part PUT is the hex MD5 of the body, so we compare
    that to avoid re-writing (and re-locking) identical content. On any error
    other than "not found" we return False so the write still happens — never
    skip a snapshot because the existence check was inconclusive.
    """
    try:
        head = s3.head_object(Bucket=BUCKET, Key=key)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code not in ("404", "NoSuchKey", "NotFound"):
            logger.warning("head_object inconclusive for %s (%s); will write", key, code)
        return False
    existing_etag = head.get("ETag", "").strip('"')
    # MD5 is not a security choice here — S3 defines the ETag of a single-part
    # PUT as the hex MD5 of the body, so this is the only digest that can be
    # compared against it. usedforsecurity=False states that intent explicitly.
    return existing_etag == hashlib.md5(body, usedforsecurity=False).hexdigest()


def _list_all(operation, result_key: str) -> list:
    """Collect every page of a paginated `agentSpaceId` list call."""
    items, token = [], None
    while True:
        kwargs = {"agentSpaceId": SPACE}
        if token:
            kwargs["nextToken"] = token
        resp = operation(**kwargs)
        items.extend(resp.get(result_key, []))
        token = resp.get("nextToken")
        if not token:
            return items


def _snapshot(key: str, obj) -> str:
    """Write `obj` to `key` unless an identical object is already there.

    Returns "written", "skipped", or "error" — the caller decides what an error
    means for the poll as a whole, since that differs between the record itself
    (recommendations) and the aid to reading it (goals).
    """
    body = json.dumps(obj, default=str).encode("utf-8")
    try:
        if _unchanged(key, body):
            return "skipped"  # identical snapshot already stored — no new version
        s3.put_object(Bucket=BUCKET, Key=key, Body=body,
                      ContentType="application/json")
        return "written"
    except ClientError as e:
        # Log and continue — don't let one failed write kill the entire poll.
        # The next scheduled run will retry it.
        logger.error("Failed to write %s: %s", key, e)
        return "error"


def handler(event, context):
    try:
        recs = _list_all(agent.list_recommendations, "recommendations")
    except ClientError as e:
        logger.error("Failed to list recommendations: %s", e)
        raise  # Scheduler will retry on next cadence

    logger.info("Fetched %d recommendations for space %s", len(recs), SPACE)

    tally = {"written": 0, "skipped": 0, "error": 0}
    for r in recs:
        key = f"recommendations/{r['recommendationId']}/v{r.get('version', 1)}.json"
        tally[_snapshot(key, r)] += 1

    logger.info("Poll complete: %d written, %d skipped (unchanged), %d errors",
                tally["written"], tally["skipped"], tally["error"])

    # Distinguish "nothing to write" (all unchanged — success) from "everything
    # failed" (systematic problem). Raise when writes were attempted and all of
    # them failed. When every rec was unchanged, `error` is 0 so this won't
    # fire; the `skipped` count must NOT gate this, or a systematic write
    # failure alongside some skips would be silently swallowed.
    if tally["error"] and tally["written"] == 0:
        raise RuntimeError(
            f"All {tally['error']} S3 writes failed — possible systematic issue"
        )

    goals = _goal_tally()

    return {
        "recommendations_seen": len(recs),
        "snapshots_written": tally["written"],
        "snapshots_skipped": tally["skipped"],
        "errors": tally["error"],
        "goals_seen": goals["seen"],
        "goal_snapshots_written": goals["written"],
        "goal_snapshots_skipped": goals["skipped"],
        "goal_errors": goals["error"],
    }


def _goal_tally() -> dict:
    """Snapshot the goals, reporting failures instead of raising.

    Deliberately non-fatal, and deliberately last. A goal snapshot only tells an
    auditor which run's advice is current; the advice itself is already safely
    archived by the time we get here. Losing the decoding aid must never cost us
    the record, so a failure here is counted and returned rather than raised —
    but it IS returned, so a permanently broken `ListGoals` grant shows up in the
    invocation result instead of quietly degrading the archive.
    """
    tally = {"seen": 0, "written": 0, "skipped": 0, "error": 0}
    try:
        goals = _list_all(agent.list_goals, "goals")
    except ClientError as e:
        logger.error("Failed to list goals; recommendations are archived but "
                     "current-vs-superseded cannot be determined: %s", e)
        tally["error"] = 1
        return tally

    tally["seen"] = len(goals)
    for g in goals:
        key = f"goals/{g['goalId']}/v{g.get('version', 1)}.json"
        tally[_snapshot(key, g)] += 1
    logger.info("Goals: %d seen, %d written, %d skipped, %d errors",
                tally["seen"], tally["written"], tally["skipped"], tally["error"])
    return tally
