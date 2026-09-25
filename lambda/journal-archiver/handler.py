"""Archive the AWS DevOps Agent journal to S3 on terminal investigation events.

Triggered by EventBridge on `Investigation Completed|Failed` (and mitigation
equivalents). Reads the full journal for the execution and writes it to S3,
keyed on execution_id so redelivery (EventBridge is at-least-once) overwrites
rather than duplicates.
"""
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


def _fetch_journal(agent_space_id: str, execution_id: str) -> list:
    """Fetch ALL journal records. The API is server-paginated (nextToken/limit);
    a single call is NOT guaranteed to return the whole journal, so we loop.

    We accept the server's default page size rather than setting an explicit
    `limit` — the API returns an encrypted continuation token regardless of
    page size, and smaller pages just mean more round-trips.
    """
    records, token = [], None
    while True:
        kwargs = {"agentSpaceId": agent_space_id, "executionId": execution_id}
        if token:
            kwargs["nextToken"] = token
        resp = agent.list_journal_records(**kwargs)
        records.extend(resp.get("records", []))
        token = resp.get("nextToken")
        if not token:
            break
    return records


def handler(event, context):
    detail = event["detail"]
    meta = detail["metadata"]
    space = meta["agent_space_id"]
    execution = meta["execution_id"]
    task = meta.get("task_id")

    logger.info(
        "Archiving journal",
        extra={"agent_space_id": space, "execution_id": execution, "task_id": task},
    )

    try:
        records = _fetch_journal(space, execution)
    except ClientError as e:
        logger.error("Failed to fetch journal: %s", e)
        raise  # Let Lambda retry via EventBridge (2 retries) then DLQ

    # Task metadata is best-effort enrichment — the journal is the audit record,
    # task context (title, trigger source) is supplementary. A failure here must
    # not prevent journal archival.
    task_detail = {}
    if task:
        try:
            task_detail = agent.get_backlog_task(agentSpaceId=space, taskId=task).get("task", {})
        except Exception as e:
            logger.warning("Best-effort task enrichment failed (non-fatal): %s", e)

    payload = {
        "agent_space_id": space,
        "execution_id": execution,
        "task_id": task,
        "status": detail.get("data", {}).get("status"),
        "detail_type": event.get("detail-type"),
        "event_time": event.get("time"),
        "summary_record_id": detail.get("data", {}).get("summary_record_id"),
        "task": task_detail,
        "record_count": len(records),
        "journal_records": records,
    }

    # Idempotent write: same execution -> same key, and IfNoneMatch='*' makes
    # the put a no-op if the object already exists. The journal is immutable
    # once an investigation reaches a terminal state, so a re-fetch yields the
    # same data -- but EventBridge is at-least-once and the bucket is versioned
    # + Object-Locked, so an unconditional put would write a NEW, retention-
    # locked version on every redelivery (billable and un-prunable until the
    # lock lapses). The conditional put avoids that atomically -- no head-then-
    # put race.
    key = f"journals/space={space}/dt={event['time'][:10]}/{execution}.json"

    try:
        s3.put_object(
            Bucket=BUCKET,
            Key=key,
            Body=json.dumps(payload, default=str).encode("utf-8"),
            ContentType="application/json",
            IfNoneMatch="*",
        )
    except ClientError as e:
        # PreconditionFailed = this execution was already archived. That is the
        # success case for a redelivery, not an error -- do not raise (raising
        # would send the event to the DLQ despite the archive being intact).
        if e.response.get("Error", {}).get("Code") in ("PreconditionFailed", "412"):
            logger.info("Journal already archived (redelivery), skipping: %s", key)
            return {"archived": key, "records": len(records), "already_archived": True}
        logger.error("Failed to write journal to S3: %s (key=%s)", e, key)
        raise  # Retry then DLQ

    logger.info("Archived %d records to %s", len(records), key)
    return {"archived": key, "records": len(records)}

