"""Test scaffolding for the Lambda handlers.

Two things make these handlers awkward to import: they live in hyphenated
directories (not valid module names) and they build their boto3 clients and
read `os.environ` at import time. `load_handler` therefore stubs the clients
and the environment *first*, then loads the module from its path. Each call
returns a freshly executed module, so no state leaks between tests.
"""
import importlib.util
import pathlib

import boto3
import pytest
from botocore.exceptions import ClientError

LAMBDA_DIR = pathlib.Path(__file__).resolve().parent.parent

BUCKET = "test-archive-bucket"
SPACE = "space-1234"


def client_error(code: str, operation: str = "Operation") -> ClientError:
    """A botocore ClientError with the given error code."""
    return ClientError({"Error": {"Code": code, "Message": code}}, operation)


NOT_FOUND = "404"


class FakeS3:
    """Records every call; `head` and `put` inject the response or raise.

    Each may be a plain value (returned as-is) or a callable taking the request
    kwargs. A callable that raises is how a test simulates an S3 failure.
    """

    def __init__(self, head=None, put=None):
        self.heads: list[dict] = []
        self.puts: list[dict] = []
        self._head = head
        self._put = put

    def head_object(self, **kwargs):
        self.heads.append(kwargs)
        if self._head is None:
            raise client_error(NOT_FOUND, "HeadObject")
        return self._head(**kwargs) if callable(self._head) else self._head

    def put_object(self, **kwargs):
        self.puts.append(kwargs)
        if self._put is None:
            return {}
        return self._put(**kwargs) if callable(self._put) else self._put

    @property
    def put_keys(self) -> list[str]:
        return [p["Key"] for p in self.puts]


class FakeAgent:
    """Serves the DevOps Agent API from canned pages.

    `journal_pages` / `recommendation_pages` are consumed one per call, so a
    multi-page list proves the handler actually follows `nextToken`. Requests
    are recorded to assert the token is threaded back.
    """

    def __init__(self, journal_pages=None, recommendation_pages=None,
                 task=None, list_error=None, goal_pages=None, goal_error=None):
        self._journal_pages = list(journal_pages or [{}])
        self._recommendation_pages = list(recommendation_pages or [{}])
        self._goal_pages = list(goal_pages or [{}])
        self.task = task
        self.list_error = list_error
        self.goal_error = goal_error
        self.journal_requests: list[dict] = []
        self.recommendation_requests: list[dict] = []
        self.goal_requests: list[dict] = []
        self.task_requests: list[dict] = []

    def list_journal_records(self, **kwargs):
        self.journal_requests.append(kwargs)
        if self.list_error:
            raise self.list_error
        return self._journal_pages.pop(0)

    def list_recommendations(self, **kwargs):
        self.recommendation_requests.append(kwargs)
        if self.list_error:
            raise self.list_error
        return self._recommendation_pages.pop(0)

    def list_goals(self, **kwargs):
        self.goal_requests.append(kwargs)
        if self.goal_error:
            raise self.goal_error
        return self._goal_pages.pop(0)

    def get_backlog_task(self, **kwargs):
        self.task_requests.append(kwargs)
        if isinstance(self.task, Exception):
            raise self.task
        return {"task": self.task or {}}


def load_handler(directory: str, monkeypatch, s3, agent, env=None):
    """Import `lambda/<directory>/handler.py` with stubbed clients and env."""
    clients = {"s3": s3, "devops-agent": agent}
    monkeypatch.setattr(boto3, "client", lambda service, *a, **kw: clients[service])
    for key, value in (env or {}).items():
        monkeypatch.setenv(key, value)

    path = LAMBDA_DIR / directory / "handler.py"
    name = f"_handler_{directory.replace('-', '_')}"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def load_journal_archiver(monkeypatch):
    def _load(s3=None, agent=None):
        s3 = s3 if s3 is not None else FakeS3()
        agent = agent if agent is not None else FakeAgent()
        module = load_handler("journal-archiver", monkeypatch, s3, agent,
                             env={"ARCHIVE_BUCKET": BUCKET})
        return module, s3, agent
    return _load


@pytest.fixture
def load_recommendations_poll(monkeypatch):
    def _load(s3=None, agent=None):
        s3 = s3 if s3 is not None else FakeS3()
        agent = agent if agent is not None else FakeAgent()
        module = load_handler("recommendations-poll", monkeypatch, s3, agent,
                              env={"ARCHIVE_BUCKET": BUCKET, "AGENT_SPACE_ID": SPACE})
        return module, s3, agent
    return _load
