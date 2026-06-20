"""
Shared pytest fixtures for the tests/ suite.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio

from utils.review_queue import ReviewQueue


# ---------------------------------------------------------------------------
# tmp_queue — used by test_all_decisions.py
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_queue(tmp_path: Path) -> ReviewQueue:
    """Return a fresh ReviewQueue backed by a temporary SQLite database."""
    db_file = tmp_path / "review_queue_test.db"
    queue = ReviewQueue(db_path=db_file)
    yield queue
    # cleanup WAL artefacts
    for ext in ("", "-shm", "-wal"):
        p = Path(str(db_file) + ext)
        if p.exists():
            try:
                p.unlink()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# client — used by test_jira.py (live integration test)
# ---------------------------------------------------------------------------

@pytest.fixture()
def client():
    """
    Return a JiraClient instance.
    Skips automatically when Jira credentials are not configured in the
    environment, so the test is only executed in environments that have
    set JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN and JIRA_PROJECT_KEY.
    """
    from config import get_settings
    from clients.jira_client import JiraClient

    s = get_settings()
    if not all([s.jira_base_url, s.jira_email, s.jira_api_token, s.jira_project_key]):
        pytest.skip("Jira credentials not configured — set JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY")
    return JiraClient()


# ---------------------------------------------------------------------------
# Quiet known httpx/asyncio shutdown noise on Windows test runs
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture(autouse=True)
async def suppress_asyncclient_loop_close_noise():
    """Suppress benign 'Event loop is closed' noise from AsyncClient shutdown.

    On Windows, httpx/anyio can occasionally emit a late AsyncClient.aclose task
    exception during loop teardown. This is non-fatal and does not indicate
    application logic failure, but it pollutes test logs.
    """
    loop = asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()

    def _handler(loop: asyncio.AbstractEventLoop, context: dict) -> None:
        exc = context.get("exception")
        fut = context.get("future")
        msg = str(context.get("message", ""))

        if isinstance(exc, RuntimeError) and "Event loop is closed" in str(exc):
            coro_name = ""
            if fut is not None and hasattr(fut, "get_coro"):
                try:
                    coro = fut.get_coro()
                    coro_name = getattr(coro, "__qualname__", "")
                except Exception:
                    coro_name = ""
            if "AsyncClient.aclose" in coro_name or "Task exception was never retrieved" in msg:
                return

        if previous_handler is not None:
            previous_handler(loop, context)
        else:
            loop.default_exception_handler(context)

    loop.set_exception_handler(_handler)
    try:
        yield
    finally:
        loop.set_exception_handler(previous_handler)
