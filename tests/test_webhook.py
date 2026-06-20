"""
Integration tests for the FastAPI webhook endpoint.
Uses httpx.AsyncClient to call the app in-process.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient, ASGITransport

from main import app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

WEBHOOK_SECRET = "test_secret"
SAMPLE_PAYLOAD = {
    "action": "created",
    "alert": {
        "number": 42,
        "state": "open",
        "dependency": {
            "package": {"ecosystem": "npm", "name": "lodash"},
            "manifest_path": "package.json",
            "scope": "development",
        },
        "security_advisory": {
            "ghsa_id": "GHSA-0000-0000-0000",
            "summary": "Prototype Pollution in lodash",
            "identifiers": [{"type": "CVE", "value": "CVE-2021-23337"}],
            "cvss": {"score": 7.2},
            "severity": "high",
            "references": [],
            "vulnerable_functions": ["merge"],
        },
        "security_vulnerability": {
            "severity": "high",
            "vulnerable_version_range": "< 4.17.21",
            "first_patched_version": {"identifier": "4.17.21"},
        },
        "url": "https://api.github.com/repos/example/repo/dependabot/alerts/42",
        "html_url": "https://github.com/example/repo/security/dependabot/42",
    },
    "repository": {
        "id": 12345,
        "name": "repo",
        "full_name": "example/repo",
        "html_url": "https://github.com/example/repo",
        "clone_url": "https://github.com/example/repo.git",
        "default_branch": "main",
        "private": False,
    },
    "sender": {"login": "dependabot[bot]"},
}


def _sign(payload: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


@pytest.fixture
def payload_bytes() -> bytes:
    return json.dumps(SAMPLE_PAYLOAD).encode()


@pytest.fixture
def valid_signature(payload_bytes: bytes) -> str:
    return _sign(payload_bytes, WEBHOOK_SECRET)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_health_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_webhook_ignores_unknown_event(payload_bytes, valid_signature):
    with patch("main.settings") as mock_cfg:
        mock_cfg.github_webhook_secret = WEBHOOK_SECRET
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/webhook/github",
                content=payload_bytes,
                headers={
                    "X-Hub-Signature-256": valid_signature,
                    "X-GitHub-Event": "push",
                },
            )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"


@pytest.mark.asyncio
async def test_webhook_rejects_bad_signature(payload_bytes):
    with patch("main.settings") as mock_cfg:
        mock_cfg.github_webhook_secret = WEBHOOK_SECRET
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/webhook/github",
                content=payload_bytes,
                headers={
                    "X-Hub-Signature-256": "sha256=badhash",
                    "X-GitHub-Event": "dependabot_alert",
                },
            )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_webhook_accepts_valid_dependabot_event(payload_bytes, valid_signature):
    with (
        patch("main.settings") as mock_cfg,
        patch("main._agent") as mock_agent,
    ):
        mock_cfg.github_webhook_secret = WEBHOOK_SECRET
        mock_decision = MagicMock()
        mock_decision.decision.value = "not_affected_dead_code"
        mock_decision.vex_status.value = "not_affected"
        mock_decision.errors = []
        mock_agent.run = AsyncMock(return_value=mock_decision)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/webhook/github",
                content=payload_bytes,
                headers={
                    "X-Hub-Signature-256": valid_signature,
                    "X-GitHub-Event": "dependabot_alert",
                    "Content-Type": "application/json",
                },
            )

        # Drain the background asyncio.create_task(_run_agent(...)) while the
        # patch is still active — otherwise _agent reverts to None before the
        # background task executes, causing a spurious AttributeError in logs.
        await asyncio.sleep(0)

        assert resp.status_code == 202
        body = resp.json()
        assert body["repo"] == "example/repo"
        assert body["alert"] == 42
        mock_agent.run.assert_called_once()
