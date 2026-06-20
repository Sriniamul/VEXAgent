"""
Tests for the VEX Agent dashboard and its backing API endpoints.

Covers:
  - GET /dashboard        → returns 200 + HTML page
  - GET /api/v1/stats     → returns valid JSON stats structure
  - GET /api/v1/pipeline-runs → returns a list
  - GET /api/v1/reviews/pending → returns a list
  - GET /api/v1/reports   → returns a list
  - DashboardStore        → records pipeline runs and report runs
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient, ASGITransport

from main import app
from utils.dashboard_store import DashboardStore, PipelineRun, ReportRun


# ---------------------------------------------------------------------------
# Helper: in-process async HTTP client
# ---------------------------------------------------------------------------

async def _get(path: str, authenticated: bool = False, **params):
    from main import _sign_session, _SESSION_COOKIE
    cookies = {_SESSION_COOKIE: _sign_session("test-user", "", True)} if authenticated else {}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await client.get(path, params=params or None, cookies=cookies)


# ---------------------------------------------------------------------------
# Dashboard HTML page
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_dashboard_returns_html():
    """GET /dashboard serves the dashboard HTML page."""
    resp = await _get("/dashboard", authenticated=True)
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    # Verify key landmarks in the rendered page
    body = resp.text
    assert "VEX Agent Dashboard" in body
    assert "decisionChart" in body
    assert "severityChart" in body
    assert "/api/v1/stats" in body


# ---------------------------------------------------------------------------
# /api/v1/stats
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stats_returns_expected_keys():
    """GET /api/v1/stats returns a dict with all required top-level keys."""
    resp = await _get("/api/v1/stats")
    assert resp.status_code == 200
    data = resp.json()
    required = {
        "server_start", "total_processed", "unique_repos",
        "error_runs", "decisions", "severities",
        "last_report", "total_reports_run",
        "jira_base_url", "review_base_url",
    }
    assert required.issubset(data.keys()), f"Missing keys: {required - data.keys()}"


@pytest.mark.asyncio
async def test_stats_after_pipeline_run():
    """Stats counters increase after a PipelineRun is recorded."""
    store = DashboardStore()
    store.record_pipeline(PipelineRun(
        repo="acme/my-service",
        alert_id=1,
        package_name="lodash",
        cve_id="CVE-2021-23337",
        severity="high",
        decision="not_affected_dev_only",
        vex_status="not_affected",
    ))
    stats = store.stats()
    assert stats["total_processed"] == 1
    assert stats["unique_repos"] == 1
    assert stats["decisions"]["not_affected_dev_only"] == 1
    assert stats["severities"]["high"] == 1


# ---------------------------------------------------------------------------
# /api/v1/pipeline-runs
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pipeline_runs_returns_list():
    """GET /api/v1/pipeline-runs returns a JSON array."""
    resp = await _get("/api/v1/pipeline-runs")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_pipeline_runs_limit_param():
    """limit query-parameter is respected (capped at 200)."""
    resp = await _get("/api/v1/pipeline-runs", limit=5)
    assert resp.status_code == 200
    # should return at most 5 items (may be less if store is empty)
    assert len(resp.json()) <= 5


# ---------------------------------------------------------------------------
# /api/v1/reviews/pending
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pending_reviews_returns_list():
    """GET /api/v1/reviews/pending returns a JSON array."""
    resp = await _get("/api/v1/reviews/pending")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ---------------------------------------------------------------------------
# /api/v1/reports
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_reports_endpoint_returns_list():
    """GET /api/v1/reports returns a JSON array."""
    resp = await _get("/api/v1/reports")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ---------------------------------------------------------------------------
# DashboardStore unit tests
# ---------------------------------------------------------------------------

def test_store_records_pipeline_run():
    """PipelineRun is stored and retrievable."""
    store = DashboardStore(max_runs=10)
    store.record_pipeline(PipelineRun(
        repo="org/repo",
        alert_id=99,
        package_name="requests",
        cve_id="CVE-2023-32681",
        severity="medium",
        decision="affected_reachable",
        vex_status="affected",
        epss_score=0.42,
        reachable=True,
        errors=[],
        duration_ms=1230.5,
    ))
    runs = store.recent_pipeline_runs()
    assert len(runs) == 1
    r = runs[0]
    assert r["repo"] == "org/repo"
    assert r["decision"] == "affected_reachable"
    assert r["epss_score"] == pytest.approx(0.42)
    assert r["duration_ms"] == pytest.approx(1230.5)


def test_store_records_report_run():
    """ReportRun is stored and appears in stats as last_report."""
    store = DashboardStore(max_reports=5)
    store.record_report(ReportRun(
        repo="org/repo",
        product_version="2026.2.0",
        sbom_generated=True,
        dependabot_count=137,
        code_scan_count=50,
        secret_count=0,
        total_alerts=187,
        saved_files=["ARM/2026.2.0/vex-report.cdx.json"],
    ))
    stats = store.stats()
    assert stats["total_reports_run"] == 1
    lr = stats["last_report"]
    assert lr["product_version"] == "2026.2.0"
    assert lr["dependabot_count"] == 137
    assert lr["total_alerts"] == 187


def test_store_max_runs_eviction():
    """Oldest runs are evicted when the ring buffer is full."""
    store = DashboardStore(max_runs=3)
    for i in range(5):
        store.record_pipeline(PipelineRun(
            repo=f"org/repo-{i}",
            alert_id=i,
            package_name="pkg",
            cve_id=None,
            severity="low",
            decision="not_affected_dev_only",
            vex_status="not_affected",
        ))
    runs = store.recent_pipeline_runs()
    assert len(runs) == 3
    # Most recent first
    assert runs[0]["alert_id"] == 4


def test_store_error_run_counted():
    """Pipeline runs with errors are tracked in error_runs counter."""
    store = DashboardStore()
    store.record_pipeline(PipelineRun(
        repo="org/repo",
        alert_id=7,
        package_name="pkg",
        cve_id=None,
        severity="high",
        decision="under_investigation",
        vex_status="under_investigation",
        errors=["Something went wrong"],
    ))
    assert store.stats()["error_runs"] == 1


def test_store_multiple_repos_counted():
    """unique_repos counts distinct repositories."""
    store = DashboardStore()
    for repo in ["org/a", "org/b", "org/a"]:
        store.record_pipeline(PipelineRun(
            repo=repo,
            alert_id=1,
            package_name="pkg",
            cve_id=None,
            severity="low",
            decision="not_affected_dev_only",
            vex_status="not_affected",
        ))
    assert store.stats()["unique_repos"] == 2
