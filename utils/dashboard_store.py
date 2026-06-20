"""
In-memory dashboard telemetry store.

Tracks the last N pipeline runs and SBOM/VEX report generations so the
/dashboard page can display live statistics without a database.

Thread-safe via ``threading.Lock``.  The store is a module-level singleton
shared across all Fast API request handlers and background tasks.
"""

from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timezone
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

class PipelineRun:
    """One completed VEX pipeline execution."""

    __slots__ = (
        "timestamp", "repo", "alert_id", "alert_type",
        "package_name", "cve_id", "severity",
        "scope",
        "decision", "vex_status", "jira_key",
        "epss_score", "reachable", "errors", "duration_ms",
        "justification", "suggested_fix", "license_risk",
    )

    def __init__(
        self,
        *,
        repo: str,
        alert_id: int,
        alert_type: str = "dependabot",
        package_name: str,
        cve_id: Optional[str],
        severity: str,
        scope: Optional[str] = None,
        decision: str,
        vex_status: str,
        jira_key: Optional[str] = None,
        epss_score: Optional[float] = None,
        reachable: Optional[bool] = None,
        errors: list[str] | None = None,
        duration_ms: Optional[float] = None,
        justification: str = "",
        suggested_fix: str = "",
        license_risk: str = "",
    ):
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.repo = repo
        self.alert_id = alert_id
        self.alert_type = alert_type
        self.package_name = package_name
        self.cve_id = cve_id
        self.severity = severity
        self.scope = scope
        self.decision = decision
        self.vex_status = vex_status
        self.jira_key = jira_key
        self.epss_score = epss_score
        self.reachable = reachable
        self.errors = errors or []
        self.duration_ms = duration_ms
        self.justification = justification
        self.suggested_fix = suggested_fix
        self.license_risk = license_risk

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "repo": self.repo,
            "alert_id": self.alert_id,
            "alert_type": self.alert_type,
            "package_name": self.package_name,
            "cve_id": self.cve_id,
            "severity": self.severity,
            "scope": self.scope or "",
            "decision": self.decision,
            "vex_status": self.vex_status,
            "jira_key": self.jira_key,
            "epss_score": self.epss_score,
            "reachable": self.reachable,
            "errors": self.errors,
            "duration_ms": self.duration_ms,
            "justification": self.justification,
            "suggested_fix": self.suggested_fix,
            "license_risk": self.license_risk,
        }


class ReportRun:
    """One execution of the --generate-report / on-demand pipeline."""

    __slots__ = (
        "timestamp", "repo", "product_version",
        "sbom_generated", "dependabot_count",
        "code_scan_count", "secret_count",
        "total_alerts", "saved_files", "errors",
    )

    def __init__(
        self,
        *,
        repo: str,
        product_version: str,
        sbom_generated: bool,
        dependabot_count: int,
        code_scan_count: int,
        secret_count: int,
        total_alerts: int,
        saved_files: list[str],
        errors: list[str] | None = None,
    ):
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.repo = repo
        self.product_version = product_version
        self.sbom_generated = sbom_generated
        self.dependabot_count = dependabot_count
        self.code_scan_count = code_scan_count
        self.secret_count = secret_count
        self.total_alerts = total_alerts
        self.saved_files = saved_files
        self.errors = errors or []

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "repo": self.repo,
            "product_version": self.product_version,
            "sbom_generated": self.sbom_generated,
            "dependabot_count": self.dependabot_count,
            "code_scan_count": self.code_scan_count,
            "secret_count": self.secret_count,
            "total_alerts": self.total_alerts,
            "saved_files": self.saved_files,
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

class DashboardStore:
    """
    Thread-safe in-memory store for pipeline telemetry.

    Keeps at most *max_runs* pipeline runs and *max_reports* report runs in
    memory (oldest entries are evicted automatically).
    """

    def __init__(self, max_runs: int = 500, max_reports: int = 50):
        self._lock = threading.Lock()
        self._pipeline_runs: deque[PipelineRun] = deque(maxlen=max_runs)
        self._report_runs: deque[ReportRun] = deque(maxlen=max_reports)
        self._start_time = datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Writers
    # ------------------------------------------------------------------

    def record_pipeline(self, run: PipelineRun) -> None:
        with self._lock:
            self._pipeline_runs.appendleft(run)

    def update_pipeline_jira_key(self, alert_id: int, jira_key: str) -> bool:
        """Backfill the jira_key on an already-recorded run. Returns True if found."""
        with self._lock:
            for run in self._pipeline_runs:
                if run.alert_id == alert_id:
                    run.jira_key = jira_key
                    return True
        return False

    def update_pipeline_decision(
        self,
        alert_id: int,
        decision: str,
        vex_status: str | None = None,
        jira_key: str | None = None,
    ) -> bool:
        """Update the decision (and optionally vex_status / jira_key) of an
        already-recorded pipeline run.  Used when a human review resolves
        a *pending_review* entry.  Returns True if a matching run was found."""
        with self._lock:
            for run in self._pipeline_runs:
                if run.alert_id == alert_id:
                    run.decision = decision
                    if vex_status is not None:
                        run.vex_status = vex_status
                    if jira_key is not None:
                        run.jira_key = jira_key
                    return True
        return False

    def update_suggested_fix(self, alert_id: int, suggested_fix: str) -> bool:
        """Update only the suggested_fix of an existing pipeline run.
        Returns True if a matching run was found and updated."""
        with self._lock:
            for run in self._pipeline_runs:
                if run.alert_id == alert_id:
                    run.suggested_fix = suggested_fix
                    return True
        return False

    def find_pipeline_run(self, alert_id: int) -> PipelineRun | None:
        """Return the PipelineRun object for the given alert_id, or None."""
        with self._lock:
            for run in self._pipeline_runs:
                if run.alert_id == alert_id:
                    return run
        return None

    def record_report(self, run: ReportRun) -> None:
        with self._lock:
            self._report_runs.appendleft(run)

    # ------------------------------------------------------------------
    # Readers
    # ------------------------------------------------------------------

    def recent_pipeline_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            runs = list(self._pipeline_runs)
        return [r.to_dict() for r in runs[:limit]]

    def recent_reports(self, limit: int = 10) -> list[dict[str, Any]]:
        with self._lock:
            runs = list(self._report_runs)
        return [r.to_dict() for r in runs[:limit]]

    def stats(self) -> dict[str, Any]:
        """Return aggregated statistics for the dashboard."""
        with self._lock:
            runs = list(self._pipeline_runs)
            reports = list(self._report_runs)

        total = len(runs)
        decision_counts: dict[str, int] = {}
        severity_counts: dict[str, int] = {}
        error_runs = 0
        repos: set[str] = set()

        for r in runs:
            decision_counts[r.decision] = decision_counts.get(r.decision, 0) + 1
            severity_counts[r.severity] = severity_counts.get(r.severity, 0) + 1
            repos.add(r.repo)
            if r.errors:
                error_runs += 1

        last_report = reports[0].to_dict() if reports else None

        return {
            "server_start": self._start_time,
            "total_processed": total,
            "unique_repos": len(repos),
            "error_runs": error_runs,
            "decisions": decision_counts,
            "severities": severity_counts,
            "last_report": last_report,
            "total_reports_run": len(reports),
        }

    def start_time(self) -> str:
        return self._start_time


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_store: Optional[DashboardStore] = None


def get_dashboard_store() -> DashboardStore:
    global _store
    if _store is None:
        _store = DashboardStore()
    return _store
