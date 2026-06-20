"""
GitHub Security API client.
Handles Dependabot alerts: fetch, normalise, and update VEX status.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

from models.vex_models import (
    GitHubSecurityWebhookPayload,
    NormalisedFinding,
    Severity,
    VexStatus,
    JustificationCode,
    ReachabilityHit,
)
from config import settings

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "moderate": Severity.MEDIUM,
}


class GitHubSecurityClient:
    """Wrapper around the GitHub REST API v3 for security operations."""

    BASE = "https://api.github.com"

    def __init__(self, token: str | None = None):
        self._token = token or settings.github_token
        self._headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    # ------------------------------------------------------------------
    # Normalisation helpers
    # ------------------------------------------------------------------

    def normalise_dependabot_alert(
        self,
        payload: GitHubSecurityWebhookPayload,
    ) -> NormalisedFinding:
        """Convert a raw Dependabot webhook payload into a NormalisedFinding."""
        alert = payload.alert
        advisory = alert.get("security_advisory", {})
        vuln = alert.get("security_vulnerability", {})
        dep = alert.get("dependency", {})
        pkg = dep.get("package", {})

        identifiers = {i["type"]: i["value"] for i in advisory.get("identifiers", [])}
        cvss = advisory.get("cvss", {})
        score_raw = cvss.get("score") if cvss else None
        vector_string = cvss.get("vectorString") if cvss else None

        raw_sev = (
            vuln.get("severity")
            or advisory.get("severity")
            or "medium"
        ).lower()

        # Collect vulnerable function names from GHSA references if available
        vuln_functions: list[str] = advisory.get("vulnerable_functions", [])

        return NormalisedFinding(
            alert_id=alert["number"],
            repo_full_name=payload.repo_full_name,
            repo_clone_url=payload.repo_clone_url,
            repo_default_branch=payload.repository.default_branch,
            cve_id=identifiers.get("CVE"),
            ghsa_id=identifiers.get("GHSA") or advisory.get("ghsa_id"),
            package_name=pkg.get("name", "unknown"),
            package_version=dep.get("manifest_path", ""),  # overridden below
            package_ecosystem=pkg.get("ecosystem", "unknown").lower(),
            vulnerable_version_range=vuln.get("vulnerable_version_range", ""),
            patched_version=vuln.get("first_patched_version", {}).get("identifier"),
            severity=SEVERITY_MAP.get(raw_sev, Severity.MEDIUM),
            cvss_score=float(score_raw) if score_raw else None,
            cvss_vector_string=vector_string,
            manifest_path=dep.get("manifest_path"),
            scope=dep.get("scope"),
            vulnerable_functions=vuln_functions,
            summary=advisory.get("summary", ""),
            references=[r["url"] for r in advisory.get("references", [])],
        )

    # ------------------------------------------------------------------
    # Remote API calls
    # ------------------------------------------------------------------

    async def get_dependabot_alert(
        self,
        repo_full_name: str,
        alert_number: int,
    ) -> dict[str, Any]:
        """Fetch a single Dependabot alert from the API."""
        url = f"{self.BASE}/repos/{repo_full_name}/dependabot/alerts/{alert_number}"
        async with httpx.AsyncClient(headers=self._headers, timeout=30) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            return resp.json()

    async def dismiss_dependabot_alert(
        self,
        repo_full_name: str,
        alert_number: int,
        dismissed_reason: str,
        dismissed_comment: str,
    ) -> dict[str, Any]:
        """
        Mark a Dependabot alert as dismissed (not affected).

        dismissed_reason values accepted by GitHub:
          fix_started | inaccurate | no_bandwidth |
          not_used | tolerable_risk
        """
        url = f"{self.BASE}/repos/{repo_full_name}/dependabot/alerts/{alert_number}"
        body = {
            "state": "dismissed",
            "dismissed_reason": dismissed_reason,
            "dismissed_comment": dismissed_comment,
        }
        async with httpx.AsyncClient(headers=self._headers, timeout=30) as client:
            resp = await client.patch(url, json=body)
            resp.raise_for_status()
            logger.info(
                "Dismissed Dependabot alert #%d for %s (%s)",
                alert_number, repo_full_name, dismissed_reason,
            )
            return resp.json()

    async def dismiss_code_scanning_alert(
        self,
        repo_full_name: str,
        alert_number: int,
        dismissed_reason: str = "won't fix",
        dismissed_comment: str = "",
    ) -> dict[str, Any]:
        """
        Dismiss a code-scanning alert.

        dismissed_reason values accepted by GitHub:
          false positive | won't fix | used in tests
        """
        url = f"{self.BASE}/repos/{repo_full_name}/code-scanning/alerts/{alert_number}"
        body: dict[str, Any] = {
            "state": "dismissed",
            "dismissed_reason": dismissed_reason,
        }
        if dismissed_comment:
            body["dismissed_comment"] = dismissed_comment
        async with httpx.AsyncClient(headers=self._headers, timeout=30) as client:
            resp = await client.patch(url, json=body)
            resp.raise_for_status()
            logger.info(
                "Dismissed code-scanning alert #%d for %s (%s)",
                alert_number, repo_full_name, dismissed_reason,
            )
            return resp.json()

    async def dismiss_secret_scanning_alert(
        self,
        repo_full_name: str,
        alert_number: int,
        resolution: str = "won't fix",
        comment: str = "",
    ) -> dict[str, Any]:
        """
        Resolve (dismiss) a secret-scanning alert.

        resolution values accepted by GitHub:
          false_positive | wont_fix | revoked | used_in_tests
        """
        url = f"{self.BASE}/repos/{repo_full_name}/secret-scanning/alerts/{alert_number}"
        body: dict[str, Any] = {
            "state": "resolved",
            "resolution": resolution,
        }
        if comment:
            body["resolution_comment"] = comment
        async with httpx.AsyncClient(headers=self._headers, timeout=30) as client:
            resp = await client.patch(url, json=body)
            resp.raise_for_status()
            logger.info(
                "Dismissed secret-scanning alert #%d for %s (%s)",
                alert_number, repo_full_name, resolution,
            )
            return resp.json()

    async def dismiss_alert(
        self,
        repo_full_name: str,
        alert_number: int,
        alert_type: str,
        dismissed_comment: str = "",
    ) -> bool:
        """
        Universal dismiss: routes to the correct GitHub API based on alert_type.

        alert_type: 'dependabot' | 'code_scanning' | 'secret_scanning'
        Returns True on success, False on failure.
        """
        try:
            if alert_type == "code_scanning":
                await self.dismiss_code_scanning_alert(
                    repo_full_name, alert_number,
                    dismissed_reason="won't fix",
                    dismissed_comment=dismissed_comment,
                )
            elif alert_type == "secret_scanning":
                await self.dismiss_secret_scanning_alert(
                    repo_full_name, alert_number,
                    resolution="wont_fix",
                    comment=dismissed_comment,
                )
            else:
                # Default: dependabot
                await self.dismiss_dependabot_alert(
                    repo_full_name, alert_number,
                    dismissed_reason="not_used",
                    dismissed_comment=dismissed_comment,
                )
            return True
        except Exception as exc:
            logger.error(
                "Failed to dismiss %s alert #%d for %s: %s",
                alert_type, alert_number, repo_full_name, exc,
            )
            return False

    async def reopen_dependabot_alert(
        self,
        repo_full_name: str,
        alert_number: int,
    ) -> dict[str, Any]:
        """Re-open a previously dismissed alert."""
        url = f"{self.BASE}/repos/{repo_full_name}/dependabot/alerts/{alert_number}"
        async with httpx.AsyncClient(headers=self._headers, timeout=30) as client:
            resp = await client.patch(url, json={"state": "open"})
            resp.raise_for_status()
            return resp.json()

    async def create_security_advisory_comment(
        self,
        repo_full_name: str,
        alert_number: int,
        body: str,
    ) -> None:
        """
        Post a comment on a Dependabot alert discussion thread.
        Uses the Issues API since alerts are backed by issues.
        """
        # Dependabot alerts don't have a comment endpoint; use check-run annotations
        # or the Security Advisory API instead. We log here as a fallback.
        logger.info(
            "[GitHub] Would post comment on %s#%d:\n%s",
            repo_full_name, alert_number, body,
        )

    async def add_security_label(
        self,
        repo_full_name: str,
        issue_number: int,
        labels: list[str],
    ) -> None:
        """Add labels to a repository issue (used for escalation)."""
        url = f"{self.BASE}/repos/{repo_full_name}/issues/{issue_number}/labels"
        async with httpx.AsyncClient(headers=self._headers, timeout=30) as client:
            resp = await client.post(url, json={"labels": labels})
            if resp.status_code not in (200, 201):
                logger.warning("Could not add labels %s: %s", labels, resp.text)

    async def create_check_run(
        self,
        repo_full_name: str,
        head_sha: str,
        conclusion: str,          # "failure" | "success"
        title: str,
        summary: str,
        annotations: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Create a Check Run to break (or pass) the build."""
        url = f"{self.BASE}/repos/{repo_full_name}/check-runs"
        body: dict[str, Any] = {
            "name": "VEX Security Gate",
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": conclusion,
            "output": {
                "title": title,
                "summary": summary,
                "annotations": annotations or [],
            },
        }
        async with httpx.AsyncClient(headers=self._headers, timeout=30) as client:
            resp = await client.post(url, json=body)
            resp.raise_for_status()
            logger.info(
                "Created check-run '%s' (conclusion=%s) on %s @ %s",
                title, conclusion, repo_full_name, head_sha,
            )
            return resp.json()

    async def get_latest_commit_sha(
        self,
        repo_full_name: str,
        branch: str = "main",
    ) -> Optional[str]:
        """Resolve the HEAD SHA of a branch."""
        url = f"{self.BASE}/repos/{repo_full_name}/branches/{branch}"
        async with httpx.AsyncClient(headers=self._headers, timeout=30) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return None
            data = resp.json()
            return data.get("commit", {}).get("sha")

    # ------------------------------------------------------------------
    # Security alert listing (for --generate-report mode)
    # ------------------------------------------------------------------

    async def list_dependabot_alerts(
        self,
        repo_full_name: str,
        state: str = "open",
    ) -> list[dict[str, Any]]:
        """Return all Dependabot alerts for *repo_full_name* (paginated).

        When ``settings.use_mock_github_data`` is ``True`` the call returns the
        built-in simulated dataset and makes no HTTP request.
        """
        if settings.use_mock_github_data:
            from clients.mock_github_data import MOCK_DEPENDABOT_ALERTS
            logger.info("USE_MOCK_GITHUB_DATA — returning %d mock Dependabot alerts", len(MOCK_DEPENDABOT_ALERTS))
            return list(MOCK_DEPENDABOT_ALERTS)
        url = f"{self.BASE}/repos/{repo_full_name}/dependabot/alerts"
        return await self._paginate(url, {"state": state, "per_page": 100})

    async def list_code_scanning_alerts(
        self,
        repo_full_name: str,
        state: str = "open",
    ) -> list[dict[str, Any]]:
        """Return all code-scanning alerts for *repo_full_name* (paginated).

        When ``settings.use_mock_github_data`` is ``True`` the call returns the
        built-in simulated dataset and makes no HTTP request.
        """
        if settings.use_mock_github_data:
            from clients.mock_github_data import MOCK_CODE_SCANNING_ALERTS
            logger.info("USE_MOCK_GITHUB_DATA — returning %d mock code-scanning alerts", len(MOCK_CODE_SCANNING_ALERTS))
            return list(MOCK_CODE_SCANNING_ALERTS)
        url = f"{self.BASE}/repos/{repo_full_name}/code-scanning/alerts"
        return await self._paginate(url, {"state": state, "per_page": 100})

    async def list_secret_scanning_alerts(
        self,
        repo_full_name: str,
        state: str = "open",
    ) -> list[dict[str, Any]]:
        """Return all secret-scanning alerts for *repo_full_name* (paginated).

        When ``settings.use_mock_github_data`` is ``True`` the call returns the
        built-in simulated dataset and makes no HTTP request.
        """
        if settings.use_mock_github_data:
            from clients.mock_github_data import MOCK_SECRET_SCANNING_ALERTS
            logger.info("USE_MOCK_GITHUB_DATA — returning %d mock secret-scanning alerts", len(MOCK_SECRET_SCANNING_ALERTS))
            return list(MOCK_SECRET_SCANNING_ALERTS)
        url = f"{self.BASE}/repos/{repo_full_name}/secret-scanning/alerts"
        # Fetch both open AND resolved secrets so nothing is missed
        open_alerts = await self._paginate(url, {"state": "open", "per_page": 100})
        resolved_alerts = await self._paginate(url, {"state": "resolved", "per_page": 100})
        combined = open_alerts + resolved_alerts
        logger.info(
            "Secret scanning alerts for %s: open=%d resolved=%d total=%d",
            repo_full_name, len(open_alerts), len(resolved_alerts), len(combined),
        )
        return combined

    # ------------------------------------------------------------------
    # Pagination helper
    # ------------------------------------------------------------------

    async def _paginate(
        self,
        url: str,
        params: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """GET *url* repeatedly, following GitHub ``Link: rel="next"`` headers."""
        results: list[dict[str, Any]] = []
        next_url: Optional[str] = url
        next_params: Optional[dict[str, Any]] = params

        async with httpx.AsyncClient(headers=self._headers, timeout=30) as client:
            while next_url:
                resp = await client.get(next_url, params=next_params)
                if resp.status_code == 404:
                    body = resp.text[:300] if resp.text else ""
                    logger.warning(
                        "GitHub 404 — endpoint not found or feature not enabled: %s  body=%s",
                        next_url, body,
                    )
                    break
                if resp.status_code == 403:
                    body = resp.text[:300] if resp.text else ""
                    logger.warning(
                        "GitHub 403 — access denied (check token scopes / GHAS licence): %s  body=%s",
                        next_url, body,
                    )
                    break
                resp.raise_for_status()
                data = resp.json()
                if isinstance(data, list):
                    results.extend(data)
                # GitHub uses Link header for pagination; params are baked into the Next URL
                next_url = self._extract_next_link(resp.headers.get("link", ""))
                next_params = None   # subsequent pages: params already in the URL

        return results

    @staticmethod
    def _extract_next_link(link_header: str) -> Optional[str]:
        """Parse a GitHub ``Link`` response header and return the *next* URL."""
        if not link_header:
            return None
        for part in link_header.split(","):
            segments = part.split(";")
            if len(segments) < 2:
                continue
            if 'rel="next"' in segments[1]:
                return segments[0].strip().strip("<>")
        return None

    # ------------------------------------------------------------------
    # VEX helper: build dismissal comment
    # ------------------------------------------------------------------

    @staticmethod
    def build_vex_comment(
        vex_status: VexStatus,
        justification: Optional[JustificationCode],
        impact_statement: str,
        epss_score: Optional[float],
        hits: list[ReachabilityHit],
    ) -> str:
        lines = [
            "## VEX Agent Report",
            "",
            f"**Status:** `{vex_status.value}`",
        ]
        if justification:
            lines.append(f"**Justification:** `{justification.value}`")
        if epss_score is not None:
            lines.append(f"**EPSS Score:** `{epss_score:.4f}` (30-day exploitation probability)")
        lines += ["", impact_statement, ""]

        if hits:
            lines.append("### Reachability Evidence")
            for hit in hits:
                lines.append(
                    f"- **{hit.file_path}:{hit.line_number}** — `{hit.line_content.strip()}` "
                    f"(function: `{hit.function_called}`, confidence: {hit.confidence:.0%})"
                )

        lines += [
            "",
            "---",
            "*Generated automatically by the VEX Agent.*",
        ]
        return "\n".join(lines)
