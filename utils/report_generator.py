"""
Security Report Generator.

Fetches all open GitHub security alerts (Dependabot, code-scanning,
secret-scanning) for a repository, generates a CycloneDX SBOM and a
combined CycloneDX VEX document, then uploads both to SharePoint
via :func:`utils.vex_file_store.save_vex_and_sbom`.

Intended to be called from the ``--generate-report`` CLI flag in main.py.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from clients.github_client import GitHubSecurityClient
from config import settings
from models.vex_models import (
    AnalysisDecision,
    NormalisedFinding,
    Severity,
    VexDecision,
    VexStatus,
)
from utils.sbom_generator import SBOMGenerator
from utils.vex_exporter import VexExporter
from utils.vex_file_store import read_product_version, save_vex_and_sbom

logger = logging.getLogger(__name__)

# Regex to extract owner/repo from a GitHub HTTPS or SSH clone URL.
_GITHUB_REPO_RE = re.compile(
    r"github\.com[:/]([^/]+/[^/\.]+?)(?:\.git)?$",
    re.IGNORECASE,
)


def _repo_name_from_url(url: str) -> str:
    """Return 'owner/repo' extracted from a GitHub clone URL, or *url* unchanged."""
    if not url:
        return url
    m = _GITHUB_REPO_RE.search(url)
    return m.group(1) if m else url


# ---------------------------------------------------------------------------
# Severity mapping shared with GitHubSecurityClient
# ---------------------------------------------------------------------------

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "warning": Severity.MEDIUM,
    "error": Severity.HIGH,
    "note": Severity.LOW,
    "informational": Severity.INFORMATIONAL,
}


# ---------------------------------------------------------------------------
# Alert normalisers
# ---------------------------------------------------------------------------

def _normalise_dependabot(
    alert: dict[str, Any],
    repo_full_name: str,
    repo_clone_url: str,
) -> NormalisedFinding:
    """Convert a raw Dependabot API response into a :class:`NormalisedFinding`."""
    advisory = alert.get("security_advisory") or {}
    vuln = alert.get("security_vulnerability") or {}
    dep = alert.get("dependency") or {}
    pkg = dep.get("package") or {}

    identifiers = {
        i["type"]: i["value"]
        for i in advisory.get("identifiers") or []
    }
    cvss = advisory.get("cvss") or {}

    raw_sev = (
        vuln.get("severity") or advisory.get("severity") or "medium"
    ).lower()

    return NormalisedFinding(
        alert_id=alert["number"],
        repo_full_name=repo_full_name,
        repo_clone_url=repo_clone_url,
        repo_default_branch="main",
        cve_id=identifiers.get("CVE"),
        ghsa_id=identifiers.get("GHSA") or advisory.get("ghsa_id"),
        package_name=pkg.get("name", "unknown"),
        package_version=dep.get("manifest_path", ""),
        package_ecosystem=(pkg.get("ecosystem") or "unknown").lower(),
        vulnerable_version_range=vuln.get("vulnerable_version_range", ""),
        patched_version=(vuln.get("first_patched_version") or {}).get("identifier"),
        severity=_SEVERITY_MAP.get(raw_sev, Severity.MEDIUM),
        cvss_score=float(cvss["score"]) if cvss.get("score") else None,
        cvss_vector_string=cvss.get("vectorString"),
        manifest_path=dep.get("manifest_path"),
        scope=dep.get("scope"),
        vulnerable_functions=advisory.get("vulnerable_functions") or [],
        summary=advisory.get("summary", ""),
        references=[r["url"] for r in (advisory.get("references") or [])],
    )


def _normalise_code_scanning(
    alert: dict[str, Any],
    repo_full_name: str,
    repo_clone_url: str,
) -> NormalisedFinding:
    """Convert a raw code-scanning API response into a :class:`NormalisedFinding`."""
    rule = alert.get("rule") or {}
    tool = alert.get("tool") or {}
    instance = alert.get("most_recent_instance") or {}
    location = instance.get("location") or {}

    raw_sev = (rule.get("severity") or rule.get("security_severity_level") or "medium").lower()
    tool_name = tool.get("name", "code-scanner")
    rule_id = rule.get("id", f"code-scan-{alert['number']}")

    return NormalisedFinding(
        alert_id=alert["number"],
        repo_full_name=repo_full_name,
        repo_clone_url=repo_clone_url,
        repo_default_branch="main",
        cve_id=None,
        ghsa_id=rule_id,   # repurpose ghsa_id for rule identifier
        package_name=repo_full_name.split("/")[-1],
        package_version="",
        package_ecosystem="source",
        vulnerable_version_range="",
        patched_version=None,
        severity=_SEVERITY_MAP.get(raw_sev, Severity.MEDIUM),
        cvss_score=None,
        cvss_vector_string=None,
        manifest_path=location.get("path"),
        scope="runtime",
        vulnerable_functions=[],
        summary=(
            rule.get("description")
            or rule.get("name")
            or f"{tool_name} rule {rule_id}"
        ),
        references=[alert.get("html_url", "")],
    )


def _normalise_secret_scanning(
    alert: dict[str, Any],
    repo_full_name: str,
    repo_clone_url: str,
) -> NormalisedFinding:
    """Convert a raw secret-scanning API response into a :class:`NormalisedFinding`."""
    secret_type = alert.get("secret_type", "unknown_secret")
    display_name = alert.get("secret_type_display_name", secret_type)

    return NormalisedFinding(
        alert_id=alert["number"],
        repo_full_name=repo_full_name,
        repo_clone_url=repo_clone_url,
        repo_default_branch="main",
        cve_id=None,
        ghsa_id=f"SECRET-{secret_type}",
        package_name=repo_full_name.split("/")[-1],
        package_version="",
        package_ecosystem="source",
        vulnerable_version_range="",
        patched_version=None,
        severity=Severity.HIGH,   # secrets are always high-priority
        cvss_score=None,
        cvss_vector_string=None,
        manifest_path=None,
        scope="runtime",
        vulnerable_functions=[],
        summary=f"Exposed secret detected: {display_name}",
        references=[alert.get("html_url", "")],
    )


def _make_vex_decision(finding: NormalisedFinding, alert_type: str) -> VexDecision:
    """Wrap a finding into a :class:`VexDecision` with UNDER_INVESTIGATION status."""
    return VexDecision(
        finding=finding,
        decision=AnalysisDecision.UNDER_INVESTIGATION,
        vex_status=VexStatus.UNDER_INVESTIGATION,
        justification_code=None,
        impact_statement=(
            f"Alert sourced from GitHub {alert_type}. "
            "Automated exploitability analysis has not been run for this entry; "
            "manual review is required."
        ),
    )


# ---------------------------------------------------------------------------
# Main report generation
# ---------------------------------------------------------------------------

class SecurityReportGenerator:
    """
    Orchestrates SBOM + VEX generation for the ``--generate-report`` CLI mode.

    Parameters
    ----------
    repo_full_name:
        ``owner/repo`` form, e.g. ``acme/my-service``.  Can be ``None`` when
        the repository is specified only via a local path and no GitHub alerts
        need to be fetched.
    local_repo_path:
        Absolute path to an already-cloned local checkout.  When ``None`` the
        generator will shallow-clone from ``TARGET_REPO_URL`` (or construct a
        clone URL from *repo_full_name*).
    branch:
        Branch to check out when cloning.
    """

    def __init__(
        self,
        repo_full_name: Optional[str] = None,
        local_repo_path: Optional[Path] = None,
        branch: str = "main",
    ):
        # Resolve to owner/repo form (strip clone URL if necessary)
        raw = repo_full_name or settings.target_repo_url or ""
        self._repo_full_name = _repo_name_from_url(raw)
        self._local_repo_path = local_repo_path or (
            Path(settings.local_repo_path) if settings.local_repo_path else None
        )
        self._branch = branch or settings.target_repo_branch or "main"
        self._github = GitHubSecurityClient()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run(self) -> dict[str, Any]:
        """
        Execute the full report pipeline:

        1. Resolve / clone the target repository.
        2. Generate SBOM from the local working tree.
        3. Fetch all GitHub security alerts (Dependabot + code scan + secrets).
        4. Build a combined CycloneDX VEX document.
        5. Upload SBOM + VEX to SharePoint ``{SHAREPOINT_FOLDER_PATH}/{JIRA_PROJECT_KEY}/{version}/``.

        Returns a summary dict with counts and saved file paths.
        """
        summary: dict[str, Any] = {
            "sbom_generated": False,
            "dependabot_alerts": 0,
            "code_scanning_alerts": 0,
            "secret_scanning_alerts": 0,
            "total_alerts": 0,
            "saved_files": [],
            "errors": [],
        }

        # ── 1. Resolve local repo path ────────────────────────────────
        repo_path, repo_name, cleanup = await self._resolve_repo()
        if repo_path is None:
            summary["errors"].append(
                "Could not resolve target repository. "
                "Set LOCAL_REPO_PATH or TARGET_REPO_URL in .env, or pass --repo-path."
            )
            return summary

        # ── 2. Read product version ────────────────────────────────────
        product_version = read_product_version(repo_path)
        logger.info("Product version resolved: %s", product_version)

        try:
            # ── 3. Generate SBOM ─────────────────────────────────────
            logger.info("Generating SBOM for %s …", repo_name)
            gen = SBOMGenerator(repo_path, repo_name)
            sbom_json = gen.generate_json()
            summary["sbom_generated"] = True
            logger.info("SBOM generated (%d bytes)", len(sbom_json))

            # ── 4. Fetch GitHub security alerts ──────────────────────
            findings = await self._fetch_all_alerts(summary)

            # ── 5. Build combined VEX document ───────────────────────
            vex_json = self._build_vex(findings)
            logger.info(
                "VEX document built with %d vulnerabilities", len(findings)
            )

            # ── 6. Persist files ─────────────────────────────────────
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            vex_filename = f"vex-report-{today}.cdx.json"
            sbom_filename = f"sbom-{repo_name}.cdx.json"

            saved = save_vex_and_sbom(
                vex_json_str=vex_json,
                sbom_json=sbom_json,
                vex_filename=vex_filename,
                sbom_filename=sbom_filename,
                repo_path=repo_path,
                product_version=product_version,
            )

            summary["saved_files"] = [str(p) for p in saved]
            if saved:
                logger.info("Files saved:")
                for p in saved:
                    logger.info("  %s", p)
            else:
                logger.warning(
                    "No files were saved — check that SHAREPOINT_TENANT_ID / SHAREPOINT_CLIENT_ID / "
                    "SHAREPOINT_CLIENT_SECRET / SHAREPOINT_SITE_URL are configured in .env."
                )

        finally:
            if cleanup:
                cleanup()

        # ── Record in dashboard store ─────────────────────────────────
        try:
            from utils.dashboard_store import get_dashboard_store, ReportRun
            get_dashboard_store().record_report(ReportRun(
                repo=self._repo_full_name or repo_name,
                product_version=product_version,
                sbom_generated=summary["sbom_generated"],
                dependabot_count=summary["dependabot_alerts"],
                code_scan_count=summary["code_scanning_alerts"],
                secret_count=summary["secret_scanning_alerts"],
                total_alerts=summary["total_alerts"],
                saved_files=summary["saved_files"],
                errors=summary["errors"],
            ))
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not record report in dashboard store: %s", exc)

        return summary

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _resolve_repo(
        self,
    ) -> tuple[Optional[Path], str, Any]:
        """
        Return ``(repo_path, repo_name, cleanup_callback)``.

        ``cleanup_callback`` is ``None`` when the path is a permanent local
        checkout, or a zero-argument callable that removes the temp clone.
        """
        # ──  Local path provided directly ────────────────────────────
        if self._local_repo_path and self._local_repo_path.is_dir():
            return self._local_repo_path, self._local_repo_path.name, None

        # ──  Clone URL available ──────────────────────────────────────
        clone_url = settings.target_repo_url
        if not clone_url and self._repo_full_name:
            # Derive HTTPS clone URL from owner/repo
            clone_url = f"https://github.com/{self._repo_full_name}.git"

        if clone_url:
            from utils.git_utils import ShallowClone  # local import

            repo_name = clone_url.rstrip("/").rstrip(".git").split("/")[-1]
            logger.info("Shallow-cloning %s (branch=%s) …", clone_url, self._branch)
            ctx = ShallowClone(
                clone_url,
                branch=self._branch,
                depth=settings.shallow_clone_depth or 1,
                github_token=settings.github_token or "",
            )
            try:
                repo_path = ctx.__enter__()
            except Exception as exc:  # noqa: BLE001
                logger.error("Clone failed: %s", exc)
                return None, "", None

            return repo_path, repo_name, lambda: ctx.__exit__(None, None, None)

        return None, "", None

    async def _fetch_all_alerts(
        self, summary: dict[str, Any]
    ) -> list[VexDecision]:
        """Fetch Dependabot + code-scanning + secret-scanning alerts concurrently."""
        if not self._repo_full_name:
            logger.warning(
                "No repo_full_name — skipping GitHub alert fetch. "
                "Pass --repo owner/repo to include alerts."
            )
            return []

        repo = self._repo_full_name
        # Build clone URL for NormalisedFinding
        clone_url = (
            settings.target_repo_url
            or f"https://github.com/{repo}.git"
        )

        # Fetch all three alert types concurrently (or use mock data)
        if settings.use_mock_github_data:
            from clients.mock_github_data import (
                MOCK_DEPENDABOT_ALERTS,
                MOCK_CODE_SCANNING_ALERTS,
                MOCK_SECRET_SCANNING_ALERTS,
                MOCK_SUMMARY,
            )
            logger.info(
                "USE_MOCK_GITHUB_DATA=true — using simulated dataset (%d total alerts)",
                MOCK_SUMMARY["total_alerts"],
            )
            dependabot_raw = MOCK_DEPENDABOT_ALERTS
            code_scan_raw = MOCK_CODE_SCANNING_ALERTS
            secret_raw = MOCK_SECRET_SCANNING_ALERTS
            # Override repo to the mock repo so normalisation is consistent
            repo = settings.mock_repo_full_name
            clone_url = f"https://github.com/{repo}.git"
        else:
            logger.info("Fetching security alerts from %s …", repo)
            dependabot_raw, code_scan_raw, secret_raw = await asyncio.gather(
                self._safe_fetch(self._github.list_dependabot_alerts(repo), "Dependabot"),
                self._safe_fetch(self._github.list_code_scanning_alerts(repo), "code-scanning"),
                self._safe_fetch(self._github.list_secret_scanning_alerts(repo), "secret-scanning"),
            )

        summary["dependabot_alerts"] = len(dependabot_raw)
        summary["code_scanning_alerts"] = len(code_scan_raw)
        summary["secret_scanning_alerts"] = len(secret_raw)
        summary["total_alerts"] = (
            summary["dependabot_alerts"]
            + summary["code_scanning_alerts"]
            + summary["secret_scanning_alerts"]
        )

        logger.info(
            "Alerts fetched — Dependabot: %d  Code scanning: %d  Secrets: %d",
            summary["dependabot_alerts"],
            summary["code_scanning_alerts"],
            summary["secret_scanning_alerts"],
        )

        decisions: list[VexDecision] = []

        for raw in dependabot_raw:
            try:
                finding = _normalise_dependabot(raw, repo, clone_url)
                decisions.append(_make_vex_decision(finding, "Dependabot"))
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not normalise Dependabot alert: %s", exc)

        for raw in code_scan_raw:
            try:
                finding = _normalise_code_scanning(raw, repo, clone_url)
                decisions.append(_make_vex_decision(finding, "code-scanning"))
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not normalise code-scanning alert: %s", exc)

        for raw in secret_raw:
            try:
                finding = _normalise_secret_scanning(raw, repo, clone_url)
                decisions.append(_make_vex_decision(finding, "secret-scanning"))
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not normalise secret-scanning alert: %s", exc)

        return decisions

    @staticmethod
    async def _safe_fetch(coro: Any, label: str) -> list[dict[str, Any]]:
        """Await *coro* and return its list result; log + return [] on error."""
        try:
            return await coro
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to fetch %s alerts: %s", label, exc)
            return []

    @staticmethod
    def _build_vex(decisions: list[VexDecision]) -> str:
        """Render a combined CycloneDX 1.5 VEX JSON string from *decisions*."""
        exporter = VexExporter(author="VEX Agent — Security Report")
        for decision in decisions:
            exporter.add_decision(decision)
        return exporter.export_json()
