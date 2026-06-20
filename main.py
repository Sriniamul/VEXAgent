"""
FastAPI webhook server.

Endpoint: POST /webhook/github
Validates the GitHub HMAC-SHA256 signature, parses the payload,
and dispatches it to the VEX Agent.
"""

from __future__ import annotations

import argparse
import base64 as _b64
import hashlib
import hmac
import json
import logging
import secrets as _secrets
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import httpx as _httpx
import uvicorn
from fastapi import Cookie, FastAPI, File, Header, HTTPException, Request, UploadFile, status
from fastapi.responses import RedirectResponse
import asyncio
from fastapi.responses import HTMLResponse, JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware

from pathlib import Path as _Path

from agents.vex_agent import VexAgent
from config import settings
from models.vex_models import GitHubSecurityWebhookPayload
from utils.sbom_generator import SBOMGenerator
from utils.vex_exporter import VexExporter
from utils.dashboard_store import get_dashboard_store, PipelineRun

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=settings.log_level,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Settings helpers
# ---------------------------------------------------------------------------

_SENSITIVE_KEYS: frozenset[str] = frozenset({
    "github_token",
    "github_webhook_secret",
    "jira_api_token",
    "teams_webhook_url",
    "copilot_token",
    "openai_api_key",
    "sharepoint_client_secret",
})
_SETTINGS_MASK = "••••••••"

# ---------------------------------------------------------------------------
# Import progress tracker (in-memory, single-process)
# ---------------------------------------------------------------------------

_import_progress: dict = {
    "active": False,
    "phase": "idle",
    "total": 0,
    "analysed": 0,
    "skipped_duplicates": 0,
    "affected": 0,
    "not_affected": 0,
    "errors": 0,
    "current_alert": "",
    "pct": 0,
}

def _reset_import_progress():
    """Reset progress to idle state."""
    _import_progress.update({
        "active": False,
        "phase": "idle",
        "total": 0,
        "analysed": 0,
        "skipped_duplicates": 0,
        "affected": 0,
        "not_affected": 0,
        "errors": 0,
        "current_alert": "",
        "pct": 0,
    })

def _update_import_progress(**kwargs):
    """Update progress and recalculate pct."""
    _import_progress.update(kwargs)
    total = _import_progress["total"]
    done = _import_progress["analysed"] + _import_progress["skipped_duplicates"]
    _import_progress["pct"] = round(done / total * 100) if total > 0 else 0

# ---------------------------------------------------------------------------
# Session / authentication helpers
# ---------------------------------------------------------------------------

_SESSION_COOKIE = "vex_session"
_SESSION_SECRET = _secrets.token_hex(32)  # random per process; restart = re-login

def _sign_session(username: str, avatar_url: str = "", is_repo_admin: bool = False) -> str:
    """Create a signed cookie value:  base64(username|avatar_url|is_admin).signature"""
    payload = f"{username}|{avatar_url}|{'1' if is_repo_admin else '0'}"
    payload_b64 = _b64.urlsafe_b64encode(payload.encode()).decode()
    sig = hmac.new(_SESSION_SECRET.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{sig}"


def _verify_session(cookie_value: str) -> dict | None:
    """Return {"username": ..., "avatar_url": ..., "is_repo_admin": bool} if valid, else None."""
    if not cookie_value or "." not in cookie_value:
        return None
    payload_b64, sig = cookie_value.rsplit(".", 1)
    expected = hmac.new(_SESSION_SECRET.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return None
    try:
        payload = _b64.urlsafe_b64decode(payload_b64).decode()
        parts = payload.split("|")
        return {
            "username": parts[0],
            "avatar_url": parts[1] if len(parts) > 1 else "",
            "is_repo_admin": parts[2] == "1" if len(parts) > 2 else False,
        }
    except Exception:
        return None


# Paths that do NOT require authentication
_PUBLIC_PATHS: frozenset[str] = frozenset({
    "/login",
    "/api/v1/login",
    "/health",
    "/openapi.json",
    "/docs",
    "/redoc",
})

# Prefixes that do NOT require authentication (webhook must work without login)
_PUBLIC_PREFIXES: tuple[str, ...] = (
    "/webhook/",
    "/api/v1/",
)

# ---------------------------------------------------------------------------
# Decision → Justification mapping (shared by all pipelines)
# ---------------------------------------------------------------------------
_DECISION_JUSTIFICATION_MAP: dict[str, str] = {
    "not_affected_dev_only":  "Development-only dependency — not included in production builds",
    "not_affected_dead_code": "Vulnerable code path is unreachable (dead code)",
    "affected_reachable":     "Vulnerable code is reachable in production",
    "break_the_build":        "Critical reachable vulnerability — build must be blocked",
    "under_investigation":    "Automated analysis inconclusive — insufficient confidence to determine reachability; manual triage required",
    "pending_review":         "Routed to human review — awaiting L1 approval",
}

_REVIEW_JUSTIFICATION_MAP: dict[str, str] = {
    "not_affected_dev_only":
        "Routed to human review — initial analysis suggests development-only dependency but confidence is below threshold; awaiting L1 approval",
    "not_affected_dead_code":
        "Routed to human review — initial analysis suggests vulnerable code is unreachable (dead code) but confidence is below threshold; awaiting L1 approval",
}


def _get_justification(decision: str, original_decision: str = "") -> str:
    """Return a human-readable justification string for a given decision.

    When *decision* is 'pending_review' and *original_decision* is
    provided, a more specific reason explains why the item was routed
    to human review rather than the generic fallback.
    """
    if decision == "pending_review" and original_decision:
        return _REVIEW_JUSTIFICATION_MAP.get(
            original_decision,
            _DECISION_JUSTIFICATION_MAP.get(decision, ""),
        )
    return _DECISION_JUSTIFICATION_MAP.get(decision, "")


# ---------------------------------------------------------------------------
# Per-level analysis summary builder (L1 / L2 / LLM → Decision)
# ---------------------------------------------------------------------------
_DECISION_REASON_SHORT: dict[str, str] = {
    "not_affected_dev_only":  "Not affected — dev-only dependency",
    "not_affected_dead_code": "Not affected — unreachable code",
    "affected_reachable":     "Affected — vulnerable code is reachable",
    "break_the_build":        "Affected — critical, build blocked",
    "under_investigation":    "Under investigation — manual triage required",
    "pending_review":         "Pending human review",
}


def _llm_reachable_reason(confidence: float | None, n_hits: int, notes: str) -> str:
    """Return a human-readable reason for an LLM 'reachable' verdict."""
    if notes:
        return notes
    if confidence is not None and confidence >= 0.85:
        return (
            "LLM identified direct import and invocation of the vulnerable function "
            "in application code with high confidence"
        )
    if confidence is not None and confidence >= 0.70:
        return (
            "LLM detected likely call paths to the vulnerable function through "
            "indirect or transitive invocations"
        )
    return (
        "LLM found potential call sites but with moderate confidence; "
        "the vulnerable function may be invoked through wrapper methods or dynamic dispatch"
    )


def _llm_unreachable_reason(confidence: float | None, notes: str) -> str:
    """Return a human-readable reason for an LLM 'not reachable' or inconclusive verdict."""
    if notes:
        return notes
    if confidence is not None and confidence >= 0.75:
        return (
            "LLM scanned all relevant source files and found no direct or indirect "
            "invocations of the vulnerable function in any production code path"
        )
    if confidence is not None and confidence >= 0.50:
        return (
            "LLM analysis suggests the vulnerable function is not called, but confidence "
            "is moderate — the package may be imported without exercising the vulnerable API surface"
        )
    if confidence is not None and confidence > 0:
        return (
            "LLM could not conclusively determine reachability — vulnerable function "
            "signatures were not found in scanned files, but indirect call chains or "
            "dynamic dispatch patterns could not be fully resolved"
        )
    return (
        "LLM analysis did not find evidence of the vulnerable function being called; "
        "however, limited source context was available for analysis"
    )


def _format_hits(hits) -> str:
    """Format a list of ReachabilityHit (or dicts) into indented call-site lines."""
    if not hits:
        return ""
    lines: list[str] = []
    for h in hits:
        fp = getattr(h, "file_path", None) or (h.get("file_path") if isinstance(h, dict) else "")
        ln = getattr(h, "line_number", None) or (h.get("line_number") if isinstance(h, dict) else 0)
        fn = getattr(h, "function_called", None) or (h.get("function_called") if isinstance(h, dict) else "")
        lc = getattr(h, "line_content", None) or (h.get("line_content") if isinstance(h, dict) else "")
        lc = lc.strip() if lc else ""
        detail = f"  → {fp}:{ln}" if fp else "  → (unknown)"
        if fn:
            detail += f"  {fn}()"
        if lc:
            detail += f"  [{lc}]"
        lines.append(detail)
    return "\n".join(lines)


def _format_import_sites(import_sites) -> str:
    """Format import-site evidence: files that import the library but do NOT
    call the vulnerable function(s).  This provides justification context
    for 'not affected / unreachable' decisions."""
    if not import_sites:
        return ""
    lines: list[str] = ["Import-site analysis (library used safely — vulnerable function(s) not called):"]
    for site in import_sites:
        fp = getattr(site, "file_path", None) or (site.get("file_path") if isinstance(site, dict) else "")
        ln = getattr(site, "line_number", None) or (site.get("line_number") if isinstance(site, dict) else 0)
        imp_stmt = getattr(site, "import_statement", None) or (site.get("import_statement") if isinstance(site, dict) else "")
        funcs_used = getattr(site, "functions_used", None) or (site.get("functions_used") if isinstance(site, dict) else [])
        lc = getattr(site, "line_content", None) or (site.get("line_content") if isinstance(site, dict) else "")
        lc = (lc or "").strip()

        detail = f"  ✓ {fp}:{ln}" if fp else "  ✓ (unknown)"
        if imp_stmt:
            detail += f"  [{imp_stmt}]"
        elif lc:
            detail += f"  [{lc}]"
        if funcs_used:
            detail += f"  — uses: {', '.join(funcs_used[:5])}"
            detail += " (none are vulnerable)"
        else:
            detail += " — imports library but does not call any vulnerable function"
        lines.append(detail)
    return "\n".join(lines)


def _build_suggested_fix(
    *,
    package_name: str,
    patched_version: str | None = None,
    decision_str: str,
    alert_type: str = "dependabot",
    severity: str = "medium",
    cve_id: str | None = None,
    ecosystem: str = "unknown",
    epss_score: float | None = None,
    reachable: bool | None = None,
    metadata_result=None,
    reachability_result=None,
    vulnerable_version_range: str = "",
    summary: str = "",
) -> str:
    """Build a context-aware suggested fix based on alert type, decision, and analysis data."""
    pkg = package_name
    patched = patched_version or "latest patched version"
    cve = cve_id or "this vulnerability"
    sev = (severity or "medium").lower()

    # ── Package manager commands ──────────────────────────────────
    _PM_UPGRADE = {
        "pip":   f"`pip install --upgrade {pkg}=={patched}`" if patched != "latest patched version" else f"`pip install --upgrade {pkg}`",
        "npm":   f"`npm install {pkg}@{patched}`" if patched != "latest patched version" else f"`npm update {pkg}`",
        "yarn":  f"`yarn upgrade {pkg}@{patched}`" if patched != "latest patched version" else f"`yarn upgrade {pkg}`",
        "maven": f"Update `<version>` for `{pkg}` to `{patched}` in `pom.xml`",
        "nuget": f"`dotnet add package {pkg} --version {patched}`" if patched != "latest patched version" else f"Update `{pkg}` via NuGet Package Manager",
        "go":    f"`go get {pkg}@v{patched}`" if patched != "latest patched version" else f"`go get -u {pkg}`",
        "rubygems": f"`bundle update {pkg}`",
        "composer": f"`composer require {pkg}:{patched}`" if patched != "latest patched version" else f"`composer update {pkg}`",
        "cargo": f"Update `{pkg}` version in `Cargo.toml` to `{patched}`",
    }
    eco_lower = (ecosystem or "unknown").lower()
    pm_cmd = _PM_UPGRADE.get(eco_lower, f"Update `{pkg}` to `{patched}` in your dependency manifest")

    # ── Secret scanning ───────────────────────────────────────────
    if alert_type == "secret_scanning":
        return (
            f"**Immediate action required — exposed secret detected.**\n\n"
            f"1. **Revoke** the exposed secret/credential immediately.\n"
            f"2. **Rotate** the credential — generate a new key/token and update all services that use it.\n"
            f"3. **Audit** access logs to determine if the secret was used by an unauthorized party.\n"
            f"4. **Remove** the secret from source code and commit history (use `git filter-branch` or BFG Repo-Cleaner).\n"
            f"5. **Prevent recurrence** — use a secrets manager (e.g. Azure Key Vault, AWS Secrets Manager) and enable pre-commit hooks.\n\n"
            f"Reference: {cve}"
        )

    # ── Code scanning ─────────────────────────────────────────────
    if alert_type == "code_scanning":
        vuln_desc = f" ({summary})" if summary else ""
        return (
            f"**Code-level fix required{vuln_desc}.**\n\n"
            f"1. Review the flagged code pattern and apply the recommended secure coding fix.\n"
            f"2. If the finding involves a dependency, {pm_cmd}.\n"
            f"3. Validate the fix by re-running the code scanning analysis.\n"
            f"4. Consider adding a unit test to cover the previously vulnerable code path.\n\n"
            f"Reference: {cve}"
        )

    # ── Dependabot / SCA — decision-aware ─────────────────────────
    is_dev = metadata_result and getattr(metadata_result, "is_dev_dependency", False)
    manifest = (metadata_result and getattr(metadata_result, "manifest_path", "")) or ""

    # Reachability detail
    hits = []
    if reachability_result and getattr(reachability_result, "hits", None):
        hits = reachability_result.hits
    hit_files = []
    for h in hits[:3]:
        fp = getattr(h, "file_path", None) or (h.get("file_path") if isinstance(h, dict) else "")
        fn = getattr(h, "function_called", None) or (h.get("function_called") if isinstance(h, dict) else "")
        if fp:
            hit_files.append(f"`{fp}`" + (f" → `{fn}()`" if fn else ""))

    vuln_range_note = f" (vulnerable range: {vulnerable_version_range})" if vulnerable_version_range else ""
    epss_note = ""
    epss_val: float | None = None
    if isinstance(epss_score, (int, float)):
        epss_val = float(epss_score)
    else:
        try:
            epss_val = float(epss_score) if epss_score is not None else None
        except Exception:
            epss_val = None

    if epss_val is not None:
        pct = round(epss_val * 100, 1)
        if epss_val >= 0.1:
            epss_note = f"\n\n⚠️ EPSS score: {pct}% — high probability of exploitation within 30 days."
        elif epss_val >= 0.01:
            epss_note = f"\n\nEPSS score: {pct}% — moderate exploitation probability."

    if decision_str == "not_affected_dev_only":
        manifest_note = f" in `{manifest}`" if manifest else ""
        return (
            f"No immediate production risk — `{pkg}` is a dev/test-only dependency{manifest_note}.\n\n"
            f"**Recommended actions:**\n"
            f"1. Upgrade to `{patched}` during next maintenance window: {pm_cmd}.\n"
            f"2. Verify dev/test environments are not exposed to untrusted input.{epss_note}\n\n"
            f"Reference: {cve}{vuln_range_note}"
        )

    if decision_str == "not_affected_dead_code":
        return (
            f"Low risk — vulnerable code in `{pkg}` is unreachable (dead code) in this project.\n\n"
            f"**Recommended actions:**\n"
            f"1. Upgrade to `{patched}` as a preventive measure: {pm_cmd}.\n"
            f"2. No functional impact expected since the vulnerable API is not called.{epss_note}\n\n"
            f"Reference: {cve}{vuln_range_note}"
        )

    if decision_str == "under_investigation":
        return (
            f"Manual review needed — automated analysis was inconclusive for `{pkg}`.\n\n"
            f"**Recommended actions:**\n"
            f"1. Manually check whether your code calls the vulnerable API in `{pkg}`.\n"
            f"2. If reachable: {pm_cmd} and verify no breaking changes.\n"
            f"3. If unreachable: mark as Not Affected with justification.{epss_note}\n\n"
            f"Reference: {cve}{vuln_range_note}"
        )

    if decision_str == "pending_review":
        return (
            f"Awaiting human review — agent flagged `{pkg}` with low confidence.\n\n"
            f"**Recommended actions:**\n"
            f"1. Review the reachability analysis and confirm or override the agent decision.\n"
            f"2. If upgrade is needed: {pm_cmd}.\n"
            f"3. Approve or dismiss the review in the dashboard.{epss_note}\n\n"
            f"Reference: {cve}{vuln_range_note}"
        )

    # AFFECTED_REACHABLE or BREAK_THE_BUILD
    urgency = "🚨 **Critical — build-blocking vulnerability.**" if decision_str == "break_the_build" else "⚠️ **Immediate action required.**"
    sev_label = f" [{sev.upper()} severity]" if sev in ("critical", "high") else ""

    call_sites = ""
    if hit_files:
        call_sites = "\n\n**Reachable call sites:**\n" + "\n".join(f"  - {f}" for f in hit_files)

    return (
        f"{urgency}{sev_label}\n\n"
        f"Vulnerable code in `{pkg}` is confirmed reachable in production.{call_sites}{epss_note}\n\n"
        f"**Fix steps:**\n"
        f"1. {pm_cmd}.\n"
        f"2. Verify the fix: search for calls to the vulnerable API and confirm they use the patched behaviour.\n"
        f"3. Run regression tests to ensure no breaking changes.\n"
        f"4. Re-run the VEX Agent to confirm the alert is resolved.\n\n"
        f"Reference: {cve}{vuln_range_note}"
    )


def _build_analysis_summary(
    metadata_result,
    reachability_result,
    decision_str: str,
    original_decision: str = "",
    alert_scope: str = "",
) -> str:
    """Build a multi-line per-level analysis summary for the Justification column.

    Format::

        L1 Metadata: …
        L2 Reachability (AST): …
          → file:line  func()  [code]
        LLM Analysis: …
        VEX Decision: …
    """
    parts: list[str] = []

    # ── GitHub scope = "development" — authoritative short-circuit ────
    # When GitHub itself marks the alert scope as "development", the dependency
    # is exclusively used in dev/test environments.  No runtime exposure is
    # possible regardless of what the manifest scanner or reachability
    # analyser report.
    if (alert_scope or "").lower() == "development":
        pkg = ""
        if metadata_result is not None:
            pkg = f" for '{getattr(metadata_result, 'manifest_path', '') or ''}'"
        parts.append(
            "L1 Metadata: Development-only dependency (GitHub alert scope: development)"
            " — not present in production builds"
        )
        parts.append("L2 Reachability (AST): Skipped — development scope confirmed by GitHub, no production code paths exist")
        parts.append("LLM Analysis: Skipped — not applicable for development-scope dependencies")
        parts.append(f"VEX Decision: {_DECISION_REASON_SHORT.get(decision_str, decision_str)}")
        return "\n".join(parts)

    # ── L1 Metadata ────────────────────────────────────────────────────
    if metadata_result is not None:
        scope = metadata_result.dependency_scope or "unknown"
        justification = getattr(metadata_result, "justification", "") or ""
        manifest = getattr(metadata_result, "manifest_path", "") or ""
        if metadata_result.is_dev_dependency:
            l1 = f"L1 Metadata: Dev/test-only dependency (scope: {scope})"
            if manifest:
                l1 += f" in {manifest}"
            if justification:
                l1 += f" — {justification}"
            else:
                l1 += " — excluded from production builds"
        elif metadata_result.is_test_dependency:
            l1 = f"L1 Metadata: Test-only dependency (scope: {scope})"
            if manifest:
                l1 += f" in {manifest}"
            if justification:
                l1 += f" — {justification}"
            else:
                l1 += " — not shipped to production"
        else:
            l1 = f"L1 Metadata: Production dependency (scope: {scope})"
            if manifest:
                l1 += f" in {manifest}"
            l1 += " — included in production builds, deep analysis required"
    else:
        l1 = "L1 Metadata: Not run"
    parts.append(l1)

    # ── L2 Reachability (AST) + LLM ───────────────────────────────────
    if reachability_result is not None:
        method = getattr(reachability_result, "method", "ast") or "ast"
        conf = getattr(reachability_result, "confidence", None)
        conf_val: float | None = None
        if isinstance(conf, (int, float)):
            conf_val = float(conf)
        else:
            try:
                conf_val = float(conf) if conf is not None else None
            except Exception:
                conf_val = None
        conf_str = f", confidence {conf_val:.0%}" if conf_val is not None else ""
        hits = reachability_result.hits if reachability_result.hits else []
        n_hits = len(hits)
        notes = getattr(reachability_result, "notes", "") or ""
        import_sites = getattr(reachability_result, "import_sites", None) or []

        if method == "llm":
            # AST ran first but found nothing → LLM took over
            parts.append("L2 Reachability (AST): Scanned source — no reachable call sites found")
            if reachability_result.reachable:
                reason = _llm_reachable_reason(conf, n_hits, notes)
                parts.append(f"LLM Analysis: Confirmed reachable — {n_hits} call site(s) identified{conf_str}. {reason}")
                hit_text = _format_hits(hits)
                if hit_text:
                    parts.append(hit_text)
            else:
                reason = _llm_unreachable_reason(conf, notes)
                parts.append(f"LLM Analysis: No reachable paths found{conf_str}. {reason}")
                # Show import sites — files that use the library safely
                if import_sites:
                    imp_text = _format_import_sites(import_sites)
                    if imp_text:
                        parts.append(imp_text)
        else:
            if reachability_result.reachable:
                parts.append(f"L2 Reachability (AST): {n_hits} reachable call site(s) found{conf_str}")
                hit_text = _format_hits(hits)
                if hit_text:
                    parts.append(hit_text)
                parts.append("LLM Analysis: Not needed — AST analysis was conclusive")
            else:
                ast_note = f" ({notes})" if notes else ""
                parts.append(f"L2 Reachability (AST): Scanned source — no reachable call sites found{conf_str}{ast_note}")
                # Show import sites — files that use the library safely
                if import_sites:
                    imp_text = _format_import_sites(import_sites)
                    if imp_text:
                        parts.append(imp_text)
                reason = _llm_unreachable_reason(conf, notes)
                parts.append(f"LLM Analysis: No reachable paths found. {reason}")
    elif metadata_result and metadata_result.is_dev_dependency:
        parts.append("L2 Reachability (AST): Skipped — dev/test dependency, not in production code paths")
        parts.append("LLM Analysis: Skipped — not applicable for dev-only dependencies")
    else:
        parts.append("L2 Reachability (AST): Not run")
        parts.append("LLM Analysis: Not run")

    # ── VEX Decision ──────────────────────────────────────────────────
    if decision_str == "pending_review" and original_decision:
        orig_label = _DECISION_REASON_SHORT.get(original_decision, original_decision)
        parts.append(f"VEX Decision: Pending human review (originally: {orig_label})")
    else:
        parts.append(f"VEX Decision: {_DECISION_REASON_SHORT.get(decision_str, decision_str)}")

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Application lifecycle
# ---------------------------------------------------------------------------

import os as _os

_agent: VexAgent | None = None
_simulate_on_start: bool = _os.environ.get("_VEX_SIMULATE", "") == "1"  # set via --simulate CLI flag


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _agent
    _agent = VexAgent()
    logger.info("VEX Agent initialised. Listening for GitHub security webhooks…")
    if _simulate_on_start:
        # Pre-populate dashboard with simulated data so stats are non-zero immediately
        try:
            result = await mock_simulate()
            logger.info("Mock data pre-loaded into dashboard store.")
        except Exception as exc:
            logger.warning("Could not pre-load mock data: %s", exc)
        # Create Jira tickets for all affected runs (no-op if Jira not configured)
        if settings.jira_base_url and settings.jira_api_token and settings.jira_project_key:
            try:
                await mock_create_jira_tickets()
                logger.info("Jira tickets created for affected mock alerts.")
            except Exception as exc:
                logger.warning("Could not create Jira tickets for mock data: %s", exc)
    elif not _simulate_on_start:
        # Clear any persisted review queue from previous runs so the dashboard starts empty
        from utils.review_queue import get_review_queue as _get_review_queue
        try:
            cleared = _get_review_queue().clear_all()
            if cleared:
                logger.info("Cleared %d stale review(s) from previous session.", cleared)
        except Exception as exc:
            logger.warning("Could not clear review queue: %s", exc)
        logger.info("Starting with empty dashboard (use --simulate to pre-load mock data).")
    yield
    logger.info("Shutting down.")


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="VEX Agent — GitHub Security Exploitability Validator",
    version="1.0.0",
    description=(
        "Automatically validates whether Dependabot / SCA findings are genuinely "
        "reachable in your production code and updates GitHub security accordingly."
    ),
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Authentication middleware
# ---------------------------------------------------------------------------

class _AuthMiddleware(BaseHTTPMiddleware):
    """Redirect unauthenticated browser requests to /login.

    API calls receive a 401 JSON response instead of a redirect.
    Public paths (login, health, webhooks, docs) are always allowed.
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Always try to attach session so endpoints like /api/v1/me can read it
        cookie = request.cookies.get(_SESSION_COOKIE, "")
        session = _verify_session(cookie)
        if session:
            request.state.user = session

        # Allow public paths through without auth
        if path in _PUBLIC_PATHS or any(path.startswith(p) for p in _PUBLIC_PREFIXES):
            return await call_next(request)

        if session:
            return await call_next(request)

        # Not authenticated — decide response type
        accept = request.headers.get("accept", "")
        if "text/html" in accept:
            return RedirectResponse(url="/login", status_code=303)
        else:
            return JSONResponse(
                {"error": "Authentication required", "login_url": "/login"},
                status_code=401,
            )


app.add_middleware(_AuthMiddleware)


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------

def _verify_signature(body: bytes, signature_header: str | None) -> None:
    """
    Validate the X-Hub-Signature-256 header sent by GitHub.
    Raises HTTP 401 if the secret is wrong or missing.
    """
    if not settings.github_webhook_secret:
        logger.warning("GITHUB_WEBHOOK_SECRET not configured — skipping signature check.")
        return

    if not signature_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Hub-Signature-256 header.",
        )

    expected = "sha256=" + hmac.new(
        settings.github_webhook_secret.encode(),
        body,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, signature_header):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature.",
        )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", include_in_schema=False)
async def root():
    """Redirect root to the dashboard."""
    return RedirectResponse(url="/dashboard")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "vex-agent"}


# ---------------------------------------------------------------------------
# Authentication routes
# ---------------------------------------------------------------------------

_LOGIN_PATH = _Path(__file__).parent / "templates" / "login.html"


@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
async def login_page() -> HTMLResponse:
    """Serve the GitHub login page."""
    return HTMLResponse(_LOGIN_PATH.read_text(encoding="utf-8"))


@app.post("/api/v1/login", summary="Authenticate via GitHub")
async def api_login(payload: dict) -> JSONResponse:
    """Validate GitHub credentials (username + Personal Access Token).

    On success sets a signed session cookie and returns user info.
    """
    username = (payload.get("username") or "").strip()
    token = (payload.get("token") or "").strip()

    if not username or not token:
        return JSONResponse(
            {"error": "Username and token are required."},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Verify against GitHub API
    try:
        async with _httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
    except Exception as exc:
        logger.warning("GitHub API request failed during login: %s", exc)
        return JSONResponse(
            {"error": "Could not reach GitHub API. Check your network connection."},
            status_code=status.HTTP_502_BAD_GATEWAY,
        )

    if resp.status_code == 401:
        return JSONResponse(
            {"error": "Invalid token. Please check your Personal Access Token."},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    if resp.status_code != 200:
        return JSONResponse(
            {"error": f"GitHub API returned HTTP {resp.status_code}."},
            status_code=status.HTTP_502_BAD_GATEWAY,
        )

    gh_user = resp.json()
    gh_login = gh_user.get("login", "")

    # Verify the provided username matches the token owner
    if gh_login.lower() != username.lower():
        return JSONResponse(
            {"error": f"Token belongs to '{gh_login}', not '{username}'."},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    avatar_url = gh_user.get("avatar_url", "")
    display_name = gh_user.get("name") or gh_login

    # ── Check repository admin rights ──────────────────────────────
    is_repo_admin = False
    target_repo = settings.mock_repo_full_name or ""
    if not target_repo and settings.target_repo_url:
        target_repo = settings.target_repo_url.rstrip("/").removesuffix(".git").split("github.com/")[-1]

    if target_repo:
        try:
            async with _httpx.AsyncClient(timeout=10) as perm_client:
                perm_resp = await perm_client.get(
                    f"https://api.github.com/repos/{target_repo}/collaborators/{gh_login}/permission",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28",
                    },
                )
                if perm_resp.status_code == 200:
                    role = perm_resp.json().get("permission", "")
                    is_repo_admin = role in ("admin", "write")
                    logger.info(
                        "User '%s' has '%s' permission on %s (admin=%s)",
                        gh_login, role, target_repo, is_repo_admin,
                    )
                else:
                    logger.info(
                        "Could not check repo permissions for '%s' on %s: HTTP %s",
                        gh_login, target_repo, perm_resp.status_code,
                    )
        except Exception as exc:
            logger.warning("Repo permission check failed for '%s': %s", gh_login, exc)

    logger.info("User '%s' authenticated via GitHub (repo_admin=%s).", gh_login, is_repo_admin)

    # Set session cookie
    cookie_value = _sign_session(gh_login, avatar_url, is_repo_admin=is_repo_admin)
    response = JSONResponse({
        "status": "ok",
        "username": gh_login,
        "display_name": display_name,
        "avatar_url": avatar_url,
    })
    response.set_cookie(
        key=_SESSION_COOKIE,
        value=cookie_value,
        httponly=True,
        samesite="lax",
        max_age=60 * 60 * 24,  # 24 hours
        path="/",
    )
    return response


@app.get("/api/v1/me", summary="Current user info")
async def api_me(request: Request) -> JSONResponse:
    """Return the currently authenticated user, or 401."""
    user = getattr(request.state, "user", None)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    return JSONResponse(user)


@app.post("/api/v1/logout", summary="Log out")
async def api_logout() -> JSONResponse:
    """Clear the session cookie."""
    response = JSONResponse({"status": "ok"})
    response.delete_cookie(key=_SESSION_COOKIE, path="/")
    return response


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

_DASHBOARD_PATH = _Path(__file__).parent / "templates" / "dashboard.html"


@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def dashboard() -> HTMLResponse:
    """Serve the live VEX Agent dashboard (reads file each request so edits are live)."""
    return HTMLResponse(_DASHBOARD_PATH.read_text(encoding="utf-8"))


@app.get("/api/v1/stats", summary="Dashboard statistics")
async def api_stats() -> dict:
    """Aggregated pipeline statistics for the dashboard."""
    store = get_dashboard_store()
    stats = store.stats()
    stats["jira_base_url"] = settings.jira_base_url or ""
    stats["review_base_url"] = settings.review_base_url or ""
    return stats


@app.get("/api/v1/settings", summary="Get current configuration")
async def api_get_settings() -> dict:
    """Return all settings with sensitive values masked."""
    d = settings.model_dump()
    return {
        k: (_SETTINGS_MASK if v else "") if k in _SENSITIVE_KEYS else v
        for k, v in d.items()
    }


@app.put("/api/v1/settings", summary="Update configuration")
async def api_update_settings(payload: dict) -> dict:
    """Write changed settings to .env and update them in-memory.

    Sensitive key values equal to the mask string are treated as unchanged.
    """
    env_path = _Path(__file__).parent / ".env"
    lines: list[str] = env_path.read_text(encoding="utf-8").splitlines() if env_path.exists() else []

    updated_keys: list[str] = []

    for key, value in payload.items():
        if not hasattr(settings, key):
            continue
        # Leave sensitive fields unchanged when the mask is sent back
        if key in _SENSITIVE_KEYS and value == _SETTINGS_MASK:
            continue

        current = getattr(settings, key)
        # Type coercion matching the existing field type
        try:
            if isinstance(current, bool):
                new_val: Any = str(value).strip().lower() in ("true", "1", "yes", "on") \
                    if isinstance(value, str) else bool(value)
            elif isinstance(current, int):
                new_val = int(value)
            elif isinstance(current, float):
                new_val = float(value)
            elif current is None and isinstance(value, str):
                new_val = value or None
            else:
                new_val = str(value) if value is not None else ""
        except (ValueError, TypeError):
            continue

        # Mutate in-memory settings
        try:
            object.__setattr__(settings, key, new_val)
        except Exception:
            pass

        updated_keys.append(key)

        # Update / append matching line in .env
        env_key = key.upper()
        str_val = ("true" if new_val else "false") if isinstance(new_val, bool) else str(new_val or "")
        found = False
        for i, line in enumerate(lines):
            # Match KEY= or KEY =
            if line.lstrip().upper().startswith(env_key + "=") or \
               line.lstrip().upper().startswith(env_key + " ="):
                lines[i] = f"{env_key}={str_val}"
                found = True
                break
        if not found:
            lines.append(f"{env_key}={str_val}")

    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    logger.info("Settings updated via API: %s", updated_keys)
    return {"updated": updated_keys, "count": len(updated_keys)}


@app.post("/api/v1/settings/sharepoint/test", summary="Test SharePoint connectivity")
async def api_test_sharepoint(payload: dict | None = None) -> dict:
    """Test SharePoint connection — surfaces raw Azure AD / Graph errors."""
    import httpx, time
    from urllib.parse import urlparse

    p = payload or {}
    tenant_id     = p.get("sharepoint_tenant_id")      or settings.sharepoint_tenant_id
    client_id     = p.get("sharepoint_client_id")      or settings.sharepoint_client_id
    client_secret = p.get("sharepoint_client_secret")  or settings.sharepoint_client_secret
    site_url      = p.get("sharepoint_site_url")       or settings.sharepoint_site_url
    folder_path   = p.get("sharepoint_folder_path")    or settings.sharepoint_folder_path
    project_key   = p.get("jira_project_key")          or settings.jira_project_key or "<PROJECT>"

    stages: list[dict] = []

    def _stage(name: str, ok: bool, detail: str = "") -> dict:
        s = {"name": name, "ok": ok, "detail": detail}
        stages.append(s)
        return s

    # ── 0. Required fields ───────────────────────────────────────────
    missing = [k for k, v in {
        "SHAREPOINT_TENANT_ID":     tenant_id,
        "SHAREPOINT_CLIENT_ID":     client_id,
        "SHAREPOINT_CLIENT_SECRET": client_secret,
        "SHAREPOINT_SITE_URL":      site_url,
    }.items() if not v]
    if missing:
        _stage("Configuration", False, f"Missing: {', '.join(missing)}")
        return {"ok": False, "stages": stages, "error": "Incomplete configuration"}
    _stage("Configuration", True, "All required fields present")

    # ── 1. OAuth token — call Azure AD directly to get the real error ─
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    token: str | None = None
    t0 = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=30) as ac:
            resp = await ac.post(token_url, data={
                "grant_type":    "client_credentials",
                "client_id":     client_id,
                "client_secret": client_secret,
                "scope":         "https://graph.microsoft.com/.default",
            })
        elapsed = round((time.monotonic() - t0) * 1000)
        body = resp.json()
        if resp.status_code == 200:
            token = body.get("access_token")
            _stage("OAuth Token", True, f"Access token obtained ({elapsed} ms)")
        else:
            # Surface the exact Azure AD error code + description
            err_code  = body.get("error", str(resp.status_code))
            err_desc  = body.get("error_description", resp.text[:400])
            corr_id   = body.get("correlation_id", "")
            detail = f"[{err_code}] {err_desc}"
            if corr_id:
                detail += f"  •  correlation_id: {corr_id}"
            _stage("OAuth Token", False, detail)
            return {"ok": False, "stages": stages, "error": err_code}
    except Exception as exc:
        _stage("OAuth Token", False, f"Network error: {exc}")
        return {"ok": False, "stages": stages, "error": "Network error"}

    # ── 2. Resolve site ID ───────────────────────────────────────────
    graph_base = "https://graph.microsoft.com/v1.0"
    headers = {"Authorization": f"Bearer {token}"}
    parsed   = urlparse(site_url)
    hostname = parsed.hostname or ""
    site_path = parsed.path.lstrip("/")
    t0 = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=20) as ac:
            resp = await ac.get(f"{graph_base}/sites/{hostname}:/{site_path}", headers=headers)
        elapsed = round((time.monotonic() - t0) * 1000)
        body = resp.json()
        if resp.status_code == 200:
            site_id = body.get("id", "")
            _stage("Resolve Site", True, f"Site ID resolved ({elapsed} ms)")
        else:
            err  = body.get("error", {})
            code = err.get("code", str(resp.status_code))
            msg  = err.get("message", resp.text[:300])
            _stage("Resolve Site", False,
                   f"[{code}] {msg}  •  Check SHAREPOINT_SITE_URL and that the app has Sites.ReadWrite.All permission with admin consent")
            return {"ok": False, "stages": stages, "error": code}
    except Exception as exc:
        _stage("Resolve Site", False, f"Network error: {exc}")
        return {"ok": False, "stages": stages, "error": "Network error"}

    # ── 3. Folder access ─────────────────────────────────────────────
    folder_ok = False
    folder_detail = ""
    try:
        async with httpx.AsyncClient(timeout=20) as ac:
            for try_path in [folder_path, folder_path.rsplit("/", 1)[0] if "/" in folder_path else folder_path]:
                encoded = try_path.replace(" ", "%20")
                resp = await ac.get(f"{graph_base}/sites/{site_id}/drive/root:/{encoded}", headers=headers)
                if resp.status_code == 200:
                    folder_ok    = True
                    folder_detail = f"Folder '{try_path}' accessible"
                    break
        if not folder_ok:
            folder_detail = f"Folder '{folder_path}' not yet created — will be made automatically on first upload"
            folder_ok = True  # non-fatal
    except Exception as exc:
        folder_detail = f"Network error: {exc}"
    _stage("Folder Access", folder_ok, folder_detail)

    # ── 4. Storage path preview ──────────────────────────────────────
    _stage("Storage Path", True,
           f"Files → {folder_path}/{project_key}/{{version}}/vex-*.cdx.json")

    return {"ok": all(s["ok"] for s in stages), "stages": stages, "error": None}


@app.get("/api/v1/import/progress", summary="Import progress")
async def api_import_progress() -> dict:
    """Return the current import progress state (polled by the dashboard)."""
    return dict(_import_progress)


# ---------------------------------------------------------------------------
# Global Source Cache — one-time clone + file-cache build
# ---------------------------------------------------------------------------
# This cache is prepared once via POST /api/v1/source-cache/prepare and then
# reused by Export & Analyse and Import & Analyse, avoiding repeated cloning
# and file-cache building on every operation.

_source_cache: dict = {
    "ready": False,
    "preparing": False,
    "repo_path": None,       # Path object when ready
    "file_cache": None,      # list[(rel_path, ext, content)]
    "clone_url": "",
    "branch": "",
    "head_sha": "",
    "file_count": 0,
    "prepared_at": None,     # ISO timestamp
    "error": None,
}

_source_cache_lock = asyncio.Lock()


def _source_cache_status() -> dict:
    """Return a serialisable snapshot of the source cache state."""
    return {
        "ready": _source_cache["ready"],
        "preparing": _source_cache["preparing"],
        "repo_path": str(_source_cache["repo_path"]) if _source_cache["repo_path"] else None,
        "clone_url": _source_cache["clone_url"],
        "branch": _source_cache["branch"],
        "head_sha": _source_cache["head_sha"],
        "file_count": _source_cache["file_count"],
        "prepared_at": _source_cache["prepared_at"],
        "error": _source_cache["error"],
    }


@app.get("/api/v1/source-cache/status", summary="Source cache status")
async def api_source_cache_status() -> dict:
    """Return the current state of the global source cache."""
    return _source_cache_status()


@app.post("/api/v1/source-cache/prepare", summary="Prepare source cache (one-time)")
async def api_source_cache_prepare(force: bool = False) -> JSONResponse:
    """Clone the target repo and build the source-file cache.

    This is a **one-time task** that should be run before Export & Analyse or
    Import & Analyse.  Subsequent calls are no-ops unless *force=True* or the
    remote HEAD has changed.

    The cache is stored in-memory and on disk (via RepoCacheManager) so it
    survives across multiple analysis runs within the same server session.

    The operation runs in the background and returns 202 immediately.
    Poll GET /api/v1/source-cache/status to track progress.
    """
    async with _source_cache_lock:
        if _source_cache["preparing"]:
            return JSONResponse(
                {"status": "already_preparing", "message": "Source cache preparation is already in progress."},
                status_code=409,
            )

        if _source_cache["ready"] and not force:
            return JSONResponse({
                "status": "already_ready",
                "message": "Source cache is already prepared. Use force=true to rebuild.",
                **_source_cache_status(),
            })

        _source_cache["preparing"] = True
        _source_cache["error"] = None

    # Launch background task and return immediately
    asyncio.get_event_loop().create_task(_prepare_source_cache_background(force))

    return JSONResponse(
        {"status": "preparing", "message": "Source cache preparation started. Poll /api/v1/source-cache/status for progress."},
        status_code=202,
    )


async def _prepare_source_cache_background(force: bool) -> None:
    """Background coroutine that clones the repo and builds the file cache."""
    import asyncio as _aio

    try:
        from utils.repo_cache import RepoCacheManager as _RCM
        from analyzers.reachability_analyzer import ReachabilityAnalyzer
        from utils.git_utils import ShallowClone, LocalRepo

        # Derive clone URL and branch
        repo = settings.target_repo_url or settings.mock_repo_full_name
        if "/" in repo and (repo.startswith("http") or repo.endswith(".git")):
            repo = repo.rstrip("/").removesuffix(".git").split("github.com/")[-1]
        clone_url = f"https://github.com/{repo}.git"
        branch = settings.target_repo_branch or "main"

        if settings.local_repo_path:
            # Use local repo path directly
            repo_ctx = LocalRepo(settings.local_repo_path, branch=branch)
            repo_path = await _aio.to_thread(repo_ctx.__enter__)
            file_cache = await _aio.to_thread(ReachabilityAnalyzer.build_file_cache, repo_path)
            head_sha = ""
            try:
                import subprocess as _sp
                _r = _sp.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                             cwd=str(repo_path), timeout=10)
                head_sha = _r.stdout.strip() if _r.returncode == 0 else ""
            except Exception:
                pass
            # Don't clean up LocalRepo — it points to user's directory
        else:
            # Use persistent RepoCacheManager
            _rcm = _RCM(
                cache_root=settings.repo_cache_dir or None,
                github_token=settings.github_token,
                default_depth=settings.shallow_clone_depth,
            )
            repo_path, file_cache = await _aio.to_thread(
                _rcm.ensure, clone_url, branch, force_rebuild=force,
            )
            head_sha = ""
            try:
                import subprocess as _sp
                _r = _sp.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                             cwd=str(repo_path), timeout=10)
                head_sha = _r.stdout.strip() if _r.returncode == 0 else ""
            except Exception:
                pass

        async with _source_cache_lock:
            _source_cache.update({
                "ready": True,
                "preparing": False,
                "repo_path": repo_path,
                "file_cache": file_cache,
                "clone_url": clone_url,
                "branch": branch,
                "head_sha": head_sha,
                "file_count": len(file_cache),
                "prepared_at": datetime.now(timezone.utc).isoformat(),
                "error": None,
            })

        logger.info("Source cache prepared: %s @ %s (%d files)", clone_url, head_sha[:8] if head_sha else "?", len(file_cache))

    except Exception as exc:
        logger.error("Source cache preparation failed: %s", exc)
        async with _source_cache_lock:
            _source_cache.update({
                "ready": False,
                "preparing": False,
                "error": str(exc),
            })


@app.post("/api/v1/source-cache/invalidate", summary="Invalidate source cache")
async def api_source_cache_invalidate() -> JSONResponse:
    """Clear the in-memory source cache, forcing a fresh prepare on next use."""
    async with _source_cache_lock:
        _source_cache.update({
            "ready": False,
            "preparing": False,
            "repo_path": None,
            "file_cache": None,
            "clone_url": "",
            "branch": "",
            "head_sha": "",
            "file_count": 0,
            "prepared_at": None,
            "error": None,
        })
    logger.info("Source cache invalidated.")
    return JSONResponse({"status": "invalidated", "message": "Source cache cleared."})


@app.get("/api/v1/pipeline-runs", summary="Recent pipeline run history")
async def api_pipeline_runs(limit: int = 50) -> list:
    """Return the last *limit* pipeline executions."""
    return get_dashboard_store().recent_pipeline_runs(min(limit, 200))


@app.get("/api/v1/reviews/pending", summary="Pending human-review items")
async def api_pending_reviews() -> list:
    """Return all currently pending review queue items."""
    from utils.review_queue import get_review_queue
    queue = get_review_queue()
    queue.expire_old()
    return [i.to_dict() for i in queue.list_pending()]


@app.get("/api/v1/reports", summary="Recent --generate-report run history")
async def api_report_runs(limit: int = 10) -> list:
    """Return the last *limit* on-demand security report executions."""
    return get_dashboard_store().recent_reports(min(limit, 50))


@app.post(
    "/api/v1/mock/create-jira-tickets",
    summary="[Mock mode] Create Jira tickets for all affected/break-the-build runs already in the store",
)
async def mock_create_jira_tickets() -> JSONResponse:
    """
    Iterates all pipeline runs already recorded in the dashboard store,
    creates a Jira ticket for every ``affected_reachable`` and
    ``break_the_build`` entry that has no ticket yet, and backfills
    the ``jira_key`` so it appears in the dashboard drilldown.
    """
    if not _simulate_on_start:
        return JSONResponse({"error": "Mock mode is not enabled. Start the server with --simulate."}, status_code=400)

    from clients.jira_client import JiraClient
    from clients.mock_github_data import (
        MOCK_DEPENDABOT_ALERTS, MOCK_CODE_SCANNING_ALERTS, MOCK_SECRET_SCANNING_ALERTS,
    )
    from utils.report_generator import (
        _normalise_dependabot, _normalise_code_scanning, _normalise_secret_scanning,
    )
    from models.vex_models import AnalysisDecision

    jira = JiraClient()
    if not (settings.jira_base_url and settings.jira_api_token and settings.jira_project_key):
        return JSONResponse({"error": "Jira not configured (JIRA_BASE_URL / JIRA_API_TOKEN / JIRA_PROJECT_KEY)"}, status_code=400)

    store   = get_dashboard_store()
    runs    = store.recent_pipeline_runs(limit=200)
    repo    = settings.mock_repo_full_name
    clone_url = f"https://github.com/{repo}.git"

    # Build a lookup: alert_id → raw alert dict
    all_raw: dict[int, tuple] = {}
    for raw in MOCK_DEPENDABOT_ALERTS:
        all_raw[raw["number"]] = ("dependabot", raw)
    for raw in MOCK_CODE_SCANNING_ALERTS:
        all_raw[raw["number"]] = ("code_scanning", raw)
    for raw in MOCK_SECRET_SCANNING_ALERTS:
        all_raw[raw["number"]] = ("secret_scanning", raw)

    created = 0
    skipped = 0
    errors  = 0
    tickets: list[dict] = []

    for run in runs:
        if run["decision"] not in ("affected_reachable", "break_the_build"):
            continue
        if run.get("jira_key"):   # already has a ticket
            skipped += 1
            continue

        alert_id = run["alert_id"]
        entry    = all_raw.get(alert_id)
        if not entry:
            continue

        alert_type, raw = entry
        try:
            if alert_type == "dependabot":
                finding = _normalise_dependabot(raw, repo, clone_url)
            elif alert_type == "code_scanning":
                finding = _normalise_code_scanning(raw, repo, clone_url)
            else:
                finding = _normalise_secret_scanning(raw, repo, clone_url)

            key = await jira.create_ticket(
                finding, AnalysisDecision(run["decision"]), [], run.get("epss_score"), ""
            )
            if key:
                store.update_pipeline_jira_key(alert_id, key)
                tickets.append({"alert_id": alert_id, "jira_key": key, "package": run["package_name"]})
                created += 1
                logger.info("create-jira-tickets: %s → %s", run["package_name"], key)
        except Exception as exc:  # noqa: BLE001
            errors += 1
            logger.warning("create-jira-tickets: failed for alert #%d: %s", alert_id, exc)

    logger.info("mock/create-jira-tickets: created=%d skipped=%d errors=%d", created, skipped, errors)
    return JSONResponse({"status": "ok", "created": created, "skipped_existing": skipped, "errors": errors, "tickets": tickets})


@app.post(
    "/api/v1/mock/simulate",
    summary="[Mock mode] Populate dashboard with all simulated GitHub alerts",
)
async def mock_simulate() -> JSONResponse:
    """
    Normalises all mock GitHub alerts (Dependabot + code-scanning + secrets)
    and records each one as a ``PipelineRun`` in the dashboard store so that
    the dashboard reflects realistic statistics without needing real webhooks.

    Only meaningful when the server is started with ``--simulate``.
    """
    if not _simulate_on_start:
        return JSONResponse(
            {"error": "Mock mode is not enabled. Start the server with --simulate."},
            status_code=400,
        )

    import random, time
    from clients.mock_github_data import (
        MOCK_DEPENDABOT_ALERTS,
        MOCK_CODE_SCANNING_ALERTS,
        MOCK_SECRET_SCANNING_ALERTS,
    )
    from utils.report_generator import (
        _normalise_dependabot,
        _normalise_code_scanning,
        _normalise_secret_scanning,
    )
    from models.vex_models import AnalysisDecision, VexStatus, Severity

    repo = settings.mock_repo_full_name
    clone_url = f"https://github.com/{repo}.git"
    store = get_dashboard_store()

    from clients.jira_client import JiraClient
    jira = JiraClient()
    jira_enabled = bool(settings.jira_base_url and settings.jira_api_token and settings.jira_project_key)
    if not jira_enabled:
        logger.info("mock/simulate: Jira not configured — skipping ticket creation")

    # Deterministic decision assignment based on severity + alert type
    def _decide(severity: str, alert_type: str):
        """Return (decision, vex_status, reachable, epss) tuple."""
        sev = severity.lower()
        if alert_type == "secret":
            # Secrets are always high-priority; assign a simulated high EPSS
            return (
                AnalysisDecision.AFFECTED_REACHABLE.value,
                VexStatus.AFFECTED.value,
                True,
                round(random.uniform(0.25, 0.92), 4),
            )
        if sev == "critical":
            opts = [
                (AnalysisDecision.BREAK_THE_BUILD.value,        VexStatus.AFFECTED.value,            True,  round(random.uniform(0.15, 0.95), 4)),
                (AnalysisDecision.AFFECTED_REACHABLE.value,     VexStatus.AFFECTED.value,            True,  round(random.uniform(0.11, 0.40), 4)),
                (AnalysisDecision.UNDER_INVESTIGATION.value,    VexStatus.UNDER_INVESTIGATION.value, False, round(random.uniform(0.05, 0.15), 4)),
            ]
            return random.choices(opts, weights=[50, 35, 15])[0]
        if sev == "high":
            opts = [
                (AnalysisDecision.AFFECTED_REACHABLE.value,     VexStatus.AFFECTED.value,            True,  round(random.uniform(0.08, 0.35), 4)),
                (AnalysisDecision.NOT_AFFECTED_DEAD_CODE.value, VexStatus.NOT_AFFECTED.value,        False, round(random.uniform(0.01, 0.09), 4)),
                (AnalysisDecision.UNDER_INVESTIGATION.value,    VexStatus.UNDER_INVESTIGATION.value, False, round(random.uniform(0.03, 0.12), 4)),
                (AnalysisDecision.BREAK_THE_BUILD.value,        VexStatus.AFFECTED.value,            True,  round(random.uniform(0.12, 0.55), 4)),
            ]
            return random.choices(opts, weights=[35, 25, 25, 15])[0]
        if sev == "medium":
            opts = [
                (AnalysisDecision.NOT_AFFECTED_DEAD_CODE.value, VexStatus.NOT_AFFECTED.value,        False, round(random.uniform(0.01, 0.06), 4)),
                (AnalysisDecision.UNDER_INVESTIGATION.value,    VexStatus.UNDER_INVESTIGATION.value, False, round(random.uniform(0.02, 0.09), 4)),
                (AnalysisDecision.AFFECTED_REACHABLE.value,     VexStatus.AFFECTED.value,            True,  round(random.uniform(0.05, 0.20), 4)),
                (AnalysisDecision.NOT_AFFECTED_DEV_ONLY.value,  VexStatus.NOT_AFFECTED.value,        False, round(random.uniform(0.01, 0.04), 4)),
            ]
            return random.choices(opts, weights=[35, 30, 20, 15])[0]
        # low severity — always assign a (small) EPSS so the column is never empty
        opts = [
            (AnalysisDecision.NOT_AFFECTED_DEV_ONLY.value,  VexStatus.NOT_AFFECTED.value,        False, round(random.uniform(0.001, 0.03), 4)),
            (AnalysisDecision.NOT_AFFECTED_DEAD_CODE.value, VexStatus.NOT_AFFECTED.value,        False, round(random.uniform(0.001, 0.02), 4)),
            (AnalysisDecision.UNDER_INVESTIGATION.value,    VexStatus.UNDER_INVESTIGATION.value, False, round(random.uniform(0.001, 0.01), 4)),
        ]
        return random.choices(opts, weights=[50, 35, 15])[0]

    # Map decisions to human-readable justification reasons
    _DECISION_JUSTIFICATION = {
        AnalysisDecision.NOT_AFFECTED_DEV_ONLY.value:  "Development-only dependency — not included in production builds",
        AnalysisDecision.NOT_AFFECTED_DEAD_CODE.value:  "Vulnerable code path is unreachable (dead code)",
        AnalysisDecision.AFFECTED_REACHABLE.value:      "Vulnerable code is reachable in production",
        AnalysisDecision.BREAK_THE_BUILD.value:         "Critical reachable vulnerability — build must be blocked",
        AnalysisDecision.UNDER_INVESTIGATION.value:     "Automated analysis inconclusive — insufficient confidence to determine reachability; manual triage required",
    }

    _REVIEW_JUSTIFICATION = {
        AnalysisDecision.NOT_AFFECTED_DEV_ONLY.value:
            "Routed to human review — initial analysis suggests development-only dependency but confidence is below threshold; awaiting L1 approval",
        AnalysisDecision.NOT_AFFECTED_DEAD_CODE.value:
            "Routed to human review — initial analysis suggests vulnerable code is unreachable (dead code) but confidence is below threshold; awaiting L1 approval",
    }

    def _justification_for(decision: str, original_decision: str = "") -> str:
        if decision == "pending_review" and original_decision:
            return _REVIEW_JUSTIFICATION.get(original_decision, _DECISION_JUSTIFICATION.get(decision, ""))
        return _DECISION_JUSTIFICATION.get(decision, "")

    _DEV_SCOPES = ["devDependencies", "dev", "test", "[tool.poetry.group.dev.dependencies]"]
    _PROD_SCOPES = ["dependencies", "runtime", "compile", "default"]

    # Detailed LLM reason strings for mock justifications
    _MOCK_LLM_INCONCLUSIVE_REASONS = [
        "Vulnerable function signatures were not found in scanned source files, but indirect call chains through wrapper methods or dynamic dispatch patterns could not be fully resolved",
        "Package is imported in application code, but the specific vulnerable API surface (e.g. deserialization endpoints) could not be traced through the abstraction layers",
        "Source files reference the vulnerable package, however the call graph is too complex to determine with certainty whether the vulnerable code path is exercised at runtime",
        "LLM scanned 8 candidate files but encountered obfuscated or generated code that prevented reliable reachability determination",
        "The vulnerable function may be invoked indirectly through reflection, dependency injection, or framework-level auto-configuration that the LLM cannot statically verify",
        "Multiple call sites reference the package but none directly invoke the known vulnerable method; transitive execution through middleware or plugin systems remains uncertain",
    ]

    _MOCK_LLM_UNREACHABLE_REASONS = [
        "LLM scanned all relevant source files and confirmed the vulnerable function is never imported or called in any production code path",
        "The vulnerable package is imported but only its safe API surface is used; the specific vulnerable method is not invoked anywhere in the codebase",
        "Application code references the package for type annotations only, with no runtime invocation of the vulnerable function",
        "The vulnerable function exists in the dependency tree but is shadowed by a patched internal implementation that does not exhibit the vulnerability",
        "LLM confirmed the vulnerable API is only referenced in commented-out code and unused test fixtures, not in any active execution path",
    ]

    _MOCK_LLM_REACHABLE_REASONS = [
        "LLM identified direct import and invocation of the vulnerable function in request-handling code that processes untrusted user input",
        "The vulnerable deserialization method is called in a REST controller that accepts external payloads, confirming an exploitable path",
        "LLM traced the call chain from an HTTP endpoint through a service layer to the vulnerable function with user-controlled input reaching the vulnerable parameter",
        "The vulnerable function is invoked during application startup configuration, processing environment variables that could be attacker-influenced in shared hosting environments",
    ]

    # Fake file paths / functions for fabricated call-site detail
    _MOCK_FILES = [
        ("src/main/java/com/app/service/AuthService.java",  "authenticate"),
        ("src/main/java/com/app/util/XmlParser.java",       "parseInput"),
        ("src/app/services/data-loader.ts",                 "fetchData"),
        ("src/app/controllers/user.controller.ts",          "handleRequest"),
        ("lib/http_client.py",                              "send_request"),
        ("lib/serializer.py",                               "deserialize"),
        ("src/utils/crypto.js",                             "decrypt"),
        ("src/handlers/webhook.py",                         "process_event"),
        ("app/models/user.rb",                              "validate_token"),
        ("src/config/database.py",                          "connect"),
    ]

    # Mock import-site data: files that import a library + the safe functions used
    _MOCK_IMPORT_SITES: list[tuple[str, str, list[str]]] = [
        ("lib/http_client.py",                                      "import requests",                            ["requests.get", "requests.post", "requests.Session"]),
        ("src/config/database.py",                                  "from cryptography.fernet import Fernet",     ["Fernet.encrypt", "Fernet.decrypt"]),
        ("src/main/java/com/app/service/AuthService.java",          "import com.fasterxml.jackson.databind.ObjectMapper;", ["ObjectMapper.readValue", "ObjectMapper.writeValueAsString"]),
        ("src/main/java/com/app/api/ReportController.java",         "import org.springframework.web.bind.annotation.*;", ["@GetMapping", "@PostMapping"]),
        ("src/app/services/data-loader.ts",                         "import axios from 'axios';",                  ["axios.get", "axios.post"]),
        ("src/app/controllers/user.controller.ts",                  "const express = require('express');",         ["express.Router", "router.get", "router.post"]),
        ("src/handlers/webhook.py",                                 "import aiohttp",                              ["aiohttp.ClientSession", "session.get"]),
        ("lib/serializer.py",                                       "import json",                                 ["json.loads", "json.dumps"]),
        ("src/utils/crypto.js",                                     "const crypto = require('crypto');",           ["crypto.createHash", "crypto.randomBytes"]),
        ("app/models/user.rb",                                      "require 'nokogiri'",                          ["Nokogiri::HTML.parse", "doc.css"]),
        ("scripts/migrate_db.py",                                   "import sqlalchemy",                           ["sqlalchemy.create_engine", "engine.connect"]),
        ("src/main/java/com/app/util/HttpUtil.java",                "import org.apache.http.client.HttpClient;",   ["HttpClient.execute", "HttpGet"]),
    ]

    def _mock_import_sites(n: int, pkg_name: str = "") -> str:
        """Generate *n* fake import-site lines for unreachable justification."""
        picks = random.sample(_MOCK_IMPORT_SITES, min(n, len(_MOCK_IMPORT_SITES)))
        lines: list[str] = ["Import-site analysis (library used safely — vulnerable function(s) not called):"]
        for fp, imp_stmt, safe_funcs in picks:
            ln = random.randint(1, 25)
            used = ", ".join(safe_funcs[:3])
            lines.append(f"  ✓ {fp}:{ln}  [{imp_stmt}]  — uses: {used} (none are vulnerable)")
        return "\n".join(lines)

    def _mock_call_sites(n: int) -> str:
        """Generate *n* fake call-site lines."""
        picks = random.sample(_MOCK_FILES, min(n, len(_MOCK_FILES)))
        lines: list[str] = []
        for fp, fn in picks:
            ln = random.randint(22, 480)
            lines.append(f"  → {fp}:{ln}  {fn}()")
        return "\n".join(lines)

    def _mock_analysis_summary(
        decision: str,
        alert_type: str,
        reachable: bool,
        original_decision: str = "",
    ) -> str:
        """Fabricate a realistic multi-line L1/L2/LLM breakdown for mock simulate."""
        parts: list[str] = []

        # ── Secrets: no SCA-style analysis ─────────────────────────
        if alert_type == "secret":
            parts.append("L1 Metadata: N/A — secret scanning alert (not a dependency-based vulnerability)")
            parts.append("L2 Reachability (AST): N/A — not applicable to secret scanning")
            parts.append("LLM Analysis: N/A — not applicable to secret scanning")
            parts.append("VEX Decision: Affected — exposed secret detected, immediate rotation required")
            return "\n".join(parts)

        # Use original_decision for L1/L2/LLM detail when item was re-routed to review
        d = original_decision if original_decision else decision

        # ── L1 Metadata ────────────────────────────────────────────
        if d == AnalysisDecision.NOT_AFFECTED_DEV_ONLY.value:
            scope = random.choice(_DEV_SCOPES)
            parts.append(
                f"L1 Metadata: Dev/test-only dependency (scope: {scope}) "
                "— excluded from production builds"
            )
        else:
            scope = random.choice(_PROD_SCOPES)
            parts.append(
                f"L1 Metadata: Production dependency (scope: {scope}) "
                "— included in production builds, deep analysis required"
            )

        # ── L2 / LLM ──────────────────────────────────────────────
        if d == AnalysisDecision.NOT_AFFECTED_DEV_ONLY.value:
            parts.append("L2 Reachability (AST): Skipped — dev/test dependency, not in production code paths")
            parts.append("LLM Analysis: Skipped — not applicable for dev-only dependencies")

        elif d == AnalysisDecision.NOT_AFFECTED_DEAD_CODE.value:
            n_imports = random.randint(1, 3)
            if random.random() < 0.6:
                conf = round(random.uniform(0.80, 0.97), 2)
                parts.append(
                    f"L2 Reachability (AST): Scanned source — no reachable call sites found, confidence {conf:.0%}"
                )
                parts.append(_mock_import_sites(n_imports))
                llm_conf = round(random.uniform(0.75, 0.94), 2)
                reason = random.choice(_MOCK_LLM_UNREACHABLE_REASONS)
                parts.append(
                    f"LLM Analysis: Confirmed unreachable — no exploitable paths detected, confidence {llm_conf:.0%}. {reason}"
                )
            else:
                conf = round(random.uniform(0.78, 0.93), 2)
                parts.append("L2 Reachability (AST): Scanned source — no reachable call sites found")
                parts.append(_mock_import_sites(n_imports))
                reason = random.choice(_MOCK_LLM_UNREACHABLE_REASONS)
                parts.append(
                    f"LLM Analysis: No reachable paths found, confidence {conf:.0%}. {reason}"
                )

        elif d in (
            AnalysisDecision.AFFECTED_REACHABLE.value,
            AnalysisDecision.BREAK_THE_BUILD.value,
        ):
            if random.random() < 0.7:
                hits = random.randint(1, 6)
                conf = round(random.uniform(0.82, 0.98), 2)
                parts.append(
                    f"L2 Reachability (AST): {hits} reachable call site(s) found, confidence {conf:.0%}"
                )
                parts.append(_mock_call_sites(hits))
                parts.append("LLM Analysis: Not needed — AST analysis was conclusive")
            else:
                hits = random.randint(1, 4)
                conf = round(random.uniform(0.72, 0.91), 2)
                parts.append("L2 Reachability (AST): Scanned source — no reachable call sites found")
                reason = random.choice(_MOCK_LLM_REACHABLE_REASONS)
                parts.append(
                    f"LLM Analysis: Confirmed reachable — {hits} call site(s) identified, confidence {conf:.0%}. {reason}"
                )
                parts.append(_mock_call_sites(hits))
        else:
            # under_investigation (direct, not re-routed)
            conf = round(random.uniform(0.45, 0.68), 2)
            parts.append("L2 Reachability (AST): Scanned source — no reachable call sites found")
            reason = random.choice(_MOCK_LLM_INCONCLUSIVE_REASONS)
            parts.append(
                f"LLM Analysis: Inconclusive — confidence too low ({conf:.0%}). {reason}"
            )

        # ── VEX Decision ──────────────────────────────────────────
        if decision == "pending_review" and original_decision:
            orig_label = _DECISION_REASON_SHORT.get(original_decision, original_decision)
            parts.append(f"VEX Decision: Pending human review (originally: {orig_label})")
        else:
            parts.append(f"VEX Decision: {_DECISION_REASON_SHORT.get(decision, decision)}")

        return "\n".join(parts)

    random.seed(42)  # reproducible results on every simulate call
    recorded = 0

    def _mock_suggested_fix(finding, decision_str: str) -> str:
        """Generate a realistic mock suggested fix based on decision."""
        pkg = finding.package_name
        patched = finding.patched_version or 'latest patched version'
        cve = finding.cve_id or finding.ghsa_id or 'this vulnerability'
        if decision_str in (AnalysisDecision.NOT_AFFECTED_DEV_ONLY.value, 'pending_review'):
            return f"No immediate action required — {pkg} is a dev-only dependency. Consider upgrading to {patched} during next maintenance window."
        if decision_str == AnalysisDecision.NOT_AFFECTED_DEAD_CODE.value:
            return f"No immediate action required — vulnerable code in {pkg} is unreachable. Upgrade to {patched} as a preventive measure."
        if decision_str == AnalysisDecision.UNDER_INVESTIGATION.value:
            return f"Manual review needed. If {pkg} is confirmed reachable, upgrade to {patched} and verify no breaking changes."
        # AFFECTED_REACHABLE or BREAK_THE_BUILD
        return (
            f"**Immediate action required.**\n\n"
            f"1. Upgrade `{pkg}` to `{patched}` in your dependency manifest.\n"
            f"2. Run `pip install --upgrade {pkg}` (or equivalent for your package manager).\n"
            f"3. Verify the fix: search for calls to vulnerable API and confirm they use the patched behaviour.\n"
            f"4. Re-run the VEX Agent to confirm the alert is resolved.\n\n"
            f"Reference: {cve}"
        )

    # ── License risk mock ────────────────────────────────────────
    from analyzers.license_analyzer import LicenseAnalyzer as _LicAnalyzer

    _lic_analyzer = _LicAnalyzer(
        deny_licenses=[p.strip() for p in settings.blocked_licenses.split(",") if p.strip()],
        warn_licenses=[p.strip() for p in settings.warn_licenses.split(",") if p.strip()],
    )

    def _mock_license_risk(finding) -> str:
        """Return a concise license risk string for the dashboard, e.g. 'GPL-2.0 (High)'."""
        if not settings.enable_license_check:
            return ""
        eco = getattr(finding, "package_ecosystem", "") or ""
        pkg = getattr(finding, "package_name", "") or ""
        result = _lic_analyzer.check(eco, pkg)
        if result.risk_level == "unknown":
            return "Unknown"
        if result.risk_level == "none":
            return f"{result.license_id} ✓"
        return f"{result.license_id} ({result.risk_level.title()})"

    _JIRA_DECISIONS = {
        AnalysisDecision.AFFECTED_REACHABLE.value,
        AnalysisDecision.BREAK_THE_BUILD.value,
    }
    _NOT_AFFECTED_DECISIONS = {
        AnalysisDecision.NOT_AFFECTED_DEV_ONLY.value,
        AnalysisDecision.NOT_AFFECTED_DEAD_CODE.value,
    }
    jira_created = 0
    jira_errors  = 0
    review_routed = 0

    async def _maybe_create_ticket(finding, decision_str: str, epss: float | None) -> str | None:
        nonlocal jira_created, jira_errors
        if not jira_enabled or decision_str not in _JIRA_DECISIONS:
            return None
        try:
            key = await jira.create_ticket(
                finding, AnalysisDecision(decision_str), [], epss, ""
            )
            if key:
                jira_created += 1
                logger.info("mock/simulate: created Jira ticket %s for alert #%d", key, finding.alert_id)
            return key
        except Exception as exc:  # noqa: BLE001
            jira_errors += 1
            logger.warning("mock/simulate: Jira ticket creation failed for alert #%d: %s", finding.alert_id, exc)
            return None

    from utils.review_queue import get_review_queue as _get_rq
    import json as _json_mod

    def _route_to_review(finding, original_decision: str, epss_val: float | None) -> None:
        """When ENABLE_HUMAN_REVIEW is on, enqueue NOT_AFFECTED findings as pending review."""
        nonlocal review_routed
        trigger = (
            "Agent decided to dismiss alert as dev-only dependency — awaiting human confirmation"
            if original_decision == AnalysisDecision.NOT_AFFECTED_DEV_ONLY.value
            else "Agent decided to dismiss alert as unreachable code path — awaiting human confirmation"
        )
        try:
            rq = _get_rq()
            finding_dict = finding.model_dump(mode="json")
            epss_dict = {"epss": epss_val, "percentile": round(epss_val * 1.1, 4), "date": "2026-03-25"} if epss_val else None
            rq.enqueue(
                repo_full_name    = finding.repo_full_name,
                alert_id          = finding.alert_id,
                cve_id            = finding.cve_id or finding.ghsa_id,
                package_name      = finding.package_name,
                agent_decision    = original_decision,
                confidence        = round(random.uniform(0.55, 0.74), 2),
                trigger_reason    = trigger,
                finding_json      = _json_mod.dumps(finding_dict),
                epss_json         = _json_mod.dumps(epss_dict) if epss_dict else None,
                reachability_json = None,
                hits_json         = "[]",
                suggested_fix     = _build_suggested_fix(
                    package_name=finding.package_name,
                    patched_version=finding.patched_version,
                    decision_str='pending_review',
                    alert_type='dependabot',
                    severity=finding.severity.value,
                    cve_id=finding.cve_id or finding.ghsa_id,
                    ecosystem=finding.package_ecosystem,
                    epss_score=epss_val,
                ),
                timeout_hours     = settings.review_timeout_hours,
            )
            review_routed += 1
        except Exception as exc:
            logger.warning("mock/simulate: review enqueue failed for alert #%d: %s", finding.alert_id, exc)

    for raw in MOCK_DEPENDABOT_ALERTS:
        try:
            f = _normalise_dependabot(raw, repo, clone_url)
            decision, vex_status, reachable, epss = _decide(f.severity.value, "dependabot")
            original_decision = decision
            # Human review gate: NOT_AFFECTED → pending review
            if settings.enable_human_review and decision in _NOT_AFFECTED_DECISIONS:
                _route_to_review(f, decision, epss)
                decision = "pending_review"
                vex_status = VexStatus.UNDER_INVESTIGATION.value
            jira_key = await _maybe_create_ticket(f, decision, epss)
            store.record_pipeline(PipelineRun(
                repo=f.repo_full_name,
                alert_id=f.alert_id,
                alert_type="dependabot",
                package_name=f.package_name,
                cve_id=f.cve_id or f.ghsa_id,
                severity=f.severity.value,
                scope=getattr(f, "scope", None),
                decision=decision,
                vex_status=vex_status,
                epss_score=epss,
                reachable=reachable,
                jira_key=jira_key,
                duration_ms=round(random.uniform(120, 3200), 1),
                justification=_mock_analysis_summary(decision, "dependabot", reachable, original_decision),
                suggested_fix=_mock_suggested_fix(f, original_decision),
                license_risk=_mock_license_risk(f),
            ))
            recorded += 1
        except Exception as exc:
            logger.warning("mock simulate: dependabot alert error: %s", exc)

    for raw in MOCK_CODE_SCANNING_ALERTS:
        try:
            f = _normalise_code_scanning(raw, repo, clone_url)
            decision, vex_status, reachable, epss = _decide(f.severity.value, "code_scanning")
            original_decision = decision
            # Human review gate: NOT_AFFECTED → pending review
            if settings.enable_human_review and decision in _NOT_AFFECTED_DECISIONS:
                _route_to_review(f, decision, epss)
                decision = "pending_review"
                vex_status = VexStatus.UNDER_INVESTIGATION.value
            jira_key = await _maybe_create_ticket(f, decision, epss)
            store.record_pipeline(PipelineRun(
                repo=f.repo_full_name,
                alert_id=f.alert_id,
                alert_type="code_scanning",
                package_name=f.package_name,
                cve_id=f.cve_id or f.ghsa_id,
                severity=f.severity.value,
                scope=None,
                decision=decision,
                vex_status=vex_status,
                epss_score=epss,
                reachable=reachable,
                jira_key=jira_key,
                duration_ms=round(random.uniform(80, 1800), 1),
                justification=_mock_analysis_summary(decision, "code_scanning", reachable, original_decision),
                suggested_fix=_mock_suggested_fix(f, original_decision),
                license_risk=_mock_license_risk(f),
            ))
            recorded += 1
        except Exception as exc:
            logger.warning("mock simulate: code_scanning alert error: %s", exc)

    for raw in MOCK_SECRET_SCANNING_ALERTS:
        try:
            f = _normalise_secret_scanning(raw, repo, clone_url)
            decision, vex_status, reachable, epss = _decide(f.severity.value, "secret")
            original_decision = decision
            # Human review gate: NOT_AFFECTED → pending review
            if settings.enable_human_review and decision in _NOT_AFFECTED_DECISIONS:
                _route_to_review(f, decision, epss)
                decision = "pending_review"
                vex_status = VexStatus.UNDER_INVESTIGATION.value
            jira_key = await _maybe_create_ticket(f, decision, epss)
            store.record_pipeline(PipelineRun(
                repo=f.repo_full_name,
                alert_id=f.alert_id,
                alert_type="secret_scanning",
                package_name=f.package_name,
                cve_id=f.cve_id or f.ghsa_id,
                severity=f.severity.value,
                scope=None,
                decision=decision,
                vex_status=vex_status,
                epss_score=epss,
                reachable=reachable,
                jira_key=jira_key,
                duration_ms=round(random.uniform(40, 600), 1),
                justification=_mock_analysis_summary(decision, "secret", reachable, original_decision),
                suggested_fix=_mock_suggested_fix(f, original_decision),
                license_risk=_mock_license_risk(f),
            ))
            recorded += 1
        except Exception as exc:
            logger.warning("mock simulate: secret alert error: %s", exc)

    # ── Seed pending-review queue ─────────────────────────────────────────
    # Pick a representative sample across all alert types and severities
    # so the Pending Reviews panel shows realistic data.
    from utils.review_queue import get_review_queue
    import json as _json

    _MOCK_REVIEWS = [
        # (alert_id, alert_type, normaliser, agent_decision, confidence, trigger_reason, epss)
        # Dependabot — critical
        (1,   "dependabot",       _normalise_dependabot,      AnalysisDecision.BREAK_THE_BUILD.value,     0.52, "critical_severity",   0.4812),
        (2,   "dependabot",       _normalise_dependabot,      AnalysisDecision.AFFECTED_REACHABLE.value,  0.61, "low_llm_confidence",   0.3104),
        (6,   "dependabot",       _normalise_dependabot,      AnalysisDecision.UNDER_INVESTIGATION.value, 0.58, "low_llm_confidence",   0.1233),
        # Dependabot — high
        (13,  "dependabot",       _normalise_dependabot,      AnalysisDecision.AFFECTED_REACHABLE.value,  0.69, "low_llm_confidence",   0.2041),
        (18,  "dependabot",       _normalise_dependabot,      AnalysisDecision.BREAK_THE_BUILD.value,     0.55, "low_llm_confidence",   0.4451),
        # Dependabot — medium
        (30,  "dependabot",       _normalise_dependabot,      AnalysisDecision.UNDER_INVESTIGATION.value, 0.63, "low_llm_confidence",   0.0612),
        # Code scanning — critical
        (101, "code_scanning",    _normalise_code_scanning,   AnalysisDecision.BREAK_THE_BUILD.value,     0.57, "critical_severity",    None),
        (107, "code_scanning",    _normalise_code_scanning,   AnalysisDecision.AFFECTED_REACHABLE.value,  0.64, "critical_severity",    None),
        # Code scanning — high
        (112, "code_scanning",    _normalise_code_scanning,   AnalysisDecision.AFFECTED_REACHABLE.value,  0.71, "low_llm_confidence",   None),
        (120, "code_scanning",    _normalise_code_scanning,   AnalysisDecision.UNDER_INVESTIGATION.value, 0.60, "low_llm_confidence",   None),
        # Secret scanning — always review
        (201, "secret_scanning",  _normalise_secret_scanning, AnalysisDecision.AFFECTED_REACHABLE.value,  0.88, "always_review",        0.5731),
        (202, "secret_scanning",  _normalise_secret_scanning, AnalysisDecision.BREAK_THE_BUILD.value,     0.91, "always_review",        0.6204),
    ]

    # Build a lookup by alert number
    _raw_by_id = {r["number"]: r for r in
                  MOCK_DEPENDABOT_ALERTS + MOCK_CODE_SCANNING_ALERTS + MOCK_SECRET_SCANNING_ALERTS}

    rq = get_review_queue()
    # Clear out any previously seeded mock reviews so re-simulate doesn't accumulate
    try:
        _mock_triggers = ("critical_severity", "low_llm_confidence", "always_review")
        with rq._connect() as _conn:
            _conn.execute(
                "DELETE FROM review_queue WHERE trigger_reason IN (?,?,?)",
                _mock_triggers,
            )
    except Exception as exc:
        logger.debug("mock simulate: could not clear old reviews: %s", exc)

    reviews_added = 0
    for aid, atype, normaliser, agent_dec, confidence, trigger, epss in _MOCK_REVIEWS:
        raw = _raw_by_id.get(aid)
        if not raw:
            continue
        try:
            finding = normaliser(raw, repo, clone_url)
            finding_dict = finding.model_dump(mode="json")
            epss_dict    = {"epss": epss, "percentile": round(epss * 1.1, 4), "date": "2026-03-25"} if epss else None
            rq.enqueue(
                repo_full_name     = repo,
                alert_id           = aid,
                cve_id             = finding.cve_id or finding.ghsa_id,
                package_name       = finding.package_name,
                agent_decision     = agent_dec,
                confidence         = confidence,
                trigger_reason     = trigger,
                finding_json       = _json.dumps(finding_dict),
                epss_json          = _json.dumps(epss_dict) if epss_dict else None,
                reachability_json  = None,
                hits_json          = "[]",
                suggested_fix      = _build_suggested_fix(
                    package_name=finding.package_name,
                    patched_version=finding.patched_version,
                    decision_str='pending_review',
                    alert_type=atype,
                    severity=finding.severity.value,
                    cve_id=finding.cve_id or finding.ghsa_id,
                    ecosystem=getattr(finding, 'package_ecosystem', 'unknown'),
                    epss_score=epss,
                ),
                timeout_hours      = settings.review_timeout_hours,
            )
            reviews_added += 1
        except Exception as exc:
            logger.warning("mock simulate: pending review error for alert #%d: %s", aid, exc)

    logger.info(
        "mock/simulate: recorded %d pipeline runs; Jira tickets created=%d errors=%d; "
        "pending reviews added=%d (seeded=%d, not_affected_routed=%d)",
        recorded, jira_created, jira_errors, reviews_added + review_routed,
        reviews_added, review_routed,
    )
    return JSONResponse({
        "status": "ok",
        "recorded": recorded,
        "repo": repo,
        "jira_tickets_created": jira_created,
        "jira_errors": jira_errors,
        "pending_reviews_added": reviews_added + review_routed,
        "not_affected_routed_to_review": review_routed,
    })


# ---------------------------------------------------------------------------
# Export endpoints (dashboard download buttons)
# ---------------------------------------------------------------------------

@app.get(
    "/api/v1/export/sbom",
    summary="Download CycloneDX SBOM",
    response_class=Response,
    responses={200: {"content": {"application/json": {}}}},
)
async def export_sbom_download() -> Response:
    """
    Generate a CycloneDX SBOM for the configured repository and return it
    as a downloadable JSON file.  Equivalent to ``GET /sbom/generate``.
    """
    if not _simulate_on_start:
        return JSONResponse(
            {"error": "Mock mode is not enabled. Start the server with --simulate."},
            status_code=400,
        )
    return await generate_sbom()


@app.get(
    "/api/v1/export/vex-report",
    summary="Download combined CycloneDX VEX report",
    response_class=Response,
    responses={200: {"content": {"application/json": {}}}},
)
async def export_vex_report_download() -> Response:
    """
    Fetch all open GitHub security alerts (Dependabot + code-scanning + secrets),
    build a combined CycloneDX 1.5 VEX document and return it as a downloadable
    JSON file.  Does NOT push to git — use ``POST /api/v1/export/run-report`` for that.
    """
    if not _simulate_on_start:
        return JSONResponse(
            {"error": "Mock mode is not enabled. Start the server with --simulate."},
            status_code=400,
        )

    from utils.report_generator import SecurityReportGenerator

    gen = SecurityReportGenerator()
    dummy: dict = {"dependabot_alerts": 0, "code_scanning_alerts": 0,
                   "secret_scanning_alerts": 0, "total_alerts": 0,
                   "saved_files": [], "errors": []}
    findings = await gen._fetch_all_alerts(dummy)
    vex_json = SecurityReportGenerator._build_vex(findings)

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return Response(
        content=vex_json,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="vex-report-{today}.cdx.json"'},
    )


@app.post(
    "/api/v1/export/run-report",
    summary="Run full security report and upload to SharePoint",
)
async def run_full_report() -> JSONResponse:
    """
    Asynchronously run the complete security report pipeline:
      1. Generate SBOM
      2. Fetch all GitHub security alerts
      3. Build CycloneDX VEX document
      4. Upload both files to SharePoint (SHAREPOINT_SITE_URL)

    Returns a JSON summary with counts and saved file paths.
    """
    if not _simulate_on_start:
        return JSONResponse(
            {"error": "Mock mode is not enabled. Start the server with --simulate."},
            status_code=400,
        )

    from utils.report_generator import SecurityReportGenerator
    gen = SecurityReportGenerator()
    result = await gen.run()
    status_code = (
        status.HTTP_500_INTERNAL_SERVER_ERROR
        if result["errors"] and not result["sbom_generated"]
        else status.HTTP_200_OK
    )
    return JSONResponse(result, status_code=status_code)


# ---------------------------------------------------------------------------
# Excel / PDF alert-export endpoints
# ---------------------------------------------------------------------------

async def _get_export_runs() -> list[dict]:
    """Return the alert rows to export.

    * **With --simulate** → data already lives in the in-memory DashboardStore.
    * **Without --simulate** → fetch live alerts from the GitHub API, convert
      them into the same dict format the exporter expects.
    """
    # 1. Try the in-memory pipeline runs first (populated by --simulate or webhooks)
    runs = get_dashboard_store().recent_pipeline_runs(limit=5000)
    if runs:
        by_type = {}
        for r in runs:
            t = r.get("alert_type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1
        logger.info("Export: using DashboardStore — %d runs — %s", len(runs), by_type)
        return runs

    # 2. Fall back to a live GitHub API fetch
    from clients.github_client import GitHubSecurityClient
    from utils.alert_exporter import raw_alerts_to_dicts

    repo = settings.target_repo_url or settings.mock_repo_full_name
    # Normalise "https://github.com/owner/repo.git" → "owner/repo"
    if "/" in repo and (repo.startswith("http") or repo.endswith(".git")):
        repo = repo.rstrip("/").removesuffix(".git").split("github.com/")[-1]

    gh = GitHubSecurityClient()
    import asyncio
    dependabot, code_scan, secrets = await asyncio.gather(
        gh.list_dependabot_alerts(repo),
        gh.list_code_scanning_alerts(repo),
        gh.list_secret_scanning_alerts(repo),
    )
    logger.info(
        "Export: fetched live alerts for %s — dependabot=%d, code_scanning=%d, secret_scanning=%d",
        repo, len(dependabot), len(code_scan), len(secrets),
    )
    return raw_alerts_to_dicts(dependabot, code_scan, secrets, repo)


@app.get(
    "/api/v1/export/alerts-excel",
    summary="Download all pipeline-run alerts as an Excel workbook",
)
async def export_alerts_excel():
    """Return an .xlsx workbook containing every pipeline run recorded on the
    dashboard.  When no pipeline runs exist, falls back to fetching live
    alerts from the GitHub API.

    The workbook includes a summary sheet plus per-alert-type sheets
    (Dependabot, Code Scanning, Secret Scanning)."""
    from utils.alert_exporter import export_excel

    runs = await _get_export_runs()
    if not runs:
        return JSONResponse(
            {"error": "No alert data available. Ensure GitHub credentials are configured "
                       "or start the server with --simulate."},
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    data = export_excel(runs)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return Response(
        content=data,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="github-alerts-{today}.xlsx"'},
    )


@app.get(
    "/api/v1/export/alerts-pdf",
    summary="Download all pipeline-run alerts as a PDF report",
)
async def export_alerts_pdf():
    """Return a PDF report summarising every pipeline run recorded on the
    dashboard.  When no pipeline runs exist, falls back to fetching live
    alerts from the GitHub API.

    Includes per-alert-type tables and severity colour-coding."""
    from utils.alert_exporter import export_pdf

    runs = await _get_export_runs()
    if not runs:
        return JSONResponse(
            {"error": "No alert data available. Ensure GitHub credentials are configured "
                       "or start the server with --simulate."},
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    data = export_pdf(runs)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return Response(
        content=data,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="github-alerts-{today}.pdf"'},
    )


# ---------------------------------------------------------------------------
# Export & Analyse — combined pipeline
# ---------------------------------------------------------------------------

# Progress tracker for export-and-analyse (re-uses the import progress infra)
_ea_progress: dict = {
    "active": False,
    "phase": "idle",
    "total": 0,
    "analysed": 0,
    "affected": 0,
    "not_affected": 0,
    "errors": 0,
    "current_alert": "",
    "pct": 0,
    "raw_export_ready": False,
    "analysis_export_ready": False,
}

def _reset_ea_progress():
    _ea_progress.update({
        "active": False, "phase": "idle", "total": 0, "analysed": 0,
        "affected": 0, "not_affected": 0, "errors": 0,
        "current_alert": "", "pct": 0,
        "raw_export_ready": False, "analysis_export_ready": False,
    })

def _update_ea_progress(**kwargs):
    _ea_progress.update(kwargs)
    total = _ea_progress["total"]
    done = _ea_progress["analysed"]
    _ea_progress["pct"] = round(done / total * 100) if total > 0 else 0


@app.get("/api/v1/export/analyse-progress", summary="Export & Analyse progress")
async def api_ea_progress() -> dict:
    """Return the current export-and-analyse progress state."""
    return dict(_ea_progress)


@app.post(
    "/api/v1/export/analyse",
    summary="Export alerts, analyse them, and export the analysed results",
)
async def export_and_analyse(
    fmt: str = "excel",
) -> JSONResponse:
    """Fetch all GitHub alerts, export the raw alerts in the chosen format
    (excel or pdf), then run the full VEX analysis pipeline on each alert,
    and finally export the analysed results as a separate file.

    Both files are returned as download URLs that the frontend can poll.
    Progress is available via GET /api/v1/export/analyse-progress.
    """
    import asyncio
    import time as _time
    from clients.epss_client import EpssClient
    from clients.jira_client import JiraClient
    from models.vex_models import AnalysisDecision, VexStatus, NormalisedFinding, Severity
    from analyzers.metadata_analyzer import MetadataAnalyzer
    from analyzers.reachability_analyzer import ReachabilityAnalyzer
    from utils.git_utils import ShallowClone, LocalRepo
    from utils.llm_analyzer import LLMReachabilityAnalyzer as _LLMAnalyzer
    from utils.alert_exporter import export_excel, export_pdf, raw_alerts_to_dicts
    from clients.github_client import GitHubSecurityClient

    _ea_llm = _LLMAnalyzer()

    if fmt not in ("excel", "pdf"):
        return JSONResponse({"error": "Format must be 'excel' or 'pdf'."}, status_code=400)

    _reset_ea_progress()
    _update_ea_progress(active=True, phase="Fetching GitHub alerts …")

    # ── Step 1: Fetch raw alerts ──────────────────────────────────────
    runs = await _get_export_runs()
    if not runs:
        _reset_ea_progress()
        return JSONResponse(
            {"error": "No alert data available. Ensure GitHub credentials are configured "
                       "or start the server with --simulate."},
            status_code=400,
        )

    # ── Step 2: Export raw alerts ─────────────────────────────────────
    _update_ea_progress(phase=f"Exporting {len(runs)} raw alerts as {fmt.upper()} …")
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if fmt == "excel":
        raw_data = export_excel(runs)
        raw_fname = f"github-alerts-raw-{today}.xlsx"
        raw_mime = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    else:
        raw_data = export_pdf(runs)
        raw_fname = f"github-alerts-raw-{today}.pdf"
        raw_mime = "application/pdf"

    # Store raw export in memory for download
    _ea_downloads["raw"] = (raw_data, raw_fname, raw_mime)
    _update_ea_progress(raw_export_ready=True, phase="Raw export ready — starting analysis …")

    # ── Step 3: Run VEX analysis pipeline on each alert ───────────────
    total = len(runs)
    _update_ea_progress(total=total)

    epss_client = EpssClient()
    store = get_dashboard_store()
    _llm = _LLMAnalyzer()

    # Jira setup
    _ea_jira = JiraClient()
    _ea_jira_enabled = bool(settings.jira_base_url and settings.jira_api_token and settings.jira_project_key)
    _EA_JIRA_DECISIONS = {"affected_reachable", "break_the_build"}

    # Clone / update repo once
    repo = settings.target_repo_url or settings.mock_repo_full_name
    if "/" in repo and (repo.startswith("http") or repo.endswith(".git")):
        repo = repo.rstrip("/").removesuffix(".git").split("github.com/")[-1]
    clone_url = f"https://github.com/{repo}.git"
    branch = settings.target_repo_branch or "main"

    # ── Use the global source cache (prepared via one-time task) ──────
    repo_ctx = None  # may stay None when using global / persistent cache

    if _source_cache["ready"] and _source_cache["file_cache"] is not None:
        # Fast path: source cache was prepared via POST /api/v1/source-cache/prepare
        repo_path = _source_cache["repo_path"]
        _file_cache = _source_cache["file_cache"]
        _update_ea_progress(phase=f"Using pre-built source cache ({_source_cache['file_count']} files) …")
        logger.info("Export & Analyse: using pre-built source cache @ %s (%d files)",
                     repo_path, len(_file_cache))
    else:
        # Fall back: clone inline (source cache was not prepared)
        logger.info("Export & Analyse: source cache not prepared — cloning inline …")
        from utils.repo_cache import RepoCacheManager as _RCM
        _use_repo_cache = settings.enable_repo_cache and not settings.local_repo_path

        if _use_repo_cache:
            _update_ea_progress(phase="Preparing repository (persistent cache) …")
            try:
                _rcm = _RCM(
                    cache_root=settings.repo_cache_dir or None,
                    github_token=settings.github_token,
                    default_depth=settings.shallow_clone_depth,
                )
                repo_path, _file_cache = await asyncio.to_thread(
                    _rcm.ensure, clone_url, branch,
                )
                logger.info("Persistent cache: repo ready at %s (%d cached files)", repo_path, len(_file_cache))
            except Exception as exc:
                logger.error("Export & Analyse: repo cache failed: %s", exc)
                _reset_ea_progress()
                return JSONResponse({"error": f"Git clone/update failed: {exc}"}, status_code=500)
        else:
            if settings.local_repo_path:
                repo_ctx = LocalRepo(settings.local_repo_path, branch=branch)
            else:
                repo_ctx = ShallowClone(
                    clone_url, branch=branch,
                    depth=settings.shallow_clone_depth,
                    github_token=settings.github_token,
                )

            _update_ea_progress(phase="Cloning / updating repository …")
            try:
                repo_path = await asyncio.to_thread(repo_ctx.__enter__)
            except Exception as exc:
                logger.error("Export & Analyse: clone failed: %s", exc)
                _reset_ea_progress()
                return JSONResponse({"error": f"Git clone/update failed: {exc}"}, status_code=500)

            # Build file cache for reachability
            _update_ea_progress(phase="Building source file cache …")
            _file_cache = await asyncio.to_thread(ReachabilityAnalyzer.build_file_cache, repo_path)

    try:

        # Bulk EPSS fetch
        _all_cves = list({
            r.get("cve_id", "") for r in runs
            if r.get("cve_id", "").upper().startswith("CVE-")
        })
        _epss_cache: dict = {}
        if _all_cves:
            _update_ea_progress(phase=f"Fetching EPSS scores for {len(_all_cves)} CVEs …")
            try:
                _epss_cache = await epss_client.get_scores_bulk(_all_cves)
            except Exception:
                pass

        # Analyse each alert
        analysed_runs: list[dict] = []
        processed = 0
        affected_c = 0
        not_affected_c = 0
        error_c = 0

        # Queue for LLM suggest_fix retries — entries that failed due to
        # rate-limits or transient errors are retried after the main loop.
        _llm_retry_queue: list[dict] = []

        for i, run in enumerate(runs):
            pkg = run.get("package_name", "unknown")
            cve = run.get("cve_id") or ""
            sev = run.get("severity", "medium")
            alert_type = run.get("alert_type", "dependabot")

            _update_ea_progress(
                phase=f"Analysing alert {i+1}/{total}: {pkg} …",
                current_alert=f"#{run.get('alert_id', i+1)} {pkg}",
            )

            t0 = _time.time()
            errors: list[str] = []
            epss_val = None
            decision_str = "under_investigation"
            vex_status_str = "under_investigation"
            reachable = False
            jira_key = run.get("jira_key")

            try:
                # EPSS
                epss_score = None
                if cve and cve.upper().startswith("CVE-"):
                    epss_score = _epss_cache.get(cve)
                    if epss_score is None:
                        try:
                            epss_score = await epss_client.get_score(cve)
                        except Exception:
                            pass
                    if epss_score:
                        epss_val = epss_score.epss

                # Determine ecosystem from alert_type and run data
                ecosystem = run.get("package_ecosystem", "unknown")
                if ecosystem == "unknown" and alert_type == "dependabot":
                    ecosystem = "pip"  # fallback

                # L1: Metadata
                meta_analyzer = MetadataAnalyzer(repo_path)
                metadata_result = await asyncio.to_thread(
                    meta_analyzer.analyse, pkg, ecosystem, run.get("manifest_path", ""),
                )

                if metadata_result.is_dev_dependency and settings.skip_dev_dependencies:
                    decision_str = "not_affected_dev_only"
                    vex_status_str = "not_affected"
                    not_affected_c += 1
                else:
                    # L2: Reachability
                    reach_analyzer = ReachabilityAnalyzer(repo_path, file_cache=_file_cache)
                    vuln_funcs = run.get("vulnerable_functions", [])
                    if isinstance(vuln_funcs, str):
                        vuln_funcs = [f.strip() for f in vuln_funcs.split(",") if f.strip()]
                    reachability_result = await asyncio.to_thread(
                        reach_analyzer.analyse, pkg, vuln_funcs or [], ecosystem,
                    )

                    if reachability_result.reachable:
                        reachable = True
                        if (settings.enable_break_the_build
                                and epss_client.is_high_risk(epss_score, settings.epss_threshold)):
                            decision_str = "break_the_build"
                        else:
                            decision_str = "affected_reachable"
                        vex_status_str = "affected"
                        affected_c += 1
                    else:
                        decision_str = "not_affected_dead_code"
                        vex_status_str = "not_affected"
                        not_affected_c += 1

            except Exception as exc:
                errors.append(str(exc))
                error_c += 1

            duration_ms = round((_time.time() - t0) * 1000, 1)

            # ── Justification ─────────────────────────────────────
            _justification = _build_analysis_summary(
                metadata_result, reachability_result, decision_str,
                alert_scope=run.get("scope") or "",
            )

            # ── Suggested fix (LLM → template fallback) ─────────
            _suggested_fix = ""
            _llm_fix_failed = False
            try:
                _ea_hits = reachability_result.hits if reachability_result else []
                # Build a finding-like object for the LLM prompt
                class _EAFinding:
                    pass
                _ea_f = _EAFinding()
                _ea_f.package_name = pkg
                _ea_f.package_version = run.get("package_version", "")
                _ea_f.cve_id = cve or None
                _ea_f.cvss_score = run.get("cvss_score")
                _ea_f.severity = type("_S", (), {"value": sev})()
                _ea_f.summary = run.get("summary", "") or run.get("description", "")
                _ea_f.vulnerable_functions = run.get("vulnerable_functions", []) or []
                _suggested_fix = await _ea_llm.suggest_fix(_ea_f, _ea_hits)
            except Exception as _fx_exc:
                _llm_fix_failed = True
                logger.debug("export_and_analyse: LLM suggest_fix queued for retry — alert #%d: %s",
                             run.get("alert_id", i + 1), _fx_exc)
            if not _suggested_fix:
                _suggested_fix = _build_suggested_fix(
                    package_name=pkg,
                    patched_version=run.get("patched_version") or run.get("first_patched_version"),
                    decision_str=decision_str,
                    alert_type=alert_type,
                    severity=sev,
                    cve_id=cve or None,
                    ecosystem=run.get("package_ecosystem", "unknown"),
                    epss_score=epss_val,
                    reachable=reachable,
                    metadata_result=metadata_result,
                    reachability_result=reachability_result,
                    vulnerable_version_range=run.get("vulnerable_version_range", ""),
                    summary=run.get("summary", ""),
                )

            # Queue for LLM retry if the LLM call failed (rate-limit, timeout, etc.)
            if _llm_fix_failed:
                _llm_retry_queue.append({
                    "alert_id": run.get("alert_id", i + 1),
                    "index": len(analysed_runs),  # index into analysed_runs list
                    "finding": _ea_f,
                    "hits": _ea_hits,
                    "template_fix": _suggested_fix,  # keep the template fallback
                })
            if not _suggested_fix:
                _suggested_fix = _build_suggested_fix(
                    package_name=pkg,
                    patched_version=run.get("patched_version") or run.get("first_patched_version"),
                    decision_str=decision_str,
                    alert_type=alert_type,
                    severity=sev,
                    cve_id=cve or None,
                    ecosystem=run.get("package_ecosystem", "unknown"),
                    epss_score=epss_val,
                    reachable=reachable,
                    metadata_result=metadata_result,
                    reachability_result=reachability_result,
                    vulnerable_version_range=run.get("vulnerable_version_range", ""),
                    summary=run.get("summary", ""),
                )

            # ── Create Jira ticket for affected findings ───────────
            if _ea_jira_enabled and decision_str in _EA_JIRA_DECISIONS and not jira_key:
                try:
                    _ea_finding = NormalisedFinding(
                        alert_id=run.get("alert_id", i + 1),
                        repo_full_name=run.get("repo", repo),
                        repo_clone_url=clone_url,
                        repo_default_branch=branch,
                        cve_id=cve or None,
                        ghsa_id=run.get("ghsa_id"),
                        package_name=pkg,
                        package_version=run.get("package_version", ""),
                        package_ecosystem=run.get("package_ecosystem", "unknown"),
                        vulnerable_version_range=run.get("vulnerable_version_range", ""),
                        patched_version=run.get("patched_version") or run.get("first_patched_version"),
                        severity=Severity(sev.lower()) if sev else Severity.MEDIUM,
                        cvss_score=run.get("cvss_score"),
                        cvss_vector_string=run.get("cvss_vector_string"),
                        summary=run.get("summary", "") or run.get("description", ""),
                        vulnerable_functions=run.get("vulnerable_functions", []) or [],
                    )
                    _ea_decision_enum = AnalysisDecision(decision_str)
                    _ea_hits_for_jira = reachability_result.hits if reachability_result else []
                    jira_key = await _ea_jira.create_ticket(
                        _ea_finding, _ea_decision_enum, _ea_hits_for_jira,
                        epss_score=epss_val,
                        suggested_fix=_suggested_fix,
                    )
                    if jira_key:
                        logger.info("Export & Analyse: created Jira ticket %s for alert #%d (%s)",
                                    jira_key, run.get("alert_id", i + 1), pkg)
                except Exception as _jira_exc:
                    logger.warning("Export & Analyse: Jira ticket creation failed for alert #%d: %s",
                                   run.get("alert_id", i + 1), _jira_exc)

            # Build analysed row (enriched copy of the original)
            analysed_row = dict(run)
            analysed_row.update({
                "decision": decision_str,
                "vex_status": vex_status_str,
                "epss_score": epss_val,
                "reachable": reachable,
                "jira_key": jira_key,
                "errors": errors,
                "duration_ms": duration_ms,
                "justification": _justification,
                "suggested_fix": _suggested_fix,
            })
            analysed_runs.append(analysed_row)

            # Record in dashboard store
            store.record_pipeline(PipelineRun(
                repo=run.get("repo", repo),
                alert_id=run.get("alert_id", i + 1),
                alert_type=alert_type,
                package_name=pkg,
                cve_id=cve or None,
                severity=sev,
                scope=run.get("scope") or None,
                decision=decision_str,
                vex_status=vex_status_str,
                epss_score=epss_val,
                reachable=reachable,
                jira_key=jira_key,
                errors=errors,
                duration_ms=duration_ms,
                justification=_justification,
                suggested_fix=_suggested_fix,
            ))

            processed += 1
            _update_ea_progress(
                analysed=processed, affected=affected_c,
                not_affected=not_affected_c, errors=error_c,
            )

        # ── LLM suggest_fix retry pass ────────────────────────────────
        # Items whose LLM call failed (rate-limit / transient error) are
        # retried now that the main analysis loop has finished and time
        # has passed.  We use exponential back-off between retries.
        if _llm_retry_queue:
            _retry_total = len(_llm_retry_queue)
            logger.info("LLM suggest_fix retry: %d items queued — starting retry pass …", _retry_total)
            _update_ea_progress(phase=f"Retrying LLM suggest_fix for {_retry_total} alerts …")

            _MAX_RETRIES = 3
            _retry_remaining = list(_llm_retry_queue)
            _retry_succeeded = 0

            for _attempt in range(1, _MAX_RETRIES + 1):
                if not _retry_remaining:
                    break
                # back-off: 10s, 30s, 60s
                _backoff = min(10 * (3 ** (_attempt - 1)), 60)
                logger.info("LLM retry attempt %d/%d — waiting %ds before retrying %d items …",
                            _attempt, _MAX_RETRIES, _backoff, len(_retry_remaining))
                _update_ea_progress(
                    phase=f"LLM retry attempt {_attempt}/{_MAX_RETRIES} "
                          f"({len(_retry_remaining)} remaining, waiting {_backoff}s) …",
                )
                await asyncio.sleep(_backoff)

                _still_failed: list[dict] = []
                for _ritem in _retry_remaining:
                    _update_ea_progress(
                        current_alert=f"Retry #{_ritem['alert_id']} (attempt {_attempt})",
                    )
                    try:
                        _fix = await _ea_llm.suggest_fix(_ritem["finding"], _ritem["hits"])
                        if _fix:
                            # Update analysed_runs row
                            _idx = _ritem["index"]
                            analysed_runs[_idx]["suggested_fix"] = _fix
                            # Update dashboard store
                            store.update_suggested_fix(_ritem["alert_id"], _fix)
                            _retry_succeeded += 1
                            logger.info("LLM retry succeeded for alert #%d (attempt %d)",
                                        _ritem["alert_id"], _attempt)
                        else:
                            # LLM returned empty — keep template fallback, don't retry
                            logger.debug("LLM retry returned empty for alert #%d", _ritem["alert_id"])
                    except Exception as _rx:
                        logger.debug("LLM retry failed for alert #%d (attempt %d): %s",
                                     _ritem["alert_id"], _attempt, _rx)
                        _still_failed.append(_ritem)
                _retry_remaining = _still_failed

            if _retry_remaining:
                logger.warning("LLM suggest_fix: %d/%d items still failed after %d retries",
                               len(_retry_remaining), _retry_total, _MAX_RETRIES)
            logger.info("LLM suggest_fix retry complete: %d/%d succeeded",
                        _retry_succeeded, _retry_total)

        # ── Generate SBOM (still have repo checkout) ──────────────────
        _update_ea_progress(phase="Generating SBOM …")
        sbom_json: str | None = None
        try:
            from utils.sbom_generator import SBOMGenerator
            _repo_short = repo.split("/")[-1] if "/" in repo else repo
            sbom_json = SBOMGenerator(repo_path, _repo_short).generate_json()
            logger.info("Export & Analyse: SBOM generated for %s", _repo_short)
        except Exception as exc:
            logger.warning("Export & Analyse: SBOM generation failed: %s", exc)

        # ── Read product version (still have repo checkout) ───────────
        _product_version: str | None = None
        try:
            from utils.vex_file_store import read_product_version
            _product_version = read_product_version(repo_path)
        except Exception:
            pass

    finally:
        if repo_ctx is not None:
            repo_ctx.__exit__(None, None, None)

    # ── Step 4: Export analysed results ────────────────────────────────
    _update_ea_progress(phase=f"Exporting analysed results as {fmt.upper()} …")
    if fmt == "excel":
        analysed_data = export_excel(analysed_runs)
        analysed_fname = f"github-alerts-analysed-{today}.xlsx"
        analysed_mime = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    else:
        analysed_data = export_pdf(analysed_runs)
        analysed_fname = f"github-alerts-analysed-{today}.pdf"
        analysed_mime = "application/pdf"

    _ea_downloads["analysed"] = (analysed_data, analysed_fname, analysed_mime)

    # ── Step 5: Generate VEX documents & upload to SharePoint ─────────
    _update_ea_progress(phase="Generating VEX documents & uploading to SharePoint …")
    vex_files_generated = 0
    sharepoint_urls: list[str] = []
    sp_error: str | None = None

    try:
        from utils.vex_exporter import VexExporter, export_vex_json
        from utils.vex_file_store import save_vex_and_sbom
        from models.vex_models import (
            AnalysisDecision, VexStatus, JustificationCode,
            NormalisedFinding, Severity, VexDecision,
        )

        _repo_short = repo.split("/")[-1] if "/" in repo else repo

        # Build a combined VEX document with all findings
        combined_exporter = VexExporter()

        for ar in analysed_runs:
            dec_str = ar.get("decision", "under_investigation")
            pkg = ar.get("package_name", "unknown")
            cve = ar.get("cve_id") or ""
            sev = ar.get("severity", "medium")

            # Map decision string → enum
            try:
                dec_enum = AnalysisDecision(dec_str)
            except ValueError:
                dec_enum = AnalysisDecision.UNDER_INVESTIGATION

            # Map vex_status string → enum
            vs_str = ar.get("vex_status", "under_investigation")
            try:
                vex_stat = VexStatus(vs_str)
            except ValueError:
                vex_stat = VexStatus.UNDER_INVESTIGATION

            # Determine justification code
            just_code = None
            if dec_enum == AnalysisDecision.NOT_AFFECTED_DEV_ONLY:
                just_code = JustificationCode.COMPONENT_NOT_PRESENT
            elif dec_enum == AnalysisDecision.NOT_AFFECTED_DEAD_CODE:
                just_code = JustificationCode.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH

            # Map severity
            try:
                sev_enum = Severity(sev.lower())
            except ValueError:
                sev_enum = Severity.MEDIUM

            # Build a NormalisedFinding for the VEX document
            finding = NormalisedFinding(
                alert_id=ar.get("alert_id", 0),
                repo_full_name=ar.get("repo", repo),
                repo_clone_url=f"https://github.com/{ar.get('repo', repo)}.git",
                repo_default_branch=branch,
                cve_id=cve or None,
                ghsa_id=ar.get("ghsa_id"),
                package_name=pkg,
                package_version=ar.get("package_version", ""),
                package_ecosystem=ar.get("package_ecosystem", "unknown"),
                vulnerable_version_range=ar.get("vulnerable_version_range", ""),
                patched_version=ar.get("patched_version") or ar.get("first_patched_version"),
                severity=sev_enum,
                cvss_score=ar.get("cvss_score"),
                manifest_path=ar.get("manifest_path"),
                vulnerable_functions=ar.get("vulnerable_functions") or [],
                summary=ar.get("summary", ""),
            )

            vex_doc = VexDecision(
                finding=finding,
                decision=dec_enum,
                vex_status=vex_stat,
                justification_code=just_code,
                impact_statement=ar.get("justification", ""),
                errors=ar.get("errors", []),
            )

            combined_exporter.add_decision(vex_doc, ar.get("suggested_fix", ""))
            vex_files_generated += 1

        # Export combined VEX JSON
        combined_vex_json = combined_exporter.export_json()

        # Store VEX & SBOM as downloadable files
        _ea_downloads["vex"] = (
            combined_vex_json.encode("utf-8"),
            f"vex-combined-{today}.cdx.json",
            "application/json",
        )
        if sbom_json:
            _ea_downloads["sbom"] = (
                sbom_json.encode("utf-8"),
                f"sbom-{_repo_short}-{today}.cdx.json",
                "application/json",
            )

        # Upload to SharePoint
        _update_ea_progress(phase="Uploading VEX & SBOM to SharePoint …")
        sp_urls = save_vex_and_sbom(
            vex_json_str=combined_vex_json,
            sbom_json=sbom_json,
            vex_filename=f"vex-combined-{today}.cdx.json",
            sbom_filename=f"sbom-{_repo_short}-{today}.cdx.json",
            product_version=_product_version,
        )
        sharepoint_urls = sp_urls
        if sp_urls:
            logger.info("Export & Analyse: uploaded %d file(s) to SharePoint", len(sp_urls))
        else:
            sp_error = "SharePoint not configured or upload failed"
            logger.info("Export & Analyse: SharePoint upload skipped/failed")

    except Exception as exc:
        sp_error = str(exc)
        logger.error("Export & Analyse: VEX/SBOM/SharePoint step failed: %s", exc)

    _update_ea_progress(
        phase="Completed", active=False, current_alert="",
        analysis_export_ready=True,
    )

    return JSONResponse({
        "status": "completed",
        "total": total,
        "affected": affected_c,
        "not_affected": not_affected_c,
        "errors": error_c,
        "raw_download_url": "/api/v1/export/analyse-download/raw",
        "analysed_download_url": "/api/v1/export/analyse-download/analysed",
        "vex_download_url": "/api/v1/export/analyse-download/vex" if vex_files_generated else None,
        "sbom_download_url": "/api/v1/export/analyse-download/sbom" if sbom_json else None,
        "vex_files_generated": vex_files_generated,
        "sbom_generated": sbom_json is not None,
        "sharepoint_urls": sharepoint_urls,
        "sharepoint_error": sp_error,
    })


# In-memory file store for export-and-analyse downloads
_ea_downloads: dict[str, tuple[bytes, str, str]] = {}


@app.get("/api/v1/export/analyse-download/{file_type}")
async def export_analyse_download(file_type: str):
    """Download a raw, analysed, VEX, or SBOM export file from the last export-and-analyse run."""
    if file_type not in ("raw", "analysed", "vex", "sbom"):
        raise HTTPException(status_code=400, detail="file_type must be 'raw', 'analysed', 'vex', or 'sbom'")
    entry = _ea_downloads.get(file_type)
    if not entry:
        raise HTTPException(status_code=404, detail=f"No {file_type} export available yet. Run Export & Analyse first.")
    data, fname, mime = entry
    return Response(
        content=data,
        media_type=mime,
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# ---------------------------------------------------------------------------
# Excel alert import + analysis endpoint
# ---------------------------------------------------------------------------

@app.post(
    "/api/v1/import/alerts-excel",
    summary="Upload an Excel file of GitHub alerts, analyse each one, and take action",
)
async def import_alerts_excel(
    file: UploadFile = File(..., description="Excel (.xlsx) file containing GitHub alert rows"),
) -> JSONResponse:
    """Accept an uploaded Excel workbook, parse the alert rows, and for each
    alert:

    1. Look up the **EPSS score** (if a CVE is present).
    2. Run **metadata analysis** (dev-dependency check) against the configured
       repository.
    3. Run **AST reachability analysis** (+ LLM fallback when enabled).
    4. Make a VEX decision (not_affected / affected / break_the_build / under_investigation).
    5. Create a **Jira ticket** for affected/break-the-build findings.
    6. Route NOT_AFFECTED findings through the **human review queue** (when
       ``ENABLE_HUMAN_REVIEW=true``).
    7. Record each result as a **PipelineRun** in the dashboard store.

    Returns a JSON summary with counts of processed, affected, and errored rows.
    """
    # ── Validate file ──────────────────────────────────────────────────
    if not file.filename or not file.filename.lower().endswith((".xlsx", ".xls")):
        return JSONResponse(
            {"error": "Please upload an Excel file (.xlsx)."},
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    contents = await file.read()
    if not contents:
        return JSONResponse(
            {"error": "Uploaded file is empty."},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # ── Parse rows ─────────────────────────────────────────────────────
    from utils.alert_importer import parse_excel, rows_to_findings

    try:
        rows = parse_excel(contents)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=status.HTTP_400_BAD_REQUEST)
    if not rows:
        return JSONResponse(
            {"error": "Excel file contained no alert rows."},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    default_repo = settings.target_repo_url or settings.mock_repo_full_name
    if "/" in default_repo and (default_repo.startswith("http") or default_repo.endswith(".git")):
        default_repo = default_repo.rstrip("/").removesuffix(".git").split("github.com/")[-1]

    finding_pairs = rows_to_findings(
        rows,
        default_repo=default_repo,
        default_branch=settings.target_repo_branch or "main",
    )
    if not finding_pairs:
        return JSONResponse(
            {"error": "Could not convert any rows to findings. Check your column headers."},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # ── Run analysis pipeline for each finding ─────────────────────────
    import asyncio
    import time as _time
    from clients.epss_client import EpssClient
    from clients.jira_client import JiraClient
    from models.vex_models import AnalysisDecision, VexStatus
    from utils.review_queue import get_review_queue as _get_rq
    import json as _json_mod
    from analyzers.metadata_analyzer import MetadataAnalyzer
    from analyzers.reachability_analyzer import ReachabilityAnalyzer
    from utils.git_utils import ShallowClone, LocalRepo

    epss_client = EpssClient()
    jira = JiraClient()
    jira_enabled = bool(
        settings.jira_base_url and settings.jira_api_token and settings.jira_project_key
    )
    store = get_dashboard_store()

    from utils.llm_analyzer import LLMReachabilityAnalyzer as _LLMAnalyzer
    _llm_fix = _LLMAnalyzer()

    # ── Build duplicate-detection set from existing pipeline runs ─────
    _existing_runs = store.recent_pipeline_runs(limit=9999)
    _existing_keys: dict[tuple[str, str, str, str], int] = {}
    for r in _existing_runs:
        _k = (
            r.get("alert_type", "").lower().strip(),
            r.get("package_name", "").lower().strip(),
            (r.get("cve_id") or "").upper().strip(),
            r.get("severity", "").lower().strip(),
        )
        if _k not in _existing_keys:
            _existing_keys[_k] = r.get("alert_id", 0)

    # Summary counters
    total = len(finding_pairs)
    processed = 0
    skipped_duplicates = 0

    # ── Initialise progress tracker ────────────────────────────────
    _reset_import_progress()
    _update_import_progress(active=True, phase="Parsing spreadsheet", total=total)
    affected_count = 0
    break_build_count = 0
    not_affected_count = 0
    under_investigation_count = 0
    jira_created = 0
    review_routed = 0
    error_count = 0
    results: list[dict] = []

    # ── Clone / update git repo ONCE before the loop ───────────────
    first_finding = finding_pairs[0][0]
    clone_url = first_finding.repo_clone_url
    branch = first_finding.repo_default_branch

    # ── Use the global source cache (prepared via one-time task) ──────
    repo_ctx = None  # may stay None when using global / persistent cache

    if _source_cache["ready"] and _source_cache["file_cache"] is not None:
        # Fast path: source cache was prepared via POST /api/v1/source-cache/prepare
        repo_path = _source_cache["repo_path"]
        _file_cache = _source_cache["file_cache"]
        _update_import_progress(phase=f"Using pre-built source cache ({_source_cache['file_count']} files) — starting analysis of {total} alerts …")
        logger.info("Import: using pre-built source cache @ %s (%d files)",
                     repo_path, len(_file_cache))
    else:
        # Fall back: clone inline (source cache was not prepared)
        logger.info("Import: source cache not prepared — cloning inline …")
        from utils.repo_cache import RepoCacheManager as _RCM_imp
        _use_repo_cache_imp = settings.enable_repo_cache and not settings.local_repo_path

        if _use_repo_cache_imp:
            _update_import_progress(phase="Preparing repository (persistent cache) …")
            try:
                _rcm_imp = _RCM_imp(
                    cache_root=settings.repo_cache_dir or None,
                    github_token=settings.github_token,
                    default_depth=settings.shallow_clone_depth,
                )
                repo_path, _file_cache = await asyncio.to_thread(
                    _rcm_imp.ensure, clone_url, branch,
                )
                _update_import_progress(phase=f"Repository ready (cached) — starting analysis of {total} alerts …")
                logger.info("Persistent cache: repo ready at %s (%d cached files)", repo_path, len(_file_cache))
            except Exception as exc:
                logger.error("Failed to prepare repository: %s", exc)
                _reset_import_progress()
                return JSONResponse(
                    {"error": f"Git clone/update failed: {exc}"},
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
        else:
            if settings.local_repo_path:
                repo_ctx = LocalRepo(settings.local_repo_path, branch=branch)
            else:
                repo_ctx = ShallowClone(
                    clone_url, branch=branch,
                    depth=settings.shallow_clone_depth,
                    github_token=settings.github_token,
                )

            _update_import_progress(phase="Cloning / updating repository …")
            try:
                repo_path = await asyncio.to_thread(repo_ctx.__enter__)
                _update_import_progress(phase=f"Repository ready — starting analysis of {total} alerts …")
                logger.info("Repository ready at %s — starting analysis of %d alerts", repo_path, total)
            except Exception as exc:
                logger.error("Failed to prepare repository: %s", exc)
                _reset_import_progress()
                return JSONResponse(
                    {"error": f"Git clone/update failed: {exc}"},
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

            # Pre-load source file cache for L2 reachability
            _update_import_progress(phase="Building source file cache for reachability analysis …")
            logger.info("Building source file cache for reachability analysis …")
            _file_cache = await asyncio.to_thread(ReachabilityAnalyzer.build_file_cache, repo_path)

    try:  # ensure repo cleanup even on unexpected errors

        # ── Bulk EPSS fetch (one HTTP call instead of N) ───────────
        _all_cves = list({
            f.cve_id for f, _ in finding_pairs
            if f.cve_id and f.cve_id.upper().startswith("CVE-")
        })
        _epss_cache: dict = {}
        if _all_cves:
            _update_import_progress(phase=f"Fetching EPSS scores in bulk for {len(_all_cves)} unique CVEs …")
            logger.info("Fetching EPSS scores in bulk for %d unique CVEs …", len(_all_cves))
            try:
                _epss_cache = await epss_client.get_scores_bulk(_all_cves)
                logger.info("Bulk EPSS fetch returned %d scores", len(_epss_cache))
            except Exception as exc:
                logger.warning("Bulk EPSS fetch failed, will fall back to per-CVE: %s", exc)

        _update_import_progress(phase="Filtering duplicates …")

        # ── Concurrent analysis ────────────────────────────────────
        _MAX_CONCURRENT = 8
        _sem = asyncio.Semaphore(_MAX_CONCURRENT)
        _counters_lock = asyncio.Lock()
        _import_llm_retry_queue: list[dict] = []  # LLM suggest_fix failures for retry

        # Duplicate filtering (must stay serial — order-dependent)
        _non_dup_pairs: list[tuple] = []
        for finding, alert_type in finding_pairs:
            _dup_key = (
                alert_type.lower().strip(),
                (finding.package_name or "").lower().strip(),
                (finding.cve_id or finding.ghsa_id or "").upper().strip(),
                finding.severity.value.lower().strip(),
            )
            if _dup_key in _existing_keys:
                _orig_alert_id = _existing_keys[_dup_key]
                skipped_duplicates += 1
                logger.info(
                    "Import: skipping duplicate alert (type=%s pkg=%s cve=%s sev=%s) — duplicate of alert #%s",
                    *_dup_key, _orig_alert_id,
                )
                results.append({
                    "alert_id": finding.alert_id,
                    "package": finding.package_name,
                    "severity": finding.severity.value,
                    "decision": "skipped_duplicate",
                    "jira_key": None,
                    "errors": [],
                })
                # Record in dashboard store so the "Duplicates Skipped" card counts it
                store.record_pipeline(PipelineRun(
                    repo=finding.repo_full_name,
                    alert_id=finding.alert_id,
                    alert_type=alert_type,
                    package_name=finding.package_name,
                    cve_id=finding.cve_id or finding.ghsa_id,
                    severity=finding.severity.value,
                    scope=getattr(finding, "scope", None),
                    decision="skipped_duplicate",
                    vex_status="skipped",
                    justification=f"Duplicate alert — already processed as alert #{_orig_alert_id}.",
                ))
                continue
            _existing_keys[_dup_key] = finding.alert_id
            _non_dup_pairs.append((finding, alert_type))

        _update_import_progress(
            phase=f"Analysing {len(_non_dup_pairs)} alerts ({skipped_duplicates} duplicates skipped) …",
            skipped_duplicates=skipped_duplicates,
        )
        logger.info(
            "Starting concurrent analysis of %d alerts (%d duplicates skipped, max %d workers) …",
            len(_non_dup_pairs), skipped_duplicates, _MAX_CONCURRENT,
        )

        # ── Per-alert async worker ─────────────────────────────────
        async def _analyse_one(finding, alert_type):
            nonlocal processed, affected_count, break_build_count
            nonlocal not_affected_count, under_investigation_count
            nonlocal jira_created, review_routed, error_count

            async with _sem:
                _update_import_progress(
                    current_alert=f"#{finding.alert_id} {finding.package_name}",
                )
                t0 = _time.time()
                errors: list[str] = []
                epss_score = None
                epss_val: float | None = None
                decision = AnalysisDecision.UNDER_INVESTIGATION
                vex_status_val = VexStatus.UNDER_INVESTIGATION
                reachable = False
                jira_key: str | None = None

                try:
                    # ── EPSS (from bulk cache, fallback to individual) ─
                    if finding.cve_id:
                        try:
                            epss_score = _epss_cache.get(finding.cve_id)
                            if epss_score is None:
                                epss_score = await epss_client.get_score(finding.cve_id)
                            if epss_score:
                                epss_val = epss_score.epss
                        except Exception as exc:
                            errors.append(f"EPSS: {exc}")

                    # ── L1/L2 Analysis (CPU-bound → run in thread) ─────
                    metadata_result = None
                    reachability_result = None

                    def _run_analysis():
                        nonlocal decision, vex_status_val, reachable
                        _meta_result = None
                        _reach_result = None

                        logger.info(
                            "[Alert #%d] L1 Metadata analysis started for %s (%s)",
                            finding.alert_id, finding.package_name, finding.package_ecosystem,
                        )
                        meta_analyzer = MetadataAnalyzer(repo_path)
                        _meta_result = meta_analyzer.analyse(
                            finding.package_name,
                            finding.package_ecosystem,
                            finding.manifest_path,
                        )
                        logger.info(
                            "[Alert #%d] L1 Metadata analysis completed — dev=%s, scope=%s",
                            finding.alert_id,
                            _meta_result.is_dev_dependency,
                            _meta_result.dependency_scope,
                        )

                        if _meta_result.is_dev_dependency and settings.skip_dev_dependencies:
                            decision = AnalysisDecision.NOT_AFFECTED_DEV_ONLY
                            vex_status_val = VexStatus.NOT_AFFECTED
                            logger.info(
                                "[Alert #%d] L1 short-circuit: dev-only dependency → NOT_AFFECTED",
                                finding.alert_id,
                            )
                        else:
                            logger.info(
                                "[Alert #%d] L2 Reachability analysis started for %s",
                                finding.alert_id, finding.package_name,
                            )
                            reach_analyzer = ReachabilityAnalyzer(repo_path, file_cache=_file_cache)
                            _reach_result = reach_analyzer.analyse(
                                finding.package_name,
                                finding.vulnerable_functions,
                                finding.package_ecosystem,
                            )
                            logger.info(
                                "[Alert #%d] L2 Reachability analysis completed — reachable=%s, method=%s, confidence=%.2f, hits=%d",
                                finding.alert_id,
                                _reach_result.reachable,
                                _reach_result.method,
                                _reach_result.confidence,
                                len(_reach_result.hits),
                            )

                            if _reach_result.reachable:
                                reachable = True
                                if (
                                    settings.enable_break_the_build
                                    and epss_client.is_high_risk(epss_score, settings.epss_threshold)
                                ):
                                    decision = AnalysisDecision.BREAK_THE_BUILD
                                    vex_status_val = VexStatus.AFFECTED
                                else:
                                    decision = AnalysisDecision.AFFECTED_REACHABLE
                                    vex_status_val = VexStatus.AFFECTED
                            else:
                                decision = AnalysisDecision.NOT_AFFECTED_DEAD_CODE
                                vex_status_val = VexStatus.NOT_AFFECTED

                        logger.info(
                            "[Alert #%d] Analysis decision: %s (vex=%s)",
                            finding.alert_id, decision.value, vex_status_val.value,
                        )
                        return _meta_result, _reach_result

                    try:
                        metadata_result, reachability_result = await asyncio.to_thread(_run_analysis)
                    except Exception as exc:
                        errors.append(f"Analysis: {exc}")
                        logger.warning("Import analysis failed for alert #%d: %s", finding.alert_id, exc)

                    # ── Human review gate ──────────────────────────────
                    recorded_decision = decision.value
                    recorded_vex = vex_status_val.value

                    if settings.enable_human_review and decision in (
                        AnalysisDecision.NOT_AFFECTED_DEV_ONLY,
                        AnalysisDecision.NOT_AFFECTED_DEAD_CODE,
                    ):
                        trigger = (
                            "Agent decided to dismiss alert as dev-only dependency — awaiting human confirmation"
                            if decision == AnalysisDecision.NOT_AFFECTED_DEV_ONLY
                            else "Agent decided to dismiss alert as unreachable code path — awaiting human confirmation"
                        )
                        try:
                            rq = _get_rq()
                            finding_dict = finding.model_dump(mode="json")
                            epss_dict = (
                                {"epss": epss_val, "percentile": 0.0, "date": ""}
                                if epss_val else None
                            )
                            rq.enqueue(
                                repo_full_name=finding.repo_full_name,
                                alert_id=finding.alert_id,
                                cve_id=finding.cve_id or finding.ghsa_id,
                                package_name=finding.package_name,
                                agent_decision=decision.value,
                                confidence=0.7,
                                trigger_reason=trigger,
                                finding_json=_json_mod.dumps(finding_dict),
                                epss_json=_json_mod.dumps(epss_dict) if epss_dict else None,
                                reachability_json=None,
                                hits_json="[]",
                                suggested_fix=_build_suggested_fix(
                                    package_name=finding.package_name,
                                    patched_version=finding.patched_version,
                                    decision_str='pending_review',
                                    alert_type=alert_type,
                                    severity=finding.severity.value,
                                    cve_id=finding.cve_id or finding.ghsa_id,
                                    ecosystem=finding.package_ecosystem,
                                    epss_score=epss_score.epss if epss_score else None,
                                    metadata_result=metadata_result,
                                    reachability_result=reachability_result,
                                ),
                                timeout_hours=settings.review_timeout_hours,
                            )
                            async with _counters_lock:
                                review_routed += 1
                        except Exception as exc:
                            errors.append(f"Review queue: {exc}")

                        recorded_decision = "pending_review"
                        recorded_vex = VexStatus.UNDER_INVESTIGATION.value
                        async with _counters_lock:
                            not_affected_count += 1

                    elif decision in (
                        AnalysisDecision.AFFECTED_REACHABLE,
                        AnalysisDecision.BREAK_THE_BUILD,
                    ):
                        async with _counters_lock:
                            affected_count += 1
                            if decision == AnalysisDecision.BREAK_THE_BUILD:
                                break_build_count += 1

                        if jira_enabled:
                            try:
                                jira_key = await jira.create_ticket(
                                    finding, decision, [], epss_val, ""
                                )
                                if jira_key:
                                    async with _counters_lock:
                                        jira_created += 1
                            except Exception as exc:
                                errors.append(f"Jira: {exc}")
                    elif decision in (
                        AnalysisDecision.NOT_AFFECTED_DEV_ONLY,
                        AnalysisDecision.NOT_AFFECTED_DEAD_CODE,
                    ):
                        async with _counters_lock:
                            not_affected_count += 1
                    else:
                        async with _counters_lock:
                            under_investigation_count += 1

                    # ── Suggested fix (LLM) ────────────────────────────
                    _fix_text = ""
                    _fix_llm_failed = False
                    try:
                        _hits = reachability_result.hits if reachability_result else []
                        _fix_text = await _llm_fix.suggest_fix(finding, _hits)
                    except Exception as _fx_exc:
                        _fix_llm_failed = True
                        logger.debug("suggest_fix queued for retry — alert #%d: %s", finding.alert_id, _fx_exc)
                    if not _fix_text:
                        _fix_text = _build_suggested_fix(
                            package_name=finding.package_name,
                            patched_version=finding.patched_version,
                            decision_str=recorded_decision,
                            alert_type=alert_type,
                            severity=finding.severity.value,
                            cve_id=finding.cve_id or finding.ghsa_id,
                            ecosystem=finding.package_ecosystem,
                            epss_score=epss_score.epss if epss_score else None,
                            reachable=reachable,
                            metadata_result=metadata_result,
                            reachability_result=reachability_result,
                            vulnerable_version_range=finding.vulnerable_version_range,
                            summary=finding.summary,
                        )

                    # Queue for LLM retry if the call failed
                    if _fix_llm_failed:
                        async with _counters_lock:
                            _import_llm_retry_queue.append({
                                "alert_id": finding.alert_id,
                                "finding": finding,
                                "hits": _hits,
                            })

                    # ── License risk ───────────────────────────────────
                    _lic_risk_text = ""
                    if settings.enable_license_check:
                        try:
                            from analyzers.license_analyzer import LicenseAnalyzer as _LicAna
                            _la = _LicAna(
                                deny_licenses=[p.strip() for p in settings.blocked_licenses.split(",") if p.strip()],
                                warn_licenses=[p.strip() for p in settings.warn_licenses.split(",") if p.strip()],
                            )
                            _lr = _la.check(
                                getattr(finding, "package_ecosystem", "") or "",
                                finding.package_name,
                            )
                            if _lr.risk_level == "unknown":
                                _lic_risk_text = "Unknown"
                            elif _lr.risk_level == "none":
                                _lic_risk_text = f"{_lr.license_id} ✓"
                            else:
                                _lic_risk_text = f"{_lr.license_id} ({_lr.risk_level.title()})"
                        except Exception as _lic_exc:
                            logger.debug("license check skipped for alert #%d: %s", finding.alert_id, _lic_exc)

                    # ── Record in dashboard ────────────────────────────
                    duration_ms = round((_time.time() - t0) * 1000, 1)
                    store.record_pipeline(PipelineRun(
                        repo=finding.repo_full_name,
                        alert_id=finding.alert_id,
                        alert_type=alert_type,
                        package_name=finding.package_name,
                        cve_id=finding.cve_id or finding.ghsa_id,
                        severity=finding.severity.value,
                        scope=getattr(finding, "scope", None),
                        decision=recorded_decision,
                        vex_status=recorded_vex,
                        epss_score=epss_val,
                        reachable=reachable,
                        jira_key=jira_key,
                        errors=errors,
                        duration_ms=duration_ms,
                        justification=_build_analysis_summary(
                            metadata_result,
                            reachability_result,
                            recorded_decision,
                            decision.value,
                            alert_scope=getattr(finding, "scope", "") or "",
                        ),
                        suggested_fix=_fix_text,
                        license_risk=_lic_risk_text,
                    ))
                    async with _counters_lock:
                        processed += 1
                        _is_aff = recorded_decision in ("affected_reachable", "break_the_build")
                        _is_na = recorded_decision in ("not_affected_dev_only", "not_affected_dead_code", "pending_review")
                        _update_import_progress(
                            analysed=processed,
                            affected=affected_count,
                            not_affected=not_affected_count,
                            errors=error_count,
                        )

                    return {
                        "alert_id": finding.alert_id,
                        "package": finding.package_name,
                        "severity": finding.severity.value,
                        "decision": recorded_decision,
                        "jira_key": jira_key,
                        "errors": errors,
                    }

                except Exception as exc:
                    async with _counters_lock:
                        error_count += 1
                        _update_import_progress(analysed=processed, errors=error_count)
                    logger.error("Import pipeline error for row: %s", exc)
                    return {
                        "alert_id": finding.alert_id,
                        "package": finding.package_name,
                        "severity": finding.severity.value,
                        "decision": "error",
                        "jira_key": None,
                        "errors": [str(exc)],
                    }

        # ── Launch all workers concurrently ────────────────────────
        tasks = [_analyse_one(f, at) for f, at in _non_dup_pairs]
        concurrent_results = await asyncio.gather(*tasks)
        results.extend(concurrent_results)

        logger.info(
            "Concurrent analysis complete: %d processed, %d affected, %d errors",
            processed, affected_count, error_count,
        )

        # ── LLM suggest_fix retry pass (import pipeline) ──────────
        if _import_llm_retry_queue:
            _retry_total = len(_import_llm_retry_queue)
            logger.info("LLM suggest_fix retry (import): %d items queued — starting retry pass …", _retry_total)
            _update_import_progress(phase=f"Retrying LLM suggest_fix for {_retry_total} alerts …")

            _MAX_RETRIES = 3
            _retry_remaining = list(_import_llm_retry_queue)
            _retry_succeeded = 0

            for _attempt in range(1, _MAX_RETRIES + 1):
                if not _retry_remaining:
                    break
                _backoff = min(10 * (3 ** (_attempt - 1)), 60)
                logger.info("LLM retry attempt %d/%d — waiting %ds before retrying %d items …",
                            _attempt, _MAX_RETRIES, _backoff, len(_retry_remaining))
                _update_import_progress(
                    phase=f"LLM retry attempt {_attempt}/{_MAX_RETRIES} "
                          f"({len(_retry_remaining)} remaining, waiting {_backoff}s) …",
                )
                await asyncio.sleep(_backoff)

                _still_failed: list[dict] = []
                for _ritem in _retry_remaining:
                    _update_import_progress(
                        current_alert=f"Retry #{_ritem['alert_id']} (attempt {_attempt})",
                    )
                    try:
                        _fix = await _llm_fix.suggest_fix(_ritem["finding"], _ritem["hits"])
                        if _fix:
                            store.update_suggested_fix(_ritem["alert_id"], _fix)
                            _retry_succeeded += 1
                            logger.info("LLM retry succeeded for alert #%d (attempt %d)",
                                        _ritem["alert_id"], _attempt)
                        else:
                            logger.debug("LLM retry returned empty for alert #%d", _ritem["alert_id"])
                    except Exception as _rx:
                        logger.debug("LLM retry failed for alert #%d (attempt %d): %s",
                                     _ritem["alert_id"], _attempt, _rx)
                        _still_failed.append(_ritem)
                    _retry_remaining = _still_failed

            if _retry_remaining:
                logger.warning("LLM suggest_fix (import): %d/%d items still failed after %d retries",
                               len(_retry_remaining), _retry_total, _MAX_RETRIES)
            logger.info("LLM suggest_fix retry (import) complete: %d/%d succeeded",
                        _retry_succeeded, _retry_total)

        _update_import_progress(phase="Completed", active=False, current_alert="")

    finally:
        # Clean up the repo context (deletes shallow clone temp dir, no-op for local)
        # Persistent-cache repos are NOT cleaned up — they stay on disk for reuse.
        if repo_ctx is not None:
            repo_ctx.__exit__(None, None, None)
        logger.info("Repository context cleaned up")

    return JSONResponse({
        "status": "completed",
        "file": file.filename,
        "total_rows": total,
        "processed": processed,
        "skipped_duplicates": skipped_duplicates,
        "affected": affected_count,
        "break_the_build": break_build_count,
        "not_affected": not_affected_count,
        "under_investigation": under_investigation_count,
        "jira_tickets_created": jira_created,
        "routed_to_review": review_routed,
        "errors": error_count,
        "results": results,
    })


@app.post("/webhook/github", status_code=status.HTTP_202_ACCEPTED)
async def github_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(default=None),
    x_github_event: str | None = Header(default=None),
) -> JSONResponse:
    """
    Receive GitHub security webhook events.

    Supported event types:
      - dependabot_alert
      - code_scanning_alert  (future)
    """
    body = await request.body()
    _verify_signature(body, x_hub_signature_256)

    if x_github_event not in ("dependabot_alert", "code_scanning_alert"):
        logger.debug("Ignoring event type: %s", x_github_event)
        return JSONResponse(
            {"status": "ignored", "reason": f"Unsupported event: {x_github_event}"},
            status_code=status.HTTP_200_OK,
        )

    try:
        raw: dict[str, Any] = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JSON payload: {exc}",
        ) from exc

    try:
        payload = GitHubSecurityWebhookPayload(**raw)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Payload validation error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    logger.info(
        "Received %s event: repo=%s alert=%s action=%s",
        x_github_event,
        payload.repo_full_name,
        payload.alert.get("number"),
        payload.action,
    )

    # Run the agent asynchronously (the HTTP response is 202 Accepted immediately)
    asyncio.create_task(_run_agent(payload, alert_type=x_github_event or "dependabot_alert"))

    return JSONResponse(
        {
            "status": "accepted",
            "repo": payload.repo_full_name,
            "alert": payload.alert.get("number"),
            "action": payload.action,
        },
        status_code=status.HTTP_202_ACCEPTED,
    )


async def _run_agent(
    payload: GitHubSecurityWebhookPayload,
    alert_type: str = "dependabot_alert",
) -> None:
    """Background task: run the full VEX pipeline."""
    import time
    t0 = time.monotonic()
    try:
        decision = await _agent.run(payload)  # type: ignore[union-attr]
        duration_ms = (time.monotonic() - t0) * 1000
        logger.info(
            "VEX pipeline complete: decision=%s vex_status=%s errors=%d",
            decision.decision.value,
            decision.vex_status.value,
            len(decision.errors),
        )
        if decision.errors:
            for err in decision.errors:
                logger.error("Pipeline error: %s", err)
        # Record in dashboard store
        f = decision.finding
        # ── License risk (webhook) ─────────────────────────────
        _wh_lic_risk = ""
        if settings.enable_license_check:
            try:
                from analyzers.license_analyzer import LicenseAnalyzer as _LicWh
                _la_wh = _LicWh(
                    deny_licenses=[p.strip() for p in settings.blocked_licenses.split(",") if p.strip()],
                    warn_licenses=[p.strip() for p in settings.warn_licenses.split(",") if p.strip()],
                )
                _lr_wh = _la_wh.check(
                    getattr(f, "package_ecosystem", "") or "",
                    f.package_name,
                )
                if _lr_wh.risk_level == "unknown":
                    _wh_lic_risk = "Unknown"
                elif _lr_wh.risk_level == "none":
                    _wh_lic_risk = f"{_lr_wh.license_id} ✓"
                else:
                    _wh_lic_risk = f"{_lr_wh.license_id} ({_lr_wh.risk_level.title()})"
            except Exception:
                pass
        get_dashboard_store().record_pipeline(PipelineRun(
            repo=f.repo_full_name,
            alert_id=f.alert_id,
            alert_type=alert_type.replace("_alert", ""),
            package_name=f.package_name,
            cve_id=f.cve_id or f.ghsa_id,
            severity=f.severity.value,
            scope=getattr(f, "scope", None),
            decision=decision.decision.value,
            vex_status=decision.vex_status.value,
            jira_key=None,   # not surfaced in VexDecision; shown via jira_ticket_updated
            epss_score=decision.epss_score.epss if decision.epss_score else None,
            reachable=(
                decision.reachability_result.reachable
                if decision.reachability_result else None
            ),
            errors=list(decision.errors),
            duration_ms=round(duration_ms, 1),
            justification=_build_analysis_summary(
                decision.metadata_result,
                decision.reachability_result,
                decision.decision.value,
                alert_scope=getattr(f, "scope", "") or "",
            ),
            suggested_fix=_build_suggested_fix(
                package_name=f.package_name,
                patched_version=f.patched_version,
                decision_str=decision.decision.value,
                alert_type=alert_type.replace("_alert", ""),
                severity=f.severity.value,
                cve_id=f.cve_id or f.ghsa_id,
                ecosystem=f.package_ecosystem,
                epss_score=decision.epss_score.epss if decision.epss_score else None,
                reachable=decision.reachability_result.reachable if decision.reachability_result else None,
                metadata_result=decision.metadata_result,
                reachability_result=decision.reachability_result,
                vulnerable_version_range=f.vulnerable_version_range,
                summary=f.summary,
            ),
            license_risk=_wh_lic_risk,
        ))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unhandled VEX pipeline error: %s", exc)


# ---------------------------------------------------------------------------
# VEX Export endpoint
# ---------------------------------------------------------------------------

# In-memory store of the most recent VexDecision per alert (repo:alert_id key)
# For production you would use a database; this suffices for single-node use.
_vex_store: dict[str, dict] = {}


@app.get(
    "/vex/export",
    summary="Export a CycloneDX VEX document",
    response_class=Response,
    responses={200: {"content": {"application/json": {}}}},
)
async def export_vex(
    repo: str,
    alert_id: int,
) -> Response:
    """
    Export a CycloneDX 1.5 VEX document for a previously processed alert.

    Query parameters:
      - repo      : repository full name, e.g. ``solarwinds-internal/arm-arm``
      - alert_id  : Dependabot alert number
    """
    key = f"{repo}:{alert_id}"
    stored = _vex_store.get(key)
    if not stored:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No VEX data found for {key}. Process the alert first via the webhook.",
        )
    from utils.vex_exporter import VexExporter, VexDecision as VDec  # local import to avoid circular
    return Response(
        content=stored["vex_json"],
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="vex-{alert_id}.cdx.json"'},
    )


@app.get(
    "/sbom/generate",
    summary="Generate a CycloneDX SBOM for a local or cloned repository",
    response_class=Response,
    responses={200: {"content": {"application/json": {}}}},
)
async def generate_sbom() -> Response:
    """
    Generate a CycloneDX 1.5 SBOM for the configured target repository.

    If ``LOCAL_REPO_PATH`` is set the local directory is scanned directly.
    Otherwise the repo is shallow-cloned from ``TARGET_REPO_URL``.
    """
    from pathlib import Path
    from utils.git_utils import LocalRepo, ShallowClone

    if not settings.local_repo_path and not settings.target_repo_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Neither LOCAL_REPO_PATH nor TARGET_REPO_URL is configured.",
        )

    try:
        if settings.local_repo_path:
            repo_path = Path(settings.local_repo_path)
            repo_name = repo_path.name
            gen = SBOMGenerator(repo_path, repo_name)
            sbom_json = gen.generate_json()
        else:
            branch = settings.target_repo_branch or "main"
            repo_name = settings.target_repo_url.rstrip("/").rstrip(".git").split("/")[-1]
            with ShallowClone(
                settings.target_repo_url,
                branch=branch,
                depth=1,
                github_token=settings.github_token,
            ) as repo_path:
                gen = SBOMGenerator(repo_path, repo_name)
                sbom_json = gen.generate_json()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return Response(
        content=sbom_json,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="sbom-{repo_name}.cdx.json"'},
    )


# ---------------------------------------------------------------------------
# Human review endpoints
# ---------------------------------------------------------------------------

from utils.review_queue import get_review_queue  # noqa: E402
from pydantic import BaseModel as _BaseModel  # noqa: E402


class ReviewActionBody(_BaseModel):
    """
    JSON body accepted by review action endpoints.
    Sent automatically by Teams Action.Http cards (comment bound from
    the inline Input.Text field); also accepted from REST clients.
    """
    comment: str = ""


class OverrideActionBody(_BaseModel):
    """JSON body for the override endpoint — includes the new decision value."""
    comment: str = ""
    decision: str = ""


@app.get(
    "/review/pending",
    summary="List all alerts awaiting human review",
)
async def list_pending_reviews() -> dict:
    """Return all review items that are still in *pending* state."""
    queue = get_review_queue()
    queue.expire_old()           # mark any timed-out items first
    items = queue.list_pending()
    return {"pending": [i.to_dict() for i in items], "count": len(items)}


@app.get(
    "/review/{review_id}",
    summary="Get a specific review item",
)
async def get_review(review_id: str) -> dict:
    item = get_review_queue().get(review_id)
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Review not found")
    return item.to_dict()


@app.get(
    "/review/{review_id}/approve",
    summary="[Browser] Approve the agent's decision",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def approve_review_browser(review_id: str, comment: str = "") -> HTMLResponse:
    """
    Called when a reviewer clicks the ✅ Approve button in the Teams card.
    Executes the approval and returns a styled HTML confirmation page.
    """
    try:
        result = await _agent.finalize_review(  # type: ignore[union-attr]
            review_id, status="approved", reviewer_comment=comment
        )
        # Update the dashboard pipeline entry from pending_review → approved decision
        get_dashboard_store().update_pipeline_decision(
            result.finding.alert_id,
            result.decision.value,
            vex_status=result.vex_status.value if result.vex_status else None,
            jira_key=result.jira_ticket_updated and getattr(result, '_jira_key', None),
        )
        return HTMLResponse(_review_html(
            title="✅ Review Approved",
            colour="#1a7f37",
            heading="Alert Dismissed Successfully",
            lines=[
                f"Package: <b>{result.finding.package_name} {result.finding.package_version}</b>",
                f"CVE: <b>{result.finding.cve_id or result.finding.ghsa_id or 'N/A'}</b>",
                f"Decision: <b>{result.decision.value}</b>",
                f"GitHub alert has been dismissed.",
                f"A resolution notification has been posted to Teams.",
            ],
        ))
    except ValueError as exc:
        return HTMLResponse(_review_html(
            title="⚠️ Already Resolved",
            colour="#9a6700",
            heading="Review Already Resolved",
            lines=[str(exc)],
        ), status_code=400)


@app.get(
    "/review/{review_id}/dismiss",
    summary="[Browser] Dismiss the pending review",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def dismiss_review_browser(review_id: str, comment: str = "") -> HTMLResponse:
    """
    Called when a reviewer clicks the ❌ Dismiss button in the Teams card.
    Closes the review without taking downstream action.
    Moves the dashboard entry to under_investigation.
    """
    try:
        result = await _agent.finalize_review(  # type: ignore[union-attr]
            review_id, status="dismissed", reviewer_comment=comment
        )
        # Update the dashboard pipeline entry → under_investigation
        get_dashboard_store().update_pipeline_decision(
            result.finding.alert_id,
            result.decision.value,
            vex_status=result.vex_status.value if result.vex_status else None,
        )
        return HTMLResponse(_review_html(
            title="❌ Review Dismissed — Under Investigation",
            colour="#cf222e",
            heading="Review Dismissed — Moved to Under Investigation",
            lines=[
                f"Package: <b>{result.finding.package_name} {result.finding.package_version}</b>",
                f"CVE: <b>{result.finding.cve_id or result.finding.ghsa_id or 'N/A'}</b>",
                f"The alert was NOT dismissed on GitHub.",
                f"Decision moved to <b>Under Investigation</b>.",
                f"No Jira ticket was created.",
                f"A resolution notification has been posted to Teams.",
            ],
        ))
    except ValueError as exc:
        return HTMLResponse(_review_html(
            title="⚠️ Already Resolved",
            colour="#9a6700",
            heading="Review Already Resolved",
            lines=[str(exc)],
        ), status_code=400)


@app.post(
    "/review/{review_id}/approve",
    summary="[API] Approve the agent's decision and proceed with the pipeline",
)
async def approve_review(
    review_id: str,
    body: ReviewActionBody = ReviewActionBody(),
    comment: str = "",
) -> dict:
    """REST API: approve a pending review."""
    reviewer_comment = body.comment or comment
    try:
        result = await _agent.finalize_review(  # type: ignore[union-attr]
            review_id, status="approved", reviewer_comment=reviewer_comment
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    # Update the dashboard pipeline entry from pending_review → approved decision
    get_dashboard_store().update_pipeline_decision(
        result.finding.alert_id,
        result.decision.value,
        vex_status=result.vex_status.value if result.vex_status else None,
    )
    return {"review_id": review_id, "status": "approved", "decision": result.decision.value}


@app.post(
    "/review/{review_id}/override",
    summary="[API] Override the agent's decision with a different verdict",
)
async def override_review(
    review_id: str,
    body: OverrideActionBody = OverrideActionBody(),
    decision: str = "",
    comment: str = "",
) -> dict:
    """REST API: override a pending review with a specific decision."""
    effective_decision = body.decision or decision
    reviewer_comment = body.comment or comment
    try:
        result = await _agent.finalize_review(  # type: ignore[union-attr]
            review_id, status="overridden",
            override_decision=effective_decision,
            reviewer_comment=reviewer_comment,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    # Update the dashboard pipeline entry with the overridden decision
    get_dashboard_store().update_pipeline_decision(
        result.finding.alert_id,
        result.decision.value,
        vex_status=result.vex_status.value if result.vex_status else None,
    )
    return {"review_id": review_id, "status": "overridden", "decision": result.decision.value}


@app.post(
    "/review/{review_id}/dismiss",
    summary="[API] Dismiss the pending review",
)
async def dismiss_review(
    review_id: str,
    body: ReviewActionBody = ReviewActionBody(),
    comment: str = "",
) -> dict:
    """REST API: dismiss a pending review."""
    reviewer_comment = body.comment or comment
    try:
        result = await _agent.finalize_review(  # type: ignore[union-attr]
            review_id, status="dismissed", reviewer_comment=reviewer_comment
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    # Update the dashboard pipeline entry → under_investigation
    get_dashboard_store().update_pipeline_decision(
        result.finding.alert_id,
        result.decision.value,
        vex_status=result.vex_status.value if result.vex_status else None,
    )
    return {"review_id": review_id, "status": "dismissed", "decision": result.decision.value}


# ---------------------------------------------------------------------------
# Direct pipeline-run approve / dismiss (no review-queue entry required)
# ---------------------------------------------------------------------------

@app.post(
    "/api/v1/pipeline-run/{alert_id}/approve",
    summary="Approve a pipeline run directly (mark as not_affected)",
)
async def approve_pipeline_run(alert_id: int) -> dict:
    """Approve an auto-decided pipeline run — confirms the not_affected decision
    and dismisses the alert on GitHub."""
    store = get_dashboard_store()
    found = store.update_pipeline_decision(alert_id, "not_affected_dead_code", vex_status="not_affected")
    if not found:
        raise HTTPException(status_code=404, detail=f"Pipeline run with alert_id {alert_id} not found")

    run = store.find_pipeline_run(alert_id)
    github_dismissed = False

    # Dismiss the alert on GitHub (routes to correct API based on alert_type)
    if run and _agent:
        dismiss_comment = (
            f"VEX Agent: Approved by human reviewer. "
            f"Decision: not_affected (dead code / unreachable). "
            f"Package: {run.package_name}. CVE: {run.cve_id or 'N/A'}."
        )
        try:
            github_dismissed = await _agent.github.dismiss_alert(
                run.repo,
                alert_id,
                alert_type=run.alert_type or "dependabot",
                dismissed_comment=dismiss_comment,
            )
            if github_dismissed:
                logger.info("GitHub %s alert %s#%d dismissed after pipeline-run approve",
                            run.alert_type, run.repo, alert_id)
            else:
                logger.warning("GitHub dismiss returned False for %s alert %s#%d",
                               run.alert_type, run.repo, alert_id)
        except Exception as exc:
            logger.warning("Failed to dismiss GitHub %s alert %s#%d: %s",
                           run.alert_type, run.repo, alert_id, exc)

        # Send Teams notification
        try:
            await _agent.teams.notify_action_resolved(
                repo=run.repo,
                package_name=run.package_name,
                cve_id=run.cve_id,
                alert_id=alert_id,
                action="approved",
                final_decision="not_affected_dead_code",
                jira_key=run.jira_key,
            )
        except Exception:
            logger.warning("Teams notification failed for pipeline-run approve alert %s", alert_id)

    return {
        "alert_id": alert_id,
        "status": "approved",
        "decision": "not_affected_dead_code",
        "github_dismissed": github_dismissed,
    }


@app.post(
    "/api/v1/pipeline-run/{alert_id}/dismiss",
    summary="Dismiss a pipeline run (move to under_investigation)",
)
async def dismiss_pipeline_run(alert_id: int) -> dict:
    """Dismiss an auto-decided pipeline run — moves it to under_investigation."""
    store = get_dashboard_store()
    found = store.update_pipeline_decision(alert_id, "under_investigation", vex_status="under_investigation")
    if not found:
        raise HTTPException(status_code=404, detail=f"Pipeline run with alert_id {alert_id} not found")
    # Send Teams notification
    run = store.find_pipeline_run(alert_id)
    if run and _agent:
        try:
            await _agent.teams.notify_action_resolved(
                repo=run.repo,
                package_name=run.package_name,
                cve_id=run.cve_id,
                alert_id=alert_id,
                action="dismissed",
                final_decision="under_investigation",
                jira_key=run.jira_key,
            )
        except Exception:
            logger.warning("Teams notification failed for pipeline-run dismiss alert %s", alert_id)
    return {"alert_id": alert_id, "status": "dismissed", "decision": "under_investigation"}


def _review_html(title: str, colour: str, heading: str, lines: list[str]) -> str:
    """Return a simple self-contained HTML confirmation page."""
    items = "".join(f"<li>{l}</li>" for l in lines)
    return f"""
<!DOCTYPE html><html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #f6f8fa; display: flex; align-items: center;
            justify-content: center; min-height: 100vh; margin: 0; }}
    .card {{ background: white; border-radius: 12px; padding: 2.5rem 3rem;
             box-shadow: 0 4px 24px rgba(0,0,0,.1); max-width: 480px; width: 90%; }}
    h1 {{ color: {colour}; font-size: 1.5rem; margin: 0 0 1rem; }}
    ul {{ color: #444; line-height: 1.8; padding-left: 1.2rem; }}
    .badge {{ display: inline-block; background: {colour}; color: white;
              border-radius: 999px; padding: .25rem .9rem; font-size: .85rem;
              margin-bottom: 1.2rem; }}
    .close {{ margin-top: 1.8rem; font-size: .85rem; color: #888; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">VEX Agent</div>
    <h1>{heading}</h1>
    <ul>{items}</ul>
    <p class="close">You may close this tab.</p>
  </div>
</body></html>
"""


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def _run_generate_report(args: "argparse.Namespace") -> None:
    """Execute the --generate-report pipeline and print a human-readable summary."""
    import asyncio
    from pathlib import Path
    from utils.report_generator import SecurityReportGenerator

    repo_path = Path(args.repo_path) if getattr(args, "repo_path", None) else None

    async def _pipeline() -> dict:
        gen = SecurityReportGenerator(
            repo_full_name=getattr(args, "repo", None),
            local_repo_path=repo_path,
            branch=getattr(args, "branch", ""),
        )
        return await gen.run()

    summary = asyncio.run(_pipeline())

    print("\n── Security Report Generation Complete ──")
    print(f"  SBOM generated:         {summary['sbom_generated']}")
    print(f"  Dependabot alerts:      {summary['dependabot_alerts']}")
    print(f"  Code scanning alerts:   {summary['code_scanning_alerts']}")
    print(f"  Secret scanning alerts: {summary['secret_scanning_alerts']}")
    print(f"  Total alerts in VEX:    {summary['total_alerts']}")
    if summary["saved_files"]:
        print("  Saved files:")
        for f in summary["saved_files"]:
            print(f"    {f}")
    else:
        print(
            "  Saved files:           (none — "
            "configure SHAREPOINT_* settings in .env to persist artefacts)"
        )
    if summary["errors"]:
        print("  Errors:")
        for err in summary["errors"]:
            print(f"    ✗ {err}")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="VEX Agent — GitHub Security Exploitability Validator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--generate-report",
        action="store_true",
        help=(
            "Generate a CycloneDX SBOM + combined VEX document from all open "
            "GitHub security alerts (Dependabot, code-scanning, secret-scanning) "
            "and upload the artefacts to SharePoint."
        ),
    )
    parser.add_argument(
        "--repo",
        metavar="OWNER/REPO",
        default="",
        help=(
            "GitHub repository in 'owner/repo' form, e.g. acme/my-service. "
            "Overrides TARGET_REPO_URL from .env."
        ),
    )
    parser.add_argument(
        "--repo-path",
        metavar="PATH",
        default="",
        help=(
            "Absolute path to an already-cloned local checkout. "
            "Overrides LOCAL_REPO_PATH from .env."
        ),
    )
    parser.add_argument(
        "--branch",
        default="",
        help="Branch to check out when cloning (default: TARGET_REPO_BRANCH or main).",
    )
    parser.add_argument(
        "--simulate",
        action="store_true",
        help=(
            "Enable mock mode and pre-load the dashboard with simulated data "
            "(80+ alerts) on startup. Without this flag the server uses the "
            "real GitHub API and starts with an empty dashboard."
        ),
    )

    args = parser.parse_args()

    if args.generate_report:
        _run_generate_report(args)
    else:
        if args.simulate:
            _os.environ["_VEX_SIMULATE"] = "1"
            _os.environ["USE_MOCK_GITHUB_DATA"] = "1"
        else:
            _os.environ.pop("_VEX_SIMULATE", None)
            _os.environ.pop("USE_MOCK_GITHUB_DATA", None)
        uvicorn.run(
            "main:app",
            host=settings.host,
            port=settings.port,
            reload=False,
            log_level=settings.log_level.lower(),
        )
