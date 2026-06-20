"""
Smoke test for Jira ticket creation via JiraClient.

Verifies connectivity, then creates a real test ticket using a synthetic
AFFECTED_REACHABLE finding so you can confirm the full pipeline works
end-to-end in Jira.

Usage:
    python test_jira.py
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

# Ensure workspace root is on sys.path when running the script directly
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)

from config import get_settings
from clients.jira_client import JiraClient
from models.vex_models import (
    NormalisedFinding,
    Severity,
    AnalysisDecision,
    ReachabilityHit,
)

FINDING = NormalisedFinding(
    alert_id=42,
    repo_full_name="example/vex-test-repo",
    repo_clone_url="https://github.com/example/vex-test-repo.git",
    repo_default_branch="main",
    package_name="pyyaml",
    package_version="5.4.1",
    package_ecosystem="pip",
    vulnerable_version_range="< 6.0",
    patched_version="6.0",
    cve_id="CVE-2020-14343",
    ghsa_id="GHSA-8q59-q68h-6hv4",
    severity=Severity.CRITICAL,
    cvss_score=9.8,
    cvss_vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    summary="Arbitrary code execution in PyYAML via yaml.load()",
    manifest_path="requirements.txt",
    vulnerable_functions=["load"],
)

HITS = [
    ReachabilityHit(
        file_path="app/config_loader.py",
        line_number=9,
        line_content="    return yaml.load(fh)",
        function_called="load",
        confidence=1.0,
    ),
    ReachabilityHit(
        file_path="app/utils/parser.py",
        line_number=34,
        line_content="data = yaml.load(open(path))",
        function_called="load",
        confidence=0.95,
    ),
]


async def test_connectivity(client) -> bool:
    """Ping the Jira API to verify credentials before creating a ticket."""
    import httpx
    async with httpx.AsyncClient(auth=client._auth, headers=client._headers, timeout=10) as c:
        resp = await c.get(f"{client._base}/rest/api/3/myself")
    if resp.status_code == 200:
        data = resp.json()
        logger.info("Jira connection OK — logged in as: %s (%s)", data.get("displayName"), data.get("emailAddress"))
        return True
    else:
        logger.error("Jira connection FAILED: %s %s", resp.status_code, resp.text[:300])
        return False


async def main():
    s = get_settings()

    print("\n" + "=" * 60)
    print("  Jira Configuration")
    print("=" * 60)
    print(f"  base_url     : {s.jira_base_url or '(not set)'}")
    print(f"  email        : {s.jira_email or '(not set)'}")
    print(f"  api_token    : {'***' if s.jira_api_token else '(not set)'}")
    print(f"  project_key  : {s.jira_project_key or '(not set)'}")
    print()

    if not all([s.jira_base_url, s.jira_email, s.jira_api_token, s.jira_project_key]):
        logger.error("Jira is not fully configured in .env — set JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY")
        sys.exit(1)

    client = JiraClient()

    # ── Step 1: Connectivity check ────────────────────────────────────────
    print("=" * 60)
    print("  Step 1: Connectivity check")
    print("=" * 60)
    ok = await test_connectivity(client)
    if not ok:
        sys.exit(1)

    # ── Step 2: Get LLM fix suggestion ───────────────────────────────────
    print()
    print("=" * 60)
    print("  Step 2: Generate LLM-suggested fix")
    print("=" * 60)
    from utils.llm_analyzer import LLMReachabilityAnalyzer
    llm = LLMReachabilityAnalyzer()
    if llm._enabled:
        print(f"  Provider : {llm._provider}  Model : {llm._model}")
        suggested_fix = await llm.suggest_fix(FINDING, HITS)
        if suggested_fix:
            print("  ✓ Fix suggestion received:")
            print()
            for line in suggested_fix.splitlines()[:20]:
                print("    " + line)
            if len(suggested_fix.splitlines()) > 20:
                print("    ... (truncated)")
        else:
            print("  ✗ No fix suggestion returned")
            suggested_fix = ""
    else:
        print("  ⚠ LLM disabled — skipping fix suggestion")
        suggested_fix = ""

    # ── Step 3: Create ticket ─────────────────────────────────────────────
    print()
    print("=" * 60)
    print("  Step 3: Create Jira ticket (AFFECTED_REACHABLE finding)")
    print("=" * 60)
    print(f"  CVE      : {FINDING.cve_id}")
    print(f"  Package  : {FINDING.package_name}@{FINDING.package_version}")
    print(f"  Severity : {FINDING.severity.value}")
    print(f"  Hits     : {len(HITS)} call sites")
    print()

    issue_key = await client.create_ticket(
        finding=FINDING,
        decision=AnalysisDecision.AFFECTED_REACHABLE,
        hits=HITS,
        epss_score=0.72,
        suggested_fix=suggested_fix,
    )

    if issue_key:
        ticket_url = f"{s.jira_base_url.rstrip('/')}/browse/{issue_key}"
        print(f"  ✓ Ticket created: {issue_key}")
        print(f"  ✓ URL: {ticket_url}")
        print()

        # ── Step 4: Add a follow-up comment ──────────────────────────────
        print("=" * 60)
        print("  Step 4: Add reachability comment to same ticket")
        print("=" * 60)
        updated_key = await client.update_ticket_with_reachability(
            finding=FINDING,
            decision=AnalysisDecision.AFFECTED_REACHABLE,
            hits=HITS,
            epss_score=0.72,
            suggested_fix=suggested_fix,
        )
        if updated_key:
            print(f"  ✓ Comment added to: {updated_key}")
        else:
            print("  ✗ Comment update failed")

        print()
        print("=" * 60)
        print("  RESULT: PASS — Jira integration is working correctly")
        print("=" * 60)
    else:
        print("  ✗ Ticket creation failed — check logs above")
        print()
        print("=" * 60)
        print("  RESULT: FAIL")
        print("=" * 60)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
