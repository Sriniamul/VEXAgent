"""
Smoke test for the Teams notification client.

Sends a sample Adaptive Card to the configured TEAMS_WEBHOOK_URL.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from config import get_settings
from clients.teams_client import TeamsClient
from models.vex_models import (
    AnalysisDecision,
    NormalisedFinding,
    ReachabilityHit,
)


async def main():
    s = get_settings()

    print()
    print("=" * 60)
    print("  Teams Notification — Smoke Test")
    print("=" * 60)
    print(f"  webhook configured : {bool(s.teams_webhook_url)}")
    if not s.teams_webhook_url:
        print("  ✗ TEAMS_WEBHOOK_URL not set in .env — aborting")
        sys.exit(1)
    print()

    # ── Build a realistic sample finding ──────────────────────────────
    finding = NormalisedFinding(
        repo_full_name="solarwinds-internal/arm-arm",
        repo_clone_url="https://github.com/solarwinds-internal/arm-arm.git",
        repo_default_branch="master",
        alert_id=42,
        package_name="requests",
        package_ecosystem="pip",
        package_version="2.27.1",
        vulnerable_version_range="< 2.31.0",
        patched_version="2.31.0",
        severity="high",
        cve_id="CVE-2023-32681",
        cvss_score=6.1,
        summary="requests forwards proxy-authorization header to destination servers",
    )

    hits = [
        ReachabilityHit(
            file_path="ARM/Services/HttpService.py",
            line_number=87,
            line_content="response = requests.get(url, proxies=proxies)",
            function_called="requests.get",
            confidence=0.95,
        )
    ]

    suggested_fix = (
        "## Root Cause\n"
        "requests < 2.31.0 leaks the Proxy-Authorization header to the destination server.\n\n"
        "## Fix\n"
        "Upgrade: `pip install 'requests>=2.31.0'`\n\n"
        "## Verification\n"
        "`pip show requests | grep Version`"
    )

    decision = AnalysisDecision.AFFECTED_REACHABLE
    epss_score = 0.0312
    jira_key = "ARM-6204"

    print("=" * 60)
    print("  Step 1: Sending Teams notification card")
    print("=" * 60)
    print(f"  finding  : {finding.cve_id} in {finding.package_name}")
    print(f"  decision : {decision.value}")
    print(f"  EPSS     : {epss_score}")
    print(f"  jira_key : {jira_key}")
    print(f"  hits     : {len(hits)}")
    print()

    tc = TeamsClient()
    ok = await tc.notify_finding(
        finding=finding,
        decision=decision,
        epss_score=epss_score,
        jira_key=jira_key,
        hits=hits,
        suggested_fix=suggested_fix,
    )

    print()
    print("=" * 60)
    if ok:
        print("  RESULT: PASS — Teams card sent successfully")
    else:
        print("  RESULT: FAIL — Card not sent (check logs above)")
        sys.exit(1)
    print("=" * 60)

    # ── Step 2: Pending-review card ────────────────────────────────────
    print()
    print("=" * 60)
    print("  Step 2: Sending pending-review card (notify_pending_review)")
    print("=" * 60)
    review_id = "test-review-abc123"
    ok2 = await tc.notify_pending_review(
        finding=finding,
        decision=decision,
        epss_score=epss_score,
        confidence=0.58,
        trigger_reason="LLM confidence 58% is below threshold 75%",
        review_id=review_id,
        hits=hits,
        base_url="http://localhost:49152",
    )
    print()
    if ok2:
        print("  RESULT: PASS — Pending-review card sent successfully")
    else:
        print("  RESULT: FAIL — Pending-review card not sent")
        sys.exit(1)
    print("=" * 60)

    # ── Step 3: Review-resolved card ───────────────────────────────────
    print()
    print("=" * 60)
    print("  Step 3: Sending resolution card (notify_review_resolved)")
    print("=" * 60)
    ok3 = await tc.notify_review_resolved(
        review_id=review_id,
        final_decision=decision.value,
        status="approved",
        reviewer_comment="Confirmed reachable — Jira ticket raised.",
        finding=finding,
        jira_key=jira_key,
    )
    print()
    if ok3:
        print("  RESULT: PASS — Resolution card sent successfully")
    else:
        print("  RESULT: FAIL — Resolution card not sent")
        sys.exit(1)
    print("=" * 60)

    print()
    print("  ALL 3 STEPS PASSED")
    print("=" * 60)


# ---------------------------------------------------------------------------
# pytest entry-point (skipped without TEAMS_WEBHOOK_URL configured)
# ---------------------------------------------------------------------------

async def test_teams_notifications() -> None:
    """Smoke test: send Teams Adaptive Cards.  Skipped if TEAMS_WEBHOOK_URL not set."""
    import pytest
    s = get_settings()
    if not s.teams_webhook_url:
        pytest.skip("TEAMS_WEBHOOK_URL not configured — skipping Teams notification smoke test")
    await main()


if __name__ == "__main__":
    asyncio.run(main())
