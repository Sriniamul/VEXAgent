"""
Live human-in-the-loop test: L1 Metadata NOT_AFFECTED_DEV_ONLY → Teams review card

Steps
-----
1. Seed a real review item into the live review queue (review_queue.db)
2. Post the Teams pending-review card with live Action.Http buttons pointing
   to the running server (http://localhost:49152)
3. Poll GET /review/pending every 10 seconds
4. When you click ✅ Approve or ❌ Dismiss in Teams, the server resolves it
5. This script detects the resolution and prints the final outcome

Requirements
------------
- Server must be running: python -m uvicorn main:app --host 0.0.0.0 --port 49152
- TEAMS_WEBHOOK_URL must be set in .env
- REVIEW_BASE_URL must be set to http://localhost:49152 (or your ngrok URL)

Run:
    python test_l1_human_review_live.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import httpx
from config import get_settings
from clients.teams_client import TeamsClient
from models.vex_models import (
    AnalysisDecision,
    EpssScore,
    MetadataAnalysisResult,
    NormalisedFinding,
    Severity,
)
from utils.review_queue import ReviewQueue

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

def cyan(s):   return f"\033[96m{s}\033[0m"
def green(s):  return f"\033[92m{s}\033[0m"
def red(s):    return f"\033[91m{s}\033[0m"
def yellow(s): return f"\033[93m{s}\033[0m"
def bold(s):   return f"\033[1m{s}\033[0m"

# ---------------------------------------------------------------------------
# Synthetic L1 finding (dev-only npm package)
# ---------------------------------------------------------------------------

FINDING = NormalisedFinding(
    alert_id=777,
    repo_full_name="solarwinds-internal/arm-arm",
    repo_clone_url="https://github.com/solarwinds-internal/arm-arm.git",
    repo_default_branch="master",
    package_name="lodash",
    package_version="4.17.20",
    package_ecosystem="npm",
    vulnerable_version_range="< 4.17.21",
    patched_version="4.17.21",
    severity=Severity.HIGH,
    cvss_score=7.5,
    cve_id="CVE-2021-23337",
    summary="Lodash command injection via template function — dev dependency",
)

METADATA_DEV = MetadataAnalysisResult(
    is_dev_dependency=True,
    is_test_dependency=False,
    dependency_scope="devDependencies",
    manifest_path="package.json",
    justification="Found in devDependencies of package.json — not shipped to production",
)

EPSS = EpssScore(cve="CVE-2021-23337", epss=0.0051, percentile=0.72, date="2026-03-19")

DECISION = AnalysisDecision.NOT_AFFECTED_DEV_ONLY
TRIGGER_REASON = (
    "Agent decided to dismiss alert as dev-only dependency — awaiting human confirmation"
)

BASE_URL = "http://localhost:49152"
POLL_INTERVAL_SECS = 10
POLL_TIMEOUT_SECS  = 300   # 5 minutes


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main() -> None:
    settings = get_settings()

    print(cyan("=" * 64))
    print(bold(cyan("  VEX Agent — L1 NOT_AFFECTED_DEV_ONLY  (LIVE human review)")))
    print(cyan("=" * 64))

    # ── Pre-flight checks ─────────────────────────────────────────────
    if not settings.teams_webhook_url:
        print(red("  ✗ TEAMS_WEBHOOK_URL not set — cannot post review card"))
        sys.exit(1)

    review_base = settings.review_base_url or BASE_URL

    async with httpx.AsyncClient(timeout=5) as client:
        try:
            r = await client.get(f"{BASE_URL}/health")
            r.raise_for_status()
        except Exception:
            print(red(f"  ✗ Server not reachable at {BASE_URL}"))
            print(red("    Start it with:  python -m uvicorn main:app --host 0.0.0.0 --port 49152"))
            sys.exit(1)

    print(green(f"  ✓ Server live at {BASE_URL}"))
    print(green(f"  ✓ Teams webhook configured"))
    print(yellow(f"  ⓘ Review buttons will POST to: {review_base}"))
    print()

    # ── Dedup: skip if this alert is already pending ──────────────────
    queue = ReviewQueue()   # uses the live review_queue.db
    existing = queue.pending_for_alert(FINDING.repo_full_name, FINDING.alert_id)
    if existing:
        review_id = existing.id
        print(yellow(f"  ⓘ Alert already in queue — reusing review_id={review_id}"))
    else:
        # ── Step 1: Enqueue the finding ───────────────────────────────
        print(cyan("[Step 1]") + " Enqueueing L1 dev-only finding in review queue")
        review_id = queue.enqueue(
            repo_full_name=FINDING.repo_full_name,
            alert_id=FINDING.alert_id,
            cve_id=FINDING.cve_id,
            package_name=FINDING.package_name,
            agent_decision=DECISION.value,
            confidence=0.0,
            trigger_reason=TRIGGER_REASON,
            finding_json=FINDING.model_dump_json(),
            epss_json=EPSS.model_dump_json(),
            reachability_json=None,
            hits_json="[]",
            suggested_fix="",
            sbom_json=None,
            metadata_json=METADATA_DEV.model_dump_json(),
            timeout_hours=settings.review_timeout_hours or 24,
        )
        print(green(f"  ✓ Enqueued: review_id={review_id}"))

        # ── Step 2: Post Teams pending-review card ────────────────────
        print()
        print(cyan("[Step 2]") + " Posting Teams pending-review card with Action.Http buttons")
        tc = TeamsClient()
        ok = await tc.notify_pending_review(
            finding=FINDING,
            decision=DECISION,
            epss_score=EPSS.epss,
            confidence=0.0,
            trigger_reason=TRIGGER_REASON,
            review_id=review_id,
            hits=[],
            base_url=review_base,
        )
        if ok:
            print(green("  ✓ Teams card posted — check your Teams channel"))
        else:
            print(red("  ✗ Teams card failed to post (check TEAMS_WEBHOOK_URL)"))

    # ── Step 3: Poll until human acts ────────────────────────────────
    print()
    print(cyan("[Step 3]") + " Waiting for human review action in Teams…")
    print(yellow(f"  → Click  ✅ Approve  or  ❌ Dismiss  on the card in Teams"))
    print(yellow(f"  → Polling every {POLL_INTERVAL_SECS}s (timeout {POLL_TIMEOUT_SECS}s)"))
    print()

    elapsed = 0
    outcome: dict | None = None

    async with httpx.AsyncClient(timeout=10, base_url=BASE_URL) as client:
        while elapsed < POLL_TIMEOUT_SECS:
            try:
                r = await client.get("/review/pending")
                data = r.json()
                still_pending = any(
                    item["id"] == review_id for item in data.get("pending", [])
                )
                if not still_pending:
                    # Resolved — fetch final state from the queue directly
                    item = queue.get(review_id)
                    if item:
                        outcome = item.to_dict()
                    break
            except Exception as exc:
                print(yellow(f"  ⚠ Poll error: {exc}"))

            dots = "." * ((elapsed // POLL_INTERVAL_SECS % 3) + 1)
            print(f"\r  ⏳ Waiting{dots:<3}  ({elapsed}s elapsed) ", end="", flush=True)
            await asyncio.sleep(POLL_INTERVAL_SECS)
            elapsed += POLL_INTERVAL_SECS

    print()  # newline after the \r line

    # ── Step 4: Report outcome ────────────────────────────────────────
    if outcome is None:
        print(red(f"\n  ✗ Timed out after {POLL_TIMEOUT_SECS}s — no action taken"))
        print(red(f"    Review ID: {review_id} is still pending"))
        sys.exit(1)

    print(cyan("[Step 4]") + " Review resolved!")
    print()
    status_colour = {
        "approved": green,
        "overridden": yellow,
        "dismissed": red,
    }.get(outcome.get("status", ""), cyan)

    print(f"  Status   : {status_colour(outcome.get('status', 'unknown').upper())}")
    print(f"  Decision : {outcome.get('final_decision', 'N/A')}")
    print(f"  Comment  : {outcome.get('reviewer_comment') or '(none)'}")
    print(f"  Jira key : {outcome.get('jira_key') or '(none)'}")
    print(f"  Resolved : {outcome.get('resolved_at', 'N/A')}")
    print()
    print(green("=" * 64))
    print(bold(green("  ✔  Live human review test completed successfully")))
    print(green("=" * 64))


# ---------------------------------------------------------------------------
# pytest entry-point (skipped without Teams + running server)
# ---------------------------------------------------------------------------

async def test_l1_human_review_live() -> None:
    """Live human-review test.  Skipped unless TEAMS_WEBHOOK_URL is set."""
    import pytest
    s = get_settings()
    if not s.teams_webhook_url:
        pytest.skip("TEAMS_WEBHOOK_URL not configured — skipping live human-review test")

    # This is a live/integration scenario; skip instead of failing when the
    # local server is not running in the current test environment.
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            r = await client.get(f"{BASE_URL}/health")
            r.raise_for_status()
    except Exception:
        pytest.skip(f"Server not reachable at {BASE_URL} — skipping live human-review test")

    await main()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(yellow("\n\n  Interrupted — review_id still in queue, server still running"))
        sys.exit(0)
    except Exception as exc:
        print(red(f"\n  ✗ {exc}"))
        import traceback; traceback.print_exc()
        sys.exit(1)
