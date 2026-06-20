"""
Integration test: L1 Metadata → NOT_AFFECTED_DEV_ONLY → Human Review Gate

Scenario
--------
A Dependabot alert fires for a package that the MetadataAnalyzer identifies as
a *dev-only* dependency (L1 check, short-circuit path).

Expected pipeline:
  _decide()  →  NOT_AFFECTED_DEV_ONLY
  _act()     →  _needs_review() == True  (ENABLE_HUMAN_REVIEW=true)
             →  finding queued, NOT dismissed yet
             →  Teams "pending review" card posted
             →  UNDER_INVESTIGATION returned

Then:
  finalize_review(status="approved")
             →  github.dismiss_dependabot_alert() called
             →  Teams "resolved" card posted
             →  queue item marked approved

Run:
    python test_l1_not_affected.py
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from models.vex_models import (
    AnalysisDecision,
    EpssScore,
    MetadataAnalysisResult,
    NormalisedFinding,
    ReachabilityAnalysisResult,
    Severity,
    VexStatus,
)
from utils.review_queue import ReviewQueue


# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

def cyan(s):   return f"\033[96m{s}\033[0m"
def green(s):  return f"\033[92m{s}\033[0m"
def red(s):    return f"\033[91m{s}\033[0m"
def yellow(s): return f"\033[93m{s}\033[0m"

def info(step, label):
    print(f"\n{cyan(f'[Step {step}]')} {label}")

def ok(msg):   print(green(f"  ✓ {msg}"))
def warn(msg): print(yellow(f"  ⚠ {msg}"))
def fail(msg): print(red(f"  ✗ {msg}"))


# ---------------------------------------------------------------------------
# Synthetic finding — dev-only npm package
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
    summary="Lodash command injection via template function",
)

METADATA_DEV = MetadataAnalysisResult(
    is_dev_dependency=True,
    is_test_dependency=False,
    dependency_scope="devDependencies",
    manifest_path="package.json",
    justification="Found in devDependencies of package.json",
)

EPSS = EpssScore(cve="CVE-2021-23337", epss=0.0051, percentile=0.72, date="2026-03-19")


# ---------------------------------------------------------------------------
# Helpers to build a VexAgent with mocked external clients
# ---------------------------------------------------------------------------

def _make_agent(tmp_queue: ReviewQueue):
    """Build a VexAgent whose external clients are all mocked."""
    from agents.vex_agent import VexAgent

    agent = VexAgent.__new__(VexAgent)

    # GitHub client — capture dismiss call
    agent.github = MagicMock()
    agent.github.dismiss_dependabot_alert = AsyncMock(return_value=None)
    agent.github.add_security_label = AsyncMock(return_value=None)
    agent.github.get_latest_commit_sha = AsyncMock(return_value=None)

    # EPSS client
    agent.epss = MagicMock()
    agent.epss.is_high_risk = MagicMock(return_value=False)

    # Jira client
    agent.jira = MagicMock()
    agent.jira.update_ticket_with_reachability = AsyncMock(return_value=None)
    agent.jira.attach_file = AsyncMock(return_value=None)

    # Teams client — capture both review card calls
    agent.teams = MagicMock()
    agent.teams.notify_finding = AsyncMock(return_value=True)
    agent.teams.notify_pending_review = AsyncMock(return_value=True)
    agent.teams.notify_review_resolved = AsyncMock(return_value=True)

    # LLM client
    agent.llm = MagicMock()
    agent.llm.suggest_fix = AsyncMock(return_value="Upgrade lodash to >= 4.17.21")

    # Inject the temp review queue so we can inspect it
    with patch("agents.vex_agent.get_review_queue", return_value=tmp_queue):
        pass  # patch only needed during _act / finalize_review calls

    return agent


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

async def run() -> None:
    print(cyan("=" * 64))
    print(cyan("  VEX Agent — L1 Metadata NOT_AFFECTED_DEV_ONLY test"))
    print(cyan("=" * 64))

    # Each _act / finalize call patches get_review_queue() to use our tmp DB
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        tmp_db = Path(tf.name)
    tmp_queue = ReviewQueue(db_path=tmp_db)

    from agents.vex_agent import VexAgent
    agent = _make_agent(tmp_queue)

    # ── Step 1: _decide() returns NOT_AFFECTED_DEV_ONLY ───────────────
    info(1, "_decide() → NOT_AFFECTED_DEV_ONLY (dev dependency, short-circuit)")
    decision = agent._decide(FINDING, METADATA_DEV, None, EPSS)
    assert decision == AnalysisDecision.NOT_AFFECTED_DEV_ONLY, f"Got: {decision}"
    ok(f"Decision = {decision.value}")

    # ── Step 2: _needs_review() confirms review is required ───────────
    info(2, "_needs_review() → (True, reason) because ENABLE_HUMAN_REVIEW=true")
    with patch("agents.vex_agent.settings") as mock_settings:
        mock_settings.enable_human_review = True
        mock_settings.review_confidence_threshold = 0.75
        needed, reason = agent._needs_review(decision, None, FINDING)
    assert needed is True, "Expected review to be required"
    ok(f"Review required: {reason}")

    # ── Step 3: _act() queues for review instead of dismissing ────────
    info(3, "_act() → review queued, NOT dismissed, returns UNDER_INVESTIGATION")
    with patch("agents.vex_agent.get_review_queue", return_value=tmp_queue), \
         patch("agents.vex_agent.settings") as mock_settings, \
         patch("agents.vex_agent.GitHubSecurityClient.build_vex_comment", return_value="VEX comment stub"):
        mock_settings.enable_human_review = True
        mock_settings.review_on_critical = True
        mock_settings.review_confidence_threshold = 0.75
        mock_settings.review_timeout_hours = 24
        mock_settings.review_base_url = "http://localhost:49152"
        mock_settings.jira_base_url = ""
        mock_settings.enable_break_the_build = False
        mock_settings.epss_threshold = 0.5

        vex = await agent._act(
            finding=FINDING,
            decision=decision,
            metadata=METADATA_DEV,
            reachability=None,
            epss_score=EPSS,
            errors=[],
            sbom_json=None,
        )

    # GitHub dismiss must NOT have been called
    agent.github.dismiss_dependabot_alert.assert_not_called()
    ok("GitHub dismiss_dependabot_alert was NOT called (held for review)")

    # Decision must be UNDER_INVESTIGATION
    assert vex.decision == AnalysisDecision.UNDER_INVESTIGATION, f"Got: {vex.decision}"
    ok(f"VexDecision returned: {vex.decision.value}")

    # Impact statement should reference the review
    assert "review" in vex.impact_statement.lower(), f"Impact: {vex.impact_statement}"
    ok(f"Impact statement: {vex.impact_statement}")

    # Teams pending-review card must have been posted
    agent.teams.notify_pending_review.assert_called_once()
    ok("Teams notify_pending_review() called once")

    # ── Step 4: Review queue contains the pending item ────────────────
    info(4, "Review queue — pending item check")
    pending = tmp_queue.list_pending()
    assert len(pending) == 1, f"Expected 1 pending, got {len(pending)}"
    review_item = pending[0]
    assert review_item.package_name == FINDING.package_name
    assert review_item.agent_decision == AnalysisDecision.NOT_AFFECTED_DEV_ONLY.value
    assert review_item.status == "pending"
    ok(f"1 pending review: id={review_item.id}")
    ok(f"  package={review_item.package_name}  decision={review_item.agent_decision}")
    ok(f"  reason={review_item.trigger_reason}")

    review_id = review_item.id

    # Dedup: re-queuing the same alert must return the existing review_id
    info(5, "Dedup check — queuing same alert again returns existing review_id")
    with patch("agents.vex_agent.get_review_queue", return_value=tmp_queue), \
         patch("agents.vex_agent.settings") as mock_settings, \
         patch("agents.vex_agent.GitHubSecurityClient.build_vex_comment", return_value="VEX comment stub"):
        mock_settings.enable_human_review = True
        mock_settings.review_on_critical = True
        mock_settings.review_confidence_threshold = 0.75
        mock_settings.review_timeout_hours = 24
        mock_settings.review_base_url = "http://localhost:49152"
        mock_settings.jira_base_url = ""
        mock_settings.enable_break_the_build = False
        mock_settings.epss_threshold = 0.5

        await agent._act(
            finding=FINDING,
            decision=decision,
            metadata=METADATA_DEV,
            reachability=None,
            epss_score=EPSS,
            errors=[],
            sbom_json=None,
        )

    pending2 = tmp_queue.list_pending()
    assert len(pending2) == 1, f"Dedup failed: {len(pending2)} items in queue"
    assert pending2[0].id == review_id
    ok(f"Dedup confirmed — still 1 item, same review_id={review_id}")

    # ── Step 5: Reviewer approves → GitHub dismiss is now called ──────
    info(6, "finalize_review(approved) → dismiss_dependabot_alert called")
    with patch("agents.vex_agent.get_review_queue", return_value=tmp_queue), \
         patch("agents.vex_agent.settings") as mock_settings, \
         patch("agents.vex_agent.export_vex_json", return_value='{"vex":"stub"}'), \
         patch("agents.vex_agent.GitHubSecurityClient.build_vex_comment", return_value="VEX comment stub"):
        mock_settings.enable_human_review = True
        mock_settings.review_on_critical = True
        mock_settings.review_confidence_threshold = 0.75
        mock_settings.review_timeout_hours = 24
        mock_settings.review_base_url = "http://localhost:49152"
        mock_settings.jira_base_url = ""
        mock_settings.enable_break_the_build = False
        mock_settings.epss_threshold = 0.5
        mock_settings.skip_dev_dependencies = True

        final_vex = await agent.finalize_review(
            review_id,
            status="approved",
            reviewer_comment="Dev-only confirmed — safe to dismiss.",
        )

    # GitHub dismiss MUST have been called now
    agent.github.dismiss_dependabot_alert.assert_called_once()
    call_args = agent.github.dismiss_dependabot_alert.call_args
    ok(f"GitHub dismiss_dependabot_alert called: reason={call_args.kwargs.get('dismissed_reason')}")

    # Final decision still NOT_AFFECTED_DEV_ONLY
    assert final_vex.decision == AnalysisDecision.NOT_AFFECTED_DEV_ONLY, \
        f"Final decision: {final_vex.decision}"
    ok(f"Final decision: {final_vex.decision.value}")

    # Teams resolution card posted
    agent.teams.notify_review_resolved.assert_called_once()
    ok("Teams notify_review_resolved() called once")

    # ── Step 6: Queue item is resolved ────────────────────────────────
    info(7, "Review queue — item resolved")
    resolved = tmp_queue.get(review_id)
    assert resolved is not None
    assert resolved.status == "approved", f"Status: {resolved.status}"
    ok(f"Review status: {resolved.status}")

    pending3 = tmp_queue.list_pending()
    assert len(pending3) == 0
    ok("No more pending reviews")

    # Cleanup temp DB
    try:
        for ext in ("", "-shm", "-wal"):
            Path(str(tmp_db) + ext).unlink(missing_ok=True)
    except OSError:
        pass

    print()
    print(green("=" * 64))
    print(green("  ALL STEPS PASSED"))
    print(green("=" * 64))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# pytest entry-point (no credentials needed — all external clients are mocked)
# ---------------------------------------------------------------------------

async def test_l1_not_affected_dev_only() -> None:
    """Pytest-compatible wrapper for the fully-mocked L1 pipeline scenario."""
    await run()


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except AssertionError as exc:
        fail(f"Assertion failed: {exc}")
        import traceback; traceback.print_exc()
        sys.exit(1)
    except Exception as exc:
        fail(f"Unexpected error: {exc}")
        import traceback; traceback.print_exc()
        sys.exit(1)
