"""
Comprehensive test: all 4 VEX Agent decision paths

Scenario 1 — NOT_AFFECTED_DEV_ONLY
  L1 MetadataAnalyzer flags lodash as devDependency
  → human review gate intercepts (ENABLE_HUMAN_REVIEW=true)
  → Teams pending-review card posted
  → GitHub dismiss only after reviewer approves

Scenario 2 — NOT_AFFECTED_DEAD_CODE
  L2 ReachabilityAnalyzer finds vulnerable function is never called
  → human review gate intercepts
  → GitHub dismiss only after reviewer approves

Scenario 3 — AFFECTED_REACHABLE
  L2/LLM finds production code calls the vulnerable function
  EPSS score ≤ threshold  → no build break
  → GitHub label added
  → Jira ticket created
  → Teams finding card posted

Scenario 4 — BREAK_THE_BUILD
  L2/LLM finds production code calls the vulnerable function
  EPSS score > threshold  → build break
  → GitHub label added
  → GitHub failing Check Run created
  → Jira ticket created  (Critical)
  → Teams 🚨 card posted

Run:
    python test_all_decisions.py
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
    ReachabilityHit,
    Severity,
    VexStatus,
)
from utils.review_queue import ReviewQueue

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def cyan(s):   return f"\033[96m{s}\033[0m"
def green(s):  return f"\033[92m{s}\033[0m"
def red(s):    return f"\033[91m{s}\033[0m"
def yellow(s): return f"\033[93m{s}\033[0m"
def bold(s):   return f"\033[1m{s}\033[0m"

def section(title):
    print(f"\n{bold(cyan('=' * 64))}")
    print(bold(cyan(f"  {title}")))
    print(bold(cyan('=' * 64)))

def step(n, label):
    print(f"\n  {cyan(f'[{n}]')} {label}")

def ok(msg):   print(green(f"    ✓ {msg}"))
def warn(msg): print(yellow(f"    ⚠ {msg}"))
def fail(msg): print(red(f"    ✗ {msg}")); raise AssertionError(msg)

# ---------------------------------------------------------------------------
# Shared finding template
# ---------------------------------------------------------------------------

def make_finding(alert_id: int = 100, severity: Severity = Severity.HIGH) -> NormalisedFinding:
    return NormalisedFinding(
        alert_id=alert_id,
        repo_full_name="solarwinds-internal/arm-arm",
        repo_clone_url="https://github.com/solarwinds-internal/arm-arm.git",
        repo_default_branch="master",
        package_name="lodash",
        package_version="4.17.20",
        package_ecosystem="npm",
        vulnerable_version_range="< 4.17.21",
        patched_version="4.17.21",
        severity=severity,
        cvss_score=7.5,
        cve_id="CVE-2021-23337",
        summary="Lodash command injection via template function",
        vulnerable_functions=["template"],
    )

EPSS_LOW  = EpssScore(cve="CVE-2021-23337", epss=0.0051, percentile=0.72, date="2026-03-19")
EPSS_HIGH = EpssScore(cve="CVE-2021-23337", epss=0.3500, percentile=0.98, date="2026-03-19")

METADATA_DEV = MetadataAnalysisResult(
    is_dev_dependency=True, is_test_dependency=False,
    dependency_scope="devDependencies", manifest_path="package.json",
    justification="Found in devDependencies",
)
METADATA_RUNTIME = MetadataAnalysisResult(
    is_dev_dependency=False, is_test_dependency=False,
    dependency_scope="dependencies", manifest_path="package.json",
    justification="Found in dependencies",
)

HITS = [ReachabilityHit(
    file_path="ARM/Utils/StringHelper.js",
    line_number=42,
    line_content="const compiled = _.template(userInput);",
    function_called="_.template",
    confidence=0.95,
)]

REACHABILITY_NONE = ReachabilityAnalysisResult(
    reachable=False, hits=[], method="ast", confidence=1.0,
    notes="No calls to vulnerable functions found"
)
REACHABILITY_HIT = ReachabilityAnalysisResult(
    reachable=True, hits=HITS, method="ast", confidence=0.95,
    notes="Direct call to _.template() found"
)

# ---------------------------------------------------------------------------
# Shared agent factory
# ---------------------------------------------------------------------------

def make_agent(tmp_queue: ReviewQueue):
    from agents.vex_agent import VexAgent
    agent = VexAgent.__new__(VexAgent)

    agent.github = MagicMock()
    agent.github.dismiss_dependabot_alert = AsyncMock(return_value={"state": "dismissed"})
    agent.github.add_security_label       = AsyncMock(return_value=None)
    agent.github.get_latest_commit_sha    = AsyncMock(return_value="abc123def456")
    agent.github.create_check_run         = AsyncMock(return_value={"id": 9999})

    agent.epss = MagicMock()
    # Default: low risk (overridden per scenario)
    agent.epss.is_high_risk = MagicMock(return_value=False)

    agent.jira = MagicMock()
    agent.jira.update_ticket_with_reachability = AsyncMock(return_value="ARM-5001")
    agent.jira.attach_file                     = AsyncMock(return_value=None)

    agent.teams = MagicMock()
    agent.teams.notify_finding        = AsyncMock(return_value=True)
    agent.teams.notify_pending_review = AsyncMock(return_value=True)
    agent.teams.notify_review_resolved = AsyncMock(return_value=True)

    agent.llm = MagicMock()
    agent.llm.suggest_fix = AsyncMock(return_value="Upgrade lodash to >= 4.17.21")

    return agent


def mock_settings(enable_review=True, enable_btb=True, epss_threshold=0.1):
    """Return a settings mock usable as a context manager patch."""
    s = MagicMock()
    s.enable_human_review          = enable_review
    s.review_on_critical           = True
    s.review_confidence_threshold  = 0.75
    s.review_timeout_hours         = 24
    s.review_base_url              = "http://localhost:49152"
    s.jira_base_url                = "https://swicloud.atlassian.net"
    s.enable_break_the_build       = enable_btb
    s.epss_threshold               = epss_threshold
    s.skip_dev_dependencies        = True
    return s


COMMON_PATCHES = dict(
    vex_agent_settings="agents.vex_agent.settings",
    build_vex_comment="agents.vex_agent.GitHubSecurityClient.build_vex_comment",
    export_vex_json="agents.vex_agent.export_vex_json",
    review_queue="agents.vex_agent.get_review_queue",
)

# ---------------------------------------------------------------------------
# Scenario 1 — NOT_AFFECTED_DEV_ONLY
# ---------------------------------------------------------------------------

async def test_not_affected_dev_only(tmp_queue: ReviewQueue) -> None:
    section("Scenario 1 — NOT_AFFECTED_DEV_ONLY  (dev dependency, L1 short-circuit)")

    finding = make_finding(alert_id=101)
    agent   = make_agent(tmp_queue)
    s       = mock_settings(enable_review=True)

    # 1a: _decide
    step(1, "_decide() — dev dependency → NOT_AFFECTED_DEV_ONLY")
    with patch("agents.vex_agent.settings", s):
        decision = agent._decide(finding, METADATA_DEV, None, EPSS_LOW)
    assert decision == AnalysisDecision.NOT_AFFECTED_DEV_ONLY
    ok(f"Decision = {decision.value}")

    # 1b: _needs_review
    step(2, "_needs_review() — should require review before dismissing")
    with patch("agents.vex_agent.settings", s):
        needed, reason = agent._needs_review(decision, None, finding)
    assert needed is True
    ok(f"Review required: {reason}")

    # 1c: _act — must NOT dismiss, must queue for review
    step(3, "_act() — review gate intercepts, GitHub NOT dismissed")
    with patch("agents.vex_agent.settings", s), \
         patch("agents.vex_agent.get_review_queue", return_value=tmp_queue), \
         patch("agents.vex_agent.GitHubSecurityClient.build_vex_comment", return_value="vex-stub"), \
         patch("agents.vex_agent.export_vex_json", return_value='{}'):
        vex = await agent._act(finding, decision, METADATA_DEV, None, EPSS_LOW, [], None)

    assert vex.decision == AnalysisDecision.UNDER_INVESTIGATION
    ok(f"Returned decision: {vex.decision.value}")
    agent.github.dismiss_dependabot_alert.assert_not_called()
    ok("dismiss_dependabot_alert NOT called")
    agent.teams.notify_pending_review.assert_called_once()
    ok("Teams pending-review card posted")

    # 1d: queue state
    step(4, "Review queue — 1 pending item for this alert")
    pending = tmp_queue.list_pending()
    item = next((i for i in pending if i.alert_id == finding.alert_id), None)
    assert item is not None
    assert item.agent_decision == AnalysisDecision.NOT_AFFECTED_DEV_ONLY.value
    ok(f"review_id={item.id}  decision={item.agent_decision}")

    # 1e: finalize with approve → dismiss now happens
    step(5, "finalize_review(approved) → dismiss_dependabot_alert called NOW")
    with patch("agents.vex_agent.settings", s), \
         patch("agents.vex_agent.get_review_queue", return_value=tmp_queue), \
         patch("agents.vex_agent.GitHubSecurityClient.build_vex_comment", return_value="vex-stub"), \
         patch("agents.vex_agent.export_vex_json", return_value='{}'):
        final = await agent.finalize_review(item.id, status="approved",
                                            reviewer_comment="Confirmed dev-only")

    agent.github.dismiss_dependabot_alert.assert_called_once()
    call = agent.github.dismiss_dependabot_alert.call_args
    assert call.kwargs.get("dismissed_reason") == "not_used"
    ok(f"dismiss_dependabot_alert called  reason={call.kwargs['dismissed_reason']}")
    ok(f"dismissed_comment included: {bool(call.kwargs.get('dismissed_comment'))}")
    assert final.decision == AnalysisDecision.NOT_AFFECTED_DEV_ONLY
    ok(f"Final decision: {final.decision.value}")
    agent.teams.notify_review_resolved.assert_called_once()
    ok("Teams resolution card posted")
    ok("SCENARIO 1 PASSED ✓")


# ---------------------------------------------------------------------------
# Scenario 2 — NOT_AFFECTED_DEAD_CODE
# ---------------------------------------------------------------------------

async def test_not_affected_dead_code(tmp_queue: ReviewQueue) -> None:
    section("Scenario 2 — NOT_AFFECTED_DEAD_CODE  (L2 AST: function never called)")

    finding = make_finding(alert_id=102)
    agent   = make_agent(tmp_queue)
    s       = mock_settings(enable_review=True)

    step(1, "_decide() — not reachable → NOT_AFFECTED_DEAD_CODE")
    with patch("agents.vex_agent.settings", s):
        decision = agent._decide(finding, METADATA_RUNTIME, REACHABILITY_NONE, EPSS_LOW)
    assert decision == AnalysisDecision.NOT_AFFECTED_DEAD_CODE
    ok(f"Decision = {decision.value}")

    step(2, "_needs_review() — should require review before dismissing")
    with patch("agents.vex_agent.settings", s):
        needed, reason = agent._needs_review(decision, REACHABILITY_NONE, finding)
    assert needed is True
    ok(f"Review required: {reason}")

    step(3, "_act() — review gate intercepts, GitHub NOT dismissed")
    with patch("agents.vex_agent.settings", s), \
         patch("agents.vex_agent.get_review_queue", return_value=tmp_queue), \
         patch("agents.vex_agent.GitHubSecurityClient.build_vex_comment", return_value="vex-stub"), \
         patch("agents.vex_agent.export_vex_json", return_value='{}'):
        vex = await agent._act(finding, decision, METADATA_RUNTIME, REACHABILITY_NONE,
                               EPSS_LOW, [], None)

    assert vex.decision == AnalysisDecision.UNDER_INVESTIGATION
    ok(f"Returned decision: {vex.decision.value}")
    agent.github.dismiss_dependabot_alert.assert_not_called()
    ok("dismiss_dependabot_alert NOT called")
    agent.teams.notify_pending_review.assert_called_once()
    ok("Teams pending-review card posted")

    step(4, "finalize_review(approved) → dismiss with 'not_used'")
    pending = tmp_queue.list_pending()
    item = next(i for i in pending if i.alert_id == finding.alert_id)
    with patch("agents.vex_agent.settings", s), \
         patch("agents.vex_agent.get_review_queue", return_value=tmp_queue), \
         patch("agents.vex_agent.GitHubSecurityClient.build_vex_comment", return_value="vex-stub"), \
         patch("agents.vex_agent.export_vex_json", return_value='{}'):
        final = await agent.finalize_review(item.id, status="approved",
                                            reviewer_comment="Dead code confirmed")

    agent.github.dismiss_alert.assert_called_once()
    call = agent.github.dismiss_alert.call_args
    ok("dismiss_alert called after review approval")
    assert final.decision == AnalysisDecision.NOT_AFFECTED_DEAD_CODE
    ok(f"Final decision: {final.decision.value}")

    step(5, "finalize_review(rejected) — alert NOT dismissed on GitHub")
    # Add a second alert for the reject test
    finding2 = make_finding(alert_id=1020)
    agent2   = make_agent(tmp_queue)
    agent2.epss.is_high_risk = MagicMock(return_value=False)
    with patch("agents.vex_agent.settings", s), \
         patch("agents.vex_agent.get_review_queue", return_value=tmp_queue), \
         patch("agents.vex_agent.GitHubSecurityClient.build_vex_comment", return_value="vex-stub"), \
         patch("agents.vex_agent.export_vex_json", return_value='{}'):
        vex2 = await agent2._act(finding2, AnalysisDecision.NOT_AFFECTED_DEAD_CODE,
                                 METADATA_RUNTIME, REACHABILITY_NONE, EPSS_LOW, [], None)
    pending2 = tmp_queue.list_pending()
    item2 = next(i for i in pending2 if i.alert_id == finding2.alert_id)
    with patch("agents.vex_agent.settings", s), \
         patch("agents.vex_agent.get_review_queue", return_value=tmp_queue), \
         patch("agents.vex_agent.GitHubSecurityClient.build_vex_comment", return_value="vex-stub"), \
         patch("agents.vex_agent.export_vex_json", return_value='{}'):
        final2 = await agent2.finalize_review(item2.id, status="dismissed",
                                              reviewer_comment="Needs more investigation")
    agent2.github.dismiss_dependabot_alert.assert_not_called()
    ok("Rejected review → dismiss_dependabot_alert NOT called")
    assert final2.decision == AnalysisDecision.UNDER_INVESTIGATION
    ok(f"Final decision on rejection: {final2.decision.value} (alert left open)")
    ok("SCENARIO 2 PASSED ✓")


# ---------------------------------------------------------------------------
# Scenario 3 — AFFECTED_REACHABLE
# ---------------------------------------------------------------------------

async def test_affected_reachable(tmp_queue: ReviewQueue) -> None:
    section("Scenario 3 — AFFECTED_REACHABLE  (L2 AST hit, low EPSS)")

    finding = make_finding(alert_id=103)
    agent   = make_agent(tmp_queue)
    s       = mock_settings(enable_review=True, enable_btb=True)
    agent.epss.is_high_risk = MagicMock(return_value=False)   # low EPSS

    step(1, "_decide() — reachable + low EPSS → AFFECTED_REACHABLE")
    with patch("agents.vex_agent.settings", s):
        decision = agent._decide(finding, METADATA_RUNTIME, REACHABILITY_HIT, EPSS_LOW)
    assert decision == AnalysisDecision.AFFECTED_REACHABLE
    ok(f"Decision = {decision.value}")

    step(2, "_needs_review() — AFFECTED_REACHABLE does NOT go to review gate")
    with patch("agents.vex_agent.settings", s):
        needed, _ = agent._needs_review(decision, REACHABILITY_HIT, finding)
    assert needed is False
    ok("Review not required for reachable findings — proceeds directly")

    step(3, "_act() — GitHub label + Jira + Teams (no build break)")
    with patch("agents.vex_agent.settings", s), \
         patch("agents.vex_agent.get_review_queue", return_value=tmp_queue), \
         patch("agents.vex_agent.GitHubSecurityClient.build_vex_comment", return_value="vex-stub"), \
         patch("agents.vex_agent.export_vex_json", return_value='{}'), \
         patch("agents.vex_agent.save_vex_and_sbom") as mock_save_vex:
        vex = await agent._act(finding, decision, METADATA_RUNTIME, REACHABILITY_HIT,
                               EPSS_LOW, [], None)

    assert vex.decision == AnalysisDecision.AFFECTED_REACHABLE
    ok(f"Returned decision: {vex.decision.value}")

    agent.github.dismiss_dependabot_alert.assert_not_called()
    ok("dismiss_dependabot_alert NOT called (alert stays open)")

    agent.github.add_security_label.assert_called_once()
    label_args = agent.github.add_security_label.call_args
    ok(f"add_security_label called: {label_args.kwargs.get('labels', label_args.args)}")

    agent.jira.update_ticket_with_reachability.assert_called_once()
    ok(f"Jira ticket created: ARM-5001")

    mock_save_vex.assert_called_once()
    ok(f"VEX/SBOM files saved to repo (save_vex_and_sbom called once)")

    agent.teams.notify_finding.assert_called_once()
    ok("Teams finding card posted")

    agent.github.create_check_run.assert_not_called()
    ok("create_check_run NOT called (no build break for low EPSS)")

    assert vex.vex_status == VexStatus.AFFECTED
    ok(f"VEX status: {vex.vex_status.value}")
    ok("SCENARIO 3 PASSED ✓")


# ---------------------------------------------------------------------------
# Scenario 4 — BREAK_THE_BUILD
# ---------------------------------------------------------------------------

async def test_break_the_build(tmp_queue: ReviewQueue) -> None:
    section("Scenario 4 — BREAK_THE_BUILD  (L2 AST hit, high EPSS > threshold)")

    finding = make_finding(alert_id=104, severity=Severity.CRITICAL)
    agent   = make_agent(tmp_queue)
    s       = mock_settings(enable_review=True, enable_btb=True, epss_threshold=0.1)
    agent.epss.is_high_risk = MagicMock(return_value=True)    # HIGH EPSS

    step(1, "_decide() — reachable + high EPSS → BREAK_THE_BUILD")
    with patch("agents.vex_agent.settings", s):
        decision = agent._decide(finding, METADATA_RUNTIME, REACHABILITY_HIT, EPSS_HIGH)
    assert decision == AnalysisDecision.BREAK_THE_BUILD
    ok(f"Decision = {decision.value}  (EPSS={EPSS_HIGH.epss} > threshold={s.epss_threshold})")

    step(2, "_needs_review() — BREAK_THE_BUILD does NOT trigger review gate")
    with patch("agents.vex_agent.settings", s):
        needed, _ = agent._needs_review(decision, REACHABILITY_HIT, finding)
    assert needed is False
    ok("Review not required — break-the-build proceeds directly")

    step(3, "_act() — GitHub label + failing Check Run + Jira + Teams")
    with patch("agents.vex_agent.settings", s), \
         patch("agents.vex_agent.get_review_queue", return_value=tmp_queue), \
         patch("agents.vex_agent.GitHubSecurityClient.build_vex_comment", return_value="vex-stub"), \
         patch("agents.vex_agent.export_vex_json", return_value='{}'), \
         patch("agents.vex_agent.save_vex_and_sbom"):
        vex = await agent._act(finding, decision, METADATA_RUNTIME, REACHABILITY_HIT,
                               EPSS_HIGH, [], None)

    assert vex.decision == AnalysisDecision.BREAK_THE_BUILD
    ok(f"Returned decision: {vex.decision.value}")

    agent.github.dismiss_dependabot_alert.assert_not_called()
    ok("dismiss_dependabot_alert NOT called (alert stays open)")

    agent.github.add_security_label.assert_called_once()
    ok("add_security_label called")

    agent.github.get_latest_commit_sha.assert_called_once()
    ok(f"get_latest_commit_sha called → sha=abc123def456")

    agent.github.create_check_run.assert_called_once()
    check_kwargs = agent.github.create_check_run.call_args.kwargs
    assert check_kwargs.get("conclusion") == "failure"
    ok(f"create_check_run called — conclusion={check_kwargs['conclusion']}")
    ok(f"  title: {check_kwargs.get('title')}")
    assert len(check_kwargs.get("annotations", [])) == len(HITS)
    ok(f"  annotations: {len(check_kwargs['annotations'])} (one per hit)")

    agent.jira.update_ticket_with_reachability.assert_called_once()
    ok("Jira ticket created: ARM-5001")

    agent.teams.notify_finding.assert_called_once()
    ok("Teams 🚨 red card posted")

    assert vex.build_broken is True
    ok("VexDecision.build_broken = True")
    assert vex.vex_status == VexStatus.AFFECTED
    ok(f"VEX status: {vex.vex_status.value}  (exploitable)")
    ok("SCENARIO 4 PASSED ✓")


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------

def print_summary(results: dict[str, bool]) -> None:
    print(f"\n{bold(cyan('=' * 64))}")
    print(bold(cyan("  RESULTS SUMMARY")))
    print(bold(cyan('=' * 64)))
    print(f"  {'Scenario':<45} {'Result'}")
    print(f"  {'-'*45} ------")
    all_pass = True
    for name, passed in results.items():
        icon = green("PASS ✓") if passed else red("FAIL ✗")
        print(f"  {name:<45} {icon}")
        if not passed:
            all_pass = False
    print()
    if all_pass:
        print(bold(green("  ✔  All 4 scenarios passed")))
    else:
        print(bold(red("  ✘  Some scenarios failed")))
    print(bold(cyan('=' * 64)))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main() -> None:
    print(bold(cyan("\n" + "=" * 64)))
    print(bold(cyan("  VEX Agent — All 4 Decision Paths Test")))
    print(bold(cyan("=" * 64)))

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        tmp_db = Path(tf.name)
    queue = ReviewQueue(db_path=tmp_db)

    results: dict[str, bool] = {}
    scenarios = [
        ("1. NOT_AFFECTED_DEV_ONLY  (L1 dev dep + review gate)", test_not_affected_dev_only),
        ("2. NOT_AFFECTED_DEAD_CODE (L2 unreachable + review gate)", test_not_affected_dead_code),
        ("3. AFFECTED_REACHABLE     (L2 hit, low EPSS)", test_affected_reachable),
        ("4. BREAK_THE_BUILD        (L2 hit, high EPSS)", test_break_the_build),
    ]

    for name, fn in scenarios:
        try:
            await fn(queue)
            results[name] = True
        except AssertionError as exc:
            print(red(f"\n  ✗ FAILED: {exc}"))
            import traceback; traceback.print_exc()
            results[name] = False
        except Exception as exc:
            print(red(f"\n  ✗ ERROR: {exc}"))
            import traceback; traceback.print_exc()
            results[name] = False

    # cleanup
    try:
        for ext in ("", "-shm", "-wal"):
            Path(str(tmp_db) + ext).unlink(missing_ok=True)
    except OSError:
        pass

    print_summary(results)
    if not all(results.values()):
        sys.exit(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(yellow("\nInterrupted"))
        sys.exit(0)
