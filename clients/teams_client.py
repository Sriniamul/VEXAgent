"""
Microsoft Teams notification client.

Sends Adaptive Card messages to a Teams channel via an Incoming Webhook URL.
Cards include vulnerability details, reachability decision, EPSS score,
Jira ticket link, and a brief suggested-fix summary.
"""

from __future__ import annotations

import logging
from typing import Optional

import httpx

from config import settings
from models.vex_models import AnalysisDecision, NormalisedFinding

logger = logging.getLogger(__name__)

# Colour sidebar per decision severity
_DECISION_COLOURS = {
    AnalysisDecision.BREAK_THE_BUILD:       "FF0000",  # red
    AnalysisDecision.AFFECTED_REACHABLE:    "FF8C00",  # orange
    AnalysisDecision.NOT_AFFECTED_DEV_ONLY: "00B050",  # green
    AnalysisDecision.NOT_AFFECTED_DEAD_CODE:"00B050",  # green
    AnalysisDecision.UNDER_INVESTIGATION:   "0078D7",  # blue
}

_DECISION_LABELS = {
    AnalysisDecision.BREAK_THE_BUILD:        "🚨 BREAK THE BUILD — Exploitable",
    AnalysisDecision.AFFECTED_REACHABLE:     "⚠️ Reachable — Affected",
    AnalysisDecision.NOT_AFFECTED_DEV_ONLY:  "✅ Not Affected (dev-only dependency)",
    AnalysisDecision.NOT_AFFECTED_DEAD_CODE: "✅ Not Affected (dead code — no reachable call)",
    AnalysisDecision.UNDER_INVESTIGATION:    "🔍 Under Investigation",
}


class TeamsClient:
    """
    Sends Adaptive Card notifications to a Microsoft Teams channel.
    Silently skips if ``TEAMS_WEBHOOK_URL`` is not configured.
    """

    def __init__(self, webhook_url: Optional[str] = None):
        self._url = webhook_url or settings.teams_webhook_url

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def notify_finding(
        self,
        finding: NormalisedFinding,
        decision: AnalysisDecision,
        epss_score: Optional[float],
        jira_key: Optional[str],
        hits: list,
        suggested_fix: str = "",
    ) -> bool:
        """
        Post a Teams notification card for a processed VEX finding.

        Returns True on success, False if skipped / failed.
        """
        if not self._url:
            logger.debug("TEAMS_WEBHOOK_URL not configured — skipping Teams notification.")
            return False

        card = self._build_card(finding, decision, epss_score, jira_key, hits, suggested_fix)
        return await self._post(card)

    # ------------------------------------------------------------------
    # Card builder
    # ------------------------------------------------------------------

    def _build_card(
        self,
        finding: NormalisedFinding,
        decision: AnalysisDecision,
        epss_score: Optional[float],
        jira_key: Optional[str],
        hits: list,
        suggested_fix: str,
    ) -> dict:
        colour = _DECISION_COLOURS.get(decision, "0078D7")
        decision_label = _DECISION_LABELS.get(decision, str(decision))

        cve_or_ghsa = finding.cve_id or finding.ghsa_id or "N/A"
        epss_text = f"{epss_score:.4f}" if epss_score is not None else "N/A"
        cvss_text = f"{finding.cvss_score:.1f}" if finding.cvss_score else "N/A"
        severity = (finding.severity or "unknown").capitalize()

        # Jira link action button (only when a ticket exists)
        actions = []
        if jira_key and settings.jira_base_url:
            jira_url = f"{settings.jira_base_url.rstrip('/')}/browse/{jira_key}"
            actions.append({
                "type": "Action.OpenUrl",
                "title": f"📋 View Jira {jira_key}",
                "url": jira_url,
            })

        # GitHub alert URL
        alert_url = (
            f"https://github.com/{finding.repo_full_name}/security/dependabot/{finding.alert_id}"
        )
        actions.append({
            "type": "Action.OpenUrl",
            "title": "🔗 View GitHub Alert",
            "url": alert_url,
        })

        # ── Facts (key-value rows) ─────────────────────────────────────
        facts = [
            {"title": "Repository",    "value": finding.repo_full_name},
            {"title": "Package",       "value": f"{finding.package_name} {finding.package_version or ''}".strip()},
            {"title": "Vuln Range",    "value": finding.vulnerable_version_range or "N/A"},
            {"title": "Vulnerability", "value": cve_or_ghsa},
            {"title": "Severity",      "value": severity},
            {"title": "CVSS Score",    "value": cvss_text},
            {"title": "EPSS Score",    "value": epss_text},
            {"title": "Decision",      "value": decision_label},
        ]
        if jira_key:
            facts.append({"title": "Jira Ticket", "value": jira_key})
        if hits:
            hit_lines = "\n".join(
                f"• {h.file_path}:{h.line_number} → `{h.function_called}()`"
                for h in hits[:5]
            )
            if len(hits) > 5:
                hit_lines += f"\n• … and {len(hits) - 5} more"
            facts.append({"title": "Reachable Hits", "value": hit_lines})

        # ── Body blocks ───────────────────────────────────────────────
        body: list[dict] = [
            {
                "type": "TextBlock",
                "text": f"VEX Agent — Security Alert Processed",
                "weight": "Bolder",
                "size": "Medium",
                "color": "Accent",
            },
            {
                "type": "TextBlock",
                "text": decision_label,
                "weight": "Bolder",
                "size": "Large",
                "wrap": True,
                "color": "Attention" if "🚨" in decision_label or "⚠️" in decision_label else "Good",
            },
            {
                "type": "FactSet",
                "facts": facts,
            },
        ]

        # Suggested fix — first 3 non-empty lines as a summary
        if suggested_fix:
            summary_lines = [ln.strip() for ln in suggested_fix.splitlines() if ln.strip()][:4]
            fix_summary = "  \n".join(summary_lines)
            body.append({
                "type": "TextBlock",
                "text": "**Suggested Fix (summary)**",
                "weight": "Bolder",
                "wrap": True,
                "spacing": "Medium",
            })
            body.append({
                "type": "TextBlock",
                "text": fix_summary,
                "wrap": True,
                "isSubtle": True,
            })

        # ── Assemble using shared helper ──────────────────────────────
        return self._wrap_adaptive_card(body, actions)

    # ------------------------------------------------------------------
    # Pending review card
    # ------------------------------------------------------------------

    async def notify_pending_review(
        self,
        finding: NormalisedFinding,
        decision: AnalysisDecision,
        epss_score: Optional[float],
        confidence: float,
        trigger_reason: str,
        review_id: str,
        hits: list,
        base_url: str = "",
    ) -> bool:
        """
        Post a 'Pending Human Review' card with Approve / Dismiss action buttons.
        """
        if not self._url:
            logger.debug("TEAMS_WEBHOOK_URL not configured — skipping review notification.")
            return False
        card = self._build_review_card(
            finding, decision, epss_score, confidence,
            trigger_reason, review_id, hits, base_url,
        )
        return await self._post(card)

    async def notify_review_resolved(
        self,
        review_id: str,
        final_decision: str,
        status: str,           # approved | overridden | dismissed
        reviewer_comment: str,
        finding: NormalisedFinding,
        jira_key: Optional[str],
    ) -> bool:
        """Post a resolution card after a human has acted on a pending review."""
        if not self._url:
            return False

        status_labels = {
            "approved":   "✅ Review APPROVED",
            "overridden": "⚠️ Review OVERRIDDEN",
            "dismissed":  "❌ Review DISMISSED",
        }
        status_colours = {
            "approved": "Good",
            "overridden": "Warning",
            "dismissed": "Attention",
        }
        label = status_labels.get(status, status.capitalize())
        colour = status_colours.get(status, "Default")
        cve = finding.cve_id or finding.ghsa_id or "N/A"

        facts = [
            {"title": "Repository",       "value": finding.repo_full_name},
            {"title": "Package",          "value": f"{finding.package_name} {finding.package_version}"},
            {"title": "Vulnerability",    "value": cve},
            {"title": "Final Decision",   "value": final_decision},
            {"title": "Outcome",          "value": label},
        ]
        if reviewer_comment:
            facts.append({"title": "Reviewer Comment", "value": reviewer_comment})
        if jira_key:
            facts.append({"title": "Jira Ticket", "value": jira_key})

        actions: list[dict] = []
        if jira_key and settings.jira_base_url:
            actions.append({
                "type": "Action.OpenUrl",
                "title": f"📋 View Jira {jira_key}",
                "url": f"{settings.jira_base_url.rstrip('/')}/browse/{jira_key}",
            })

        body = [
            {"type": "TextBlock", "text": "VEX Agent — Human Review Resolved",
             "weight": "Bolder", "size": "Medium", "color": "Accent"},
            {"type": "TextBlock", "text": label, "weight": "Bolder",
             "size": "Large", "wrap": True, "color": colour},
            {"type": "FactSet", "facts": facts},
        ]
        card = self._wrap_adaptive_card(body, actions)
        return await self._post(card)

    async def notify_action_resolved(
        self,
        *,
        repo: str,
        package_name: str,
        cve_id: str | None,
        alert_id: int,
        action: str,          # "approved" | "dismissed"
        final_decision: str,
        jira_key: str | None = None,
    ) -> bool:
        """Post a lightweight resolution card when a user approves/dismisses
        a pipeline run directly (no review-queue entry)."""
        if not self._url:
            return False

        status_labels = {
            "approved":  "\u2705 Approved \u2014 confirmed not affected. Dismissed GHAS alert",
            "dismissed": "\u274c Dismissed \u2014 moved to Under Investigation",
        }
        status_colours = {
            "approved":  "Good",
            "dismissed": "Attention",
        }
        label  = status_labels.get(action, action.capitalize())
        colour = status_colours.get(action, "Default")

        facts = [
            {"title": "Repository",    "value": repo},
            {"title": "Package",       "value": package_name},
            {"title": "Vulnerability", "value": cve_id or "N/A"},
            {"title": "Alert ID",      "value": str(alert_id)},
            {"title": "Final Decision","value": final_decision},
            {"title": "Outcome",       "value": label},
        ]
        if jira_key:
            facts.append({"title": "Jira Ticket", "value": jira_key})

        actions: list[dict] = []
        alert_url = f"https://github.com/{repo}/security/dependabot/{alert_id}"
        actions.append({"type": "Action.OpenUrl", "title": "\U0001f517 View GitHub Alert", "url": alert_url})
        if jira_key and settings.jira_base_url:
            actions.append({
                "type": "Action.OpenUrl",
                "title": f"\U0001f4cb View Jira {jira_key}",
                "url": f"{settings.jira_base_url.rstrip('/')}/browse/{jira_key}",
            })

        body = [
            {"type": "TextBlock", "text": "VEX Agent \u2014 Review Action",
             "weight": "Bolder", "size": "Medium", "color": "Accent"},
            {"type": "TextBlock", "text": label, "weight": "Bolder",
             "size": "Large", "wrap": True, "color": colour},
            {"type": "FactSet", "facts": facts},
        ]
        card = self._wrap_adaptive_card(body, actions)
        return await self._post(card)

    def _build_review_card(
        self,
        finding: NormalisedFinding,
        decision: AnalysisDecision,
        epss_score: Optional[float],
        confidence: float,
        trigger_reason: str,
        review_id: str,
        hits: list,
        base_url: str,
    ) -> dict:
        cve = finding.cve_id or finding.ghsa_id or "N/A"
        epss_text = f"{epss_score:.4f}" if epss_score is not None else "N/A"
        cvss_text = f"{finding.cvss_score:.1f}" if finding.cvss_score else "N/A"
        conf_text = f"{confidence * 100:.0f}%"
        decision_label = _DECISION_LABELS.get(decision, decision.value)

        facts = [
            {"title": "Repository",       "value": finding.repo_full_name},
            {"title": "Package",          "value": f"{finding.package_name} {finding.package_version}"},
            {"title": "Vuln Range",       "value": finding.vulnerable_version_range or "N/A"},
            {"title": "Vulnerability",    "value": cve},
            {"title": "Severity",         "value": (finding.severity or "unknown").capitalize()},
            {"title": "CVSS Score",       "value": cvss_text},
            {"title": "EPSS Score",       "value": epss_text},
            {"title": "Agent Verdict",    "value": decision_label},
            {"title": "LLM Confidence",   "value": conf_text},
            {"title": "Review Reason",    "value": trigger_reason},
        ]
        if hits:
            hit_lines = "\n".join(
                f"• {h.file_path}:{h.line_number} → `{h.function_called}()`"
                for h in hits[:5]
            )
            if len(hits) > 5:
                hit_lines += f"\n• … and {len(hits) - 5} more"
            facts.append({"title": "Reachable Hits", "value": hit_lines})

        body = [
            {"type": "TextBlock", "text": "VEX Agent — ⏳ Pending Human Review",
             "weight": "Bolder", "size": "Medium", "color": "Accent"},
            {"type": "TextBlock",
             "text": "🔍 The agent requires your decision before proceeding.",
             "weight": "Bolder", "size": "Large", "wrap": True, "color": "Warning"},
            {"type": "FactSet", "facts": facts},
        ]

        # Action buttons — Action.OpenUrl opens a confirmation page in the browser.
        # The page executes the action server-side and shows a styled result.
        actions: list[dict] = []
        if base_url:
            base = base_url.rstrip("/")
            actions += [
                {"type": "Action.OpenUrl", "title": "✅ Approve — dismiss alert",
                 "url": f"{base}/review/{review_id}/approve"},
                {"type": "Action.OpenUrl", "title": "❌ Reject — keep alert open",
                 "url": f"{base}/review/{review_id}/dismiss"},
            ]

        alert_url = (
            f"https://github.com/{finding.repo_full_name}"
            f"/security/dependabot/{finding.alert_id}"
        )
        actions.append({
            "type": "Action.OpenUrl",
            "title": "🔗 View GitHub Alert",
            "url": alert_url,
        })

        return self._wrap_adaptive_card(body, actions)

    # ------------------------------------------------------------------
    # Card assembly helper
    # ------------------------------------------------------------------

    @staticmethod
    def _wrap_adaptive_card(body: list, actions: list) -> dict:
        card: dict = {
            "type": "AdaptiveCard",
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "version": "1.4",
            "msteams": {"width": "Full"},
            "body": body,
        }
        if actions:
            card["actions"] = actions
        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": card,
                }
            ],
        }

    # ------------------------------------------------------------------
    # HTTP helper
    # ------------------------------------------------------------------

    async def _post(self, payload: dict) -> bool:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(self._url, json=payload)
            if resp.status_code in (200, 202):
                logger.info("Teams notification sent (HTTP %s).", resp.status_code)
                return True
            logger.warning(
                "Teams webhook returned HTTP %s: %s", resp.status_code, resp.text[:200]
            )
            return False
        except Exception as exc:  # noqa: BLE001
            logger.error("Teams notification failed: %s", exc)
            return False
