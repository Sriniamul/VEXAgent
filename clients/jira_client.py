"""
Jira REST API v3 client.
Updates existing tickets linked to security alerts with reachability evidence.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

from config import settings
from models.vex_models import NormalisedFinding, ReachabilityHit, AnalysisDecision

logger = logging.getLogger(__name__)


class JiraClient:
    """Thin wrapper around the Jira Cloud REST API v3."""

    def __init__(
        self,
        base_url: str | None = None,
        email: str | None = None,
        api_token: str | None = None,
    ):
        self._base = (base_url or settings.jira_base_url).rstrip("/")
        auth_email = email or settings.jira_email
        auth_token = api_token or settings.jira_api_token
        self._auth = (auth_email, auth_token) if auth_email and auth_token else None
        self._headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            auth=self._auth,
            headers=self._headers,
            timeout=30,
        )

    async def _get_issue_key_for_alert(
        self,
        cve_id: Optional[str],
        repo_full_name: str,
        alert_id: int,
    ) -> Optional[str]:
        """
        Search Jira for an existing ticket related to this CVE / alert.

        Searches by label only (label-based JQL uses an index and is supported
        on all Jira Cloud plans).  Two search attempts are made, progressively
        broadening:
          1. Both the alert-fingerprint label AND the repo label (most precise)
          2. Alert-fingerprint label only (catches cross-repo dupes)
        """
        alert_label = f"vex-alert-{alert_id}"
        repo_label = f"repo-{repo_full_name.replace('/', '-')}"

        queries = [
            # Most specific — same alert in the same repo
            f'labels = "{alert_label}" AND labels = "{repo_label}" ORDER BY created DESC',
            # Fallback — same alert number in any repo
            f'labels = "{alert_label}" ORDER BY created DESC',
        ]

        try:
            async with self._client() as c:
                for jql in queries:
                    # Use the current Jira Cloud search endpoint (POST /search/jql).
                    # The legacy GET /search was deprecated and returns 410 Gone.
                    resp = await c.post(
                        f"{self._base}/rest/api/3/search/jql",
                        json={"jql": jql, "maxResults": 1, "fields": ["key", "summary"]},
                    )
                    if resp.status_code == 200:
                        issues = resp.json().get("issues", [])
                        if issues:
                            logger.debug("Dedup found existing ticket %s via JQL: %s", issues[0]["key"], jql)
                            return issues[0]["key"]
                    elif resp.status_code in (400, 410):
                        logger.debug("JQL endpoint returned %s, trying next query", resp.status_code)
                    else:
                        logger.warning("Jira search returned %s for JQL: %s", resp.status_code, jql)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Jira search failed: %s", exc)
        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def update_ticket_with_reachability(
        self,
        finding: NormalisedFinding,
        decision: AnalysisDecision,
        hits: list[ReachabilityHit],
        epss_score: Optional[float] = None,
        suggested_fix: str = "",
    ) -> Optional[str]:
        """
        Find the Jira ticket for this finding and append reachability evidence.
        Returns the issue key if updated, else None.
        """
        if not self._base or not self._auth:
            logger.info("Jira not configured; skipping ticket update.")
            return None

        issue_key = await self._get_issue_key_for_alert(
            finding.cve_id,
            finding.repo_full_name,
            finding.alert_id,
        )

        if not issue_key:
            issue_key = await self.create_ticket(finding, decision, hits, epss_score, suggested_fix)
            if not issue_key:
                return None
        else:
            await self._add_comment(issue_key, finding, decision, hits, epss_score, suggested_fix)
            await self._update_priority(issue_key, decision)

        return issue_key

    # ------------------------------------------------------------------
    # Custom field helpers
    # ------------------------------------------------------------------

    # CVSS Score select: integer 0-10 → Jira option id
    _CVSS_SCORE_IDS: dict[int, str] = {
        0: "10514", 1: "10515", 2: "10516", 3: "10517", 4: "10518",
        5: "10519", 6: "10520", 7: "10521", 8: "10522", 9: "10523",
        10: "10524",
    }
    _CVSS_SCORE_UNKNOWN_ID = "11635"

    # Risk select: severity → Jira option id
    _RISK_IDS: dict[str, str] = {
        "critical": "11888",
        "high": "10469",
        "medium": "10468",
        "low": "10467",
        "informational": "10466",
    }

    def _cvss_score_option(self, score: Optional[float]) -> dict[str, str]:
        """Map a float CVSS score to the nearest integer Jira option."""
        if score is None:
            return {"id": self._CVSS_SCORE_UNKNOWN_ID}
        rounded = min(10, max(0, round(score)))
        return {"id": self._CVSS_SCORE_IDS.get(rounded, self._CVSS_SCORE_UNKNOWN_ID)}

    def _risk_option(self, severity: str) -> dict[str, str]:
        return {"id": self._RISK_IDS.get(severity.lower(), self._RISK_IDS["medium"])}

    async def create_ticket(
        self,
        finding: NormalisedFinding,
        decision: AnalysisDecision,
        hits: list[ReachabilityHit],
        epss_score: Optional[float] = None,
        suggested_fix: str = "",
    ) -> Optional[str]:
        """Create a new Jira Security Vuln ticket for a confirmed-reachable vulnerability."""
        if not settings.jira_project_key:
            logger.warning("JIRA_PROJECT_KEY not set; cannot create ticket.")
            return None

        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        today_str = now.strftime("%Y-%m-%d")
        now_str = now.strftime("%Y-%m-%dT%H:%M:%S.000+0000")

        priority = self._map_priority(decision, finding.severity.value)
        _vuln_id = finding.cve_id or finding.ghsa_id or "VULNERABILITY"
        _short_summary = (finding.summary or "").strip()
        if _short_summary:
            # Truncate to fit Jira's 255-char limit for summary field
            _prefix = f"[VEX] {_vuln_id} – {finding.package_name}: "
            _max_desc = 255 - len(_prefix)
            if len(_short_summary) > _max_desc:
                _short_summary = _short_summary[:_max_desc - 1] + "…"
            summary = _prefix + _short_summary
        else:
            summary = (
                f"[VEX] {_vuln_id} – "
                f"{finding.package_name}@{finding.package_version} in {finding.repo_full_name}"
            )

        body = self._build_adf_description(finding, decision, hits, epss_score, suggested_fix)

        payload: dict[str, Any] = {
            "fields": {
                "project": {"key": settings.jira_project_key},
                "summary": summary,
                "issuetype": {"id": "10341"},          # Security Vuln
                "priority": {"name": priority},
                "description": body,
                # ── Security Vuln custom fields ──────────────────────
                "customfield_10369": today_str,          # Vuln Report Date
                "customfield_11414": [{"id": "12971"}],  # Reporter source: int - GHAS dependabot
                "customfield_10374": finding.cve_id or "",             # CVE ID
                "customfield_10135": self._cvss_score_option(finding.cvss_score),  # CVSS Score
                "customfield_10322": finding.cvss_vector_string or "",  # CVSS Vector String
                "customfield_10392": finding.repo_full_name,             # Vulnerable (SWI) Component
                "customfield_10118": self._risk_option(finding.severity.value),    # Risk
                "customfield_10289": {"id": "11574"},   # OWASP TOP 10: A9 - Using Components with Known Vulnerabilities
                "customfield_11884": now_str,            # First Response
                "labels": [
                    "security",
                    "vex-agent",
                    f"vex-alert-{finding.alert_id}",
                    f"repo-{finding.repo_full_name.replace('/', '-')}",
                    finding.severity.value,
                ],
            }
        }

        # Assign to configured user (e.g. "GitHub Copilot")
        if settings.jira_default_assignee:
            payload["fields"]["assignee"] = {"accountId": settings.jira_default_assignee}

        # Link to parent EPIC if configured
        if settings.jira_epic_key:
            payload["fields"]["parent"] = {"key": settings.jira_epic_key}

        try:
            async with self._client() as c:
                resp = await c.post(
                    f"{self._base}/rest/api/3/issue",
                    json=payload,
                )
                if resp.status_code >= 400:
                    body = resp.text
                    logger.error("Jira API %d response body: %s", resp.status_code, body)
                resp.raise_for_status()
                key = resp.json()["key"]
                logger.info("Created Jira ticket %s for %s", key, finding.cve_id)
                return key
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to create Jira ticket: %s", exc)
            return None

    async def _add_comment(
        self,
        issue_key: str,
        finding: NormalisedFinding,
        decision: AnalysisDecision,
        hits: list[ReachabilityHit],
        epss_score: Optional[float],
        suggested_fix: str = "",
    ) -> None:
        comment_body = self._build_adf_description(finding, decision, hits, epss_score, suggested_fix)
        try:
            async with self._client() as c:
                resp = await c.post(
                    f"{self._base}/rest/api/3/issue/{issue_key}/comment",
                    json={"body": comment_body},
                )
                resp.raise_for_status()
                logger.info("Added comment to Jira %s", issue_key)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to add Jira comment: %s", exc)

    async def attach_file(
        self,
        issue_key: str,
        filename: str,
        content: bytes,
        mime_type: str = "application/json",
    ) -> bool:
        """
        Upload a file as an attachment to a Jira issue.

        Uses the REST API v2 multipart attachment endpoint which is available
        on all Jira Cloud plans.
        """
        if not self._base or not self._auth:
            return False
        # Jira requires the X-Atlassian-Token: no-check CSRF bypass header
        try:
            async with httpx.AsyncClient(auth=self._auth, timeout=60) as c:
                resp = await c.post(
                    f"{self._base}/rest/api/2/issue/{issue_key}/attachments",
                    headers={"X-Atlassian-Token": "no-check"},
                    files={"file": (filename, content, mime_type)},
                )
            if resp.status_code in (200, 201):
                logger.info("Attached %s to Jira %s", filename, issue_key)
                return True
            logger.warning(
                "Jira attachment failed HTTP %s: %s", resp.status_code, resp.text[:200]
            )
            return False
        except Exception as exc:  # noqa: BLE001
            logger.error("Jira attach_file error: %s", exc)
            return False

    async def _update_priority(
        self,
        issue_key: str,
        decision: AnalysisDecision,
    ) -> None:
        priority = self._map_priority(decision)
        try:
            async with self._client() as c:
                await c.put(
                    f"{self._base}/rest/api/3/issue/{issue_key}",
                    json={"fields": {"priority": {"name": priority}}},
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to update Jira priority: %s", exc)

    # ------------------------------------------------------------------
    # Formatting helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _map_priority(
        decision: AnalysisDecision,
        severity: str = "medium",
    ) -> str:
        if decision == AnalysisDecision.BREAK_THE_BUILD:
            return "Highest"
        if decision == AnalysisDecision.AFFECTED_REACHABLE:
            return "High" if severity in ("critical", "high") else "Medium"
        return "Low"

    @staticmethod
    def _build_adf_description(
        finding: NormalisedFinding,
        decision: AnalysisDecision,
        hits: list[ReachabilityHit],
        epss_score: Optional[float],
        suggested_fix: str = "",
    ) -> dict[str, Any]:
        """Build an Atlassian Document Format (ADF) body for the Jira comment/description."""
        paragraphs: list[dict[str, Any]] = [
            {
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": "VEX Agent automated analysis report.", "marks": [{"type": "strong"}]},
                ],
            },
            {
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": f"Decision: {decision.value}"},
                ],
            },
        ]

        if epss_score is not None:
            paragraphs.append({
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": f"EPSS Score: {epss_score:.4f} (30-day exploitation probability)"},
                ],
            })

        if hits:
            rows: list[dict[str, Any]] = [
                {
                    "type": "tableRow",
                    "content": [
                        {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "File"}]}]},
                        {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Line"}]}]},
                        {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Function"}]}]},
                        {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Code"}]}]},
                    ],
                }
            ]
            for hit in hits:
                rows.append({
                    "type": "tableRow",
                    "content": [
                        {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": hit.file_path}]}]},
                        {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": str(hit.line_number)}]}]},
                        {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": hit.function_called}]}]},
                        {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": hit.line_content.strip()}]}]},
                    ],
                })
            paragraphs.append({"type": "table", "content": rows})

        # ── Suggested fix section ──────────────────────────────────────
        if suggested_fix and suggested_fix.strip():
            paragraphs.append({
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": "Suggested Fix", "marks": [{"type": "strong"}]},
                ],
            })
            # Split the markdown into lines and emit each non-empty line
            # as a paragraph so it renders readably in Jira.
            for line in suggested_fix.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                # Detect markdown headings (## Heading) → bold text
                if stripped.startswith("## "):
                    paragraphs.append({
                        "type": "paragraph",
                        "content": [{"type": "text", "text": stripped[3:], "marks": [{"type": "strong"}]}],
                    })
                elif stripped.startswith("### "):
                    paragraphs.append({
                        "type": "paragraph",
                        "content": [{"type": "text", "text": stripped[4:], "marks": [{"type": "strong"}]}],
                    })
                else:
                    # Plain paragraph (strip leading markdown bullet/number)
                    text = stripped.lstrip("-*0123456789. ")
                    if text:
                        paragraphs.append({
                            "type": "paragraph",
                            "content": [{"type": "text", "text": text}],
                        })

        return {"version": 1, "type": "doc", "content": paragraphs}
        paragraphs: list[dict[str, Any]] = [
            {
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": "VEX Agent automated analysis report.", "marks": [{"type": "strong"}]},
                ],
            },
            {
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": f"Decision: {decision.value}"},
                ],
            },
        ]

        if epss_score is not None:
            paragraphs.append({
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": f"EPSS Score: {epss_score:.4f} (30-day exploitation probability)"},
                ],
            })

        if hits:
            rows: list[dict[str, Any]] = [
                {
                    "type": "tableRow",
                    "content": [
                        {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "File"}]}]},
                        {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Line"}]}]},
                        {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Function"}]}]},
                        {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Code"}]}]},
                    ],
                }
            ]
            for hit in hits:
                rows.append({
                    "type": "tableRow",
                    "content": [
                        {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": hit.file_path}]}]},
                        {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": str(hit.line_number)}]}]},
                        {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": hit.function_called}]}]},
                        {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": hit.line_content.strip()}]}]},
                    ],
                })
            paragraphs.append({"type": "table", "content": rows})

        return {"version": 1, "type": "doc", "content": paragraphs}
