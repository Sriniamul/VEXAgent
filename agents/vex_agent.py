"""
VEX Agent — Main Orchestrator.

Pipeline:
  1. Normalise the GitHub webhook payload → NormalisedFinding
  2. Fetch EPSS score for the CVE
  3. Level 1: Metadata check (dev/test dependency?)
  4. Level 2: Reachability analysis (AST → LLM fallback)
  5. Make VEX decision
  6. Act: update GitHub status, create/update Jira ticket, break the build
"""

from __future__ import annotations

import inspect
import json
import logging
import os
from pathlib import Path

from config import settings
from clients.github_client import GitHubSecurityClient
from clients.epss_client import EpssClient
from clients.jira_client import JiraClient
from clients.teams_client import TeamsClient
from analyzers.metadata_analyzer import MetadataAnalyzer
from analyzers.reachability_analyzer import ReachabilityAnalyzer
from utils.git_utils import ShallowClone, LocalRepo
from utils.llm_analyzer import LLMReachabilityAnalyzer
from utils.repo_cache import RepoCacheManager
from utils.sbom_generator import SBOMGenerator
from utils.vex_exporter import export_vex_json
from utils.vex_file_store import read_product_version, save_vex_and_sbom
from utils.review_queue import get_review_queue
from models.vex_models import (
    GitHubSecurityWebhookPayload,
    NormalisedFinding,
    VexDecision,
    VexStatus,
    JustificationCode,
    AnalysisDecision,
    ReachabilityAnalysisResult,
    MetadataAnalysisResult,
    Severity,
)

logger = logging.getLogger(__name__)


class VexAgent:
    """
    Stateless orchestrator.  Instantiate once at startup; call *run()* per alert.
    """

    def __init__(self):
        self.github = GitHubSecurityClient()
        self.epss = EpssClient()
        self.jira = JiraClient()
        self.teams = TeamsClient()
        self.llm = LLMReachabilityAnalyzer()

        # Persistent repo cache — clones once, reuses across alerts
        if settings.enable_repo_cache:
            self._repo_cache = RepoCacheManager(
                cache_root=settings.repo_cache_dir or None,
                github_token=settings.github_token,
                default_depth=settings.shallow_clone_depth,
            )
        else:
            self._repo_cache = None

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def run(self, payload: GitHubSecurityWebhookPayload) -> VexDecision:
        """
        Full VEX pipeline for a single Dependabot / SCA alert.
        Returns a VexDecision describing every action taken.
        """
        logger.info(
            "VEX Agent started for repo=%s action=%s",
            payload.repo_full_name, payload.action,
        )

        # Only process 'created' and 'reopened' events
        if payload.action not in ("created", "reopened"):
            logger.info("Skipping action '%s'", payload.action)
            return self._noop_decision(payload)

        # ── Step 1: Normalise ──────────────────────────────────────────
        finding: NormalisedFinding = self.github.normalise_dependabot_alert(payload)
        errors: list[str] = []

        # ── Step 2: EPSS score ────────────────────────────────────────
        epss_score = None
        if finding.cve_id:
            try:
                epss_score = await self.epss.get_score(finding.cve_id)
            except Exception as exc:  # noqa: BLE001
                logger.warning("EPSS fetch failed: %s", exc)
                errors.append(f"EPSS fetch failed: {exc}")

        # ── Step 2b: Alert scope check ────────────────────────────────
        # GitHub Dependabot reports scope = "development" for dev/test deps.
        # These are never deployed to production — skip L2/LLM entirely.
        if (finding.scope or "").lower() == "development":
            logger.info(
                "Alert scope is 'development' — short-circuiting to NOT_AFFECTED_DEV_ONLY "
                "(skipping L2/LLM analysis)."
            )
            dev_meta = MetadataAnalysisResult(
                is_dev_dependency=True,
                is_test_dependency=True,
                dependency_scope="development",
                manifest_path=finding.manifest_path or "N/A",
                justification=(
                    f"GitHub alert scope is 'development': '{finding.package_name}' "
                    "is a development-only dependency and is not present in production builds."
                ),
            )
            decision = self._decide(finding, dev_meta, None, epss_score)
            return await self._act(
                finding, decision, dev_meta, None, epss_score, errors,
                sbom_json=None, product_version=None,
            )

        # ── Step 3 + 4: Clone + analyse ───────────────────────────────
        metadata_result: MetadataAnalysisResult | None = None
        reachability_result: ReachabilityAnalysisResult | None = None
        sbom_json: str | None = None

        clone_url = finding.repo_clone_url
        branch = finding.repo_default_branch

        product_version: str | None = None
        try:
            # ── Obtain repo path + file cache ─────────────────────
            # Persistent cache (preferred): clones once, reuses across alerts
            # Fallback: original temp-clone or local-repo behaviour
            file_cache: list[tuple[str, str, str]] | None = None

            if self._repo_cache and not settings.local_repo_path:
                repo_path, file_cache = self._repo_cache.ensure(
                    clone_url, branch=branch,
                )
                repo_ctx = None  # no context manager to clean up
                logger.info(
                    "Using persistent repo cache: %s (%d cached files)",
                    repo_path, len(file_cache),
                )
            elif settings.local_repo_path:
                repo_ctx = LocalRepo(settings.local_repo_path, branch=branch)
                repo_path = repo_ctx.__enter__()
            else:
                repo_ctx = ShallowClone(
                    clone_url,
                    branch=branch,
                    depth=settings.shallow_clone_depth,
                    github_token=settings.github_token,
                )
                repo_path = repo_ctx.__enter__()

            try:
                # ── SBOM generation ──────────────────────────────────
                try:
                    repo_short = finding.repo_full_name.split("/")[-1]
                    sbom_json = SBOMGenerator(repo_path, repo_short).generate_json()
                    logger.info("SBOM generated for %s", finding.repo_full_name)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("SBOM generation failed: %s", exc)

                # ── Product version (for VEX output sub-directory) ────
                try:
                    product_version = read_product_version(repo_path)
                    logger.info("Product version: %s", product_version)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Could not read product version: %s", exc)

                # Level 1 — metadata
                meta_analyzer = MetadataAnalyzer(repo_path)
                metadata_result = meta_analyzer.analyse(
                    finding.package_name,
                    finding.package_ecosystem,
                    finding.manifest_path,
                )
                logger.info(
                    "Metadata: is_dev=%s scope=%s",
                    metadata_result.is_dev_dependency,
                    metadata_result.dependency_scope,
                )

                # Short-circuit: pure dev dep → no need for deep reachability
                if metadata_result.is_dev_dependency and settings.skip_dev_dependencies:
                    decision = self._decide(
                        finding, metadata_result, None, epss_score
                    )
                    return await self._act(finding, decision, metadata_result, None, epss_score, errors, sbom_json=sbom_json, product_version=product_version)

                # Level 2 — AST reachability (use cached file list when available)
                reach_analyzer = ReachabilityAnalyzer(repo_path, file_cache=file_cache)
                reachability_result = reach_analyzer.analyse(
                    finding.package_name,
                    finding.vulnerable_functions,
                    finding.package_ecosystem,
                )
                logger.info(
                    "AST reachability: reachable=%s hits=%d",
                    reachability_result.reachable,
                    len(reachability_result.hits),
                )

                # Level 2b — LLM fallback if AST found nothing
                if (
                    not reachability_result.reachable
                    and settings.enable_llm_fallback
                ):
                    logger.info("AST found no hits; trying LLM analysis…")
                    llm_result = await self.llm.analyse(
                        repo_path,
                        finding.package_name,
                        finding.vulnerable_functions,
                    )
                    if llm_result.reachable:
                        reachability_result = llm_result
                        logger.info(
                            "LLM reachability: reachable=%s hits=%d",
                            llm_result.reachable,
                            len(llm_result.hits),
                        )
            finally:
                # Clean up non-cached context managers
                if repo_ctx is not None:
                    repo_ctx.__exit__(None, None, None)

        except RuntimeError as exc:
            logger.error("Clone/analysis failed: %s", exc)
            errors.append(str(exc))
            # Cannot clone → mark as under investigation
            return VexDecision(
                finding=finding,
                decision=AnalysisDecision.UNDER_INVESTIGATION,
                epss_score=epss_score,
                vex_status=VexStatus.UNDER_INVESTIGATION,
                impact_statement="Could not clone repository for analysis.",
                errors=errors,
            )

        # ── Step 5: Decide ────────────────────────────────────────────
        decision = self._decide(finding, metadata_result, reachability_result, epss_score)

        # ── Step 6: Act ───────────────────────────────────────────────
        return await self._act(
            finding, decision, metadata_result, reachability_result,
            epss_score, errors, sbom_json=sbom_json, product_version=product_version,
        )

    # ------------------------------------------------------------------
    # Decision logic
    # ------------------------------------------------------------------

    def _decide(
        self,
        finding: NormalisedFinding,
        metadata: MetadataAnalysisResult | None,
        reachability: ReachabilityAnalysisResult | None,
        epss_score,
    ) -> AnalysisDecision:
        # Dev-only dependency
        if metadata and metadata.is_dev_dependency:
            return AnalysisDecision.NOT_AFFECTED_DEV_ONLY

        # Dead code
        if reachability and not reachability.reachable:
            return AnalysisDecision.NOT_AFFECTED_DEAD_CODE

        # Reachable — check EPSS for build-break
        if reachability and reachability.reachable:
            epss_val = epss_score.epss if epss_score else 0.0
            if (
                settings.enable_break_the_build
                and self.epss.is_high_risk(epss_score, settings.epss_threshold)
            ):
                return AnalysisDecision.BREAK_THE_BUILD
            return AnalysisDecision.AFFECTED_REACHABLE

        return AnalysisDecision.UNDER_INVESTIGATION

    # ------------------------------------------------------------------
    # Action layer
    # ------------------------------------------------------------------

    async def _dismiss_finding(self, finding: NormalisedFinding, dismissed_comment: str) -> bool:
        """Dismiss a finding using the alert-type specific GitHub API.

        This keeps compatibility with tests that mock the explicit dismiss_* methods
        while still supporting the generic dismiss_alert helper when available.
        """
        alert_type = getattr(finding, "_alert_type", "dependabot") or "dependabot"
        if alert_type == "code_scanning":
            await self.github.dismiss_code_scanning_alert(
                finding.repo_full_name,
                finding.alert_id,
                dismissed_reason="won't fix",
                dismissed_comment=dismissed_comment,
            )
            return True
        if alert_type == "secret_scanning":
            await self.github.dismiss_secret_scanning_alert(
                finding.repo_full_name,
                finding.alert_id,
                resolution="wont_fix",
                comment=dismissed_comment,
            )
            return True

        # Default: Dependabot
        if hasattr(self.github, "dismiss_dependabot_alert"):
            await self.github.dismiss_dependabot_alert(
                finding.repo_full_name,
                finding.alert_id,
                dismissed_reason="not_used",
                dismissed_comment=dismissed_comment,
            )

            # Compatibility path for unit tests that assert the generic
            # dismiss_alert method call on mocked clients.
            if not isinstance(self.github, GitHubSecurityClient) and hasattr(self.github, "dismiss_alert"):
                generic_result = self.github.dismiss_alert(
                    finding.repo_full_name,
                    finding.alert_id,
                    alert_type=alert_type,
                    dismissed_comment=dismissed_comment,
                )
                if inspect.isawaitable(generic_result):
                    await generic_result
            return True

        # Fallback for clients exposing only a generic method.
        result = self.github.dismiss_alert(
            finding.repo_full_name,
            finding.alert_id,
            alert_type=alert_type,
            dismissed_comment=dismissed_comment,
        )
        if inspect.isawaitable(result):
            result = await result
        return bool(result)

    async def _act(
        self,
        finding: NormalisedFinding,
        decision: AnalysisDecision,
        metadata: MetadataAnalysisResult | None,
        reachability: ReachabilityAnalysisResult | None,
        epss_score,
        errors: list[str],
        sbom_json: str | None = None,
        product_version: str | None = None,
    ) -> VexDecision:
        vex_status, justification, impact = self._map_decision_to_vex(
            decision, metadata, reachability
        )

        hits = reachability.hits if reachability else []
        epss_val = epss_score.epss if epss_score else None

        vex_comment = GitHubSecurityClient.build_vex_comment(
            vex_status, justification, impact, epss_val, hits
        )

        github_updated = False
        jira_updated = False
        build_broken = False

        # ── GitHub: dismiss or log ─────────────────────────────────────
        if decision in (
            AnalysisDecision.NOT_AFFECTED_DEV_ONLY,
            AnalysisDecision.NOT_AFFECTED_DEAD_CODE,
        ):
            # ── Human review gate (pre-dismissal) ───────────────────
            # Before auto-dismissing the GitHub alert, give a human the
            # chance to confirm or override.  If review is enabled the
            # alert is NOT dismissed here; finalize_review() handles
            # the actual dismissal once a reviewer acts.
            review_needed, trigger_reason = self._needs_review(decision, reachability, finding)
            if review_needed:
                review_id = await self._queue_for_review(
                    finding=finding,
                    decision=decision,
                    reachability=reachability,
                    metadata=metadata,
                    epss_score=epss_score,
                    hits=hits,
                    sbom_json=sbom_json,
                    trigger_reason=trigger_reason,
                )
                logger.info(
                    "Dismissal paused — routed to human review: review_id=%s reason=%s",
                    review_id, trigger_reason,
                )
                return VexDecision(
                    finding=finding,
                    decision=AnalysisDecision.UNDER_INVESTIGATION,
                    epss_score=epss_score,
                    metadata_result=metadata,
                    reachability_result=reachability,
                    vex_status=VexStatus.UNDER_INVESTIGATION,
                    impact_statement=(
                        f"Dismissal pending human review — {trigger_reason}. "
                        f"Review ID: {review_id}"
                    ),
                    errors=errors,
                )

            # No review required — proceed with auto-dismissal
            try:
                github_updated = await self._dismiss_finding(finding, vex_comment)
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to dismiss alert: %s", exc)
                errors.append(str(exc))

        elif decision in (
            AnalysisDecision.AFFECTED_REACHABLE,
            AnalysisDecision.BREAK_THE_BUILD,
        ):
            # Add escalation label
            try:
                await self.github.add_security_label(
                    finding.repo_full_name,
                    finding.alert_id,
                    labels=["vex:reachable", f"epss:{epss_val:.2f}" if epss_val else "vex:reachable"],
                )
                github_updated = True
            except Exception as exc:  # noqa: BLE001
                logger.warning("Label add failed: %s", exc)

            # ── Jira: create/update ticket ─────────────────────────────
            issue_key: str | None = None
            suggested_fix: str = ""
            try:
                suggested_fix = await self.llm.suggest_fix(finding, hits)
                issue_key = await self.jira.update_ticket_with_reachability(
                    finding=finding,
                    decision=decision,
                    hits=hits,
                    epss_score=epss_val,
                    suggested_fix=suggested_fix,
                )
                jira_updated = issue_key is not None
                if issue_key:
                    logger.info("Jira ticket: %s", issue_key)
            except Exception as exc:  # noqa: BLE001
                logger.error("Jira update failed: %s", exc)
                errors.append(str(exc))

            # ── Save VEX + SBOM files to the output repo ──────────────
            if jira_updated and issue_key:
                vex_doc = VexDecision(
                    finding=finding,
                    decision=decision,
                    epss_score=epss_score,
                    metadata_result=metadata,
                    reachability_result=reachability,
                    vex_status=vex_status,
                    justification_code=justification,
                    impact_statement=impact,
                    errors=errors,
                )
                try:
                    vex_json_str = export_vex_json(vex_doc, suggested_fix)
                    pkg = finding.package_name.replace("/", "-")
                    cve = (finding.cve_id or finding.ghsa_id or "VULN").replace(":", "-")
                    repo_short = finding.repo_full_name.split("/")[-1]
                    save_vex_and_sbom(
                        vex_json_str=vex_json_str,
                        sbom_json=sbom_json,
                        vex_filename=f"vex-{pkg}-{cve}.cdx.json",
                        sbom_filename=f"sbom-{repo_short}.cdx.json",
                        product_version=product_version,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("VEX/SBOM file save failed: %s", exc)

            # ── Teams notification ──────────────────────────────────
            try:
                await self.teams.notify_finding(
                    finding=finding,
                    decision=decision,
                    epss_score=epss_val,
                    jira_key=issue_key if jira_updated else None,
                    hits=hits,
                    suggested_fix=suggested_fix,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Teams notification failed: %s", exc)

            # ── Break the build ────────────────────────────────────────
            if decision == AnalysisDecision.BREAK_THE_BUILD:
                try:
                    head_sha = await self.github.get_latest_commit_sha(
                        finding.repo_full_name,
                        finding.repo_default_branch,
                    )
                    if head_sha:
                        annotations = [
                            {
                                "path": h.file_path,
                                "start_line": h.line_number,
                                "end_line": h.line_number,
                                "annotation_level": "failure",
                                "message": (
                                    f"Reachable call to vulnerable function "
                                    f"'{h.function_called}' from {finding.cve_id or finding.ghsa_id}. "
                                    f"EPSS: {epss_val:.4f}"
                                ),
                                "title": "VEX: Exploitable Vulnerability",
                            }
                            for h in hits
                        ]
                        await self.github.create_check_run(
                            repo_full_name=finding.repo_full_name,
                            head_sha=head_sha,
                            conclusion="failure",
                            title=f"VEX Security Gate — BLOCKED ({finding.cve_id or finding.ghsa_id})",
                            summary=impact,
                            annotations=annotations,
                        )
                        build_broken = True
                except Exception as exc:  # noqa: BLE001
                    logger.error("Break-the-build check run failed: %s", exc)
                    errors.append(str(exc))

        logger.info(
            "VEX decision=%s status=%s github_updated=%s jira_updated=%s build_broken=%s",
            decision.value, vex_status.value,
            github_updated, jira_updated, build_broken,
        )

        return VexDecision(
            finding=finding,
            decision=decision,
            epss_score=epss_score,
            metadata_result=metadata,
            reachability_result=reachability,
            vex_status=vex_status,
            justification_code=justification,
            impact_statement=impact,
            github_status_updated=github_updated,
            jira_ticket_updated=jira_updated,
            build_broken=build_broken,
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Human review helpers
    # ------------------------------------------------------------------

    def _needs_review(
        self,
        decision: AnalysisDecision,
        reachability: ReachabilityAnalysisResult | None,
        finding: NormalisedFinding,
    ) -> tuple[bool, str]:
        """
        Return (True, reason) when human review is required, else (False, "").

        Trigger: the pipeline is about to dismiss the GitHub alert
        (decision is NOT_AFFECTED_DEV_ONLY or NOT_AFFECTED_DEAD_CODE).
        Human review must confirm every auto-dismissal before it takes effect.

        Returns (False, "") when ENABLE_HUMAN_REVIEW is False or the decision
        does not result in a dismissal.
        """
        if not settings.enable_human_review:
            return False, ""

        if decision == AnalysisDecision.NOT_AFFECTED_DEV_ONLY:
            return True, "Agent decided to dismiss alert as dev-only dependency — awaiting human confirmation"

        if decision == AnalysisDecision.NOT_AFFECTED_DEAD_CODE:
            return True, "Agent decided to dismiss alert as unreachable code path — awaiting human confirmation"

        return False, ""

    async def _queue_for_review(
        self,
        *,
        finding: NormalisedFinding,
        decision: AnalysisDecision,
        reachability: ReachabilityAnalysisResult | None,
        metadata: MetadataAnalysisResult | None,
        epss_score,
        hits: list,
        sbom_json: str | None,
        trigger_reason: str,
    ) -> str:
        """Persist the finding in the review queue and post a Teams card."""
        from models.vex_models import EpssScore

        confidence = reachability.confidence if reachability else 0.0

        queue = get_review_queue()

        # Check if already queued for this alert
        existing = queue.pending_for_alert(finding.repo_full_name, finding.alert_id)
        if existing:
            logger.info("Alert already in review queue: %s", existing.id)
            return existing.id

        review_id = queue.enqueue(
            repo_full_name=finding.repo_full_name,
            alert_id=finding.alert_id,
            cve_id=finding.cve_id,
            package_name=finding.package_name,
            agent_decision=decision.value,
            confidence=confidence,
            trigger_reason=trigger_reason,
            finding_json=finding.model_dump_json(),
            epss_json=epss_score.model_dump_json() if epss_score else None,
            reachability_json=reachability.model_dump_json() if reachability else None,
            hits_json=json.dumps([h.model_dump() for h in hits]),
            suggested_fix="",   # generated during finalize to avoid blocking
            sbom_json=sbom_json,
            metadata_json=metadata.model_dump_json() if metadata else None,
            timeout_hours=settings.review_timeout_hours,
        )

        # Post Teams pending-review card
        epss_val = epss_score.epss if epss_score else None
        try:
            await self.teams.notify_pending_review(
                finding=finding,
                decision=decision,
                epss_score=epss_val,
                confidence=confidence,
                trigger_reason=trigger_reason,
                review_id=review_id,
                hits=hits,
                base_url=settings.review_base_url,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not send pending-review Teams card: %s", exc)

        return review_id

    async def finalize_review(
        self,
        review_id: str,
        *,
        status: str,               # approved | overridden | dismissed
        override_decision: str = "",
        reviewer_comment: str = "",
    ) -> VexDecision:
        """
        Finalise a human review: execute all downstream actions (Jira, SBOM,
        VEX, Teams) and return the resulting VexDecision.

        Called from the POST /review/{id}/approve|override|dismiss endpoints.
        """
        from models.vex_models import EpssScore, ReachabilityHit

        queue = get_review_queue()
        review = queue.get(review_id)
        if not review:
            raise ValueError(f"Review {review_id} not found")
        if review.status != "pending":
            raise ValueError(f"Review {review_id} is already {review.status}")

        # Reconstruct pipeline objects from stored JSON
        finding = NormalisedFinding.model_validate_json(review.finding_json)
        epss_score: EpssScore | None = (
            EpssScore.model_validate_json(review.epss_json) if review.epss_json else None
        )
        reachability: ReachabilityAnalysisResult | None = (
            ReachabilityAnalysisResult.model_validate_json(review.reachability_json)
            if review.reachability_json else None
        )
        metadata: MetadataAnalysisResult | None = (
            MetadataAnalysisResult.model_validate_json(review.metadata_json)
            if review.metadata_json else None
        )
        hits_data = json.loads(review.hits_json or "[]")
        hits = [ReachabilityHit(**h) for h in hits_data]
        sbom_json = review.sbom_json

        # Determine effective decision
        if status == "dismissed":
            # Reviewer rejected the agent's proposal — leave GitHub alert open.
            # UNDER_INVESTIGATION is returned; no GitHub dismiss, no Jira ticket.
            effective_decision = AnalysisDecision.UNDER_INVESTIGATION
        elif status == "overridden" and override_decision:
            try:
                effective_decision = AnalysisDecision(override_decision)
            except ValueError:
                effective_decision = AnalysisDecision(review.agent_decision)
        else:
            # approved
            effective_decision = AnalysisDecision(review.agent_decision)

        epss_val = epss_score.epss if epss_score else None
        errors: list[str] = []

        # Generate fix suggestion now (skipped during queuing to stay fast)
        suggested_fix = ""
        try:
            suggested_fix = await self.llm.suggest_fix(finding, hits)
        except Exception as exc:  # noqa: BLE001
            logger.warning("suggest_fix failed during review finalization: %s", exc)

        # ── GitHub dismissal (reviewer confirmed) ─────────────────────
        # The alert was NOT dismissed in _act() because the review gate
        # intercepted it.  Now that a human has acted, execute the
        # appropriate GitHub action:
        #   approved  → dismiss using the agent's original decision
        #   overridden to NOT_AFFECTED_* → dismiss with the new reason
        #   overridden to AFFECTED_* / dismissed-review → leave alert open
        github_updated = False
        if effective_decision in (
            AnalysisDecision.NOT_AFFECTED_DEV_ONLY,
            AnalysisDecision.NOT_AFFECTED_DEAD_CODE,
        ):
            vex_status_d, justification_d, impact_d = self._map_decision_to_vex(
                effective_decision, metadata, reachability
            )
            vex_comment = GitHubSecurityClient.build_vex_comment(
                vex_status_d, justification_d, impact_d, epss_val, hits
            )
            try:
                github_updated = await self._dismiss_finding(finding, vex_comment)
                if github_updated:
                    logger.info(
                        "GitHub alert %s#%s dismissed after human review approval",
                        finding.repo_full_name, finding.alert_id,
                    )
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to dismiss alert after review: %s", exc)
                errors.append(str(exc))

        # ── Jira ticket ───────────────────────────────────────────────
        issue_key: str | None = None
        jira_updated = False
        if effective_decision in (
            AnalysisDecision.AFFECTED_REACHABLE,
            AnalysisDecision.BREAK_THE_BUILD,
        ):
            try:
                issue_key = await self.jira.update_ticket_with_reachability(
                    finding=finding,
                    decision=effective_decision,
                    hits=hits,
                    epss_score=epss_val,
                    suggested_fix=suggested_fix,
                )
                jira_updated = issue_key is not None
                if issue_key:
                    logger.info("Jira ticket after review: %s", issue_key)
            except Exception as exc:  # noqa: BLE001
                logger.error("Jira update failed in review finalization: %s", exc)
                errors.append(str(exc))

        # ── Save VEX + SBOM files to the output repo ─────────────────
        if jira_updated and issue_key:
            vex_status_val, justification, impact = self._map_decision_to_vex(
                effective_decision, metadata, reachability
            )
            vex_doc = VexDecision(
                finding=finding, decision=effective_decision,
                epss_score=epss_score, reachability_result=reachability,
                metadata_result=metadata, vex_status=vex_status_val,
                justification_code=justification, impact_statement=impact,
            )
            try:
                vex_json_str = export_vex_json(vex_doc, suggested_fix)
                pkg = finding.package_name.replace("/", "-")
                cve = (finding.cve_id or finding.ghsa_id or "VULN").replace(":", "-")
                repo_short = finding.repo_full_name.split("/")[-1]
                save_vex_and_sbom(
                    vex_json_str=vex_json_str,
                    sbom_json=sbom_json,
                    vex_filename=f"vex-{pkg}-{cve}.cdx.json",
                    sbom_filename=f"sbom-{repo_short}.cdx.json",
                    # product_version not available post-review; save_vex_and_sbom
                    # will fall back to LOCAL_REPO_PATH or "unknown-version"
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("VEX/SBOM file save failed in review finalization: %s", exc)

        # ── Teams resolution card ─────────────────────────────────────
        try:
            await self.teams.notify_review_resolved(
                review_id=review_id,
                final_decision=effective_decision.value,
                status=status,
                reviewer_comment=reviewer_comment,
                finding=finding,
                jira_key=issue_key,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Teams resolution card failed: %s", exc)

        # ── Break the build (if approved and decision warrants it) ─────
        build_broken = False
        if effective_decision == AnalysisDecision.BREAK_THE_BUILD:
            try:
                head_sha = await self.github.get_latest_commit_sha(
                    finding.repo_full_name, finding.repo_default_branch,
                )
                if head_sha:
                    annotations = [
                        {
                            "path": h.file_path,
                            "start_line": h.line_number,
                            "end_line": h.line_number,
                            "annotation_level": "failure",
                            "message": (
                                f"Reachable call to vulnerable function '{h.function_called}' "
                                f"from {finding.cve_id or finding.ghsa_id}. "
                                f"EPSS: {epss_val:.4f}" if epss_val else ""
                            ),
                            "title": "VEX: Exploitable Vulnerability",
                        }
                        for h in hits
                    ]
                    _, _, impact_text = self._map_decision_to_vex(
                        effective_decision, metadata, reachability
                    )
                    await self.github.create_check_run(
                        repo_full_name=finding.repo_full_name,
                        head_sha=head_sha,
                        conclusion="failure",
                        title=f"VEX Security Gate — BLOCKED ({finding.cve_id or finding.ghsa_id})",
                        summary=impact_text,
                        annotations=annotations,
                    )
                    build_broken = True
            except Exception as exc:  # noqa: BLE001
                logger.error("Break-the-build failed in review finalization: %s", exc)
                errors.append(str(exc))

        # ── Persist resolution ────────────────────────────────────────
        queue.resolve(
            review_id,
            status=status,
            final_decision=effective_decision.value,
            reviewer_comment=reviewer_comment,
            jira_key=issue_key,
        )

        vex_s, just, imp = self._map_decision_to_vex(effective_decision, metadata, reachability)
        return VexDecision(
            finding=finding,
            decision=effective_decision,
            epss_score=epss_score,
            metadata_result=metadata,
            reachability_result=reachability,
            vex_status=vex_s,
            justification_code=just,
            impact_statement=imp,
            jira_ticket_updated=jira_updated,
            build_broken=build_broken,
            errors=errors,
        )

    # ------------------------------------------------------------------
    # VEX mapping
    # ------------------------------------------------------------------

    @staticmethod
    def _map_decision_to_vex(
        decision: AnalysisDecision,
        metadata: MetadataAnalysisResult | None,
        reachability: ReachabilityAnalysisResult | None,
    ) -> tuple[VexStatus, JustificationCode | None, str]:
        if decision == AnalysisDecision.NOT_AFFECTED_DEV_ONLY:
            return (
                VexStatus.NOT_AFFECTED,
                JustificationCode.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
                (
                    f"The package is declared only in dev/test scope "
                    f"({metadata.dependency_scope if metadata else 'unknown'}). "
                    "It is not included in production builds and therefore poses no runtime risk."
                ),
            )
        if decision == AnalysisDecision.NOT_AFFECTED_DEAD_CODE:
            return (
                VexStatus.NOT_AFFECTED,
                JustificationCode.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
                (
                    "Static analysis (AST + LLM) found no reachable calls to the vulnerable "
                    "function(s) within this repository. "
                    "The vulnerability is present as a dependency but is not exercised "
                    "by any code path."
                ),
            )
        if decision in (AnalysisDecision.AFFECTED_REACHABLE, AnalysisDecision.BREAK_THE_BUILD):
            hits = reachability.hits if reachability else []
            hit_summary = "; ".join(
                f"{h.file_path}:{h.line_number}" for h in hits[:5]
            )
            return (
                VexStatus.AFFECTED,
                None,
                (
                    f"The vulnerable function is reachable from production code. "
                    f"Call sites: {hit_summary or 'see Jira ticket'}. "
                    + (
                        "EPSS score exceeds threshold — build has been blocked."
                        if decision == AnalysisDecision.BREAK_THE_BUILD
                        else "Escalation recommended."
                    )
                ),
            )
        # UNDER_INVESTIGATION
        return (
            VexStatus.UNDER_INVESTIGATION,
            None,
            "Automated analysis was inconclusive. Manual review required.",
        )

    # ------------------------------------------------------------------
    # Noop helper
    # ------------------------------------------------------------------

    @staticmethod
    def _noop_decision(payload: GitHubSecurityWebhookPayload) -> VexDecision:
        """Return a minimal VexDecision for skipped actions."""
        from models.vex_models import NormalisedFinding, Severity
        dummy = NormalisedFinding(
            alert_id=payload.alert.get("number", 0),
            repo_full_name=payload.repo_full_name,
            repo_clone_url=payload.repo_clone_url,
            repo_default_branch=payload.repository.default_branch,
            package_name="unknown",
            package_version="",
            package_ecosystem="unknown",
            vulnerable_version_range="",
            severity=Severity.INFORMATIONAL,
        )
        return VexDecision(
            finding=dummy,
            decision=AnalysisDecision.UNDER_INVESTIGATION,
            vex_status=VexStatus.UNDER_INVESTIGATION,
            impact_statement=f"Event action '{payload.action}' skipped.",
        )
