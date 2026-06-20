"""
CycloneDX VEX (Vulnerability Exploitability eXchange) document exporter.

Exports VexDecision results as a standards-compliant CycloneDX 1.5 VEX JSON
document that can be shared with customers, uploaded to Dependency-Track,
or attached to Jira tickets.

CycloneDX VEX spec: https://cyclonedx.org/capabilities/vex/
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from models.vex_models import (
    AnalysisDecision,
    JustificationCode,
    NormalisedFinding,
    VexDecision,
    VexStatus,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal mappings  (our enums → CycloneDX vocabulary)
# ---------------------------------------------------------------------------

# VEX analysis state
_ANALYSIS_STATE: dict[AnalysisDecision, str] = {
    AnalysisDecision.BREAK_THE_BUILD:       "exploitable",
    AnalysisDecision.AFFECTED_REACHABLE:    "exploitable",
    AnalysisDecision.NOT_AFFECTED_DEV_ONLY: "not_affected",
    AnalysisDecision.NOT_AFFECTED_DEAD_CODE:"not_affected",
    AnalysisDecision.UNDER_INVESTIGATION:   "in_triage",
}

# Justification codes
_JUSTIFICATION: dict[JustificationCode, str] = {
    JustificationCode.COMPONENT_NOT_PRESENT:                            "component_not_present",
    JustificationCode.VULNERABLE_CODE_NOT_PRESENT:                      "code_not_present",
    JustificationCode.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH:              "code_not_reachable",
    JustificationCode.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY:"protected_by_compiler",
    JustificationCode.INLINE_MITIGATIONS_ALREADY_EXIST:                 "protected_by_mitigating_control",
}

# Recommended response per analysis state
_RESPONSES: dict[str, list[str]] = {
    "exploitable":   ["update", "workaround_available"],
    "not_affected":  ["will_not_fix"],
    "in_triage":     [],
}


# ---------------------------------------------------------------------------
# Exporter
# ---------------------------------------------------------------------------

class VexExporter:
    """
    Converts one or more VexDecision objects into a CycloneDX 1.5 VEX document.

    Example usage::

        exporter = VexExporter()
        exporter.add_decision(vex_decision, suggested_fix="Upgrade to X")
        json_str = exporter.export_json()
    """

    def __init__(self, author: str = "VEX Agent"):
        self._author = author
        self._vulnerabilities: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_decision(self, decision: VexDecision, suggested_fix: str = "") -> str:
        """
        Add a single VexDecision to the document.

        Returns the bom-ref assigned to the vulnerability entry.
        """
        bom_ref = str(uuid.uuid4())
        vuln = self._build_vulnerability(decision, suggested_fix, bom_ref)
        self._vulnerabilities.append(vuln)
        return bom_ref

    def export(self) -> dict[str, Any]:
        """Return the full CycloneDX VEX document as a dict."""
        return self._build_document()

    def export_json(self, indent: int = 2) -> str:
        """Return the CycloneDX VEX document serialised as a JSON string."""
        return json.dumps(self.export(), indent=indent)

    # ------------------------------------------------------------------
    # Document builder
    # ------------------------------------------------------------------

    def _build_document(self) -> dict[str, Any]:
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": now_iso,
                "tools": [
                    {
                        "vendor": "VEX Agent",
                        "name": "vex-agent",
                        "version": "1.0.0",
                    }
                ],
                "authors": [{"name": self._author}],
            },
            "vulnerabilities": self._vulnerabilities,
        }

    def _build_vulnerability(
        self,
        decision: VexDecision,
        suggested_fix: str,
        bom_ref: str,
    ) -> dict[str, Any]:
        finding = decision.finding
        cve_id = finding.cve_id or finding.ghsa_id or "UNKNOWN"

        # ── Source / reference ────────────────────────────────────────
        source = self._build_source(cve_id)

        # ── Ratings (CVSS) ────────────────────────────────────────────
        ratings = self._build_ratings(finding)

        # ── Affects ───────────────────────────────────────────────────
        affects = self._build_affects(finding, decision)

        # ── Analysis ──────────────────────────────────────────────────
        analysis = self._build_analysis(decision, suggested_fix)

        # ── Evidence: reachability hits ───────────────────────────────
        evidence = self._build_evidence(decision)

        vuln: dict[str, Any] = {
            "bom-ref": bom_ref,
            "id": cve_id,
            "source": source,
            "description": finding.summary or f"Vulnerability in {finding.package_name} {finding.vulnerable_version_range}",
            "affects": affects,
            "analysis": analysis,
        }
        if ratings:
            vuln["ratings"] = ratings
        if evidence:
            vuln["evidence"] = evidence
        if finding.references:
            vuln["references"] = [{"id": r, "source": {"url": r}} for r in finding.references[:10]]

        return vuln

    def _build_source(self, cve_id: str) -> dict[str, Any]:
        if cve_id.startswith("CVE-"):
            return {
                "name": "NVD",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }
        if cve_id.startswith("GHSA-"):
            return {
                "name": "GitHub Advisory Database",
                "url": f"https://github.com/advisories/{cve_id}",
            }
        return {"name": "Unknown"}

    def _build_ratings(self, finding: NormalisedFinding) -> list[dict[str, Any]]:
        ratings = []
        if finding.cvss_score is not None:
            rating: dict[str, Any] = {
                "source": {"name": "NVD"},
                "score": finding.cvss_score,
                "severity": finding.severity.value,
                "method": "CVSSv31",
            }
            if finding.cvss_vector_string:
                rating["vector"] = finding.cvss_vector_string
            ratings.append(rating)
        else:
            # Severity-only rating
            ratings.append({
                "source": {"name": "GitHub Advisory Database"},
                "severity": finding.severity.value,
            })
        return ratings

    def _build_affects(
        self,
        finding: NormalisedFinding,
        decision: VexDecision,
    ) -> list[dict[str, Any]]:
        # Build a PURL for the affected package
        eco = finding.package_ecosystem.lower()
        name = finding.package_name.lower()
        version = finding.package_version

        purl_map = {
            "pip": f"pkg:pypi/{name}@{version}",
            "pypi": f"pkg:pypi/{name}@{version}",
            "npm": f"pkg:npm/{name}@{version}",
            "maven": f"pkg:maven/{name}@{version}",
            "go": f"pkg:golang/{name}@{version}",
            "cargo": f"pkg:cargo/{name}@{version}",
            "nuget": f"pkg:nuget/{name}@{version}",
            "rubygems": f"pkg:gem/{name}@{version}",
        }
        purl = purl_map.get(eco, f"pkg:generic/{name}@{version}")

        version_status = (
            "affected"
            if decision.decision in (AnalysisDecision.AFFECTED_REACHABLE, AnalysisDecision.BREAK_THE_BUILD)
            else "unaffected"
        )

        return [
            {
                "ref": purl,
                "versions": [
                    {
                        "version": version,
                        "status": version_status,
                        "range": finding.vulnerable_version_range,
                    }
                ],
            }
        ]

    def _build_analysis(
        self,
        decision: VexDecision,
        suggested_fix: str,
    ) -> dict[str, Any]:
        state = _ANALYSIS_STATE.get(decision.decision, "in_triage")
        finding = decision.finding

        analysis: dict[str, Any] = {
            "state": state,
            "detail": decision.impact_statement or "",
        }

        if decision.justification_code:
            cdx_just = _JUSTIFICATION.get(decision.justification_code)
            if cdx_just:
                analysis["justification"] = cdx_just

        responses = list(_RESPONSES.get(state, []))
        # Only recommend "update" for exploitable findings that have a fix available
        if state == "exploitable" and finding.patched_version and "update" not in responses:
            responses.insert(0, "update")
        # Surface workaround if fix text was generated
        if suggested_fix and "workaround_available" not in responses:
            responses.append("workaround_available")
        if responses:
            analysis["response"] = responses

        if suggested_fix:
            # Truncate to first 4 lines for the brief detail field
            brief = "\n".join(suggested_fix.splitlines()[:4])
            analysis["detail"] = (analysis.get("detail", "") + "\n\n" + brief).strip()

        return analysis

    def _build_evidence(self, decision: VexDecision) -> Optional[dict[str, Any]]:
        hits = (decision.reachability_result.hits if decision.reachability_result else [])
        if not hits:
            return None
        return {
            "occurrences": [
                {
                    "location": f"{h.file_path}:{h.line_number}",
                    "symbol": h.function_called,
                    "additionalContext": h.line_content.strip(),
                }
                for h in hits
            ]
        }


# ---------------------------------------------------------------------------
# Convenience factory: single-decision export
# ---------------------------------------------------------------------------

def export_vex_for_decision(
    decision: VexDecision,
    suggested_fix: str = "",
) -> dict[str, Any]:
    """Shortcut: export a single VexDecision as a CycloneDX VEX document dict."""
    exporter = VexExporter()
    exporter.add_decision(decision, suggested_fix)
    return exporter.export()


def export_vex_json(
    decision: VexDecision,
    suggested_fix: str = "",
    indent: int = 2,
) -> str:
    """Shortcut: export a single VexDecision as a CycloneDX VEX JSON string."""
    exporter = VexExporter()
    exporter.add_decision(decision, suggested_fix)
    return exporter.export_json(indent=indent)
