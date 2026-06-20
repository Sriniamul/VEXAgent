"""
Pydantic models for the VEX Agent pipeline.
Covers GitHub webhook payloads, internal analysis state, and VEX output.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class VexStatus(str, Enum):
    """VEX Vulnerability Exploitability eXchange statuses (OpenVEX spec)."""
    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


class JustificationCode(str, Enum):
    """OpenVEX justification codes for NOT_AFFECTED status."""
    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = "vulnerable_code_cannot_be_controlled_by_adversary"
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class AnalysisDecision(str, Enum):
    NOT_AFFECTED_DEV_ONLY = "not_affected_dev_only"
    NOT_AFFECTED_DEAD_CODE = "not_affected_dead_code"
    AFFECTED_REACHABLE = "affected_reachable"
    BREAK_THE_BUILD = "break_the_build"
    UNDER_INVESTIGATION = "under_investigation"


# ---------------------------------------------------------------------------
# GitHub Webhook Payload Models
# ---------------------------------------------------------------------------

class GitHubRepo(BaseModel):
    id: int
    name: str
    full_name: str
    html_url: str
    clone_url: str
    default_branch: str = "main"
    private: bool = False


class DependabotAlert(BaseModel):
    number: int
    state: str
    dependency: dict[str, Any]
    security_advisory: dict[str, Any]
    security_vulnerability: dict[str, Any]
    url: str
    html_url: str
    auto_dismissed_at: Optional[str] = None
    dismissed_at: Optional[str] = None


class CodeScanningAlert(BaseModel):
    number: int
    state: str
    rule: dict[str, Any]
    tool: dict[str, Any]
    most_recent_instance: dict[str, Any]
    url: str
    html_url: str


class GitHubSecurityWebhookPayload(BaseModel):
    """Unified webhook payload for dependabot_alert and code_scanning_alert events."""
    action: str
    alert: dict[str, Any]
    repository: GitHubRepo
    installation: Optional[dict[str, Any]] = None
    sender: Optional[dict[str, Any]] = None

    @property
    def repo_full_name(self) -> str:
        return self.repository.full_name

    @property
    def repo_clone_url(self) -> str:
        return self.repository.clone_url


# ---------------------------------------------------------------------------
# Normalised Finding (internal representation)
# ---------------------------------------------------------------------------

class NormalisedFinding(BaseModel):
    """Internal canonical representation of a security finding."""
    alert_id: int
    repo_full_name: str
    repo_clone_url: str
    repo_default_branch: str

    cve_id: Optional[str] = None
    ghsa_id: Optional[str] = None
    package_name: str
    package_version: str
    package_ecosystem: str          # npm, pip, maven, go, etc.
    vulnerable_version_range: str
    patched_version: Optional[str] = None

    severity: Severity
    cvss_score: Optional[float] = None
    cvss_vector_string: Optional[str] = None

    # Where the dependency appears in the manifest
    manifest_path: Optional[str] = None
    scope: Optional[str] = None     # "runtime" | "development"

    # Vulnerable function/method reported by the advisory (may be None)
    vulnerable_functions: list[str] = Field(default_factory=list)

    summary: str = ""
    references: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# EPSS Models
# ---------------------------------------------------------------------------

class EpssScore(BaseModel):
    cve: str
    epss: float          # 0.0 – 1.0  probability of exploitation in 30 days
    percentile: float    # relative to all scored CVEs
    date: str


# ---------------------------------------------------------------------------
# Analysis Result Models
# ---------------------------------------------------------------------------

class MetadataAnalysisResult(BaseModel):
    is_dev_dependency: bool
    is_test_dependency: bool
    dependency_scope: str           # "devDependencies", "dependencies", etc.
    manifest_path: str
    justification: str = ""


class ReachabilityHit(BaseModel):
    file_path: str
    line_number: int
    line_content: str
    function_called: str
    confidence: float               # 0.0 – 1.0


class ImportSite(BaseModel):
    """A file that imports/references the package but does NOT call the
    vulnerable function(s).  Used to explain *why* the code is not affected."""
    file_path: str
    line_number: int = 0
    line_content: str = ""
    import_statement: str = ""      # e.g. "import requests"
    functions_used: list[str] = Field(default_factory=list)  # safe APIs called


class ReachabilityAnalysisResult(BaseModel):
    reachable: bool
    hits: list[ReachabilityHit] = Field(default_factory=list)
    import_sites: list[ImportSite] = Field(default_factory=list)
    method: str = ""                # "ast", "llm", "endor", "snyk"
    confidence: float = 0.0
    notes: str = ""


# ---------------------------------------------------------------------------
# Final VEX Decision
# ---------------------------------------------------------------------------

class VexDecision(BaseModel):
    finding: NormalisedFinding
    decision: AnalysisDecision

    epss_score: Optional[EpssScore] = None
    metadata_result: Optional[MetadataAnalysisResult] = None
    reachability_result: Optional[ReachabilityAnalysisResult] = None

    vex_status: VexStatus
    justification_code: Optional[JustificationCode] = None
    impact_statement: str = ""

    # Actions taken
    github_status_updated: bool = False
    jira_ticket_updated: bool = False
    build_broken: bool = False

    # Error tracking
    errors: list[str] = Field(default_factory=list)
