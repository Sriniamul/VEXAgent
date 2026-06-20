"""
Application configuration.
All values can be supplied as environment variables or via a .env file.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # GitHub
    # ------------------------------------------------------------------
    github_token: str = ""
    """GitHub Personal Access Token (or GitHub App installation token)
    with permissions: security_events:read/write, contents:read, checks:write"""

    github_webhook_secret: str = ""
    """HMAC-SHA256 secret configured in the GitHub webhook settings."""

    # ------------------------------------------------------------------
    # Jira
    # ------------------------------------------------------------------
    jira_base_url: str = ""
    """e.g. https://yourorg.atlassian.net"""

    jira_email: str = ""
    jira_api_token: str = ""
    jira_project_key: str = ""
    """The Jira project key where tickets will be created, e.g. SEC"""

    jira_epic_key: str = ""
    """Jira EPIC key under which all created tickets will be grouped.
    e.g. ARM-6725"""

    jira_default_assignee: str = ""
    """Jira account ID to assign newly created tickets to.
    Use the Jira REST API to look up the account ID:
      GET /rest/api/3/user/search?query=GitHub+Copilot
    e.g. 712020:1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"""

    # ------------------------------------------------------------------
    # Microsoft Teams (optional — notifications via Incoming Webhook)
    # ------------------------------------------------------------------
    teams_webhook_url: str = ""
    """Incoming Webhook URL for a Teams channel.
    When set, an Adaptive Card is posted after each finding is processed.
    e.g. https://yourorg.webhook.office.com/webhookb2/..."""

    # ------------------------------------------------------------------
    # GitHub Copilot / GitHub Models (LLM analysis — preferred when token is set)
    # ------------------------------------------------------------------
    copilot_token: Optional[str] = None
    """GitHub token for LLM access.
    - PAT (ghp_ / github_pat_) with 'models:read' scope → GitHub Models API
    - VS Code OAuth session token → GitHub Copilot API
    When set, this is used in preference to OPENAI_API_KEY."""

    copilot_model: str = "gpt-4o"
    """Model to request from the LLM provider.
    Examples: gpt-4o, gpt-4o-mini, Meta-Llama-3.1-405B-Instruct"""

    copilot_api_base: str = ""
    """Override the API base URL.
    Leave empty to let the app auto-select based on token type:
      PAT  → https://models.inference.ai.azure.com
      OAuth/session → https://api.githubcopilot.com"""

    # ------------------------------------------------------------------
    # OpenAI (LLM analysis — fallback when copilot_token is not set)
    # ------------------------------------------------------------------
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4o"
    """Model used for LLM-assisted reachability analysis."""

    # ------------------------------------------------------------------
    # Target repository (used by clone tests and manual pipeline runs)
    # ------------------------------------------------------------------
    local_repo_path: str = ""
    """Absolute path to an already-cloned local repository.
    When set the agent will use this directory directly (checkout branch + pull)
    instead of performing a fresh shallow clone.
    e.g. C:/repos/arm-arm"""

    target_repo_url: str = ""
    """Clone URL of the repository to analyse, e.g.
    https://github.com/solarwinds-internal/arm-arm.git"""

    target_repo_branch: str = "main"
    """Branch to check out when cloning the target repository."""

    # ------------------------------------------------------------------
    # Persistent repo cache
    # ------------------------------------------------------------------
    repo_cache_dir: str = ""
    """Directory where persistent repository clones and source-file caches are
    stored.  When set, the agent clones a repo only once; subsequent runs
    use ``git fetch`` + ``git reset`` and reuse the built file cache if HEAD
    has not changed.  Defaults to ``{cwd}/.repo_cache`` when empty.
    e.g. D:/vex-cache"""

    enable_repo_cache: bool = True
    """Enable the persistent repo cache.  When False, the agent falls back to
    the original behaviour of shallow-cloning into a temp directory per
    invocation and discarding it afterward."""

    # ------------------------------------------------------------------
    # EPSS
    # ------------------------------------------------------------------
    epss_threshold: float = 0.1
    """EPSS score above which a reachable CVE triggers 'break the build'."""

    # ------------------------------------------------------------------
    # Agent behaviour
    # ------------------------------------------------------------------
    skip_dev_dependencies: bool = True
    """Automatically mark findings in devDependencies as NOT_AFFECTED."""

    enable_llm_fallback: bool = True
    """Use the LLM analyzer when AST analysis finds no hits."""

    enable_break_the_build: bool = True
    """Create a failing GitHub Check Run when EPSS > threshold and reachable."""

    # ------------------------------------------------------------------
    # License compliance
    # ------------------------------------------------------------------
    enable_license_check: bool = True
    """When True, each dependency is checked against the license policy
    and a License Risk value is included in the dashboard."""

    blocked_licenses: str = "AGPL,SSPL,GPL"
    """Comma-separated list of license patterns that are denied outright.
    Matching is case-insensitive regex against the SPDX identifier.
    e.g. AGPL,SSPL,GPL  (LGPL is NOT matched by 'GPL' — the pattern uses \\bGPL\\b)."""

    warn_licenses: str = "LGPL,MPL,EPL,CDDL"
    """Comma-separated list of license patterns that produce a warning.
    These don't block the build but appear as medium risk in the dashboard."""

    # ------------------------------------------------------------------
    # Human review
    # ------------------------------------------------------------------
    enable_human_review: bool = False
    """When True, findings that meet the review criteria are paused for human
    approval before Jira tickets are created and the build is broken."""

    review_confidence_threshold: float = 0.75
    """Require human review when LLM reachability confidence is below this value."""

    review_on_critical: bool = True
    """Always require human review for critical-severity findings."""

    review_timeout_hours: int = 24
    """Auto-mark a review as timed_out if no action is taken within this period."""

    review_base_url: str = ""
    """Public base URL of this agent, used to build Approve/Dismiss button URLs
    in the Teams review card.  e.g. https://vex-agent.yourcompany.com
    If empty, buttons will be rendered as plain text links."""

    # ------------------------------------------------------------------
    # VEX / SBOM output — SharePoint (Microsoft Graph API)
    # ------------------------------------------------------------------
    sharepoint_tenant_id: str = ""
    """Azure AD tenant ID (GUID) for the Microsoft 365 organisation."""

    sharepoint_client_id: str = ""
    """App registration client ID (GUID).
    The app must have the Graph API application permission Sites.ReadWrite.All
    (or Files.ReadWrite.All scoped to the target site)."""

    sharepoint_client_secret: str = ""
    """Client secret for the app registration above."""

    sharepoint_site_url: str = ""
    """Full URL to the destination SharePoint site.
    e.g. https://myorg.sharepoint.com/sites/MySite"""

    sharepoint_folder_path: str = "Shared Documents/VEX-Store"
    """Root folder path inside the document library where artefacts are stored.
    Files are uploaded as:
      {sharepoint_folder_path}/{JIRA_PROJECT_KEY}/{product_version}/vex-*.cdx.json
      {sharepoint_folder_path}/{JIRA_PROJECT_KEY}/{product_version}/sbom-*.cdx.json
    Defaults to 'Shared Documents/VEX-Store'."""

    # ------------------------------------------------------------------
    # Mock / simulation mode
    # ------------------------------------------------------------------
    use_mock_github_data: bool = False
    """When True, all GitHub alert fetching (Dependabot, code-scanning,
    secret-scanning) returns the built-in simulated dataset instead of calling
    the real GitHub API.  Controlled automatically by the --simulate CLI flag;
    do NOT set manually in .env."""

    mock_repo_full_name: str = "solarwinds-internal/arm-arm"
    """Repository name reported in findings when USE_MOCK_GITHUB_DATA=true."""

    shallow_clone_depth: int = 1
    log_level: str = "INFO"
    host: str = "0.0.0.0"
    port: int = 49152


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings: Settings = get_settings()
