# GitVexAgent

Automated VEX (Vulnerability Exploitability eXchange) triage agent that processes GitHub security alerts, performs multi-level reachability analysis, and produces standards-compliant CycloneDX VEX/SBOM documents — so your team only fixes what actually matters.

---

## Overview

**GitVexAgent** is a FastAPI-based service that listens for GitHub Dependabot and code-scanning webhook events, then automatically determines whether each vulnerability is actually exploitable in your codebase. It produces machine-readable **CycloneDX VEX** and **SBOM** documents, creates or updates **Jira** tickets for real findings, and can **block the build** when a high-risk, reachable vulnerability is detected.

Key goals:

- **Reduce alert fatigue** — automatically dismiss findings that only affect dev/test dependencies or involve unreachable code.
- **Standards-compliant output** — generate CycloneDX 1.5 VEX and SBOM JSON artefacts.
- **Full traceability** — every decision is justified and recorded (GitHub comments, Jira tickets, VEX docs).
- **Human-in-the-loop** — optional review queue for low-confidence or critical findings before action is taken.

---

## Architecture

```
GitHub (Dependabot / Code Scanning)
        │  webhook
        ▼
┌───────────────────────────────────────────┐
│              GitVexAgent (FastAPI)         │
│                                           │
│  ┌─────────────┐   ┌──────────────────┐   │
│  │ VEX Agent   │──▶│ L1: Metadata     │   │
│  │ Orchestrator│   │    Analyzer       │   │
│  │             │──▶│ L2: Reachability  │   │
│  │             │   │    (AST + LLM)    │   │
│  │             │──▶│ EPSS Score Fetch  │   │
│  └──────┬──────┘   └──────────────────┘   │
│         │                                 │
│         ▼                                 │
│  ┌──────────────────────────────────────┐ │
│  │  Actions:                            │ │
│  │  • Dismiss alert on GitHub           │ │
│  │  • Create / update Jira ticket       │ │
│  │  • Break the build (Check Run)       │ │
│  │  • Notify Microsoft Teams            │ │
│  │  • Generate CycloneDX VEX + SBOM     │ │
│  │  • Upload to SharePoint              │ │
│  │  • Queue for human review            │ │
│  └──────────────────────────────────────┘ │
│                                           │
│  ┌──────────────────────────────────────┐ │
│  │  Web Dashboard  (live stats, export) │ │
│  └──────────────────────────────────────┘ │
└───────────────────────────────────────────┘
```

---

## Analysis Pipeline

Each incoming alert flows through a deterministic pipeline:

| Step | Name | Description |
|------|------|-------------|
| 1 | **Normalise** | Parse the GitHub webhook payload into a canonical `NormalisedFinding`. |
| 2 | **EPSS** | Fetch the [EPSS](https://www.first.org/epss/) score (probability of exploitation in 30 days). |
| 3 | **L1 — Metadata** | Check manifest files (package.json, requirements.txt, pyproject.toml, pom.xml, …) to determine if the package is dev/test-only. |
| 4 | **L2 — Reachability (AST)** | Parse source code ASTs (Python, JS/TS, Java) and grep for calls to known vulnerable functions. |
| 4b | **L2b — Reachability (LLM)** | If AST finds no hits and `ENABLE_LLM_FALLBACK=true`, send focused code snippets to an LLM for deeper analysis. |
| 5 | **Decide** | Map analysis results to a VEX decision: `not_affected`, `affected`, `under_investigation`, or `break_the_build`. |
| 6 | **Act** | Execute downstream actions (GitHub dismiss, Jira, Teams, VEX/SBOM export, build gate). |

### Decision Matrix

| Condition | Decision | VEX Status |
|-----------|----------|------------|
| Dev/test-only dependency | `NOT_AFFECTED_DEV_ONLY` | `not_affected` |
| Vulnerable code is unreachable | `NOT_AFFECTED_DEAD_CODE` | `not_affected` |
| Vulnerable code is reachable | `AFFECTED_REACHABLE` | `affected` |
| Reachable + EPSS > threshold | `BREAK_THE_BUILD` | `affected` |
| Analysis inconclusive | `UNDER_INVESTIGATION` | `under_investigation` |

---

## Features

- **GitHub Webhook Integration** — Processes `dependabot_alert` and `code_scanning_alert` events with HMAC-SHA256 signature verification.
- **Multi-Ecosystem Support** — Analyses npm, pip, Poetry, Bundler, Maven, Gradle, Go, Cargo, and .NET manifests.
- **AST + LLM Reachability** — Two-tier analysis: fast AST/regex scan, then optional LLM fallback (GitHub Copilot API or OpenAI).
- **EPSS Risk Scoring** — Fetches real-time EPSS scores to gauge exploitation likelihood.
- **CycloneDX VEX & SBOM** — Generates standards-compliant CycloneDX 1.5 JSON documents.
- **Build Gate** — Creates a failing GitHub Check Run to block merges when a critical reachable vulnerability is found.
- **Jira Integration** — Automatically creates or updates Jira tickets with reachability evidence and suggested fixes.
- **Microsoft Teams Notifications** — Posts Adaptive Cards with decision summaries, EPSS scores, and action buttons.
- **Human Review Queue** — SQLite-backed queue for low-confidence or critical findings with approve/override/dismiss workflow.
- **SharePoint Upload** — Uploads VEX and SBOM artefacts to a SharePoint document library via Microsoft Graph API.
- **Live Dashboard** — Web UI showing pipeline run history, statistics, and export options.
- **Excel/PDF Export & Import** — Export alert reports to `.xlsx` or `.pdf`; import alerts from Excel for batch analysis.
- **Simulation Mode** — Built-in mock data for demos and testing without a live GitHub connection.
- **GitHub OAuth Login** — Dashboard authentication via GitHub token with session cookies.

---

## Project Structure

```
GitVexAgent/
├── main.py                        # FastAPI app, webhook endpoint, dashboard, all API routes
├── config.py                      # Pydantic-based settings (env vars / .env file)
├── requirements.txt               # Python dependencies
├── pytest.ini                     # Pytest configuration
├── mock-vex-report.cdx.json       # Sample CycloneDX VEX document
│
├── agents/
│   └── vex_agent.py               # VEX Agent orchestrator (pipeline, decision logic, actions)
│
├── analyzers/
│   ├── metadata_analyzer.py       # L1: Dev/test dependency detection (multi-ecosystem)
│   └── reachability_analyzer.py   # L2: AST-based reachability analysis (Python, JS/TS, Java)
│
├── clients/
│   ├── epss_client.py             # FIRST.org EPSS API client
│   ├── github_client.py           # GitHub REST API client (alerts, check runs, dismissals)
│   ├── jira_client.py             # Jira REST API v3 client (ticket creation/update)
│   ├── teams_client.py            # Microsoft Teams Incoming Webhook (Adaptive Cards)
│   └── mock_github_data.py        # Simulated GitHub alerts for --simulate mode
│
├── models/
│   └── vex_models.py              # Pydantic models (findings, decisions, VEX/EPSS types)
│
├── utils/
│   ├── alert_exporter.py          # Excel (.xlsx) & PDF export for alert reports
│   ├── alert_importer.py          # Excel import → batch analysis pipeline
│   ├── dashboard_store.py         # In-memory dashboard telemetry store
│   ├── git_utils.py               # Shallow clone, local repo, source file iteration
│   ├── llm_analyzer.py            # LLM-assisted reachability (Copilot / OpenAI)
│   ├── report_generator.py        # Full security report generator (SBOM + VEX + SharePoint)
│   ├── review_queue.py            # SQLite-backed human review queue
│   ├── sbom_generator.py          # CycloneDX 1.5 SBOM generator
│   ├── vex_exporter.py            # CycloneDX 1.5 VEX document exporter
│   └── vex_file_store.py          # SharePoint (Graph API) VEX/SBOM upload
│
├── templates/
│   ├── dashboard.html             # Live dashboard UI
│   └── login.html                 # GitHub login page
│
└── tests/                         # Pytest suite (unit + integration)
    ├── conftest.py
    ├── test_all_decisions.py
    ├── test_build_blocked.py
    ├── test_clone.py
    ├── test_dashboard.py
    ├── test_jira.py
    ├── test_l1_human_review_live.py
    ├── test_l1_not_affected.py
    ├── test_llm.py
    ├── test_metadata_analyzer.py
    ├── test_reachability_analyzer.py
    ├── test_review.py
    ├── test_sbom_vex.py
    ├── test_simulate_flag.py
    ├── test_teams.py
    └── test_webhook.py
```

---

## Prerequisites

- **Python 3.11+**
- **Git** (for shallow cloning target repositories)
- A **GitHub Personal Access Token** with scopes: `security_events`, `contents:read`, `checks:write`
- (Optional) **Jira** cloud account + API token
- (Optional) **Microsoft Teams** Incoming Webhook URL
- (Optional) **OpenAI API key** or **GitHub Copilot** token for LLM-assisted analysis
- (Optional) **Azure AD app registration** for SharePoint upload

---

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/GitVexAgent.git
cd GitVexAgent

# Create a virtual environment
python -m venv .venv

# Activate it
# Windows
.venv\Scripts\Activate.ps1
# Linux / macOS
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## Configuration

All configuration is done via **environment variables** or a `.env` file in the project root. See [config.py](config.py) for the full list.

### Required

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | GitHub PAT with `security_events`, `contents:read`, `checks:write` |
| `GITHUB_WEBHOOK_SECRET` | HMAC-SHA256 secret for webhook signature verification |

### Optional — Jira

| Variable | Description |
|----------|-------------|
| `JIRA_BASE_URL` | e.g. `https://yourorg.atlassian.net` |
| `JIRA_EMAIL` | Jira account email |
| `JIRA_API_TOKEN` | Jira API token |
| `JIRA_PROJECT_KEY` | Project key (e.g. `SEC`) |
| `JIRA_EPIC_KEY` | Epic key to group tickets under |

### Optional — Teams

| Variable | Description |
|----------|-------------|
| `TEAMS_WEBHOOK_URL` | Incoming Webhook URL for a Teams channel |

### Optional — LLM Analysis

| Variable | Description |
|----------|-------------|
| `COPILOT_TOKEN` | GitHub token for Copilot/Models API (preferred over OpenAI) |
| `COPILOT_MODEL` | Model name (default: `gpt-4o`) |
| `OPENAI_API_KEY` | OpenAI API key (fallback when `COPILOT_TOKEN` is not set) |

### Optional — SharePoint

| Variable | Description |
|----------|-------------|
| `SHAREPOINT_TENANT_ID` | Azure AD tenant ID |
| `SHAREPOINT_CLIENT_ID` | App registration client ID |
| `SHAREPOINT_CLIENT_SECRET` | Client secret |
| `SHAREPOINT_SITE_URL` | e.g. `https://myorg.sharepoint.com/sites/MySite` |
| `SHAREPOINT_FOLDER_PATH` | Upload folder (default: `Shared Documents/VEX-Store`) |

### Agent Behaviour

| Variable | Default | Description |
|----------|---------|-------------|
| `EPSS_THRESHOLD` | `0.1` | EPSS score above which reachable CVEs trigger build break |
| `SKIP_DEV_DEPENDENCIES` | `true` | Auto-dismiss dev-only dependencies |
| `ENABLE_LLM_FALLBACK` | `true` | Use LLM when AST finds no hits |
| `ENABLE_BREAK_THE_BUILD` | `true` | Create failing Check Run for high-risk findings |
| `ENABLE_HUMAN_REVIEW` | `false` | Require human approval before dismissing alerts |
| `REVIEW_TIMEOUT_HOURS` | `24` | Auto-timeout for unreviewed items |
| `LOG_LEVEL` | `INFO` | Logging level |

---

## Usage

### Webhook Mode (Production)

Start the server and configure a GitHub webhook to point at your instance:

```bash
# Start the server
python main.py

# Or with uvicorn directly
uvicorn main:app --host 0.0.0.0 --port 49152
```

Then in your GitHub repository settings:
1. Go to **Settings → Webhooks → Add webhook**
2. **Payload URL**: `https://your-host:49152/webhook/github`
3. **Content type**: `application/json`
4. **Secret**: same value as `GITHUB_WEBHOOK_SECRET`
5. **Events**: select `Dependabot alerts` and `Code scanning alerts`

### Simulation Mode (Demo / Testing)

Run the agent with built-in mock data — no live GitHub connection needed:

```bash
python main.py --simulate
```

This uses the mock dataset from `mock_github_data.py` and processes all simulated alerts through the full pipeline.

### Generate Security Report

Generate a full security report (SBOM + VEX) for a repository:

```bash
python main.py --generate-report --target-repo https://github.com/org/repo.git
```

The report is uploaded to SharePoint if credentials are configured.

### Dashboard

Once the server is running, visit:

```
http://localhost:49152/dashboard
```

The dashboard shows:
- Pipeline run history with per-alert decisions
- Aggregated statistics (affected vs. not-affected vs. under-investigation)
- Pending human reviews
- Export buttons for Excel, PDF, SBOM, and VEX documents

---

## API Endpoints

### Webhook

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/webhook/github` | Receive GitHub security webhook events |

### Dashboard & Auth

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/dashboard` | Live dashboard UI |
| `GET` | `/login` | GitHub login page |
| `POST` | `/api/v1/login` | Authenticate (GitHub username + PAT) |
| `POST` | `/api/v1/logout` | Log out |
| `GET` | `/api/v1/me` | Current user info |
| `GET` | `/api/v1/stats` | Dashboard statistics |
| `GET` | `/api/v1/pipeline-runs` | Recent pipeline runs |
| `GET` | `/api/v1/settings` | Current configuration (masked) |
| `PUT` | `/api/v1/settings` | Update configuration at runtime |

### Export / Import

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/export/sbom` | Download CycloneDX SBOM |
| `GET` | `/api/v1/export/vex-report` | Download CycloneDX VEX report |
| `GET` | `/api/v1/export/alerts-excel` | Export alerts as `.xlsx` |
| `GET` | `/api/v1/export/alerts-pdf` | Export alerts as PDF |
| `POST` | `/api/v1/export/run-report` | Generate full report + upload to SharePoint |
| `POST` | `/api/v1/import/alerts-excel` | Upload Excel → batch analysis |
| `GET` | `/api/v1/import/progress` | Poll import progress |

### Human Review

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/review/pending` | List pending reviews |
| `GET` | `/review/{id}` | Get review detail |
| `POST` | `/review/{id}/approve` | Approve the agent's decision |
| `POST` | `/review/{id}/override` | Override with a different decision |
| `POST` | `/review/{id}/dismiss` | Dismiss the review (leave alert open) |

### Simulation (Dev/Test)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/mock/simulate` | Populate dashboard with simulated alerts |
| `POST` | `/api/v1/mock/create-jira-tickets` | Create mock Jira tickets |

---

## Human Review Workflow

When `ENABLE_HUMAN_REVIEW=true`, the agent pauses before auto-dismissing alerts:

1. The agent analyses the alert and decides `NOT_AFFECTED`.
2. Instead of dismissing immediately, it **queues the finding for review** (SQLite).
3. A **Teams Adaptive Card** is posted with Approve / Override / Dismiss buttons.
4. A reviewer clicks a button (or uses the API / dashboard).
5. The agent **finalises**: dismisses the GitHub alert (if approved), creates Jira tickets (if overridden to affected), and posts a resolution card to Teams.
6. If no action is taken within `REVIEW_TIMEOUT_HOURS`, the review is marked as `timed_out`.

---

## Integrations

| Service | Purpose | Required |
|---------|---------|----------|
| **GitHub** | Webhook events, alert management, Check Runs | Yes |
| **FIRST.org EPSS** | Exploitation probability scoring | Auto (public API) |
| **Jira** | Ticket creation for affected findings | Optional |
| **Microsoft Teams** | Adaptive Card notifications | Optional |
| **GitHub Copilot / OpenAI** | LLM-assisted reachability analysis | Optional |
| **SharePoint** | VEX/SBOM document storage | Optional |

---

## Testing

```bash
# Run the full test suite
pytest

# Run a specific test file
pytest tests/test_webhook.py -v

# Run with coverage
pytest --cov=. --cov-report=term-missing
```

The test suite includes:
- Webhook signature verification
- All decision paths (dev-only, dead code, reachable, build-blocked)
- Human review lifecycle
- Jira ticket creation
- Teams notification formatting
- SBOM/VEX generation
- LLM analyzer mocking
- Dashboard API
- Simulation mode

---

