"""
LLM-assisted reachability analysis.

Supports two providers, selected automatically based on available credentials:
  1. GitHub Copilot API  (preferred)  — set COPILOT_TOKEN
  2. OpenAI API          (fallback)   — set OPENAI_API_KEY

Both providers are accessed through the OpenAI-compatible chat-completions
interface, so the same client code works for both.
"""

from __future__ import annotations

import logging
import textwrap
import time
from pathlib import Path
from typing import Optional

from config import settings
from models.vex_models import ReachabilityAnalysisResult, ReachabilityHit
from utils.git_utils import iter_source_files

logger = logging.getLogger(__name__)


_SYSTEM_PROMPT = """\
You are a senior application security engineer performing a code reachability audit.
Your task is to determine whether a specific vulnerable function from a third-party
library is actually called (directly or indirectly) in the provided source file.

Respond ONLY with valid JSON in the following schema:
{
  "reachable": true | false,
  "confidence": 0.0 - 1.0,
  "evidence": [
    { "line_number": <int>, "line_content": "<string>", "function_called": "<string>" }
  ],
  "reasoning": "<one-sentence explanation>"
}
"""


class LLMReachabilityAnalyzer:
    """
    Sends focused source-code snippets to an LLM and parses its JSON verdict.

    Provider selection (first match wins):
      1. COPILOT_TOKEN  → GitHub Copilot API (``copilot_api_base``)
      2. OPENAI_API_KEY → OpenAI API

    When COPILOT_TOKEN is a GitHub PAT (starts with ``ghp_`` or
    ``github_pat_``) the analyzer automatically exchanges it for a
    short-lived Copilot session token before every batch of LLM calls.
    Session tokens are cached until 60 s before expiry.
    """

    _copilot_session_token: str = ""
    _copilot_session_expires_at: float = 0.0   # unix timestamp

    def __init__(self):
        if settings.copilot_token:
            self._enabled = True
            self._provider = "copilot"
            self._api_key = settings.copilot_token
            self._model = settings.copilot_model

            # Auto-select base URL based on token type if not overridden
            if settings.copilot_api_base:
                self._base_url: str | None = settings.copilot_api_base
            elif self._is_pat(settings.copilot_token):
                # GitHub PAT → GitHub Models API (accepts PATs, supports Claude)
                self._base_url = "https://models.inference.ai.azure.com"
                self._provider = "github_models"
            else:
                # OAuth / session token → GitHub Copilot API
                self._base_url = "https://api.githubcopilot.com"

            logger.info(
                "LLM analyzer enabled: %s (model=%s, base=%s)",
                self._provider,
                self._model,
                self._base_url,
            )
        elif settings.openai_api_key:
            self._enabled = True
            self._provider = "openai"
            self._api_key = settings.openai_api_key
            self._base_url = None
            self._model = settings.openai_model
            logger.info("LLM analyzer enabled: OpenAI API (model=%s)", self._model)
        else:
            self._enabled = False
            self._provider = "none"
            self._api_key = ""
            self._base_url = None
            self._model = ""
            logger.info("LLM analyzer disabled: set COPILOT_TOKEN or OPENAI_API_KEY.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def analyse(
        self,
        repo_root: Path,
        package_name: str,
        vulnerable_functions: list[str],
        candidate_files: Optional[list[str]] = None,
        max_files: int = 10,
        max_chars_per_file: int = 8_000,
    ) -> ReachabilityAnalysisResult:
        """
        Analyse the most promising source files with the LLM.
        *candidate_files* can be pre-filtered by the AST analyzer to reduce tokens.
        """
        if not self._enabled:
            return ReachabilityAnalysisResult(
                reachable=False,
                method="llm",
                confidence=0.0,
                notes="LLM analyzer is disabled (no COPILOT_TOKEN or OPENAI_API_KEY).",
            )

        try:
            from openai import AsyncOpenAI  # lazy import
        except ImportError:
            return ReachabilityAnalysisResult(
                reachable=False,
                method="llm",
                confidence=0.0,
                notes="openai package not installed.",
            )

        # Build client — works for both Copilot and OpenAI since Copilot
        # exposes an OpenAI-compatible chat/completions endpoint.
        if self._provider in ("copilot", "github_models"):
            resolved_key = await self._resolve_copilot_token()
        else:
            resolved_key = self._api_key

        client_kwargs: dict = {"api_key": resolved_key}
        if self._base_url:
            client_kwargs["base_url"] = self._base_url
        client = AsyncOpenAI(**client_kwargs)

        files_to_scan = self._select_files(
            repo_root, candidate_files, max_files, package_name
        )

        all_hits: list[ReachabilityHit] = []
        max_confidence: float = 0.0

        for rel_path, abs_path in files_to_scan:
            content = abs_path.read_text(encoding="utf-8", errors="replace")
            if len(content) > max_chars_per_file:
                content = content[:max_chars_per_file] + "\n... [truncated]"

            user_message = textwrap.dedent(f"""\
                ## File: {rel_path}

                ```
                {content}
                ```

                ## Vulnerable package: {package_name}
                ## Vulnerable functions: {', '.join(vulnerable_functions) or 'unknown'}

                Is any of these functions called (or imported and used) in this file?
            """)

            try:
                response = await client.chat.completions.create(
                    model=self._model,
                    messages=[
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": user_message},
                    ],
                    temperature=0,
                    response_format={"type": "json_object"},
                    timeout=30,
                )
            except Exception as exc:  # noqa: BLE001
                err_str = str(exc)
                if "models` permission" in err_str or "models permission" in err_str:
                    logger.error(
                        "LLM call failed: token is missing the 'models' permission. "
                        "Create a new PAT at https://github.com/settings/tokens with the "
                        "'Models: Read and write' permission under GitHub Models."
                    )
                elif "Personal Access Tokens are not supported" in err_str:
                    logger.error(
                        "LLM call failed: this endpoint requires an OAuth session token, not a PAT. "
                        "Use a PAT with the 'models' scope or set COPILOT_API_BASE explicitly."
                    )
                else:
                    logger.warning("LLM call failed for %s: %s", rel_path, exc)
                continue

            verdict = self._parse_verdict(response.choices[0].message.content or "{}")
            if verdict.get("reachable"):
                conf = float(verdict.get("confidence", 0.5))
                max_confidence = max(max_confidence, conf)
                for ev in verdict.get("evidence", []):
                    all_hits.append(ReachabilityHit(
                        file_path=rel_path,
                        line_number=int(ev.get("line_number", 0)),
                        line_content=str(ev.get("line_content", "")),
                        function_called=str(ev.get("function_called", "unknown")),
                        confidence=conf,
                    ))

        return ReachabilityAnalysisResult(
            reachable=len(all_hits) > 0,
            hits=all_hits,
            method="llm",
            confidence=max_confidence,
            notes=f"LLM provider={self._provider} model={self._model} scanned {len(files_to_scan)} file(s).",
        )

    async def suggest_fix(
        self,
        finding,
        hits: list[ReachabilityHit],
    ) -> str:
        """
        Ask the LLM to produce a concise, actionable remediation guide for
        the confirmed-reachable vulnerability.

        Returns a plain Markdown string, or an empty string when the LLM
        is disabled / unavailable.
        """
        if not self._enabled:
            return ""

        try:
            from openai import AsyncOpenAI
        except ImportError:
            return ""

        if self._provider in ("copilot", "github_models"):
            resolved_key = await self._resolve_copilot_token()
        else:
            resolved_key = self._api_key

        client_kwargs: dict = {"api_key": resolved_key}
        if self._base_url:
            client_kwargs["base_url"] = self._base_url
        client = AsyncOpenAI(**client_kwargs)

        hit_lines = "\n".join(
            f"  - {h.file_path}:{h.line_number}  `{h.line_content.strip()}`"
            for h in hits[:8]
        )

        user_message = textwrap.dedent(f"""\
            ## Vulnerability summary
            - Package      : {finding.package_name} {getattr(finding, 'package_version', '')}
            - CVE          : {finding.cve_id or 'N/A'}
            - CVSS score   : {finding.cvss_score or 'N/A'}
            - Severity     : {finding.severity.value}
            - Description  : {finding.summary}
            - Vuln functions: {', '.join(finding.vulnerable_functions) or 'unknown'}

            ## Confirmed call sites in this repository
{hit_lines}

            ## Your task
            Provide a short, developer-friendly remediation guide with:
            1. **Root cause** – why this specific usage is dangerous (1-2 sentences).
            2. **Safe alternative** – the exact safe API / version to use instead,
               with a before/after code snippet.
            3. **Upgrade path** – minimum safe version and any breaking-change notes.
            4. **Quick verification** – a one-liner to check the fix was applied.

            Format your response in Markdown.  Keep it under 400 words.
        """)

        try:
            response = await client.chat.completions.create(
                model=self._model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a senior application security engineer. "
                            "You give concise, accurate remediation advice for software vulnerabilities."
                        ),
                    },
                    {"role": "user", "content": user_message},
                ],
                temperature=0.2,
                timeout=45,
            )
            return response.choices[0].message.content or ""
        except Exception as exc:  # noqa: BLE001
            logger.warning("suggest_fix LLM call failed: %s", exc)
            return ""

    # ------------------------------------------------------------------
    # Copilot token exchange
    # ------------------------------------------------------------------

    @staticmethod
    def _is_pat(token: str) -> bool:
        """Return True if *token* looks like a GitHub Personal Access Token."""
        return token.startswith(("ghp_", "github_pat_")) or (
            # Classic fine-grained tokens are 40-char hex strings
            len(token) == 40 and all(c in "0123456789abcdefABCDEF" for c in token)
        )

    async def _resolve_copilot_token(self) -> str:
        """
        Return a valid Copilot session token.

        - PATs going to GitHub Models API are used as-is (no exchange needed).
        - Session tokens (``tid=``) are used as-is.
        - OAuth tokens are exchanged for a short-lived Copilot session token
          via the Copilot internal API and cached until 60 s before expiry.
        """
        raw = self._api_key

        # PATs used with GitHub Models API — pass through directly
        if self._provider == "github_models" or self._is_pat(raw):
            return raw

        # Already a session token — use directly
        if raw.startswith("tid=") or raw.startswith("ghu_"):
            return raw

        # Check cache
        if self._copilot_session_token and time.time() < self._copilot_session_expires_at:
            return self._copilot_session_token

        # Exchange OAuth token → session token
        import httpx
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                resp = await http.get(
                    "https://api.github.com/copilot_internal/v2/token",
                    headers={
                        "Authorization": f"token {raw}",
                        "Accept": "application/json",
                        "Editor-Version": "vscode/1.90.0",
                        "Editor-Plugin-Version": "copilot/1.0",
                        "User-Agent": "vex-agent/1.0",
                    },
                )
            resp.raise_for_status()
            data = resp.json()
            session_token: str = data["token"]
            expires_at_str: str = data.get("expires_at", "")
            if expires_at_str:
                from datetime import datetime, timezone
                dt = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
                expires_ts = dt.timestamp()
            else:
                expires_ts = time.time() + 1500   # default: 25 min

            LLMReachabilityAnalyzer._copilot_session_token = session_token
            LLMReachabilityAnalyzer._copilot_session_expires_at = expires_ts - 60
            logger.info("Copilot session token obtained (expires in ~%ds)", int(expires_ts - time.time()))
            return session_token
        except Exception as exc:
            logger.warning("Copilot token exchange failed: %s — using raw token", exc)
            return raw

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _select_files(
        self,
        repo_root: Path,
        candidate_files: Optional[list[str]],
        max_files: int,
        package_name: str,
    ) -> list[tuple[str, Path]]:
        if candidate_files:
            result = []
            for rel in candidate_files[:max_files]:
                abs_p = repo_root / rel
                if abs_p.exists():
                    result.append((rel, abs_p))
            return result

        # Build a set of name variants to search for (e.g. pyyaml → pyyaml, yaml)
        pkg_lower = package_name.lower().replace("-", "_")
        variants: list[str] = [pkg_lower]
        # Strip common language prefixes (py-, python-, node-, js-, lib-)
        for prefix in ("py", "python", "node", "js", "lib"):
            if pkg_lower.startswith(prefix) and len(pkg_lower) > len(prefix):
                variants.append(pkg_lower[len(prefix):])

        all_files: list[tuple[str, Path]] = list(iter_source_files(repo_root))
        scored: list[tuple[int, str, Path]] = []
        for rel, abs_p in all_files:
            try:
                content = abs_p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            content_lower = content.lower()
            score = sum(content_lower.count(v) for v in variants)
            scored.append((score, rel, abs_p))

        scored.sort(reverse=True)

        # If nothing scored at all, fall back to all source files
        if all(s == 0 for s, _, _ in scored):
            return [(rel, p) for _, rel, p in scored[:max_files]]

        return [(rel, p) for score, rel, p in scored[:max_files] if score > 0]

    @staticmethod
    def _parse_verdict(raw: str) -> dict:
        import json
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("LLM returned invalid JSON: %s", raw[:200])
            return {}
