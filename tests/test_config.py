from __future__ import annotations

import pytest

from config import Settings, get_env_file_path


def test_env_file_path_prefers_dotenv(tmp_path):
    env_path = tmp_path / ".env"
    env_txt_path = tmp_path / ".env.txt"
    env_txt_path.write_text("TARGET_REPO_BRANCH=from-txt\n", encoding="utf-8")
    env_path.write_text("TARGET_REPO_BRANCH=from-env\n", encoding="utf-8")

    assert get_env_file_path(tmp_path) == env_path


def test_env_file_path_falls_back_to_env_txt(tmp_path):
    env_txt_path = tmp_path / ".env.txt"
    env_txt_path.write_text("TARGET_REPO_BRANCH=from-txt\n", encoding="utf-8")

    assert get_env_file_path(tmp_path) == env_txt_path


def test_settings_load_values_from_env_txt(tmp_path):
    env_txt_path = tmp_path / ".env.txt"
    env_txt_path.write_text(
        "\n".join(
            [
                "JIRA_BASE_URL=https://example.atlassian.net",
                "TARGET_REPO_BRANCH=release-2026",
                "ENABLE_HUMAN_REVIEW=true",
                "EPSS_THRESHOLD=0.42",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    settings = Settings(_env_file=env_txt_path)

    assert settings.jira_base_url == "https://example.atlassian.net"
    assert settings.target_repo_branch == "release-2026"
    assert settings.enable_human_review is True
    assert settings.epss_threshold == pytest.approx(0.42)


@pytest.mark.asyncio
async def test_dashboard_settings_update_writes_active_env_txt(tmp_path, monkeypatch):
    env_txt_path = tmp_path / ".env.txt"
    env_txt_path.write_text("TARGET_REPO_BRANCH=main\n", encoding="utf-8")

    import main

    monkeypatch.setattr(main, "settings", Settings(_env_file=env_txt_path))
    monkeypatch.setattr(main, "get_env_file_path", lambda _base_dir=None: env_txt_path)

    result = await main.api_update_settings(
        {
            "target_repo_branch": "release-2026",
            "enable_human_review": True,
            "github_webhook_secret": main._SETTINGS_MASK,
        }
    )

    saved = env_txt_path.read_text(encoding="utf-8")

    assert result["count"] == 2
    assert "TARGET_REPO_BRANCH=release-2026" in saved
    assert "ENABLE_HUMAN_REVIEW=true" in saved
    assert "GITHUB_WEBHOOK_SECRET" not in saved


@pytest.mark.asyncio
async def test_export_analyse_uses_target_repo_not_mock_dashboard_rows(monkeypatch):
    import main
    import clients.github_client as github_client

    class FakeGitHubSecurityClient:
        async def list_dependabot_alerts(self, repo: str):
            assert repo == "Sriniamul/WebGoat"
            return [
                {
                    "created_at": "2026-06-22T00:00:00Z",
                    "number": 1,
                    "state": "open",
                    "dependency": {
                        "package": {"ecosystem": "maven", "name": "org.webgoat:webgoat"},
                        "scope": "runtime",
                    },
                    "security_advisory": {
                        "identifiers": [{"type": "CVE", "value": "CVE-2026-0001"}],
                        "severity": "high",
                    },
                    "security_vulnerability": {"severity": "high"},
                }
            ]

        async def list_code_scanning_alerts(self, repo: str):
            assert repo == "Sriniamul/WebGoat"
            return []

        async def list_secret_scanning_alerts(self, repo: str):
            assert repo == "Sriniamul/WebGoat"
            return []

    monkeypatch.setattr(
        main,
        "settings",
        Settings(
            target_repo_url="https://github.com/Sriniamul/WebGoat.git",
            mock_repo_full_name="solarwinds-internal/arm-arm",
        ),
    )
    monkeypatch.setattr(github_client, "GitHubSecurityClient", FakeGitHubSecurityClient)

    rows = await main._get_export_runs(prefer_dashboard=False)

    assert rows[0]["repo"] == "Sriniamul/WebGoat"
    assert rows[0]["package_name"] == "org.webgoat:webgoat"
