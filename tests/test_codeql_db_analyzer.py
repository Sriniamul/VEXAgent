from __future__ import annotations

import zipfile
from pathlib import Path

import httpx
import pytest
import respx

from analyzers.codeql_db_analyzer import (
    build_reachability_query,
    infer_codeql_language_from_repo,
    search_codeql_database,
    search_codeql_database_zip,
)
from clients.github_client import GitHubSecurityClient
from main import _infer_codeql_language


def test_search_codeql_database_zip_finds_function_reference(tmp_path):
    db_zip = tmp_path / "codeql-db.zip"
    with zipfile.ZipFile(db_zip, "w") as zf:
        zf.writestr(
            "db-javac/src/main/java/org/example/App.java",
            "class App { void x() { logger.info(\"hello\"); } }\n",
        )

    hits = search_codeql_database_zip(db_zip, ["logger.info"])

    assert len(hits) == 1
    assert hits[0].file_path.startswith("codeql-db:")
    assert hits[0].function_called == "logger.info"


def test_search_codeql_database_zip_no_match(tmp_path):
    db_zip = tmp_path / "codeql-db.zip"
    with zipfile.ZipFile(db_zip, "w") as zf:
        zf.writestr("src/App.java", "class App { void x() {} }\n")

    assert search_codeql_database_zip(db_zip, ["logger.info"]) == []


def test_build_reachability_query_java_contains_real_codeql_call_query():
    query = build_reachability_query("java", ["logger.info", "readObject"])

    assert "import java" in query
    assert "from MethodAccess call" in query
    assert 'targetName = "logger.info"' in query
    assert 'targetName = "readObject"' in query
    assert "call.getMethod().getQualifiedName()" in query


def test_search_codeql_database_runs_query_and_decodes_bqrs(monkeypatch, tmp_path):
    import analyzers.codeql_db_analyzer as analyzer

    db_zip = tmp_path / "codeql-db.zip"
    with zipfile.ZipFile(db_zip, "w") as zf:
        zf.writestr("java-db/codeql-database.yml", "name: java-db\n")

    calls: list[list[str]] = []

    class FakeCompleted:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(args, check, capture_output, text, timeout):
        calls.append(args)
        if args[1:3] == ["bqrs", "decode"]:
            output_arg = next(a for a in args if a.startswith("--output="))
            json_path = Path(output_arg.split("=", 1)[1])
            json_path.write_text(
                '{"#select":{"tuples":[["src/main/java/App.java",42,"logger.info(\\"x\\")","logger.info"]]}}',
                encoding="utf-8",
            )
        return FakeCompleted()

    monkeypatch.setattr(analyzer.shutil, "which", lambda name: "C:/tools/codeql.exe")
    monkeypatch.setattr(analyzer.subprocess, "run", fake_run)

    hits = search_codeql_database(
        db_zip,
        ["logger.info"],
        language="java",
        work_dir=tmp_path / "work",
    )

    assert len(hits) == 1
    assert hits[0].file_path == "codeql-db:src/main/java/App.java"
    assert hits[0].line_number == 42
    assert hits[0].function_called == "logger.info"
    assert calls[0][1:3] == ["query", "run"]
    assert calls[1][1:3] == ["bqrs", "decode"]


def test_infer_codeql_language_for_maven_alert():
    assert _infer_codeql_language("dependabot", "org.example:demo", "maven", "CVE-1") == "java"


def test_infer_codeql_language_from_repo_pom_xml(tmp_path):
    (tmp_path / "pom.xml").write_text("<project />\n", encoding="utf-8")

    assert infer_codeql_language_from_repo(tmp_path) == "java"


def test_infer_codeql_language_from_repo_package_json(tmp_path):
    (tmp_path / "package.json").write_text("{}\n", encoding="utf-8")

    assert infer_codeql_language_from_repo(tmp_path) == "javascript"


def test_github_error_message_includes_status_and_body():
    request = httpx.Request("GET", "https://api.github.com/test")
    response = httpx.Response(404, json={"message": "No CodeQL databases found"}, request=request)

    msg = GitHubSecurityClient._github_error_message(response, "download CodeQL database 'java'")

    assert "GitHub 404" in msg
    assert "No CodeQL databases found" in msg


@pytest.mark.asyncio
async def test_github_resolve_ghsa_to_cve():
    with respx.mock:
        respx.get("https://api.github.com/advisories/GHSA-abcd-1234-wxyz").mock(
            return_value=httpx.Response(
                200,
                json={
                    "ghsa_id": "GHSA-abcd-1234-wxyz",
                    "identifiers": [
                        {"type": "GHSA", "value": "GHSA-abcd-1234-wxyz"},
                        {"type": "CVE", "value": "CVE-2026-12345"},
                    ],
                },
            )
        )

        cve = await GitHubSecurityClient(token="token").resolve_ghsa_to_cve(
            "GHSA-abcd-1234-wxyz"
        )

    assert cve == "CVE-2026-12345"


@pytest.mark.asyncio
async def test_resolve_cve_for_epss_resolves_ghsa_with_cache():
    import main

    class FakeGitHub:
        calls = 0

        async def resolve_ghsa_to_cve(self, ghsa_id):
            self.calls += 1
            assert ghsa_id == "GHSA-abcd-1234-wxyz"
            return "CVE-2026-12345"

    gh = FakeGitHub()
    cache: dict[str, str | None] = {}

    first = await main._resolve_cve_for_epss("GHSA-abcd-1234-wxyz", gh, cache)
    second = await main._resolve_cve_for_epss("GHSA-abcd-1234-wxyz", gh, cache)

    assert first == "CVE-2026-12345"
    assert second == "CVE-2026-12345"
    assert gh.calls == 1


@pytest.mark.asyncio
async def test_codeql_download_error_is_appended_to_l2_notes(monkeypatch, tmp_path):
    import main
    from models.vex_models import ReachabilityAnalysisResult

    class FakeGitHub:
        async def download_codeql_database(self, repo, language, dest_dir):
            raise RuntimeError("GitHub 404 while trying to download CodeQL database 'java': Not Found")

    reachability_result = ReachabilityAnalysisResult(
        reachable=False,
        hits=[],
        method="ast",
        confidence=0,
        notes="AST scanned source.",
    )

    monkeypatch.setattr(main, "_CODEQL_DB_CACHE_DIR", tmp_path)

    codeql_language = main._infer_codeql_language("dependabot", "org.example:demo", "maven", "CVE-1")
    try:
        await FakeGitHub().download_codeql_database("owner/repo", codeql_language, tmp_path)
    except Exception as exc:
        reachability_result.notes = f"{reachability_result.notes} CodeQL DB search: ERROR - {exc}"

    assert "CodeQL DB search: ERROR" in reachability_result.notes
    assert "GitHub 404" in reachability_result.notes


@pytest.mark.asyncio
async def test_codeql_enrichment_merges_hits_and_appears_in_justification(tmp_path, monkeypatch):
    import main
    from models.vex_models import ReachabilityAnalysisResult

    db_zip = tmp_path / "codeql-db.zip"
    with zipfile.ZipFile(db_zip, "w") as zf:
        zf.writestr(
            "db-java/src/main/java/org/example/App.java",
            "class App { void x() { logger.info(\"hello\"); } }\n",
        )

    class FakeGitHub:
        async def download_codeql_database(self, repo, language, dest_dir):
            assert repo == "owner/repo"
            assert language == "java"
            return db_zip

    reachability_result = ReachabilityAnalysisResult(
        reachable=False,
        hits=[],
        method="ast",
        confidence=0,
        notes="AST scanned source.",
    )
    monkeypatch.setattr(main, "_CODEQL_DB_CACHE_DIR", tmp_path)

    await main._enrich_reachability_with_codeql_db(
        github_client=FakeGitHub(),
        repo_full_name="owner/repo",
        alert_type="dependabot",
        package_name="org.example:demo",
        ecosystem="maven",
        cve_or_rule="CVE-1",
        vulnerable_functions=["logger.info"],
        reachability_result=reachability_result,
    )

    assert reachability_result.reachable is True
    assert reachability_result.method == "ast+codeql-db"
    assert len(reachability_result.hits) == 1
    assert "CodeQL DB search: downloaded java database" in reachability_result.notes

    summary = main._build_analysis_summary(
        None,
        reachability_result,
        "affected_reachable",
    )
    assert "L2 Reachability (CodeQL DB): CodeQL DB search: downloaded java database" in summary
    assert "codeql-db:db-java/src/main/java/org/example/App.java" in summary


@pytest.mark.asyncio
async def test_codeql_enrichment_infers_language_from_repo_when_alert_metadata_unknown(tmp_path, monkeypatch):
    import main
    from models.vex_models import ReachabilityAnalysisResult

    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / "pom.xml").write_text("<project />\n", encoding="utf-8")

    db_zip = tmp_path / "codeql-db.zip"
    with zipfile.ZipFile(db_zip, "w") as zf:
        zf.writestr(
            "db-java/src/main/java/org/example/App.java",
            "class App { void x() { logger.info(\"hello\"); } }\n",
        )

    class FakeGitHub:
        async def download_codeql_database(self, repo, language, dest_dir):
            assert language == "java"
            return db_zip

    reachability_result = ReachabilityAnalysisResult(
        reachable=False,
        hits=[],
        method="ast",
        confidence=0,
        notes="AST scanned source.",
    )
    monkeypatch.setattr(main, "_CODEQL_DB_CACHE_DIR", tmp_path)

    await main._enrich_reachability_with_codeql_db(
        github_client=FakeGitHub(),
        repo_full_name="owner/repo",
        alert_type="code_scanning",
        package_name="unknown",
        ecosystem="unknown",
        cve_or_rule="",
        vulnerable_functions=["logger.info"],
        reachability_result=reachability_result,
        repo_path=repo_path,
    )

    assert reachability_result.reachable is True
    assert "CodeQL DB search: downloaded java database" in reachability_result.notes
