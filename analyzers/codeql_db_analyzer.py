"""
CodeQL database reachability helpers.

The primary path runs a real CodeQL query against a downloaded database bundle.
The older zip text scan is retained as a fallback when the CodeQL CLI is not
available or a database cannot be extracted locally.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import re
import zipfile
from pathlib import Path

from models.vex_models import ReachabilityHit


_TEXT_SUFFIXES = {
    ".java", ".kt", ".kts",
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".py", ".rb", ".go", ".cs", ".cpp", ".cc", ".c", ".h", ".hpp",
    ".xml", ".properties", ".gradle", ".pom",
}

_LANGUAGE_MARKER_FILES: tuple[tuple[str, str], ...] = (
    ("java", "pom.xml"),
    ("java", "build.gradle"),
    ("java", "build.gradle.kts"),
    ("javascript", "package.json"),
    ("python", "requirements.txt"),
    ("python", "pyproject.toml"),
    ("python", "setup.py"),
    ("python", "setup.cfg"),
    ("go", "go.mod"),
    ("ruby", "Gemfile"),
    ("csharp", "*.csproj"),
    ("csharp", "*.sln"),
    ("c-cpp", "CMakeLists.txt"),
    ("c-cpp", "compile_commands.json"),
)

_LANGUAGE_SOURCE_SUFFIXES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("java", (".java", ".kt", ".kts")),
    ("javascript", (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")),
    ("python", (".py",)),
    ("go", (".go",)),
    ("ruby", (".rb",)),
    ("csharp", (".cs",)),
    ("c-cpp", (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh")),
)


class CodeQLCliUnavailable(RuntimeError):
    """Raised when the CodeQL CLI cannot be found on PATH."""


class CodeQLQueryError(RuntimeError):
    """Raised when CodeQL query execution or result decoding fails."""


def search_codeql_database(
    db_zip_path: Path,
    functions: list[str],
    *,
    language: str,
    work_dir: Path,
    codeql_cli: str = "codeql",
    max_hits: int = 25,
) -> list[ReachabilityHit]:
    """Run a real CodeQL query against a downloaded database zip."""
    search_terms = [term for term in functions if term]
    if not search_terms:
        return []

    cli_path = resolve_codeql_cli(codeql_cli)
    if not cli_path:
        raise CodeQLCliUnavailable(f"CodeQL CLI '{codeql_cli}' was not found on PATH")

    query_text = build_reachability_query(language, search_terms)
    if not query_text:
        raise CodeQLQueryError(f"No CodeQL reachability query template for language '{language}'")

    work_dir.mkdir(parents=True, exist_ok=True)
    db_dir = extract_codeql_database(db_zip_path, work_dir / db_zip_path.stem)
    query_dir = work_dir / "queries"
    query_dir.mkdir(parents=True, exist_ok=True)
    query_path = query_dir / f"reachability-{language}.ql"
    query_path.write_text(query_text, encoding="utf-8")

    result_dir = work_dir / "results"
    result_dir.mkdir(parents=True, exist_ok=True)
    bqrs_path = result_dir / f"{db_zip_path.stem}-{language}.bqrs"
    json_path = result_dir / f"{db_zip_path.stem}-{language}.json"

    _run_codeql(
        [
            cli_path,
            "query",
            "run",
            f"--database={db_dir}",
            f"--output={bqrs_path}",
            "--",
            str(query_path),
        ]
    )
    _run_codeql(
        [
            cli_path,
            "bqrs",
            "decode",
            "--format=json",
            f"--output={json_path}",
            "--",
            str(bqrs_path),
        ]
    )

    return parse_bqrs_json(json_path, max_hits=max_hits)


def build_reachability_query(language: str, functions: list[str]) -> str:
    terms = [term for term in functions if term]
    if not terms:
        return ""
    predicate = _ql_string_predicate("targetName", terms)
    language = language.lower()

    if language == "java":
        return f"""/**
 * @name VEX reachability call search
 * @description Finds calls whose target name matches vulnerable function names.
 * @kind table
 */
import java

predicate isTarget(string targetName) {{
  {predicate}
}}

from MethodAccess call, string targetName
where
  isTarget(targetName) and
  (
    call.getMethod().getName() = targetName or
    call.getMethod().getQualifiedName().matches("%." + targetName) or
    call.toString().matches("%" + targetName + "%")
  )
select
  call.getLocation().getFile().getRelativePath(),
  call.getLocation().getStartLine(),
  call.toString(),
  targetName
"""

    if language in ("javascript", "typescript"):
        return f"""/**
 * @name VEX reachability call search
 * @description Finds JavaScript/TypeScript calls matching vulnerable function names.
 * @kind table
 */
import javascript

predicate isTarget(string targetName) {{
  {predicate}
}}

from CallExpr call, string targetName
where
  isTarget(targetName) and
  (
    call.getCalleeName() = targetName or
    call.getCallee().toString().matches("%" + targetName + "%")
  )
select
  call.getLocation().getFile().getRelativePath(),
  call.getLocation().getStartLine(),
  call.toString(),
  targetName
"""

    if language == "python":
        return f"""/**
 * @name VEX reachability call search
 * @description Finds Python calls matching vulnerable function names.
 * @kind table
 */
import python

predicate isTarget(string targetName) {{
  {predicate}
}}

from Call call, string targetName
where
  isTarget(targetName) and
  call.getFunc().toString().matches("%" + targetName + "%")
select
  call.getLocation().getFile().getRelativePath(),
  call.getLocation().getStartLine(),
  call.toString(),
  targetName
"""

    return ""


def infer_codeql_language_from_repo(repo_path: Path | str | None) -> str:
    """Infer CodeQL language from repository files when alert metadata is weak."""
    if not repo_path:
        return ""
    root = Path(repo_path)
    if not root.exists() or not root.is_dir():
        return ""

    for language, pattern in _LANGUAGE_MARKER_FILES:
        if any(root.glob(pattern)):
            return language

    counts: dict[str, int] = {}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel_parts = {part.lower() for part in path.relative_to(root).parts[:-1]}
        if rel_parts.intersection({".git", ".venv", "node_modules", "target", "build", "dist"}):
            continue
        suffix = path.suffix.lower()
        for language, suffixes in _LANGUAGE_SOURCE_SUFFIXES:
            if suffix in suffixes:
                counts[language] = counts.get(language, 0) + 1
                break

    if not counts:
        return ""
    return max(counts.items(), key=lambda item: item[1])[0]


def resolve_codeql_cli(codeql_cli: str = "codeql") -> str | None:
    """Resolve CodeQL from PATH or common manual-install locations."""
    cli_path = shutil.which(codeql_cli)
    if cli_path:
        return cli_path

    candidates: list[Path] = []
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        candidates.extend([
            Path(local_app_data) / "Programs" / "codeql" / "codeql.exe",
            Path(local_app_data) / "Programs" / "CodeQL" / "codeql.exe",
        ])
    candidates.extend([
        Path("C:/codeql/codeql.exe"),
        Path("C:/Program Files/codeql/codeql.exe"),
    ])

    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return None


def extract_codeql_database(zip_path: Path, dest_dir: Path) -> Path:
    """Extract a CodeQL database zip and return the database root directory."""
    marker = dest_dir / ".extracted"
    if not marker.exists():
        if dest_dir.exists():
            shutil.rmtree(dest_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zip_path) as zf:
            for info in zf.infolist():
                target = (dest_dir / info.filename).resolve()
                if not _is_relative_to(target, dest_dir.resolve()):
                    raise CodeQLQueryError(f"Unsafe path in CodeQL database zip: {info.filename}")
                zf.extract(info, dest_dir)
        marker.write_text("ok", encoding="ascii")

    candidates = [dest_dir, *[p for p in dest_dir.rglob("*") if p.is_dir()]]
    for candidate in candidates:
        if (candidate / "codeql-database.yml").exists():
            return candidate
    return dest_dir


def parse_bqrs_json(json_path: Path, *, max_hits: int = 25) -> list[ReachabilityHit]:
    """Parse CodeQL BQRS JSON output into reachability hits."""
    data = json.loads(json_path.read_text(encoding="utf-8"))
    rows = _extract_bqrs_rows(data)

    hits: list[ReachabilityHit] = []
    for row in rows:
        values = [_normalise_bqrs_value(value) for value in row]
        if len(values) < 4:
            continue
        file_path, line_raw, snippet, function_called = values[:4]
        line_number = _parse_line_number(line_raw)
        hits.append(
            ReachabilityHit(
                file_path=f"codeql-db:{file_path}",
                line_number=line_number,
                line_content=snippet[:500],
                function_called=function_called,
                confidence=0.85,
            )
        )
        if len(hits) >= max_hits:
            return hits
    return hits


def search_codeql_database_zip(
    zip_path: Path,
    functions: list[str],
    *,
    max_hits: int = 25,
) -> list[ReachabilityHit]:
    """Search a downloaded CodeQL database zip for vulnerable function strings."""
    search_terms = [term for term in functions if term]
    if not search_terms:
        return []

    hits: list[ReachabilityHit] = []
    lowered_terms = [(term, term.lower()) for term in search_terms]

    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            if info.is_dir() or info.file_size > 1_000_000:
                continue
            name = info.filename
            suffix = Path(name).suffix.lower()
            if suffix and suffix not in _TEXT_SUFFIXES:
                continue

            try:
                raw = zf.read(info)
                text = raw.decode("utf-8", errors="replace")
            except Exception:
                continue

            for line_number, line in enumerate(text.splitlines(), start=1):
                line_l = line.lower()
                for term, term_l in lowered_terms:
                    if _term_matches(line_l, term_l):
                        hits.append(
                            ReachabilityHit(
                                file_path=f"codeql-db:{name}",
                                line_number=line_number,
                                line_content=line.strip()[:500],
                                function_called=term,
                                confidence=0.65,
                            )
                        )
                        if len(hits) >= max_hits:
                            return hits
    return hits


def _term_matches(line: str, term: str) -> bool:
    if not term:
        return False
    if not re.search(re.escape(term), line, re.IGNORECASE):
        return False
    return True


def _run_codeql(args: list[str]) -> None:
    try:
        completed = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        raise CodeQLQueryError("CodeQL query timed out") from exc

    if completed.returncode != 0:
        stderr = (completed.stderr or completed.stdout or "").strip()
        raise CodeQLQueryError(stderr[:1000] or f"CodeQL exited with {completed.returncode}")


def _ql_string_predicate(variable_name: str, values: list[str]) -> str:
    comparisons = [f'{variable_name} = "{_escape_ql_string(value)}"' for value in values]
    return " or\n  ".join(comparisons)


def _escape_ql_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _extract_bqrs_rows(data) -> list:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if isinstance(data.get("tuples"), list):
            return data["tuples"]
        if isinstance(data.get("#select"), dict) and isinstance(data["#select"].get("tuples"), list):
            return data["#select"]["tuples"]
        for value in data.values():
            if isinstance(value, dict) and isinstance(value.get("tuples"), list):
                return value["tuples"]
    return []


def _normalise_bqrs_value(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    if isinstance(value, dict):
        for key in ("label", "string", "value", "url", "id"):
            if key in value:
                return _normalise_bqrs_value(value[key])
        if "tuple" in value and isinstance(value["tuple"], list):
            return " ".join(_normalise_bqrs_value(v) for v in value["tuple"])
    if isinstance(value, list):
        return " ".join(_normalise_bqrs_value(v) for v in value)
    return str(value)


def _parse_line_number(value: str) -> int:
    try:
        return int(value)
    except Exception:
        match = re.search(r"\d+", value or "")
        return int(match.group(0)) if match else 0


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
