"""
Level 2 Reachability Analyzer.

Uses AST parsing to locate calls to vulnerable functions in the repository.
Falls back to regex grep when AST is not available for the language.
Supports Python, JavaScript/TypeScript, and Java out of the box.
"""

from __future__ import annotations

import ast
import logging
import re
import warnings
from pathlib import Path
from typing import Optional

from models.vex_models import ReachabilityAnalysisResult, ReachabilityHit, ImportSite
from utils.git_utils import iter_source_files

logger = logging.getLogger(__name__)


class ReachabilityAnalyzer:
    """
    Statically scan source files under *repo_root* for calls to the
    functions listed in *vulnerable_functions*.
    """

    def __init__(self, repo_root: Path, file_cache: list[tuple[str, str, str]] | None = None):
        self.root = repo_root
        # file_cache: list of (rel_path, extension, content) — pre-loaded to
        # avoid re-reading the entire repo for every alert during bulk import.
        self._file_cache = file_cache

    # ------------------------------------------------------------------
    # Build a reusable file cache for bulk operations
    # ------------------------------------------------------------------

    @staticmethod
    def build_file_cache(repo_root: Path) -> list[tuple[str, str, str]]:
        """Read all source files once; return list of (rel_path, ext, content)."""
        cache: list[tuple[str, str, str]] = []
        for rel_path, abs_path in iter_source_files(repo_root):
            try:
                content = abs_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            cache.append((rel_path, abs_path.suffix.lower(), content))
        logger.info("File cache built: %d source files loaded from %s", len(cache), repo_root)
        return cache

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def analyse(
        self,
        package_name: str,
        vulnerable_functions: list[str],
        ecosystem: str = "npm",
    ) -> ReachabilityAnalysisResult:
        if not vulnerable_functions:
            # No specific function information → fall back to import search
            vulnerable_functions = self._guess_entry_points(package_name)

        hits: list[ReachabilityHit] = []
        import_sites: list[ImportSite] = []

        # Use pre-loaded cache if available; otherwise read files on the fly
        if self._file_cache is not None:
            file_iter = self._file_cache
        else:
            file_iter = []
            for rel_path, abs_path in iter_source_files(self.root):
                try:
                    content = abs_path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                file_iter.append((rel_path, abs_path.suffix.lower(), content))

        for rel_path, ext, content in file_iter:
            if ext == ".py":
                file_hits, file_imports = self._scan_python(content, rel_path, package_name, vulnerable_functions)
            elif ext in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"):
                file_hits, file_imports = self._scan_js(content, rel_path, package_name, vulnerable_functions)
            elif ext == ".java":
                file_hits, file_imports = self._scan_java(content, rel_path, package_name, vulnerable_functions)
            else:
                file_hits = self._scan_generic(content, rel_path, vulnerable_functions)
                file_imports = []

            hits.extend(file_hits)
            import_sites.extend(file_imports)

        reachable = len(hits) > 0
        confidence = min(1.0, len(hits) * 0.3) if reachable else 0.0

        return ReachabilityAnalysisResult(
            reachable=reachable,
            hits=hits,
            import_sites=import_sites,
            method="ast",
            confidence=confidence,
            notes=f"Scanned {self.root} for {len(vulnerable_functions)} vulnerable function(s).",
        )

    # ------------------------------------------------------------------
    # Python AST scanner
    # ------------------------------------------------------------------

    def _scan_python(
        self,
        source: str,
        rel_path: str,
        package_name: str,
        functions: list[str],
    ) -> tuple[list[ReachabilityHit], list[ImportSite]]:
        hits: list[ReachabilityHit] = []

        # Check import first
        imported_as: dict[str, str] = {}   # alias → module or attribute
        import_lines: list[tuple[int, str]] = []  # (lineno, raw line)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                tree = ast.parse(source)
        except SyntaxError:
            return self._scan_generic(source, rel_path, functions), []

        pkg_norm = package_name.replace("-", "_").lower()
        lines = source.splitlines()

        for node in ast.walk(tree):
            # Record import aliases
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod_root = alias.name.lower().split(".")[0]
                    if pkg_norm in mod_root or mod_root in pkg_norm:
                        imported_as[alias.asname or alias.name] = alias.name
                        ln = getattr(node, "lineno", 0)
                        import_lines.append((ln, lines[ln - 1].strip() if ln <= len(lines) else ""))
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                mod_root = module.lower().split(".")[0]
                if pkg_norm in mod_root or mod_root in pkg_norm:
                    for alias in node.names:
                        imported_as[alias.asname or alias.name] = alias.name
                    ln = getattr(node, "lineno", 0)
                    import_lines.append((ln, lines[ln - 1].strip() if ln <= len(lines) else ""))

        if not imported_as:
            # Package not imported → not reachable (by AST)
            return [], []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            called_name = self._extract_call_name(node)
            if not called_name:
                continue

            for fn in functions:
                if fn.lower() in called_name.lower():
                    lineno = node.lineno
                    line_content = lines[lineno - 1] if lineno <= len(lines) else ""
                    hits.append(ReachabilityHit(
                        file_path=rel_path,
                        line_number=lineno,
                        line_content=line_content,
                        function_called=fn,
                        confidence=0.9,
                    ))

        # If imported but no vulnerable-function calls → record as import site
        import_sites: list[ImportSite] = []
        if not hits and import_lines:
            # Collect safe functions actually called via the imported names
            safe_funcs: list[str] = []
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                called_name = self._extract_call_name(node)
                if not called_name:
                    continue
                for alias in imported_as:
                    if alias.lower() in called_name.lower():
                        if not any(fn.lower() in called_name.lower() for fn in functions):
                            safe_funcs.append(called_name)
            safe_funcs = list(dict.fromkeys(safe_funcs))[:5]  # dedupe, cap at 5

            for ln, raw in import_lines:
                import_sites.append(ImportSite(
                    file_path=rel_path,
                    line_number=ln,
                    line_content=raw,
                    import_statement=raw,
                    functions_used=safe_funcs,
                ))

        return hits, import_sites

    @staticmethod
    def _extract_call_name(node: ast.Call) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

    # ------------------------------------------------------------------
    # JavaScript / TypeScript regex scanner
    # ------------------------------------------------------------------

    def _scan_js(
        self,
        source: str,
        rel_path: str,
        package_name: str,
        functions: list[str],
    ) -> tuple[list[ReachabilityHit], list[ImportSite]]:
        pkg_norm = package_name.lower()
        lines = source.splitlines()

        # Check if the package is imported at all
        import_pattern = re.compile(
            rf"""(?:require\s*\(\s*['"]|from\s+['"]).{{0,10}}{re.escape(pkg_norm)}""",
            re.IGNORECASE,
        )
        if not import_pattern.search(source):
            return [], []

        # Find import line(s)
        import_lines: list[tuple[int, str]] = []
        for i, line in enumerate(lines, start=1):
            if import_pattern.search(line):
                import_lines.append((i, line.strip()))

        hits: list[ReachabilityHit] = []
        for fn in functions:
            fn_pat = re.compile(
                rf"""\b{re.escape(fn)}\s*\(""",
                re.IGNORECASE,
            )
            for i, line in enumerate(lines, start=1):
                if fn_pat.search(line):
                    hits.append(ReachabilityHit(
                        file_path=rel_path,
                        line_number=i,
                        line_content=line,
                        function_called=fn,
                        confidence=0.75,
                    ))

        # If imported but no vulnerable-function calls → record as import site
        import_sites: list[ImportSite] = []
        if not hits and import_lines:
            for ln, raw in import_lines:
                import_sites.append(ImportSite(
                    file_path=rel_path,
                    line_number=ln,
                    line_content=raw,
                    import_statement=raw,
                ))

        return hits, import_sites

    # ------------------------------------------------------------------
    # Java regex scanner
    # ------------------------------------------------------------------

    def _scan_java(
        self,
        source: str,
        rel_path: str,
        package_name: str,
        functions: list[str],
    ) -> tuple[list[ReachabilityHit], list[ImportSite]]:
        pkg_norm = package_name.lower().replace("-", "").replace("_", "")
        lines = source.splitlines()

        import_lines: list[tuple[int, str]] = []
        import_found = False
        for i, line in enumerate(lines, start=1):
            if line.strip().startswith("import") and pkg_norm in line.lower():
                import_found = True
                import_lines.append((i, line.strip()))
        if not import_found:
            return [], []

        hits: list[ReachabilityHit] = []
        for fn in functions:
            fn_pat = re.compile(rf"""\b{re.escape(fn)}\s*\(""")
            for i, line in enumerate(lines, start=1):
                if fn_pat.search(line):
                    hits.append(ReachabilityHit(
                        file_path=rel_path,
                        line_number=i,
                        line_content=line,
                        function_called=fn,
                        confidence=0.7,
                    ))

        # If imported but no vulnerable-function calls → record as import site
        import_sites: list[ImportSite] = []
        if not hits and import_lines:
            for ln, raw in import_lines:
                import_sites.append(ImportSite(
                    file_path=rel_path,
                    line_number=ln,
                    line_content=raw,
                    import_statement=raw,
                ))

        return hits, import_sites

    # ------------------------------------------------------------------
    # Generic grep fallback
    # ------------------------------------------------------------------

    def _scan_generic(
        self,
        source: str,
        rel_path: str,
        functions: list[str],
    ) -> list[ReachabilityHit]:
        hits: list[ReachabilityHit] = []
        lines = source.splitlines()
        for fn in functions:
            pat = re.compile(re.escape(fn), re.IGNORECASE)
            for i, line in enumerate(lines, start=1):
                if pat.search(line):
                    hits.append(ReachabilityHit(
                        file_path=rel_path,
                        line_number=i,
                        line_content=line,
                        function_called=fn,
                        confidence=0.5,
                    ))
        return hits

    # ------------------------------------------------------------------
    # Heuristic: guess vulnerable entry points from package name
    # ------------------------------------------------------------------

    @staticmethod
    def _guess_entry_points(package_name: str) -> list[str]:
        """
        When the advisory doesn't list specific vulnerable functions,
        guess likely API entry points from the package name.
        This is intentionally conservative (returns a minimal set).
        """
        base = package_name.split("/")[-1].replace("-", "_")  # scoped npm → last segment
        return [base, f"{base}.parse", f"{base}.deserialize", f"{base}.load"]
