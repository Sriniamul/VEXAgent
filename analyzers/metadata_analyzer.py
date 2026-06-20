"""
Level 1 Metadata Analyzer.

Checks whether a vulnerable dependency is declared only in a dev/test
scope (devDependencies, test extras, etc.). If so, it is almost certainly
not deployed to production and can be marked NOT_AFFECTED.

Supported ecosystems:
  npm / yarn      → package.json  (devDependencies, optionalDependencies)
  Python (pip)    → requirements*.txt, pyproject.toml [tool.poetry.dev-dependencies],
                    setup.cfg [options.extras_require:test], Pipfile [dev-packages]
  Bundler (Ruby)  → Gemfile       (:development, :test groups)
  Maven / Gradle  → pom.xml       (<scope>test</scope>) / testImplementation
  Go              → no dev scope concept; returns inconclusive
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Optional

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # backport
    except ImportError:
        tomllib = None  # type: ignore[assignment]

from models.vex_models import MetadataAnalysisResult

logger = logging.getLogger(__name__)

_DEV_TEST_KEYWORDS = re.compile(
    r"\b(dev|test|spec|lint|mock|fixture|e2e|ci|build|tool|check|format)\b",
    re.IGNORECASE,
)


class MetadataAnalyzer:
    """
    Inspect manifest files in a shallow-cloned repository to determine
    whether the flagged package is used only in dev/test scope.
    """

    def __init__(self, repo_root: Path):
        self.root = repo_root

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def analyse(
        self,
        package_name: str,
        ecosystem: str,
        manifest_path: Optional[str] = None,
    ) -> MetadataAnalysisResult:
        ecosystem = ecosystem.lower()
        dispatch = {
            "npm": self._check_npm,
            "pip": self._check_pip,
            "pipenv": self._check_pip,
            "poetry": self._check_poetry,
            "rubygems": self._check_bundler,
            "maven": self._check_maven,
            "gradle": self._check_gradle,
        }

        checker = dispatch.get(ecosystem)
        if checker is None:
            return self._inconclusive(
                package_name, manifest_path or "N/A",
                f"No metadata analyzer for ecosystem '{ecosystem}'",
            )

        try:
            return checker(package_name, manifest_path)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Metadata analysis error: %s", exc)
            return self._inconclusive(package_name, manifest_path or "N/A", str(exc))

    # ------------------------------------------------------------------
    # npm / yarn
    # ------------------------------------------------------------------

    def _check_npm(
        self, package_name: str, manifest_path: Optional[str]
    ) -> MetadataAnalysisResult:
        candidates = (
            [self.root / manifest_path] if manifest_path else []
        ) + list(self.root.rglob("package.json"))

        for pkg_json_path in candidates:
            if not pkg_json_path.exists():
                continue
            try:
                data = json.loads(pkg_json_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue

            for scope in ("devDependencies", "optionalDependencies", "peerDependencies"):
                if package_name in data.get(scope, {}):
                    is_dev = scope in ("devDependencies", "optionalDependencies")
                    return MetadataAnalysisResult(
                        is_dev_dependency=is_dev,
                        is_test_dependency=is_dev,
                        dependency_scope=scope,
                        manifest_path=str(pkg_json_path.relative_to(self.root)),
                        justification=(
                            f"Package '{package_name}' found only in '{scope}' "
                            f"in {pkg_json_path.name}."
                        ),
                    )
            if package_name in data.get("dependencies", {}):
                return MetadataAnalysisResult(
                    is_dev_dependency=False,
                    is_test_dependency=False,
                    dependency_scope="dependencies",
                    manifest_path=str(pkg_json_path.relative_to(self.root)),
                    justification=f"Package '{package_name}' is a runtime dependency.",
                )

        return self._inconclusive(package_name, manifest_path or "package.json not found")

    # ------------------------------------------------------------------
    # pip / requirements.txt
    # ------------------------------------------------------------------

    def _check_pip(
        self, package_name: str, manifest_path: Optional[str]
    ) -> MetadataAnalysisResult:
        req_files = list(self.root.rglob("requirements*.txt"))
        req_files += list(self.root.rglob("constraints*.txt"))

        dev_files_found: list[str] = []
        runtime_files_found: list[str] = []

        norm_name = package_name.lower().replace("-", "_").replace(".", "_")

        for req_file in req_files:
            try:
                lines = req_file.read_text(encoding="utf-8").lower().splitlines()
            except OSError:
                continue
            for line in lines:
                clean = re.split(r"[=<>!;#\[]", line)[0].strip().replace("-", "_").replace(".", "_")
                if clean == norm_name:
                    rel = str(req_file.relative_to(self.root))
                    if _DEV_TEST_KEYWORDS.search(req_file.name):
                        dev_files_found.append(rel)
                    else:
                        runtime_files_found.append(rel)

        if dev_files_found and not runtime_files_found:
            return MetadataAnalysisResult(
                is_dev_dependency=True,
                is_test_dependency=True,
                dependency_scope="dev",
                manifest_path=", ".join(dev_files_found),
                justification=(
                    f"'{package_name}' found only in dev/test requirements: "
                    + ", ".join(dev_files_found)
                ),
            )
        if runtime_files_found:
            return MetadataAnalysisResult(
                is_dev_dependency=False,
                is_test_dependency=False,
                dependency_scope="runtime",
                manifest_path=", ".join(runtime_files_found),
                justification=f"'{package_name}' is a runtime requirement.",
            )

        return MetadataAnalysisResult(
            is_dev_dependency=False,
            is_test_dependency=False,
            dependency_scope="unknown",
            manifest_path="not found in manifest files (transitive dependency)",
            justification=(
                f"'{package_name}' not explicitly listed in any requirements*.txt — "
                "likely a transitive dependency pulled in by pip's resolver"
            ),
        )

    # ------------------------------------------------------------------
    # poetry (pyproject.toml)
    # ------------------------------------------------------------------

    def _check_poetry(
        self, package_name: str, manifest_path: Optional[str]
    ) -> MetadataAnalysisResult:
        if tomllib is None:
            return self._inconclusive(package_name, "pyproject.toml", "tomllib not available")

        toml_path = self.root / "pyproject.toml"
        if not toml_path.exists():
            return self._inconclusive(package_name, "pyproject.toml")

        data = tomllib.loads(toml_path.read_text(encoding="utf-8"))
        poetry = data.get("tool", {}).get("poetry", {})
        norm = package_name.lower()

        dev_groups = poetry.get("dev-dependencies", {})
        group_deps = poetry.get("group", {})
        for grp_name, grp_val in group_deps.items():
            if _DEV_TEST_KEYWORDS.search(grp_name):
                dev_groups.update(grp_val.get("dependencies", {}))

        if norm in {k.lower() for k in dev_groups}:
            return MetadataAnalysisResult(
                is_dev_dependency=True,
                is_test_dependency=True,
                dependency_scope="dev-dependencies",
                manifest_path="pyproject.toml",
                justification=f"'{package_name}' is a Poetry dev dependency.",
            )
        if norm in {k.lower() for k in poetry.get("dependencies", {})}:
            return MetadataAnalysisResult(
                is_dev_dependency=False,
                is_test_dependency=False,
                dependency_scope="dependencies",
                manifest_path="pyproject.toml",
                justification=f"'{package_name}' is a Poetry runtime dependency.",
            )

        return self._inconclusive(package_name, "pyproject.toml")

    # ------------------------------------------------------------------
    # Bundler (Gemfile)
    # ------------------------------------------------------------------

    def _check_bundler(
        self, package_name: str, manifest_path: Optional[str]
    ) -> MetadataAnalysisResult:
        gemfile = self.root / "Gemfile"
        if not gemfile.exists():
            return self._inconclusive(package_name, "Gemfile")

        content = gemfile.read_text(encoding="utf-8")
        # Find gem declarations inside :development / :test groups
        in_dev_group = False
        for line in content.splitlines():
            stripped = line.strip()
            if re.match(r"group\s+.*:(?:development|test)", stripped):
                in_dev_group = True
            if stripped == "end":
                in_dev_group = False
            if re.search(rf"""gem\s+['"]{ re.escape(package_name) }['"]""", stripped):
                return MetadataAnalysisResult(
                    is_dev_dependency=in_dev_group,
                    is_test_dependency=in_dev_group,
                    dependency_scope="development/test" if in_dev_group else "runtime",
                    manifest_path="Gemfile",
                    justification=(
                        f"'{package_name}' is in a {'development/test' if in_dev_group else 'runtime'} group."
                    ),
                )

        return self._inconclusive(package_name, "Gemfile")

    # ------------------------------------------------------------------
    # Maven (pom.xml)
    # ------------------------------------------------------------------

    def _check_maven(
        self, package_name: str, manifest_path: Optional[str]
    ) -> MetadataAnalysisResult:
        try:
            import xml.etree.ElementTree as ET
        except ImportError:
            return self._inconclusive(package_name, "pom.xml", "xml module not available")

        pom = self.root / "pom.xml"
        if not pom.exists():
            return self._inconclusive(package_name, "pom.xml")

        tree = ET.parse(str(pom))
        ns = {"m": "http://maven.apache.org/POM/4.0.0"}
        for dep in tree.findall(".//m:dependency", ns) + tree.findall(".//dependency"):
            artifact = (dep.findtext("m:artifactId", namespaces=ns) or
                        dep.findtext("artifactId") or "")
            scope = (dep.findtext("m:scope", namespaces=ns) or
                     dep.findtext("scope") or "compile")
            if artifact.lower() == package_name.lower():
                is_dev = scope.lower() in ("test", "provided")
                return MetadataAnalysisResult(
                    is_dev_dependency=is_dev,
                    is_test_dependency=scope.lower() == "test",
                    dependency_scope=scope,
                    manifest_path="pom.xml",
                    justification=f"'{package_name}' has Maven scope '{scope}'.",
                )

        return self._inconclusive(package_name, "pom.xml")

    # ------------------------------------------------------------------
    # Gradle (build.gradle)
    # ------------------------------------------------------------------

    def _check_gradle(
        self, package_name: str, manifest_path: Optional[str]
    ) -> MetadataAnalysisResult:
        gradle_files = list(self.root.rglob("build.gradle")) + list(self.root.rglob("build.gradle.kts"))
        for gradle_path in gradle_files:
            try:
                content = gradle_path.read_text(encoding="utf-8")
            except OSError:
                continue
            # Match lines like: testImplementation 'group:artifact:version'
            pattern = re.compile(
                rf"""(?P<conf>\w+)\s+['"]?[^'"]*{re.escape(package_name)}[^'"]*['"]?""",
                re.IGNORECASE,
            )
            m = pattern.search(content)
            if m:
                conf = m.group("conf").lower()
                is_dev = conf.startswith("test") or "test" in conf
                return MetadataAnalysisResult(
                    is_dev_dependency=is_dev,
                    is_test_dependency=is_dev,
                    dependency_scope=conf,
                    manifest_path=str(gradle_path.relative_to(self.root)),
                    justification=f"'{package_name}' uses Gradle configuration '{conf}'.",
                )

        return self._inconclusive(package_name, "build.gradle")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _inconclusive(
        package_name: str,
        manifest_path: str,
        reason: str = "",
    ) -> MetadataAnalysisResult:
        msg = f"Could not determine scope for '{package_name}'"
        if manifest_path and manifest_path != "N/A":
            msg += f" in '{manifest_path}'"
        msg += " — scope is unknown."
        if reason:
            msg += f" Reason: {reason}"
        return MetadataAnalysisResult(
            is_dev_dependency=False,
            is_test_dependency=False,
            dependency_scope="unknown",
            manifest_path=manifest_path,
            justification=msg,
        )
