"""
Tests for MetadataAnalyzer (Level 1 checks).
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from analyzers.metadata_analyzer import MetadataAnalyzer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_repo(files: dict[str, str]) -> Path:
    """Write *files* dict to a temporary directory and return its Path."""
    tmpdir = tempfile.mkdtemp(prefix="vex_test_")
    root = Path(tmpdir)
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return root


# ---------------------------------------------------------------------------
# npm tests
# ---------------------------------------------------------------------------

class TestNpmMetadata:
    def _analyzer(self, files: dict[str, str]) -> MetadataAnalyzer:
        return MetadataAnalyzer(make_repo(files))

    def test_dev_dependency_is_flagged(self):
        pkg = json.dumps({
            "dependencies": {"express": "^4.18.0"},
            "devDependencies": {"lodash": "^4.17.21"},
        })
        result = self._analyzer({"package.json": pkg}).analyse("lodash", "npm")
        assert result.is_dev_dependency is True
        assert result.dependency_scope == "devDependencies"

    def test_runtime_dependency_not_flagged(self):
        pkg = json.dumps({
            "dependencies": {"axios": "^1.0.0"},
            "devDependencies": {"jest": "^29.0.0"},
        })
        result = self._analyzer({"package.json": pkg}).analyse("axios", "npm")
        assert result.is_dev_dependency is False
        assert result.dependency_scope == "dependencies"

    def test_missing_package_returns_inconclusive(self):
        pkg = json.dumps({"dependencies": {}})
        result = self._analyzer({"package.json": pkg}).analyse("nonexistent-pkg", "npm")
        assert result.dependency_scope == "unknown"

    def test_optional_dependency_marked_dev(self):
        pkg = json.dumps({
            "optionalDependencies": {"fsevents": "^2.3.0"},
        })
        result = self._analyzer({"package.json": pkg}).analyse("fsevents", "npm")
        assert result.is_dev_dependency is True


# ---------------------------------------------------------------------------
# pip tests
# ---------------------------------------------------------------------------

class TestPipMetadata:
    def _analyzer(self, files: dict[str, str]) -> MetadataAnalyzer:
        return MetadataAnalyzer(make_repo(files))

    def test_dev_requirements_file(self):
        result = self._analyzer({
            "requirements.txt": "flask==3.0.0\n",
            "requirements-dev.txt": "pytest==8.0.0\nbandit==1.7.0\n",
        }).analyse("pytest", "pip")
        assert result.is_dev_dependency is True

    def test_runtime_requirements_file(self):
        result = self._analyzer({
            "requirements.txt": "requests==2.31.0\n",
        }).analyse("requests", "pip")
        assert result.is_dev_dependency is False

    def test_package_in_both_runtime_and_dev(self):
        """If it appears in a runtime file, it is considered a runtime dep."""
        result = self._analyzer({
            "requirements.txt": "requests==2.31.0\n",
            "requirements-dev.txt": "requests==2.31.0\n",
        }).analyse("requests", "pip")
        assert result.is_dev_dependency is False


# ---------------------------------------------------------------------------
# Maven tests
# ---------------------------------------------------------------------------

class TestMavenMetadata:
    POM_TEMPLATE = """\
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>{scope}</scope>
    </dependency>
  </dependencies>
</project>
"""

    def _analyzer(self, pom_content: str) -> MetadataAnalyzer:
        return MetadataAnalyzer(make_repo({"pom.xml": pom_content}))

    def test_test_scope(self):
        result = self._analyzer(self.POM_TEMPLATE.format(scope="test")).analyse("junit", "maven")
        assert result.is_dev_dependency is True
        assert result.dependency_scope == "test"

    def test_compile_scope(self):
        result = self._analyzer(self.POM_TEMPLATE.format(scope="compile")).analyse("junit", "maven")
        assert result.is_dev_dependency is False
