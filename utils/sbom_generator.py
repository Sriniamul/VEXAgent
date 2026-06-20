"""
CycloneDX SBOM Generator.

Scans a repository for dependency manifest files and generates a
CycloneDX 1.5 Software Bill-of-Materials (SBOM) in JSON format.

Supported ecosystems:
  - Python  : requirements*.txt, Pipfile, pyproject.toml, setup.cfg
  - Node.js : package.json
  - Go      : go.mod
  - Maven   : pom.xml (simplified)
  - Cargo   : Cargo.toml
  - .NET    : *.csproj / packages.config
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------

class Component:
    """A single dependency extracted from a manifest."""

    def __init__(
        self,
        name: str,
        version: str,
        purl: str,
        ecosystem: str,
        scope: str = "required",   # required | optional | excluded
        manifest_path: str = "",
    ):
        self.bom_ref = str(uuid.uuid4())
        self.name = name
        self.version = version
        self.purl = purl
        self.ecosystem = ecosystem
        self.scope = scope
        self.manifest_path = manifest_path

    def to_cyclonedx(self) -> dict[str, Any]:
        return {
            "type": "library",
            "bom-ref": self.bom_ref,
            "name": self.name,
            "version": self.version,
            "purl": self.purl,
            "scope": self.scope,
            "evidence": {
                "identity": [
                    {
                        "field": "purl",
                        "confidence": 1,
                        "methods": [
                            {
                                "technique": "manifest-analysis",
                                "confidence": 1,
                                "value": self.manifest_path,
                            }
                        ],
                    }
                ]
            },
        }


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

class SBOMGenerator:
    """
    Scans a local repository and produces a CycloneDX 1.5 SBOM JSON document.
    """

    def __init__(self, repo_path: Path, repo_name: str = ""):
        self._root = repo_path
        self._repo_name = repo_name or repo_path.name

    def generate(self) -> dict[str, Any]:
        """Scan the repo and return the full CycloneDX SBOM as a dict."""
        components: list[Component] = []

        for manifest in self._root.rglob("*"):
            if not manifest.is_file():
                continue
            rel = str(manifest.relative_to(self._root))
            # Skip noise directories
            if any(p in rel for p in (".git", "node_modules", "__pycache__", ".venv", "dist", "build", "vendor")):
                continue

            name_lower = manifest.name.lower()
            try:
                if re.match(r"requirements.*\.txt$", name_lower):
                    components.extend(self._parse_requirements_txt(manifest, rel))
                elif name_lower == "pipfile":
                    components.extend(self._parse_pipfile(manifest, rel))
                elif name_lower == "pyproject.toml":
                    components.extend(self._parse_pyproject_toml(manifest, rel))
                elif name_lower == "package.json":
                    components.extend(self._parse_package_json(manifest, rel))
                elif name_lower == "go.mod":
                    components.extend(self._parse_go_mod(manifest, rel))
                elif name_lower == "cargo.toml":
                    components.extend(self._parse_cargo_toml(manifest, rel))
                elif name_lower == "pom.xml":
                    components.extend(self._parse_pom_xml(manifest, rel))
                elif name_lower == "packages.config":
                    components.extend(self._parse_packages_config(manifest, rel))
                elif name_lower.endswith(".csproj"):
                    components.extend(self._parse_csproj(manifest, rel))
            except Exception as exc:  # noqa: BLE001
                logger.debug("Could not parse %s: %s", rel, exc)

        # Deduplicate by purl
        seen: set[str] = set()
        unique: list[Component] = []
        for c in components:
            if c.purl not in seen:
                seen.add(c.purl)
                unique.append(c)

        logger.info("SBOM: discovered %d unique components from %s", len(unique), self._repo_name)
        return self._build_sbom(unique)

    def generate_json(self, indent: int = 2) -> str:
        """Return the SBOM serialised as a JSON string."""
        return json.dumps(self.generate(), indent=indent)

    # ------------------------------------------------------------------
    # Parsers
    # ------------------------------------------------------------------

    def _parse_requirements_txt(self, path: Path, rel: str) -> list[Component]:
        components = []
        for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("#", "-r", "--")):
                continue
            # Strip extras, environment markers
            line = re.split(r"[;#]", line)[0].strip()
            line = re.sub(r"\[.*?\]", "", line)
            m = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:[=!<>~^]+\s*([A-Za-z0-9.*+_-]+))?", line)
            if m:
                name, version = m.group(1), (m.group(2) or "").strip() or "unknown"
                version = version.lstrip("=").strip()
                components.append(Component(
                    name=name, version=version,
                    purl=f"pkg:pypi/{name.lower()}@{version}",
                    ecosystem="pypi", manifest_path=rel,
                ))
        return components

    def _parse_pipfile(self, path: Path, rel: str) -> list[Component]:
        """Minimal Pipfile parser (no full TOML needed — regex-based)."""
        components = []
        in_packages = False
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            stripped = line.strip()
            if stripped.startswith("["):
                in_packages = stripped in ("[packages]", "[dev-packages]")
                continue
            if not in_packages or not stripped or stripped.startswith("#"):
                continue
            m = re.match(r'^([A-Za-z0-9_.-]+)\s*=\s*["\']?([^"\']+)["\']?', stripped)
            if m:
                name, version = m.group(1), m.group(2).strip().lstrip("=").strip()
                if version in ("*", ""):
                    version = "unknown"
                components.append(Component(
                    name=name, version=version,
                    purl=f"pkg:pypi/{name.lower()}@{version}",
                    ecosystem="pypi", manifest_path=rel,
                ))
        return components

    def _parse_pyproject_toml(self, path: Path, rel: str) -> list[Component]:
        """Extract dependencies from [project].dependencies and [tool.poetry.dependencies]."""
        components = []
        text = path.read_text(encoding="utf-8", errors="ignore")
        # PEP 621 / poetry: "package>=1.0" strings
        for m in re.finditer(r'"([A-Za-z0-9_.-]+)\s*([><=!~^][^"]*)"', text):
            name = m.group(1)
            ver_raw = m.group(2).strip().lstrip(">=<!~^").split(",")[0].strip() or "unknown"
            components.append(Component(
                name=name, version=ver_raw,
                purl=f"pkg:pypi/{name.lower()}@{ver_raw}",
                ecosystem="pypi", manifest_path=rel,
            ))
        return components

    def _parse_package_json(self, path: Path, rel: str) -> list[Component]:
        components = []
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except json.JSONDecodeError:
            return components
        for section, scope in [("dependencies", "required"), ("devDependencies", "optional"), ("peerDependencies", "optional")]:
            for name, version_spec in data.get(section, {}).items():
                version = re.sub(r"[^A-Za-z0-9._+-]", "", str(version_spec)) or "unknown"
                # Handle scoped packages: @org/name
                purl_name = name.lstrip("@").replace("/", "%2F") if name.startswith("@") else name
                components.append(Component(
                    name=name, version=version,
                    purl=f"pkg:npm/{purl_name}@{version}",
                    ecosystem="npm", scope=scope, manifest_path=rel,
                ))
        return components

    def _parse_go_mod(self, path: Path, rel: str) -> list[Component]:
        components = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            # require lines: module/path v1.2.3
            m = re.match(r"^([a-z0-9A-Z./\-_]+)\s+(v[A-Za-z0-9.+-]+)", line)
            if m and not line.startswith("//") and not line.startswith("module"):
                module, version = m.group(1), m.group(2)
                components.append(Component(
                    name=module, version=version,
                    purl=f"pkg:golang/{module}@{version}",
                    ecosystem="golang", manifest_path=rel,
                ))
        return components

    def _parse_cargo_toml(self, path: Path, rel: str) -> list[Component]:
        components = []
        in_deps = False
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            stripped = line.strip()
            if stripped.startswith("["):
                in_deps = "dependencies" in stripped.lower()
                continue
            if not in_deps or not stripped or stripped.startswith("#"):
                continue
            m = re.match(r'^([A-Za-z0-9_-]+)\s*=\s*["\']?([0-9][^"\']*)["\']?', stripped)
            if m:
                name, version = m.group(1), m.group(2).strip()
                components.append(Component(
                    name=name, version=version,
                    purl=f"pkg:cargo/{name}@{version}",
                    ecosystem="cargo", manifest_path=rel,
                ))
        return components

    def _parse_pom_xml(self, path: Path, rel: str) -> list[Component]:
        """Very simplified pom.xml parser — extracts groupId/artifactId/version triples."""
        components = []
        text = path.read_text(encoding="utf-8", errors="ignore")
        for dep_block in re.findall(r"<dependency>(.*?)</dependency>", text, re.DOTALL):
            g = re.search(r"<groupId>(.*?)</groupId>", dep_block)
            a = re.search(r"<artifactId>(.*?)</artifactId>", dep_block)
            v = re.search(r"<version>(.*?)</version>", dep_block)
            if g and a:
                group_id = g.group(1).strip()
                artifact_id = a.group(1).strip()
                version = v.group(1).strip() if v else "unknown"
                # Skip property placeholders
                if "${" in version:
                    version = "unknown"
                components.append(Component(
                    name=f"{group_id}:{artifact_id}", version=version,
                    purl=f"pkg:maven/{group_id}/{artifact_id}@{version}",
                    ecosystem="maven", manifest_path=rel,
                ))
        return components

    def _parse_packages_config(self, path: Path, rel: str) -> list[Component]:
        components = []
        text = path.read_text(encoding="utf-8", errors="ignore")
        for m in re.finditer(r'<package\s+id="([^"]+)"\s+version="([^"]+)"', text):
            name, version = m.group(1), m.group(2)
            components.append(Component(
                name=name, version=version,
                purl=f"pkg:nuget/{name}@{version}",
                ecosystem="nuget", manifest_path=rel,
            ))
        return components

    def _parse_csproj(self, path: Path, rel: str) -> list[Component]:
        components = []
        text = path.read_text(encoding="utf-8", errors="ignore")
        for m in re.finditer(r'<PackageReference\s+Include="([^"]+)"(?:\s+Version="([^"]+)")?', text):
            name = m.group(1)
            version = m.group(2) or "unknown"
            components.append(Component(
                name=name, version=version,
                purl=f"pkg:nuget/{name}@{version}",
                ecosystem="nuget", manifest_path=rel,
            ))
        return components

    # ------------------------------------------------------------------
    # CycloneDX document builder
    # ------------------------------------------------------------------

    def _build_sbom(self, components: list[Component]) -> dict[str, Any]:
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": now_iso,
                "tools": [
                    {
                        "vendor": "VEX Agent",
                        "name": "vex-agent-sbom-generator",
                        "version": "1.0.0",
                    }
                ],
                "component": {
                    "type": "application",
                    "name": self._repo_name,
                    "version": "unknown",
                },
            },
            "components": [c.to_cyclonedx() for c in components],
        }
