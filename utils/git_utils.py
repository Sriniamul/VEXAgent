"""
Git utilities: shallow clone, cleanup, and file tree helpers.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import tempfile
import webbrowser
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Regex to extract the SAML SSO authorization URL from a git-clone error message
_SAML_SSO_URL_RE = re.compile(r"https://github\.com/enterprises/[^\s]+/sso\?[^\s]+")


class ShallowClone:
    """
    Context manager that performs a shallow git clone and cleans up afterward.

    If GitHub returns a SAML SSO enforcement error the clone will:
      1. Extract the authorization URL from the error message.
      2. Open it in the default browser automatically.
      3. Prompt the user to press Enter once they have authorized.
      4. Retry the clone (once).

    Usage:
        with ShallowClone(clone_url, branch="main") as repo_path:
            # repo_path is a Path pointing to the cloned directory
    """

    def __init__(
        self,
        clone_url: str,
        branch: str = "main",
        depth: int = 1,
        github_token: Optional[str] = None,
    ):
        self._clone_url = clone_url
        self._branch = branch
        self._depth = depth
        self._token = github_token
        self._tmpdir: Optional[str] = None
        self.path: Optional[Path] = None

    def __enter__(self) -> Path:
        self._tmpdir = tempfile.mkdtemp(prefix="vex_agent_")
        self._do_clone(retry=True)
        self.path = Path(self._tmpdir)
        return self.path

    def _do_clone(self, retry: bool = True) -> None:
        """Run git clone; on SAML SSO error open browser and retry once."""
        url = self._inject_token(self._clone_url)
        cmd = [
            "git", "clone",
            "--depth", str(self._depth),
            "--branch", self._branch,
            "--single-branch",
            url,
            self._tmpdir,
        ]
        logger.info("Shallow-cloning %s (branch=%s) …", self._clone_url, self._branch)
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired as exc:
            self._cleanup()
            raise RuntimeError("git clone timed out after 120 s") from exc
        except FileNotFoundError as exc:
            self._cleanup()
            raise RuntimeError("git not found on PATH; install Git") from exc

        if result.returncode == 0:
            return  # success

        stderr = result.stderr
        # ── SAML SSO enforcement? ──────────────────────────────────────────
        if retry and ("SAML" in stderr or "sso?" in stderr):
            sso_url = self._extract_sso_url(stderr)
            if sso_url:
                logger.warning(
                    "SAML SSO authorization required for this repository.\n"
                    "Opening browser to: %s", sso_url
                )
                print("\n" + "=" * 70)
                print("  SAML SSO authorization required")
                print("  Opening browser — please click 'Authorize' then press Enter here.")
                print("  URL: " + sso_url)
                print("=" * 70)
                webbrowser.open(sso_url)
                input("\n  Press Enter after you have authorized the token in the browser... ")
                # Wipe the failed clone dir and retry into a fresh one
                self._wipe_tmpdir()
                logger.info("Retrying clone after SSO authorization …")
                self._do_clone(retry=False)
                return

        self._cleanup()
        raise RuntimeError(f"git clone failed:\n{stderr}")

    def _extract_sso_url(self, text: str) -> Optional[str]:
        m = _SAML_SSO_URL_RE.search(text)
        return m.group(0) if m else None

    def _wipe_tmpdir(self) -> None:
        """Delete and recreate the temp directory without clearing self._tmpdir."""
        if self._tmpdir:
            def _force_remove(func, path, _exc_info):
                import os, stat
                try:
                    os.chmod(path, stat.S_IWRITE)
                    func(path)
                except Exception:
                    pass
            shutil.rmtree(self._tmpdir, onerror=_force_remove)
            import os
            os.makedirs(self._tmpdir, exist_ok=True)

    def __exit__(self, *_: object) -> None:
        self._cleanup()

    def _cleanup(self) -> None:
        if self._tmpdir:
            def _force_remove(func, path, _exc_info):
                import os, stat
                try:
                    os.chmod(path, stat.S_IWRITE)
                    func(path)
                except Exception:
                    pass
            shutil.rmtree(self._tmpdir, onerror=_force_remove)
            self._tmpdir = None
            self.path = None

    def _inject_token(self, url: str) -> str:
        """Embed GitHub PAT into HTTPS clone URL for authentication."""
        if self._token and url.startswith("https://"):
            url = url.replace("https://", f"https://x-access-token:{self._token}@")
        return url


class LocalRepo:
    """
    Context manager that uses an existing local repository rather than cloning.

    On entry it checks out the requested branch and runs ``git pull`` so the
    working tree is up-to-date.  On exit it does **not** delete anything —
    the local repo is left exactly as it was after the pull.

    Usage::

        with LocalRepo("/path/to/arm-arm", branch="master") as repo_path:
            # repo_path is a Path pointing to the local directory
    """

    def __init__(self, repo_path: str, branch: str = "master"):
        self._repo_path = Path(repo_path).resolve()
        self._branch = branch
        self.path: Optional[Path] = None

    def __enter__(self) -> Path:
        if not self._repo_path.is_dir():
            raise RuntimeError(
                f"LOCAL_REPO_PATH does not exist or is not a directory: {self._repo_path}"
            )
        if not (self._repo_path / ".git").is_dir():
            raise RuntimeError(
                f"Directory is not a git repository (no .git folder): {self._repo_path}"
            )

        logger.info("Using local repo at %s (branch=%s)", self._repo_path, self._branch)

        # Checkout the target branch
        self._run(["git", "checkout", self._branch], "git checkout")

        # Pull latest changes
        self._run(["git", "pull", "--ff-only"], "git pull")

        self.path = self._repo_path
        return self.path

    def __exit__(self, *_: object) -> None:
        # Nothing to clean up — the local repo stays intact.
        self.path = None

    def _run(self, cmd: list[str], label: str) -> None:
        """Run a git command inside the local repo directory."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(self._repo_path),
                timeout=60,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"{label} timed out after 60 s") from exc
        except FileNotFoundError as exc:
            raise RuntimeError("git not found on PATH; install Git") from exc

        if result.returncode != 0:
            raise RuntimeError(f"{label} failed:\n{result.stderr}")

        logger.info("%s OK: %s", label, (result.stdout or result.stderr).strip())


# ---------------------------------------------------------------------------
# File tree helpers
# ---------------------------------------------------------------------------

def iter_source_files(
    root: Path,
    include_extensions: tuple[str, ...] = (
        ".py", ".js", ".ts", ".jsx", ".tsx",
        ".java", ".go", ".rb", ".php", ".cs", ".cpp", ".c",
        ".rs", ".swift", ".kt",
    ),
    exclude_dirs: tuple[str, ...] = (
        ".git", "node_modules", "__pycache__", ".venv",
        "dist", "build", "vendor", "third_party",
    ),
):
    """
    Yield (relative_path, absolute_path) for every source file under *root*,
    skipping common noise directories.
    """
    for path in root.rglob("*"):
        if path.is_file():
            # Skip if any ancestor directory is in the exclusion list
            relative = path.relative_to(root)
            parts = relative.parts
            if any(part in exclude_dirs for part in parts[:-1]):
                continue
            if path.suffix.lower() in include_extensions:
                yield str(relative), path


def find_manifest_files(root: Path) -> dict[str, Path]:
    """
    Locate known dependency manifest files within the repo.
    Returns a mapping of filename → absolute Path.
    """
    manifests = {}
    known = {
        "package.json", "requirements.txt", "Pipfile", "pyproject.toml",
        "Gemfile", "pom.xml", "build.gradle", "go.mod", "Cargo.toml",
        "composer.json", "*.csproj", "packages.config",
    }
    for name in known:
        for found in root.rglob(name):
            manifests[str(found.relative_to(root))] = found
    return manifests
