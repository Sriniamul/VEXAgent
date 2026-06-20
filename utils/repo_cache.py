"""
Persistent Repository Cache.

Clones a repository **once** to a local directory and builds a source-file
cache that is reused across pipeline invocations.  Subsequent calls skip the
clone (using ``git fetch``/``git pull`` instead) and only rebuild the file
cache when the HEAD commit changes.

Layout on disk::

    {cache_root}/
      {owner}--{repo}/               ← persistent working-tree
        .git/
        ...
      .vex_cache/
        {owner}--{repo}/
          head_sha.txt                ← commit SHA when file cache was built
          file_cache.json             ← serialised list[(rel_path, ext, content)]

Usage::

    from utils.repo_cache import RepoCacheManager

    mgr = RepoCacheManager()
    repo_path, file_cache = mgr.ensure(
        clone_url="https://github.com/owner/repo.git",
        branch="main",
    )
    # repo_path:  Path to the up-to-date working-tree
    # file_cache: list[(rel_path, ext, content)] ready for ReachabilityAnalyzer
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Optional

from analyzers.reachability_analyzer import ReachabilityAnalyzer

logger = logging.getLogger(__name__)

# Regex to extract owner/repo from common GitHub URL patterns
_REPO_SLUG_RE = re.compile(
    r"(?:github\.com[:/])([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)


def _slug_from_url(clone_url: str) -> str:
    """
    Derive a filesystem-safe identifier from a clone URL.

    ``https://github.com/acme/my-repo.git`` → ``acme--my-repo``
    """
    m = _REPO_SLUG_RE.search(clone_url)
    if m:
        return m.group(1).replace("/", "--")
    # Fallback: hash the full URL
    return hashlib.sha256(clone_url.encode()).hexdigest()[:24]


def _force_remove(func, path, _exc_info):
    """onerror handler for shutil.rmtree — remove read-only files on Windows."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


class RepoCacheManager:
    """
    Manages a persistent clone + source-file cache for one or more repos.

    Parameters
    ----------
    cache_root
        Top-level directory where all cached repos live.
        Defaults to ``{cwd}/.repo_cache``.
    github_token
        Personal-access-token injected into HTTPS clone URLs.
    default_depth
        ``--depth`` passed to ``git clone`` (0 = full clone).
    """

    def __init__(
        self,
        cache_root: str | Path | None = None,
        github_token: str = "",
        default_depth: int = 1,
    ):
        if cache_root:
            self._root = Path(cache_root).resolve()
        else:
            self._root = Path.cwd() / ".repo_cache"
        self._root.mkdir(parents=True, exist_ok=True)
        self._token = github_token
        self._depth = default_depth

        # In-memory cache keyed by slug → (head_sha, file_cache)
        self._mem_cache: dict[str, tuple[str, list[tuple[str, str, str]]]] = {}

        logger.info("RepoCacheManager initialised — cache_root=%s", self._root)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ensure(
        self,
        clone_url: str,
        branch: str = "main",
        *,
        force_rebuild: bool = False,
    ) -> tuple[Path, list[tuple[str, str, str]]]:
        """
        Return ``(repo_path, file_cache)`` for the given repository.

        1. If a cached clone already exists → ``git fetch`` + ``git checkout``
           + ``git reset --hard origin/{branch}``
        2. Otherwise → ``git clone``
        3. Compare HEAD SHA against the stored value; rebuild the file cache
           only when they differ (or *force_rebuild* is ``True``).

        The returned *file_cache* is a list of
        ``(relative_path, extension, file_content)`` tuples ready for
        ``ReachabilityAnalyzer(repo_path, file_cache=file_cache)``.
        """
        slug = _slug_from_url(clone_url)
        repo_dir = self._root / slug
        cache_dir = self._root / ".vex_cache" / slug
        cache_dir.mkdir(parents=True, exist_ok=True)

        # ── 1. Clone or update ────────────────────────────────────────
        if (repo_dir / ".git").is_dir():
            self._update(repo_dir, branch)
        else:
            self._clone(clone_url, repo_dir, branch)

        # ── 2. Read current HEAD ──────────────────────────────────────
        current_sha = self._head_sha(repo_dir)

        # ── 3. Load or rebuild file cache ─────────────────────────────
        sha_file = cache_dir / "head_sha.txt"
        cache_file = cache_dir / "file_cache.json"

        cached_sha = sha_file.read_text().strip() if sha_file.exists() else ""

        if (
            not force_rebuild
            and cached_sha == current_sha
            and cache_file.exists()
        ):
            # Fast path → check in-memory first
            if slug in self._mem_cache and self._mem_cache[slug][0] == current_sha:
                logger.info("File cache hit (memory): %s @ %s", slug, current_sha[:8])
                return repo_dir, self._mem_cache[slug][1]

            # Load from disk
            logger.info("File cache hit (disk): %s @ %s", slug, current_sha[:8])
            file_cache = self._load_cache(cache_file)
            self._mem_cache[slug] = (current_sha, file_cache)
            return repo_dir, file_cache

        # Rebuild
        logger.info(
            "Rebuilding file cache for %s (old=%s → new=%s) …",
            slug, cached_sha[:8] if cached_sha else "<none>", current_sha[:8],
        )
        file_cache = ReachabilityAnalyzer.build_file_cache(repo_dir)
        self._save_cache(cache_file, file_cache)
        sha_file.write_text(current_sha)
        self._mem_cache[slug] = (current_sha, file_cache)
        logger.info("File cache built and saved: %d files for %s", len(file_cache), slug)
        return repo_dir, file_cache

    def invalidate(self, clone_url: str) -> None:
        """Delete the cached clone and file cache for a repository."""
        slug = _slug_from_url(clone_url)
        repo_dir = self._root / slug
        cache_dir = self._root / ".vex_cache" / slug
        if repo_dir.exists():
            shutil.rmtree(repo_dir, onerror=_force_remove)
        if cache_dir.exists():
            shutil.rmtree(cache_dir, onerror=_force_remove)
        self._mem_cache.pop(slug, None)
        logger.info("Cache invalidated for %s", slug)

    def get_repo_path(self, clone_url: str) -> Path | None:
        """Return the cached repo path if it exists, else None."""
        slug = _slug_from_url(clone_url)
        repo_dir = self._root / slug
        return repo_dir if (repo_dir / ".git").is_dir() else None

    # ------------------------------------------------------------------
    # Git operations
    # ------------------------------------------------------------------

    def _clone(self, clone_url: str, dest: Path, branch: str) -> None:
        """Shallow-clone the repository into *dest*."""
        url = self._inject_token(clone_url)
        cmd = [
            "git", "clone",
            "--branch", branch,
            "--single-branch",
            url,
            str(dest),
        ]
        if self._depth > 0:
            cmd[2:2] = ["--depth", str(self._depth)]
        logger.info("Cloning %s (branch=%s) → %s …", clone_url, branch, dest)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        if result.returncode != 0:
            raise RuntimeError(f"git clone failed:\n{result.stderr}")
        logger.info("Clone complete: %s", dest)

    def _update(self, repo_dir: Path, branch: str) -> None:
        """Fetch + checkout + hard-reset to bring an existing clone up-to-date."""
        logger.info("Updating cached clone at %s (branch=%s) …", repo_dir, branch)

        # Ensure the remote URL has the current token
        origin_url = self._get_origin_url(repo_dir)
        if origin_url and self._token:
            new_url = self._inject_token(origin_url)
            self._git(repo_dir, ["git", "remote", "set-url", "origin", new_url], "set-url")

        self._git(repo_dir, ["git", "fetch", "origin", branch], "fetch")
        self._git(repo_dir, ["git", "checkout", branch], "checkout")
        self._git(repo_dir, ["git", "reset", "--hard", f"origin/{branch}"], "reset")
        logger.info("Update complete: %s", repo_dir)

    def _head_sha(self, repo_dir: Path) -> str:
        """Return the full SHA of the current HEAD."""
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, cwd=str(repo_dir), timeout=10,
        )
        return result.stdout.strip() if result.returncode == 0 else ""

    def _get_origin_url(self, repo_dir: Path) -> str:
        """Return the remote origin URL (without embedded token)."""
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True, text=True, cwd=str(repo_dir), timeout=10,
        )
        url = result.stdout.strip() if result.returncode == 0 else ""
        # Strip any embedded token from the URL for comparison
        return re.sub(r"https://[^@]+@", "https://", url)

    def _inject_token(self, url: str) -> str:
        """Embed GitHub PAT into HTTPS clone URL."""
        # First strip any existing embedded credentials
        clean = re.sub(r"https://[^@]+@", "https://", url)
        if self._token and clean.startswith("https://"):
            return clean.replace("https://", f"https://x-access-token:{self._token}@")
        return clean

    @staticmethod
    def _git(cwd: Path, cmd: list[str], label: str) -> str:
        """Run a git command and return stdout; raise on failure."""
        result = subprocess.run(
            cmd, capture_output=True, text=True, cwd=str(cwd), timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(f"git {label} failed:\n{result.stderr}")
        return result.stdout

    # ------------------------------------------------------------------
    # File cache serialisation
    # ------------------------------------------------------------------

    @staticmethod
    def _save_cache(path: Path, cache: list[tuple[str, str, str]]) -> None:
        """Serialise the file cache to a JSON file."""
        # Store as a list of [rel_path, ext, content]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cache, f)
        logger.debug("File cache saved: %s (%.1f MB)", path, path.stat().st_size / 1_048_576)

    @staticmethod
    def _load_cache(path: Path) -> list[tuple[str, str, str]]:
        """Deserialise the file cache from a JSON file."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Convert lists back to tuples
        cache = [(item[0], item[1], item[2]) for item in data]
        logger.debug("File cache loaded: %s (%d files)", path, len(cache))
        return cache
