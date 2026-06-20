"""
Smoke test for the ShallowClone util.

Clones a small public GitHub repo (using the configured GITHUB_TOKEN),
then verifies the contents look correct and that cleanup works.

Usage:
    python test_clone.py [owner/repo]   (default: octocat/Hello-World)
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

# Ensure workspace root is on sys.path
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)

from config import get_settings
from utils.git_utils import LocalRepo, ShallowClone, iter_source_files


def main():
    s = get_settings()

    # ── Decide: local repo path or remote clone ─────────────────────────
    use_local = bool(s.local_repo_path)
    branch = s.target_repo_branch or "master"

    # CLI override > env setting > fallback default
    if len(sys.argv) > 1:
        repo_arg = sys.argv[1]
        # Accept full URL or owner/repo shorthand
        if repo_arg.startswith("https://"):
            clone_url = repo_arg
            repo = clone_url.rstrip("/").rstrip(".git").split("/")[-2] + "/" + clone_url.rstrip("/").rstrip(".git").split("/")[-1]
        else:
            repo = repo_arg
            clone_url = f"https://github.com/{repo}.git"
        branch = "main"
        use_local = False  # explicit CLI arg → always clone
    elif use_local:
        clone_url = s.target_repo_url
        repo = s.local_repo_path
    elif s.target_repo_url:
        clone_url = s.target_repo_url
        repo = "/".join(clone_url.rstrip("/").rstrip(".git").split("/")[-2:])
    else:
        repo = "octocat/Hello-World"
        clone_url = f"https://github.com/{repo}.git"
        branch = "master"
        use_local = False

    print()
    print("=" * 60)
    print("  Clone configuration")
    print("=" * 60)
    if use_local:
        print(f"  mode       : LOCAL (checkout + pull)")
        print(f"  local path : {s.local_repo_path}")
    else:
        print(f"  mode       : REMOTE (shallow clone)")
        print(f"  repo       : {repo}")
        print(f"  clone_url  : {clone_url}")
        print(f"  depth      : {s.shallow_clone_depth}")
        print(f"  token set  : {bool(s.github_token)}")
    print(f"  branch     : {branch}")
    print()

    # ── Step 1: Acquire repo ────────────────────────────────────
    print("=" * 60)
    if use_local:
        print("  Step 1: Use local repo (checkout + pull)")
    else:
        print("  Step 1: Shallow clone")
    print("=" * 60)

    ctx = (
        LocalRepo(s.local_repo_path, branch=branch)
        if use_local
        else ShallowClone(
            clone_url,
            branch=branch,
            depth=s.shallow_clone_depth,
            github_token=s.github_token,
        )
    )

    try:
        with ctx as repo_path:
            label = "Using local" if use_local else "Cloned to "
            print(f"  ✓ {label}  : {repo_path}")

            # ── Step 2: Verify directory exists and has files ───────────
            print()
            print("=" * 60)
            print("  Step 2: Verify contents")
            print("=" * 60)

            all_files = list(repo_path.rglob("*"))
            non_git = [f for f in all_files if ".git" not in f.parts and f.is_file()]
            print(f"  Total files  (excl .git) : {len(non_git)}")
            for f in sorted(non_git)[:15]:
                print(f"    {f.relative_to(repo_path)}")
            if len(non_git) > 15:
                print(f"    ... ({len(non_git) - 15} more)")

            if not non_git:
                print("  ✗ No files found in cloned repo — unexpected!")
                sys.exit(1)
            print("  ✓ Files present")

            # ── Step 3: iter_source_files helper ───────────────────────
            print()
            print("=" * 60)
            print("  Step 3: Source file iterator")
            print("=" * 60)
            src_files = list(iter_source_files(repo_path))
            print(f"  Source files found : {len(src_files)}")
            for rel, _ in src_files[:10]:
                print(f"    {rel}")

            # ── Step 4: Confirm tmpdir exists before exit ────────────────────
            tmpdir = repo_path
            print()
            print("=" * 60)
            if use_local:
                print("  Step 4: Verify local repo path persists after exit")
            else:
                print("  Step 4: Cleanup on context exit")
            print("=" * 60)
            print(f"  path before exit : {'exists' if tmpdir.exists() else 'missing'}")

        # After `with` block
        if use_local:
            # Local repo should still exist — nothing was cleaned up
            if tmpdir.exists():
                print(f"  \u2713 Local repo path still intact: {tmpdir}")
            else:
                print(f"  \u2717 Local repo path unexpectedly gone: {tmpdir}")
                sys.exit(1)
        else:
            # Temp clone dir should have been removed
            still_exists = tmpdir.exists()
            if still_exists:
                print(f"  \u2717 tmpdir still exists after cleanup: {tmpdir}")
                sys.exit(1)
            else:
                print(f"  \u2713 tmpdir cleaned up successfully")

    except RuntimeError as exc:
        mode = "local repo" if use_local else "clone"
        print(f"  ✗ {mode} failed: {exc}")
        sys.exit(1)

    print()
    print("=" * 60)
    if use_local:
        print("  RESULT: PASS — local repo checkout, inspect, and persist all succeeded")
    else:
        print("  RESULT: PASS — clone, inspect, and cleanup all succeeded")
    print("=" * 60)


# ---------------------------------------------------------------------------
# pytest entry-point (skipped without GITHUB_TOKEN configured)
# ---------------------------------------------------------------------------

def test_clone_smoke() -> None:
    """Smoke test: shallow-clone a public repo.  Skipped if GITHUB_TOKEN not set."""
    import pytest
    s = get_settings()
    if not s.github_token:
        pytest.skip("GITHUB_TOKEN not configured — skipping live clone smoke test")
    # Neutralise pytest's CLI args so main()'s sys.argv branch picks the default repo.
    import unittest.mock
    with unittest.mock.patch("sys.argv", ["test_clone.py"]):
        main()


if __name__ == "__main__":
    main()
