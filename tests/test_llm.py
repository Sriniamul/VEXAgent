"""
Quick smoke test for the LLM (Copilot) reachability analyzer.

Creates a temporary repo with a known-vulnerable code pattern, sends it to
the configured LLM provider, and prints the verdict.

Usage:
    python test_llm.py
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
import sys

# Ensure workspace root is on sys.path when running directly
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


VULN_CODE = """\
import yaml

def load_config(path: str) -> dict:
    \"\"\"Load application config from a YAML file.\"\"\"
    with open(path) as fh:
        # yaml.load without Loader= is unsafe — CVE-2020-14343
        return yaml.load(fh)


if __name__ == "__main__":
    cfg = load_config("config.yaml")
    print(cfg)
"""

SAFE_CODE = """\
import yaml

def load_config(path: str) -> dict:
    with open(path) as fh:
        return yaml.safe_load(fh)   # safe — not vulnerable
"""


def make_repo(files: dict[str, str]) -> Path:
    tmpdir = tempfile.mkdtemp(prefix="vex_llm_test_")
    root = Path(tmpdir)
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return root


async def run_test(label: str, code: str, expect_reachable: bool) -> bool:
    from utils.llm_analyzer import LLMReachabilityAnalyzer

    analyzer = LLMReachabilityAnalyzer()

    if not analyzer._enabled:
        print(f"[SKIP] LLM analyzer is disabled — set COPILOT_TOKEN or OPENAI_API_KEY in .env")
        return False

    print(f"\n{'='*60}")
    print(f"  Test : {label}")
    print(f"  Provider : {analyzer._provider}")
    print(f"  Model    : {analyzer._model}")
    print(f"  Expects  : reachable={expect_reachable}")
    print(f"{'='*60}")

    repo = make_repo({"app/config_loader.py": code})

    result = await analyzer.analyse(
        repo_root=repo,
        package_name="pyyaml",
        vulnerable_functions=["load"],
    )

    print(f"  reachable  : {result.reachable}")
    print(f"  confidence : {result.confidence:.2f}")
    print(f"  notes      : {result.notes}")
    if result.hits:
        print(f"  hits ({len(result.hits)}):")
        for h in result.hits:
            print(f"    line {h.line_number}: {h.line_content.strip()!r}  [{h.function_called}]")

    passed = result.reachable == expect_reachable
    status = "PASS" if passed else "FAIL"
    print(f"\n  >>> {status}")
    return passed


async def main():
    # Show which provider is active
    from config import get_settings
    s = get_settings()
    print("Provider config:")
    print(f"  copilot_token set : {bool(s.copilot_token)}")
    print(f"  openai_key set    : {bool(s.openai_api_key)}")
    print(f"  copilot_model     : {s.copilot_model}")
    print(f"  copilot_api_base  : {s.copilot_api_base or '(auto)'}")

    from utils.llm_analyzer import LLMReachabilityAnalyzer
    a = LLMReachabilityAnalyzer()
    print(f"  resolved provider : {a._provider}")
    print(f"  resolved base_url : {a._base_url}")
    if a._provider == "github_models":
        print()
        print("  NOTE: GitHub Models API requires a PAT with the 'Models: Read and write'")
        print("  permission. Create/update your token at:")
        print("  https://github.com/settings/tokens → Fine-grained → GitHub Models")
        print()

    results = []
    results.append(await run_test("Vulnerable yaml.load() call", VULN_CODE, expect_reachable=True))
    results.append(await run_test("Safe yaml.safe_load() call", SAFE_CODE, expect_reachable=False))

    passed = sum(results)
    total = len(results)
    print(f"\n{'='*60}")
    print(f"  Results: {passed}/{total} passed")
    print(f"{'='*60}")


# ---------------------------------------------------------------------------
# pytest entry-point (skipped without LLM credentials)
# ---------------------------------------------------------------------------

async def test_llm_reachability_analysis() -> None:
    """LLM reachability smoke test.  Skipped unless COPILOT_TOKEN or OPENAI_API_KEY is set."""
    import pytest
    from config import get_settings
    s = get_settings()
    if not s.copilot_token and not s.openai_api_key:
        pytest.skip("No LLM credentials set (COPILOT_TOKEN / OPENAI_API_KEY) — skipping")
    await main()


if __name__ == "__main__":
    asyncio.run(main())
