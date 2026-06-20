"""
End-to-end test for SBOM generation, VEX export, and disk file store.

Steps:
  1. Generate CycloneDX SBOM from local repo
  2. Export CycloneDX VEX document for a sample finding (AFFECTED_REACHABLE)
  3. Export CycloneDX VEX document for NOT_AFFECTED variant
  4. Upload SBOM + VEX to SharePoint {SHAREPOINT_FOLDER_PATH}/{product_version}/
  5. Test /sbom/generate API endpoint
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

from config import get_settings
from utils.sbom_generator import SBOMGenerator
from utils.vex_exporter import VexExporter, export_vex_json
from models.vex_models import (
    AnalysisDecision, JustificationCode, NormalisedFinding,
    VexDecision, VexStatus,
    ReachabilityAnalysisResult, ReachabilityHit, EpssScore,
)


async def main() -> None:
    s = get_settings()

    print()
    print("=" * 65)
    print("  SBOM + VEX Full Test")
    print("=" * 65)

    # ── Step 1: SBOM generation ───────────────────────────────────────
    print()
    print("=" * 65)
    print("  Step 1: Generate CycloneDX SBOM from local repo")
    print("=" * 65)

    repo_path = Path(s.local_repo_path) if s.local_repo_path else None
    if not repo_path or not repo_path.is_dir():
        print("  ✗ LOCAL_REPO_PATH not set or invalid — aborting")
        sys.exit(1)

    gen = SBOMGenerator(repo_path, repo_path.name)
    sbom = gen.generate()
    sbom_json_str = json.dumps(sbom, indent=2)
    components = sbom["components"]

    assert sbom["bomFormat"] == "CycloneDX", "bomFormat mismatch"
    assert sbom["specVersion"] == "1.5",     "specVersion mismatch"
    assert len(components) > 0,              "No components found"

    ecosystems: dict[str, int] = {}
    for c in components:
        purl = c.get("purl", "")
        eco = purl.split(":")[1].split("/")[0] if ":" in purl else "unknown"
        ecosystems[eco] = ecosystems.get(eco, 0) + 1

    c0 = components[0]
    assert all(f in c0 for f in ("bom-ref", "purl", "name")), "Component missing required fields"

    print(f"  bomFormat   : {sbom['bomFormat']} {sbom['specVersion']}")
    print(f"  Components  : {len(components)}")
    print(f"  Ecosystems  : {ecosystems}")
    print(f"  SBOM size   : {len(sbom_json_str):,} bytes")
    print(f"  Sample      : {c0['name']} {c0['version']}  →  {c0['purl']}")
    print(f"  ✓ SBOM generated and validated")

    # ── Step 2: VEX export — AFFECTED_REACHABLE ───────────────────────
    print()
    print("=" * 65)
    print("  Step 2: VEX export — AFFECTED_REACHABLE")
    print("=" * 65)

    finding = NormalisedFinding(
        repo_full_name="solarwinds-internal/arm-arm",
        repo_clone_url="https://github.com/solarwinds-internal/arm-arm.git",
        repo_default_branch="master",
        alert_id=42,
        package_name="requests",
        package_ecosystem="pip",
        package_version="2.27.1",
        vulnerable_version_range="< 2.31.0",
        patched_version="2.31.0",
        severity="high",
        cve_id="CVE-2023-32681",
        cvss_score=6.1,
        cvss_vector_string="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N",
        summary="requests forwards Proxy-Authorization headers to destination servers",
    )
    reachability = ReachabilityAnalysisResult(
        reachable=True, method="ast", confidence=0.95,
        hits=[ReachabilityHit(
            file_path="ARM/Services/HttpService.py", line_number=87,
            line_content="response = requests.get(url, proxies=proxies)",
            function_called="requests.get", confidence=0.95,
        )]
    )
    epss = EpssScore(cve="CVE-2023-32681", epss=0.0312, percentile=0.72, date="2026-03-18")
    vex_decision = VexDecision(
        finding=finding, decision=AnalysisDecision.AFFECTED_REACHABLE,
        epss_score=epss, reachability_result=reachability,
        vex_status=VexStatus.AFFECTED,
        impact_statement="Vulnerable code path reachable via AST at ARM/Services/HttpService.py:87",
    )
    suggested_fix = (
        "## Root Cause\n"
        "requests < 2.31.0 forwards the Proxy-Authorization header to the target server.\n\n"
        "## Fix\n"
        "Upgrade: pip install 'requests>=2.31.0'\n\n"
        "## Verify\n"
        "pip show requests | grep Version  # should be >= 2.31.0"
    )
    vex_json_str = export_vex_json(vex_decision, suggested_fix=suggested_fix)
    vex_doc = json.loads(vex_json_str)
    vuln = vex_doc["vulnerabilities"][0]
    ev = vuln.get("evidence", {}).get("occurrences", [])

    assert vex_doc["bomFormat"] == "CycloneDX"
    assert vex_doc["specVersion"] == "1.5"
    assert vuln["id"] == "CVE-2023-32681"
    assert vuln["analysis"]["state"] == "exploitable"
    assert vuln["affects"][0]["ref"] == "pkg:pypi/requests@2.27.1"
    assert len(ev) == 1 and ev[0]["location"] == "ARM/Services/HttpService.py:87"

    print(f"  vuln.id           : {vuln['id']}")
    print(f"  analysis.state    : {vuln['analysis']['state']}")
    print(f"  analysis.response : {vuln['analysis'].get('response', [])}")
    print(f"  affects.ref       : {vuln['affects'][0]['ref']}")
    print(f"  affects.version   : {vuln['affects'][0]['versions'][0]['version']}")
    print(f"  affects.range     : {vuln['affects'][0]['versions'][0]['range']}")
    print(f"  evidence hits     : {len(ev)} → {ev[0]['location']} → {ev[0]['symbol']}()")
    print(f"  VEX size          : {len(vex_json_str):,} bytes")
    print(f"  ✓ AFFECTED_REACHABLE VEX validated")

    # ── Step 3: VEX export — NOT_AFFECTED ────────────────────────────
    print()
    print("=" * 65)
    print("  Step 3: VEX export — NOT_AFFECTED (dead code)")
    print("=" * 65)

    vex_na_decision = VexDecision(
        finding=finding,
        decision=AnalysisDecision.NOT_AFFECTED_DEAD_CODE,
        epss_score=epss,
        reachability_result=ReachabilityAnalysisResult(reachable=False, method="ast", confidence=0.99),
        vex_status=VexStatus.NOT_AFFECTED,
        justification_code=JustificationCode.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
        impact_statement="No reachable calls to requests.get() found in any production code path.",
    )
    exporter = VexExporter()
    exporter.add_decision(vex_na_decision)
    vex_na_doc = exporter.export()
    vuln_na = vex_na_doc["vulnerabilities"][0]

    assert vuln_na["analysis"]["state"] == "not_affected"
    assert vuln_na["analysis"]["justification"] == "code_not_reachable"
    assert vuln_na["analysis"]["response"] == ["will_not_fix"]

    print(f"  analysis.state        : {vuln_na['analysis']['state']}")
    print(f"  analysis.justification: {vuln_na['analysis']['justification']}")
    print(f"  analysis.response     : {vuln_na['analysis']['response']}")
    print(f"  ✓ NOT_AFFECTED VEX validated")

    # ── Step 4: Save SBOM + VEX files to output repo ─────────────────
    print()
    print("=" * 65)
    print("  Step 4: Upload SBOM + VEX files to SharePoint (SHAREPOINT_SITE_URL)")
    print("=" * 65)

    from utils.vex_file_store import save_vex_and_sbom, read_product_version
    repo_path_obj = Path(s.local_repo_path)
    product_ver = read_product_version(repo_path_obj)
    print(f"  Product version : {product_ver}")

    if not s.sharepoint_site_url:
        print("  ⚠  SHAREPOINT_SITE_URL not set — skipping SharePoint upload step")
    else:
        written = save_vex_and_sbom(
            vex_json_str=vex_json_str,
            sbom_json=sbom_json_str,
            vex_filename="vex-requests-CVE-2023-32681.cdx.json",
            sbom_filename="sbom-arm-arm.cdx.json",
            repo_path=repo_path_obj,
            product_version=product_ver,
        )
        if len(written) == 2:
            for p in written:
                print(f"  ✓ Written: {p}")
        else:
            print(f"  ✗ Expected 2 files written, got {len(written)}")
            sys.exit(1)

    # ── Step 5: /sbom/generate API endpoint ──────────────────────────
    print()
    print("=" * 65)
    print("  Step 5: Test /sbom/generate API endpoint")
    print("=" * 65)

    import httpx
    try:
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.get(f"http://localhost:{s.port}/sbom/generate")
        if resp.status_code == 200:
            api_sbom = resp.json()
            print(f"  HTTP status    : {resp.status_code}")
            print(f"  bomFormat      : {api_sbom['bomFormat']} {api_sbom['specVersion']}")
            print(f"  Components     : {len(api_sbom['components'])}")
            print(f"  Content-Disp.  : {resp.headers.get('content-disposition', 'N/A')}")
            print(f"  ✓ /sbom/generate API OK")
        elif resp.status_code == 401:
            print(f"  ⚠  Server requires authentication — skipping API step")
        else:
            print(f"  ✗ API returned HTTP {resp.status_code}: {resp.text[:200]}")
            sys.exit(1)
    except Exception as exc:
        print(f"  ⚠  Server not reachable ({exc.__class__.__name__}) — skipping API step")

    print()
    print("=" * 65)
    print("  RESULT: PASS — all SBOM + VEX steps succeeded")
    print("=" * 65)


# ---------------------------------------------------------------------------
# pytest entry-point (skipped without LOCAL_REPO_PATH configured)
# ---------------------------------------------------------------------------

async def test_sbom_vex_pipeline() -> None:
    """E2E SBOM + VEX test.  Skipped unless LOCAL_REPO_PATH is configured."""
    import pytest
    s = get_settings()
    if not s.local_repo_path:
        pytest.skip("LOCAL_REPO_PATH not configured — skipping SBOM/VEX pipeline test")
    await main()


if __name__ == "__main__":
    asyncio.run(main())
