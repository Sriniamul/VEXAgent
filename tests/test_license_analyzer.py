"""
Tests for the License Compliance Analyzer.
"""

import pytest
from analyzers.license_analyzer import LicenseAnalyzer, LicenseResult, _classify_license


# ═══════════════════════════════════════════════════════════════════════════
# 1. Classification function tests
# ═══════════════════════════════════════════════════════════════════════════

class TestClassifyLicense:
    """Direct tests for _classify_license()."""

    @pytest.mark.parametrize("spdx,expected_risk", [
        ("AGPL-3.0",     "critical"),
        ("AGPL-3.0-only", "critical"),
        ("SSPL-1.0",     "critical"),
        ("Affero GPL",   "critical"),
    ])
    def test_critical_licenses(self, spdx, expected_risk):
        risk_level, _, copyleft, commercial_ok = _classify_license(spdx)
        assert risk_level == expected_risk
        assert copyleft is True
        assert commercial_ok is False

    @pytest.mark.parametrize("spdx,expected_risk", [
        ("GPL-2.0",      "high"),
        ("GPL-3.0",      "high"),
        ("GPLv3",        "high"),
        ("GPLv2",        "high"),
        ("GPL",          "high"),
        ("OSL-3.0",      "high"),
    ])
    def test_high_risk_licenses(self, spdx, expected_risk):
        risk_level, _, copyleft, commercial_ok = _classify_license(spdx)
        assert risk_level == expected_risk
        assert copyleft is True
        assert commercial_ok is False

    @pytest.mark.parametrize("spdx,expected_risk", [
        ("LGPL-2.1",     "medium"),
        ("LGPL-3.0",     "medium"),
        ("MPL-2.0",      "medium"),
        ("EPL-2.0",      "medium"),
        ("CDDL-1.0",    "medium"),
        ("Eclipse Public License", "medium"),
    ])
    def test_medium_risk_licenses(self, spdx, expected_risk):
        risk_level, _, copyleft, commercial_ok = _classify_license(spdx)
        assert risk_level == expected_risk
        assert copyleft is True
        assert commercial_ok is True

    @pytest.mark.parametrize("spdx,expected_risk", [
        ("MIT",          "none"),
        ("Unlicense",    "none"),
        ("CC0-1.0",      "none"),
        ("0BSD",         "none"),
        ("WTFPL",        "none"),
        ("BSL-1.0",      "none"),
    ])
    def test_none_risk_licenses(self, spdx, expected_risk):
        risk_level, _, copyleft, commercial_ok = _classify_license(spdx)
        assert risk_level == expected_risk
        assert copyleft is False
        assert commercial_ok is True

    @pytest.mark.parametrize("spdx,expected_risk", [
        ("Apache-2.0",  "low"),
        ("BSD-3-Clause", "low"),
        ("BSD-2-Clause", "low"),
        ("ISC",          "low"),
        ("Zlib",         "low"),
        ("PSF-2.0",      "low"),
    ])
    def test_low_risk_licenses(self, spdx, expected_risk):
        risk_level, _, copyleft, commercial_ok = _classify_license(spdx)
        assert risk_level == expected_risk
        assert copyleft is False
        assert commercial_ok is True

    @pytest.mark.parametrize("spdx", ["unknown", "other", "none", "NoAssertion", "", None])
    def test_unknown_license(self, spdx):
        risk_level, _, _, _ = _classify_license(spdx)
        assert risk_level == "unknown"

    def test_dual_license_mit_apache(self):
        """MIT OR Apache-2.0 should match MIT first (none risk)."""
        risk, _, _, _ = _classify_license("MIT OR Apache-2.0")
        assert risk == "none"

    def test_lgpl_not_matched_by_gpl_pattern(self):
        """LGPL should be medium, not high — GPL pattern uses word boundary."""
        risk, _, _, _ = _classify_license("LGPL-2.1")
        assert risk == "medium"


# ═══════════════════════════════════════════════════════════════════════════
# 2. LicenseAnalyzer.check() tests
# ═══════════════════════════════════════════════════════════════════════════

class TestLicenseAnalyzerCheck:
    """Tests for the LicenseAnalyzer.check() method."""

    def setup_method(self):
        self.analyzer = LicenseAnalyzer()

    # ── Known packages ────────────────────────────────────────────────

    def test_pip_requests_is_permissive(self):
        r = self.analyzer.check("pip", "requests")
        assert r.license_id == "Apache-2.0"
        assert r.risk_level == "low"
        assert r.commercial_ok is True

    def test_pip_mysqlclient_is_gpl(self):
        r = self.analyzer.check("pip", "mysqlclient")
        assert r.license_id == "GPL-2.0"
        assert r.risk_level == "high"
        assert r.copyleft is True
        assert r.commercial_ok is False

    def test_pip_paramiko_is_lgpl(self):
        r = self.analyzer.check("pip", "paramiko")
        assert r.license_id == "LGPL-2.1"
        assert r.risk_level == "medium"
        assert r.copyleft is True
        assert r.commercial_ok is True

    def test_maven_itext_is_agpl(self):
        r = self.analyzer.check("maven", "itext")
        assert r.license_id == "AGPL-3.0"
        assert r.risk_level == "critical"
        assert r.copyleft is True
        assert r.commercial_ok is False

    def test_npm_lodash_is_mit(self):
        r = self.analyzer.check("npm", "lodash")
        assert r.license_id == "MIT"
        assert r.risk_level == "none"
        assert r.commercial_ok is True

    def test_nuget_epplus_is_lgpl(self):
        r = self.analyzer.check("nuget", "EPPlus")
        assert r.license_id == "LGPL-2.1"
        assert r.risk_level == "medium"

    def test_cargo_serde_dual_license(self):
        r = self.analyzer.check("cargo", "serde")
        assert r.license_id == "MIT OR Apache-2.0"
        assert r.risk_level == "none"

    def test_go_gin_is_mit(self):
        r = self.analyzer.check("go", "github.com/gin-gonic/gin")
        assert r.license_id == "MIT"
        assert r.risk_level == "none"

    # ── Unknown package ───────────────────────────────────────────────

    def test_unknown_package(self):
        r = self.analyzer.check("pip", "some-nonexistent-package-xyz")
        assert r.risk_level == "unknown"
        assert r.license_id == "Unknown"

    # ── Override SPDX ─────────────────────────────────────────────────

    def test_override_spdx(self):
        r = self.analyzer.check("pip", "requests", override_spdx="GPL-3.0")
        assert r.license_id == "GPL-3.0"
        assert r.risk_level == "high"

    # ── Case insensitive ecosystem ────────────────────────────────────

    def test_ecosystem_case_insensitive(self):
        r = self.analyzer.check("PIP", "requests")
        assert r.license_id == "Apache-2.0"


# ═══════════════════════════════════════════════════════════════════════════
# 3. Custom deny/warn list tests
# ═══════════════════════════════════════════════════════════════════════════

class TestCustomPolicies:
    """Tests for custom deny and warn lists."""

    def test_deny_list_overrides_to_critical(self):
        analyzer = LicenseAnalyzer(deny_licenses=["Apache"])
        r = analyzer.check("pip", "requests")
        assert r.risk_level == "critical"
        assert "Denied" in r.risk_label
        assert r.commercial_ok is False

    def test_warn_list_elevates_to_medium(self):
        analyzer = LicenseAnalyzer(warn_licenses=["MIT"])
        r = analyzer.check("npm", "lodash")
        # MIT is normally "none", warn should lift it to "medium"
        assert r.risk_level == "medium"
        assert "Warning" in r.risk_label

    def test_deny_takes_precedence_over_warn(self):
        analyzer = LicenseAnalyzer(deny_licenses=["MIT"], warn_licenses=["MIT"])
        r = analyzer.check("npm", "lodash")
        assert r.risk_level == "critical"

    def test_warn_does_not_lower_high_risk(self):
        analyzer = LicenseAnalyzer(warn_licenses=["GPL"])
        r = analyzer.check("pip", "mysqlclient")
        # GPL-2.0 is already high; warn should not change it
        assert r.risk_level == "high"

    def test_default_blocked_licenses_from_config_string(self):
        """Simulate parsing config.blocked_licenses = 'AGPL,SSPL,GPL'."""
        blocked = "AGPL,SSPL,GPL"
        patterns = [p.strip() for p in blocked.split(",") if p.strip()]
        analyzer = LicenseAnalyzer(deny_licenses=patterns)
        # GPL package should be critical (denied)
        r = analyzer.check("pip", "mysqlclient")
        assert r.risk_level == "critical"
        # MIT package should be unaffected
        r2 = analyzer.check("npm", "lodash")
        assert r2.risk_level == "none"


# ═══════════════════════════════════════════════════════════════════════════
# 4. Bulk check tests
# ═══════════════════════════════════════════════════════════════════════════

class TestBulkCheck:
    """Tests for check_bulk()."""

    def test_bulk_returns_all_packages(self):
        analyzer = LicenseAnalyzer()
        packages = [("pip", "requests"), ("npm", "lodash"), ("maven", "itext")]
        results = analyzer.check_bulk(packages)
        assert len(results) == 3
        assert "requests" in results
        assert "lodash" in results
        assert "itext" in results

    def test_bulk_mixed_risks(self):
        analyzer = LicenseAnalyzer()
        packages = [("pip", "requests"), ("pip", "mysqlclient"), ("maven", "itext")]
        results = analyzer.check_bulk(packages)
        assert results["requests"].risk_level == "low"
        assert results["mysqlclient"].risk_level == "high"
        assert results["itext"].risk_level == "critical"


# ═══════════════════════════════════════════════════════════════════════════
# 5. LicenseResult dataclass tests
# ═══════════════════════════════════════════════════════════════════════════

class TestLicenseResult:
    """Tests for the LicenseResult dataclass."""

    def test_frozen(self):
        r = LicenseResult(
            license_id="MIT", risk_level="none", risk_label="Permissive",
            copyleft=False, commercial_ok=True,
        )
        with pytest.raises(AttributeError):
            r.risk_level = "high"  # type: ignore[misc]

    def test_note_default_empty(self):
        r = LicenseResult(
            license_id="MIT", risk_level="none", risk_label="Permissive",
            copyleft=False, commercial_ok=True,
        )
        assert r.note == ""

    def test_note_custom(self):
        r = LicenseResult(
            license_id="MIT", risk_level="none", risk_label="Permissive",
            copyleft=False, commercial_ok=True, note="test note",
        )
        assert r.note == "test note"


# ═══════════════════════════════════════════════════════════════════════════
# 6. Dashboard integration smoke test
# ═══════════════════════════════════════════════════════════════════════════

class TestDashboardIntegration:
    """Verify PipelineRun accepts and serialises license_risk."""

    def test_pipeline_run_with_license_risk(self):
        from utils.dashboard_store import PipelineRun
        run = PipelineRun(
            repo="org/repo",
            alert_id=1,
            alert_type="dependabot",
            package_name="mysqlclient",
            cve_id="CVE-2024-0001",
            severity="high",
            decision="affected_reachable",
            vex_status="affected",
            license_risk="GPL-2.0 (High)",
        )
        d = run.to_dict()
        assert d["license_risk"] == "GPL-2.0 (High)"

    def test_pipeline_run_license_risk_default_empty(self):
        from utils.dashboard_store import PipelineRun
        run = PipelineRun(
            repo="org/repo",
            alert_id=2,
            alert_type="dependabot",
            package_name="requests",
            cve_id="CVE-2024-0002",
            severity="medium",
            decision="not_affected_dev_only",
            vex_status="not_affected",
        )
        d = run.to_dict()
        assert d["license_risk"] == ""
