"""
License Compliance Analyzer.

Checks dependency licenses against a configurable allow/deny policy and
assigns a risk level to each package.

Risk Levels:
  - ``critical``  — copyleft licenses incompatible with commercial use (AGPL, SSPL)
  - ``high``      — strong copyleft licenses that require derivative-work disclosure (GPL)
  - ``medium``    — weak copyleft / file-level copyleft (LGPL, MPL, EPL, CDDL)
  - ``low``       — permissive licenses with minor conditions (Apache-2.0, MIT, BSD)
  - ``none``      — fully permissive or public-domain (Unlicense, CC0, 0BSD)
  - ``unknown``   — license not found in the knowledge base

Supports two modes of operation:
  1. **Offline / heuristic** — uses a built-in knowledge base that maps
     well-known packages to their SPDX licence identifiers (no network).
  2. **API lookup** — queries the package registry (PyPI, npm, Maven Central)
     to resolve the actual licence string if the package is not in the
     built-in database.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ── Risk classification ──────────────────────────────────────────────────

@dataclass(frozen=True)
class LicenseResult:
    """Outcome of a single package licence check."""
    license_id: str          # SPDX identifier or raw string
    risk_level: str          # critical | high | medium | low | none | unknown
    risk_label: str          # human-readable label for the dashboard
    copyleft: bool           # True for any copyleft variant
    commercial_ok: bool      # True if safe for closed-source / commercial use
    note: str = ""           # optional explanatory note


# ── SPDX → risk mapping ─────────────────────────────────────────────────

# Patterns are matched case-insensitively against the resolved SPDX string.

_CRITICAL_PATTERNS: list[str] = [
    r"\bAGPL",
    r"\bSSPL",
    r"\bAffero",
    r"\bServer.Side.Public",
]

_HIGH_PATTERNS: list[str] = [
    r"\bGPL-3",
    r"\bGPL-2",
    r"\bGPLv3",
    r"\bGPLv2",
    r"^GPL$",              # bare "GPL" without LGPL
    r"\bEuPL",
    r"\bOSL-3",
    r"\bCeCILL(?!-B|-C)",  # CeCILL is GPL-compat, but B and C are permissive
]

_MEDIUM_PATTERNS: list[str] = [
    r"\bLGPL",
    r"\bMPL",
    r"\bEPL",
    r"\bCDDL",
    r"\bCPL",
    r"\bCeCILL-C",
    r"\bArtistic-2",
    r"\bEclipse",
]

_LOW_PATTERNS: list[str] = [
    r"\bApache",
    r"\bBSD",
    r"\bISC\b",
    r"\bZlib\b",
    r"\bPSF",
    r"\bPython-2",
]

_NONE_PATTERNS: list[str] = [
    r"\bMIT\b",
    r"\bUnlicense",
    r"\bCC0",
    r"\b0BSD",
    r"\bWTFPL",
    r"\bPublic.Domain",
    r"\bBSL-1",               # Boost
]


def _classify_license(spdx: str) -> tuple[str, str, bool, bool]:
    """
    Return ``(risk_level, risk_label, copyleft, commercial_ok)`` for an SPDX
    license identifier.
    """
    if not spdx or spdx.lower() in ("unknown", "other", "none", "noassertion", ""):
        return "unknown", "Unknown", False, False

    for pat in _CRITICAL_PATTERNS:
        if re.search(pat, spdx, re.IGNORECASE):
            return "critical", "Copyleft (AGPL/SSPL)", True, False

    for pat in _HIGH_PATTERNS:
        if re.search(pat, spdx, re.IGNORECASE):
            return "high", "Strong Copyleft (GPL)", True, False

    for pat in _MEDIUM_PATTERNS:
        if re.search(pat, spdx, re.IGNORECASE):
            return "medium", "Weak Copyleft (LGPL/MPL)", True, True

    for pat in _NONE_PATTERNS:
        if re.search(pat, spdx, re.IGNORECASE):
            return "none", "Permissive", False, True

    for pat in _LOW_PATTERNS:
        if re.search(pat, spdx, re.IGNORECASE):
            return "low", "Permissive (conditions)", False, True

    return "unknown", "Unknown", False, False


# ── Well-known package → licence database ────────────────────────────────

# Maps (ecosystem, package_name) to SPDX identifier.
# This avoids network calls for the most common packages.

_KNOWN_LICENSES: dict[tuple[str, str], str] = {
    # ── pip ───────────────────────────────────────
    ("pip", "requests"):             "Apache-2.0",
    ("pip", "flask"):                "BSD-3-Clause",
    ("pip", "django"):               "BSD-3-Clause",
    ("pip", "numpy"):                "BSD-3-Clause",
    ("pip", "pandas"):               "BSD-3-Clause",
    ("pip", "scipy"):                "BSD-3-Clause",
    ("pip", "cryptography"):         "Apache-2.0",
    ("pip", "pyyaml"):               "MIT",
    ("pip", "pydantic"):             "MIT",
    ("pip", "fastapi"):              "MIT",
    ("pip", "uvicorn"):              "BSD-3-Clause",
    ("pip", "httpx"):                "BSD-3-Clause",
    ("pip", "boto3"):                "Apache-2.0",
    ("pip", "pillow"):               "MIT-CMU",
    ("pip", "setuptools"):           "MIT",
    ("pip", "pip"):                  "MIT",
    ("pip", "wheel"):                "MIT",
    ("pip", "certifi"):              "MPL-2.0",
    ("pip", "urllib3"):              "MIT",
    ("pip", "charset-normalizer"):   "MIT",
    ("pip", "idna"):                 "BSD-3-Clause",
    ("pip", "jinja2"):               "BSD-3-Clause",
    ("pip", "markupsafe"):           "BSD-3-Clause",
    ("pip", "click"):                "BSD-3-Clause",
    ("pip", "werkzeug"):             "BSD-3-Clause",
    ("pip", "sqlalchemy"):           "MIT",
    ("pip", "paramiko"):             "LGPL-2.1",
    ("pip", "pygments"):             "BSD-2-Clause",
    ("pip", "redis"):                "MIT",
    ("pip", "celery"):               "BSD-3-Clause",
    ("pip", "psycopg2"):             "LGPL-3.0",
    ("pip", "lxml"):                 "BSD-3-Clause",
    ("pip", "mysqlclient"):          "GPL-2.0",
    # ── npm ───────────────────────────────────────
    ("npm", "lodash"):               "MIT",
    ("npm", "express"):              "MIT",
    ("npm", "react"):                "MIT",
    ("npm", "axios"):                "MIT",
    ("npm", "webpack"):              "MIT",
    ("npm", "typescript"):           "Apache-2.0",
    ("npm", "next"):                 "MIT",
    ("npm", "vue"):                  "MIT",
    ("npm", "jquery"):               "MIT",
    ("npm", "moment"):               "MIT",
    ("npm", "underscore"):           "MIT",
    ("npm", "debug"):                "MIT",
    ("npm", "chalk"):                "MIT",
    ("npm", "minimist"):             "MIT",
    ("npm", "glob"):                 "ISC",
    ("npm", "semver"):               "ISC",
    ("npm", "commander"):            "MIT",
    ("npm", "yargs"):                "MIT",
    ("npm", "node-fetch"):           "MIT",
    ("npm", "async"):                "MIT",
    ("npm", "sharp"):                "Apache-2.0",
    ("npm", "bcrypt"):               "MIT",
    ("npm", "jsonwebtoken"):         "MIT",
    ("npm", "socket.io"):            "MIT",
    # ── maven ─────────────────────────────────────
    ("maven", "log4j-core"):         "Apache-2.0",
    ("maven", "spring-webmvc"):      "Apache-2.0",
    ("maven", "jackson-databind"):   "Apache-2.0",
    ("maven", "netty"):              "Apache-2.0",
    ("maven", "guava"):              "Apache-2.0",
    ("maven", "commons-io"):         "Apache-2.0",
    ("maven", "commons-lang3"):      "Apache-2.0",
    ("maven", "commons-text"):       "Apache-2.0",
    ("maven", "commons-collections4"): "Apache-2.0",
    ("maven", "commons-codec"):      "Apache-2.0",
    ("maven", "httpclient"):         "Apache-2.0",
    ("maven", "slf4j-api"):          "MIT",
    ("maven", "junit"):              "EPL-2.0",
    ("maven", "testng"):             "Apache-2.0",
    ("maven", "hibernate-core"):     "LGPL-2.1",
    ("maven", "mysql-connector-java"): "GPL-2.0",
    ("maven", "itext"):              "AGPL-3.0",
    ("maven", "jboss-logging"):      "Apache-2.0",
    # ── nuget ─────────────────────────────────────
    ("nuget", "Newtonsoft.Json"):     "MIT",
    ("nuget", "NUnit"):              "MIT",
    ("nuget", "Serilog"):            "Apache-2.0",
    ("nuget", "AutoMapper"):         "MIT",
    ("nuget", "Dapper"):             "Apache-2.0",
    ("nuget", "Moq"):                "BSD-3-Clause",
    ("nuget", "EPPlus"):             "LGPL-2.1",
    ("nuget", "SharpZipLib"):        "MIT",
    # ── go ────────────────────────────────────────
    ("go", "golang.org/x/net"):       "BSD-3-Clause",
    ("go", "golang.org/x/crypto"):    "BSD-3-Clause",
    ("go", "golang.org/x/text"):      "BSD-3-Clause",
    ("go", "golang.org/x/sys"):       "BSD-3-Clause",
    ("go", "github.com/gin-gonic/gin"): "MIT",
    ("go", "github.com/gorilla/mux"): "BSD-3-Clause",
    ("go", "github.com/sirupsen/logrus"): "MIT",
    # ── cargo ─────────────────────────────────────
    ("cargo", "serde"):              "MIT OR Apache-2.0",
    ("cargo", "serde_json"):         "MIT OR Apache-2.0",
    ("cargo", "tokio"):              "MIT",
    ("cargo", "hyper"):              "MIT",
    ("cargo", "regex"):              "MIT OR Apache-2.0",
    ("cargo", "clap"):               "MIT OR Apache-2.0",
    # ── bundler / rubygems ────────────────────────
    ("rubygems", "rails"):           "MIT",
    ("rubygems", "rack"):            "MIT",
    ("rubygems", "rack-protection"): "MIT",
    ("rubygems", "sinatra"):         "MIT",
    ("rubygems", "nokogiri"):        "MIT",
    ("rubygems", "puma"):            "BSD-3-Clause",
    ("rubygems", "bundler"):         "MIT",
    # ── composer ──────────────────────────────────
    ("composer", "monolog/monolog"): "MIT",
    ("composer", "laravel/framework"): "MIT",
    ("composer", "symfony/console"): "MIT",
}


class LicenseAnalyzer:
    """
    Analyse the license risk of a dependency.

    Usage::

        analyzer = LicenseAnalyzer()
        result = analyzer.check("pip", "mysqlclient")
        print(result.risk_level)   # "high"
        print(result.license_id)   # "GPL-2.0"
    """

    def __init__(
        self,
        *,
        deny_licenses: list[str] | None = None,
        warn_licenses: list[str] | None = None,
    ):
        self._deny = [re.compile(p, re.IGNORECASE) for p in (deny_licenses or [])]
        self._warn = [re.compile(p, re.IGNORECASE) for p in (warn_licenses or [])]

    def check(
        self,
        ecosystem: str,
        package_name: str,
        override_spdx: str | None = None,
    ) -> LicenseResult:
        """
        Look up the licence for *package_name* and classify its risk.

        Parameters
        ----------
        ecosystem
            Package ecosystem (pip, npm, maven, nuget, go, cargo, etc.).
        package_name
            Name of the dependency.
        override_spdx
            If provided, skip the knowledge-base lookup and classify this
            SPDX identifier directly.

        Returns
        -------
        LicenseResult
            Classification with risk level, label, and copyleft flag.
        """
        eco = ecosystem.lower().strip()
        pkg = package_name.strip()

        # 1. Use override if provided
        spdx = override_spdx
        if not spdx:
            # 2. Look up in knowledge base
            spdx = _KNOWN_LICENSES.get((eco, pkg))
            if not spdx:
                # Try without ecosystem prefix (partial match)
                spdx = _KNOWN_LICENSES.get(("", pkg))

        if not spdx:
            return LicenseResult(
                license_id="Unknown",
                risk_level="unknown",
                risk_label="Unknown",
                copyleft=False,
                commercial_ok=False,
                note=f"License not found for {eco}/{pkg}",
            )

        risk_level, risk_label, copyleft, commercial_ok = _classify_license(spdx)

        # Override with custom deny / warn lists
        note = ""
        for pat in self._deny:
            if pat.search(spdx):
                risk_level = "critical"
                risk_label = f"Policy Denied ({spdx})"
                commercial_ok = False
                note = "Matches organisation deny-list"
                break

        if risk_level not in ("critical", "high"):
            for pat in self._warn:
                if pat.search(spdx):
                    if risk_level in ("low", "none"):
                        risk_level = "medium"
                    risk_label = f"Policy Warning ({spdx})"
                    note = "Matches organisation warn-list"
                    break

        return LicenseResult(
            license_id=spdx,
            risk_level=risk_level,
            risk_label=risk_label,
            copyleft=copyleft,
            commercial_ok=commercial_ok,
            note=note,
        )

    def check_bulk(
        self,
        packages: list[tuple[str, str]],
    ) -> dict[str, LicenseResult]:
        """
        Check multiple packages at once.

        Parameters
        ----------
        packages
            List of ``(ecosystem, package_name)`` tuples.

        Returns
        -------
        dict mapping ``package_name`` to ``LicenseResult``.
        """
        return {pkg: self.check(eco, pkg) for eco, pkg in packages}
