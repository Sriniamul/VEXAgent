"""
Simulated GitHub security alert mock data for the ARM repository.

Contains 80+ alerts across all three alert types:
  - Dependabot (SCA / dependency vulnerability)
  - Code Scanning (SAST)
  - Secret Scanning

Covers severity levels: critical, high, medium, low
Covers ecosystems: pip, npm, maven, nuget, rubygems, cargo, go, composer
Covers code-scanning tools: CodeQL, Semgrep, Bandit, Trivy, Snyk

Usage
-----
    from clients.mock_github_data import (
        MOCK_DEPENDABOT_ALERTS,
        MOCK_CODE_SCANNING_ALERTS,
        MOCK_SECRET_SCANNING_ALERTS,
    )
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_REPO = "solarwinds-internal/arm-arm"
_HTML_BASE = f"https://github.com/{_REPO}"


def _da(  # dependabot alert short-form builder
    number: int,
    pkg: str,
    ecosystem: str,
    cve: str | None,
    ghsa: str,
    severity: str,
    cvss: float,
    vuln_range: str,
    patched: str | None,
    summary: str,
    manifest: str,
    scope: str = "runtime",
    vector: str | None = None,
) -> dict:
    identifiers = [{"type": "GHSA", "value": ghsa}]
    if cve:
        identifiers.insert(0, {"type": "CVE", "value": cve})
    return {
        "number": number,
        "state": "open",
        "dependency": {
            "package": {"ecosystem": ecosystem, "name": pkg},
            "manifest_path": manifest,
            "scope": scope,
        },
        "security_advisory": {
            "ghsa_id": ghsa,
            "cve_id": cve,
            "summary": summary,
            "description": summary,
            "severity": severity,
            "identifiers": identifiers,
            "references": [{"url": f"https://github.com/advisories/{ghsa}"}],
            "cvss": {"score": cvss, "vectorString": vector or f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N"},
            "vulnerable_functions": [],
        },
        "security_vulnerability": {
            "package": {"ecosystem": ecosystem, "name": pkg},
            "severity": severity,
            "vulnerable_version_range": vuln_range,
            "first_patched_version": {"identifier": patched} if patched else None,
        },
        "url": f"https://api.github.com/repos/{_REPO}/dependabot/alerts/{number}",
        "html_url": f"{_HTML_BASE}/security/dependabot/{number}",
        "auto_dismissed_at": None,
        "dismissed_at": None,
    }


def _cs(  # code-scanning alert short-form builder
    number: int,
    rule_id: str,
    rule_name: str,
    severity: str,
    tool: str,
    path: str,
    start_line: int,
    description: str,
    cwe: str | None = None,
) -> dict:
    tags = ["security"]
    if cwe:
        tags.append(cwe)
    return {
        "number": number,
        "state": "open",
        "rule": {
            "id": rule_id,
            "name": rule_name,
            "severity": severity,
            "security_severity_level": severity,
            "description": description,
            "tags": tags,
        },
        "tool": {"name": tool, "version": "2.13.5"},
        "most_recent_instance": {
            "ref": "refs/heads/main",
            "state": "open",
            "location": {
                "path": path,
                "start_line": start_line,
                "end_line": start_line + 3,
                "start_column": 1,
                "end_column": 80,
            },
            "message": {"text": description},
        },
        "url": f"https://api.github.com/repos/{_REPO}/code-scanning/alerts/{number}",
        "html_url": f"{_HTML_BASE}/security/code-scanning/{number}",
    }


def _ss(  # secret-scanning alert short-form builder
    number: int,
    secret_type: str,
    display_name: str,
    state: str = "open",
    resolution: str | None = None,
    validity: str = "unknown",
    push_protection_bypassed: bool = False,
) -> dict:
    return {
        "number": number,
        "state": state,
        "created_at": "2025-09-15T08:30:00Z",
        "updated_at": "2025-09-15T08:30:00Z",
        "secret_type": secret_type,
        "secret_type_display_name": display_name,
        "secret": "***REDACTED***",
        "resolution": resolution,
        "resolved_at": None,
        "validity": validity,
        "push_protection_bypassed": push_protection_bypassed,
        "push_protection_bypassed_at": None,
        "url": f"https://api.github.com/repos/{_REPO}/secret-scanning/alerts/{number}",
        "html_url": f"{_HTML_BASE}/security/secret-scanning/{number}",
    }


# ===========================================================================
# DEPENDABOT ALERTS  (40 alerts)
# ===========================================================================

MOCK_DEPENDABOT_ALERTS: list[dict] = [
    # ── CRITICAL ────────────────────────────────────────────────────────────
    _da(1,  "log4j-core",       "maven",    "CVE-2021-44228", "GHSA-jfh8-c2jp-hdwn", "critical", 10.0,  "< 2.15.0",        "2.15.0",  "Log4Shell: RCE via JNDI lookups in log messages",                   "pom.xml",            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    _da(2,  "spring-webmvc",    "maven",    "CVE-2022-22965", "GHSA-36p3-wjmg-h94x", "critical", 9.8,   "< 5.3.18",        "5.3.18",  "Spring4Shell: RCE via data binding on JDK9+",                        "pom.xml",            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    _da(3,  "jackson-databind", "maven",    "CVE-2020-36518", "GHSA-57j2-w4cx-9mjj", "critical", 9.6,   "< 2.13.2.1",      "2.13.2.1","Deeply nested arrays cause stack overflow — RCE possible",           "pom.xml"),
    _da(4,  "netty",            "maven",    "CVE-2023-34462", "GHSA-6mjq-h674-j845", "critical", 9.4,   "< 4.1.94.Final",  "4.1.94.Final","SslHandler native OOM/RCE on malformed TLS ClientHello",          "pom.xml"),
    _da(5,  "requests",         "pip",      "CVE-2023-32681", "GHSA-j8r2-6x86-q33q", "critical", 9.1,   "< 2.31.0",        "2.31.0",  "Unintended leak of Proxy-Authorization header to destination server", "requirements.txt"),
    _da(6,  "cryptography",     "pip",      "CVE-2023-49083", "GHSA-w7pp-m8wf-vj6r", "critical", 9.1,   "< 41.0.6",        "41.0.6",  "NULL pointer dereference in PKCS12 parsing",                         "requirements.txt"),
    _da(7,  "lodash",           "npm",      "CVE-2021-23337", "GHSA-35jh-r3h4-6jhm", "critical", 9.1,   "< 4.17.21",       "4.17.21", "Command injection via _.template",                                   "package.json"),
    _da(8,  "vm2",              "npm",      "CVE-2023-29017", "GHSA-7jxr-cg7f-gpgv", "critical", 9.8,   "< 3.9.15",        "3.9.15",  "Sandbox escape: host object prototype pollution via exception",       "package.json"),
    _da(9,  "Newtonsoft.Json",  "nuget",    "CVE-2024-21907", "GHSA-5crp-9r3c-p9vr", "critical", 9.5,   "< 13.0.1",        "13.0.1",  "ReDoS and deserialisation of untrusted data",                        "arm.sln"),
    _da(10, "rack",             "rubygems", "CVE-2022-44570", "GHSA-65f5-mfpf-vfhj", "critical", 9.8,   "< 2.0.9.1",       "2.0.9.1", "ReDoS via Content-Type / Accept headers",                            "Gemfile.lock"),

    # ── HIGH ─────────────────────────────────────────────────────────────────
    _da(11, "numpy",            "pip",      "CVE-2021-41495", "GHSA-f7c7-j99h-c22f", "high",     7.5,   "< 1.22.0",        "1.22.0",  "NULL pointer dereference in ndarray calculations",                   "requirements.txt"),
    _da(12, "pillow",           "pip",      "CVE-2023-50447", "GHSA-3f63-hfp8-52jq", "high",     8.8,   "< 10.2.0",        "10.2.0",  "Arbitrary code execution via crafted image in Imagepath.make()",     "requirements.txt"),
    _da(13, "aiohttp",          "pip",      "CVE-2024-23334", "GHSA-5h86-8mv2-5q98", "high",     7.5,   "< 3.9.2",         "3.9.2",   "Path traversal in static file handler",                              "requirements.txt"),
    _da(14, "paramiko",         "pip",      "CVE-2022-24302", "GHSA-f8q4-jwww-x3wv", "high",     8.1,   "< 2.10.1",        "2.10.1",  "Race condition during private key file creation (0o666 mode)",       "requirements.txt"),
    _da(15, "axios",            "npm",      "CVE-2023-45857", "GHSA-wf5p-g6vw-rhxx", "high",     8.8,   "< 1.6.0",         "1.6.0",   "Cookie leak to third-party sites via XSRF-TOKEN header",             "package.json"),
    _da(16, "semver",           "npm",      "CVE-2022-25883", "GHSA-c2qf-rxjj-qqgw", "high",     7.5,   "< 7.5.2",         "7.5.2",   "ReDoS via overly large version string",                              "package.json"),
    _da(17, "express",          "npm",      "CVE-2024-29041", "GHSA-rv95-896h-c2vc", "high",     7.5,   "< 4.19.2",        "4.19.2",  "Path traversal vulnerability in express static middleware",          "package.json"),
    _da(18, "ip",               "npm",      "CVE-2023-42282", "GHSA-78xj-cgh5-2h22", "high",     9.8,   "< 2.0.1",         "2.0.1",   "Private IP detect bypass: SSRF risk via IPv4-mapped IPv6",          "package.json"),
    _da(19, "Microsoft.Data.SqlClient", "nuget", "CVE-2024-0056", "GHSA-98g6-xh36-x9qr", "high", 8.7, "< 5.1.4",         "5.1.4",   "MitM possible through TLS session resumption cache poisoning",       "arm.sln"),
    _da(20, "System.Text.Json", "nuget",    "CVE-2024-30105", "GHSA-hh2w-p6rv-4g7w", "high",     7.5,   "< 8.0.4",         "8.0.4",   "Stack overflow via deeply nested JSON object deserialisation",       "arm.sln"),
    _da(21, "nokogiri",         "rubygems", "CVE-2022-29181", "GHSA-xh29-r2w5-wx8m", "high",     8.2,   "< 1.13.6",        "1.13.6",  "XML injection via improper handling of nil element names",           "Gemfile.lock"),
    _da(22, "activesupport",    "rubygems", "CVE-2023-28120", "GHSA-pj73-v5mw-pm9j", "high",     8.8,   "< 7.0.4.3",       "7.0.4.3", "XSS via sanitize helper when output is utf8_encode",                "Gemfile.lock"),
    _da(23, "golang.org/x/net", "go",       "CVE-2023-44487", "GHSA-qppj-fm56-g6im", "high",     7.5,   "< 0.17.0",        "0.17.0",  "HTTP/2 Rapid Reset Attack (DDoS)",                                  "go.mod"),
    _da(24, "golang.org/x/crypto", "go",    "CVE-2022-27191", "GHSA-8c26-wmh5-6g9v", "high",     7.5,   "< 0.0.0-20220314234659", "0.0.0-20220315185526", "Host key verification bypass in ssh client",     "go.mod"),
    _da(25, "serde_json",       "cargo",    "CVE-2022-3715",  "GHSA-r7x9-g574-9jv7", "high",     7.6,   "< 1.0.94",        "1.0.94",  "Stack overflow on deeply nested serde_json::Value",                 "Cargo.lock"),

    # ── MEDIUM ───────────────────────────────────────────────────────────────
    _da(26, "urllib3",          "pip",      "CVE-2023-45803", "GHSA-g4mx-q9vg-27p4", "medium",   4.2,   "< 2.0.7",         "2.0.7",   "Request body not stripped after redirect on HTTP 301 (GET→POST)",   "requirements.txt"),
    _da(27, "httpx",            "pip",      "CVE-2021-41945", "GHSA-h8pj-cxx2-jfg2", "medium",   7.4,   "< 0.23.0",        "0.23.0",  "CRLF injection in URL path",                                         "requirements.txt"),
    _da(28, "certifi",          "pip",      "CVE-2023-37920", "GHSA-xqr8-7jwr-rhge", "medium",   5.9,   "< 2023.7.22",     "2023.7.22","Removal of root CA e-Tugra from bundle",                            "requirements.txt"),
    _da(29, "wheel",            "pip",      "CVE-2022-40898", "GHSA-qwmp-2cf2-g9g6", "medium",   5.9,   "< 0.38.1",        "0.38.1",  "ReDoS via crafted wheel filename",                                   "requirements.txt"),
    _da(30, "moment",           "npm",      "CVE-2022-24785", "GHSA-8hfj-j24r-96c4", "medium",   7.5,   "< 2.29.2",        "2.29.2",  "Path traversal via locale string",                                   "package.json"),
    _da(31, "minimatch",        "npm",      "CVE-2022-3517",  "GHSA-f8q4-j684-j9v5", "medium",   7.5,   "< 3.0.5",         "3.0.5",   "ReDoS via crafted glob pattern",                                     "package.json"),
    _da(32, "http-cache-semantics", "npm",  "CVE-2022-25881", "GHSA-rc47-6667-2j5j", "medium",   7.5,   "< 4.1.1",         "4.1.1",   "ReDoS via malformed Cache-Control header",                           "package.json"),
    _da(33, "word-wrap",        "npm",      "CVE-2023-26115", "GHSA-j8xg-fqg3-53r7", "medium",   7.5,   "< 1.2.4",         "1.2.4",   "ReDoS via crafted string",                                           "package.json"),
    _da(34, "Microsoft.AspNetCore.Http", "nuget", "CVE-2023-44487", "GHSA-qr2h-7pwm-pf2w", "medium", 5.9, "< 8.0.0", "8.0.0",       "HTTP/2 rapid reset vulnerability",                                   "arm.sln"),
    _da(35, "System.Net.Http",  "nuget",    "CVE-2022-24512", "GHSA-vh55-786g-wjwf", "medium",   5.5,   "< 7.0.0",         "7.0.0",   "Remote code execution via command injection in dotnet run",          "arm.sln"),
    _da(36, "puma",             "rubygems", "CVE-2022-24790", "GHSA-r584-hp8p-8xx7", "medium",   7.3,   "< 5.6.4",         "5.6.4",   "HTTP request smuggling via front-end proxy",                         "Gemfile.lock"),
    _da(37, "rack-protection", "rubygems",  "CVE-2022-29970", "GHSA-hjpg-f59j-q9vm", "medium",   6.3,   "< 2.2.4",         "2.2.4",   "ReDoS via path-traversal pattern matching",                          "Gemfile.lock"),
    _da(38, "github.com/prometheus/client_golang", "go", "CVE-2022-21698", "GHSA-cg3q-j54f-5p7p", "medium", 7.5, "< 1.11.1", "1.11.1","ReDoS in HTTP label validator",                                     "go.mod"),
    _da(39, "tokio",            "cargo",    "CVE-2021-45710", "GHSA-fg7r-2g4j-5cgr", "medium",   7.4,   "< 1.8.4",         "1.8.4",   "Data race in time::Sleep",                                           "Cargo.lock"),
    _da(40, "openssl",          "cargo",    "CVE-2023-0464",  "GHSA-v5g6-m46w-c45f", "medium",   5.9,   "< 0.10.48",       "0.10.48", "Excessive resource usage in certificate verification chain",          "Cargo.lock"),

    # ── LOW ──────────────────────────────────────────────────────────────────
    _da(41, "setuptools",       "pip",      "CVE-2022-40897", "GHSA-r9hh-6x7r-4rvj", "low",      5.9,   "< 65.5.1",        "65.5.1",  "ReDoS via package name in requires.txt",                             "requirements.txt"),
    _da(42, "idna",             "pip",      "CVE-2024-3651",  "GHSA-jjg7-2v4v-x38h", "low",      3.7,   "< 3.7",           "3.7",     "ReDoS via crafted DNS label / IDNA name",                            "requirements.txt"),
    _da(43, "minimist",         "npm",      "CVE-2021-44906", "GHSA-xvch-5gv4-984h", "low",      5.6,   "< 1.2.6",         "1.2.6",   "Prototype pollution via constructor property",                       "package.json"),
    _da(44, "trim",             "npm",      "CVE-2020-7753",  "GHSA-w5p7-h5w8-2hfq", "low",      5.9,   "< 0.0.3",         "0.0.3",   "ReDoS via crafted string",                                           "package.json"),
    _da(45, "undici",           "npm",      "CVE-2023-45143", "GHSA-wqq4-5wpv-mx2g", "low",      3.9,   "< 5.26.2",        "5.26.2",  "Cookie header not cleared on cross-origin redirect",                 "package.json"),
]


# ===========================================================================
# CODE SCANNING ALERTS  (28 alerts)
# ===========================================================================

MOCK_CODE_SCANNING_ALERTS: list[dict] = [
    # ── CodeQL – Critical / High ─────────────────────────────────────────────
    _cs(101, "java/sql-injection",                "SQL Injection",                       "critical", "CodeQL", "src/main/java/com/arm/db/UserRepository.java",        42,  "User-controlled data flows to SQL query without sanitisation",     "CWE-89"),
    _cs(102, "java/path-traversal",               "Path Traversal",                      "critical", "CodeQL", "src/main/java/com/arm/api/FileController.java",        87,  "Unsanitised request parameter used to construct file path",        "CWE-22"),
    _cs(103, "java/reflected-xss",                "Reflected Cross-Site Scripting",      "high",     "CodeQL", "src/main/java/com/arm/web/SearchServlet.java",          33,  "User input reflected without HTML encoding in response",           "CWE-79"),
    _cs(104, "java/xxe",                          "XML External Entity Injection",       "high",     "CodeQL", "src/main/java/com/arm/parser/ConfigParser.java",         19,  "XML parser configured to allow external entities",                "CWE-611"),
    _cs(105, "java/command-injection",            "OS Command Injection",                "critical", "CodeQL", "src/main/java/com/arm/util/ScriptRunner.java",          55,  "Shell command constructed from user-supplied string",              "CWE-78"),
    _cs(106, "java/ldap-injection",               "LDAP Injection",                      "high",     "CodeQL", "src/main/java/com/arm/auth/DirectoryService.java",       72,  "User input concatenated into LDAP filter string",                  "CWE-90"),
    _cs(107, "java/unsafe-deserialization",       "Unsafe Deserialization",              "critical", "CodeQL", "src/main/java/com/arm/rpc/ObjectHandler.java",           14,  "ObjectInputStream.readObject() called on untrusted stream",        "CWE-502"),
    _cs(108, "java/ssrf",                         "Server-Side Request Forgery",         "high",     "CodeQL", "src/main/java/com/arm/integration/WebhookProxy.java",    98,  "URL fetched from request parameter without allow-list check",      "CWE-918"),

    # ── CodeQL – Medium ──────────────────────────────────────────────────────
    _cs(109, "java/insecure-randomness",          "Insecure Randomness",                 "medium",   "CodeQL", "src/main/java/com/arm/auth/TokenService.java",           61,  "java.util.Random used for security-sensitive token generation",    "CWE-338"),
    _cs(110, "java/cleartext-logging",            "Cleartext Logging of Sensitive Data", "medium",   "CodeQL", "src/main/java/com/arm/auth/OAuthHandler.java",           29,  "Access token written to application log",                         "CWE-532"),
    _cs(111, "java/open-redirect",                "Open Redirect",                       "medium",   "CodeQL", "src/main/java/com/arm/web/RedirectController.java",      44,  "Redirect location derived from user-supplied URL parameter",       "CWE-601"),
    _cs(112, "py/sql-injection",                  "SQL Injection (Python)",              "high",     "CodeQL", "scripts/migrate_db.py",                                  18,  "String-formatted SQL query with user input",                      "CWE-89"),
    _cs(113, "py/path-traversal",                 "Path Traversal (Python)",             "high",     "CodeQL", "scripts/import_data.py",                                 77,  "os.path.join with untrusted prefix not normalised",               "CWE-22"),

    # ── Semgrep – High / Medium ──────────────────────────────────────────────
    _cs(114, "java.spring.security.injection.tainted-sql-from-http-request", "Spring SQL from HTTP", "high", "Semgrep", "src/main/java/com/arm/api/ReportController.java", 112, "Tainted data from HTTP request reaches JPA query",              "CWE-89"),
    _cs(115, "java.lang.security.audit.formatted-sql-string",               "Formatted SQL String", "high", "Semgrep", "src/main/java/com/arm/service/AnalyticsService.java", 68,  "SQL built with String.format containing request parameters",     "CWE-89"),
    _cs(116, "javascript.lang.security.audit.prototype-pollution",          "Prototype Pollution",  "high", "Semgrep", "frontend/src/utils/merge.js",                         22,  "Object.assign merges untrusted JSON without prototype guard",     "CWE-1321"),
    _cs(117, "javascript.express.security.audit.xss.mustache-template-injection", "Template Injection", "medium", "Semgrep", "frontend/src/views/report.ejs", 10,             "EJS template renders user input without escaping",                 "CWE-94"),
    _cs(118, "python.django.security.injection.sql.django-rawsql-injection", "Django Raw SQL", "high", "Semgrep", "api/views/search.py",                                  34,  "Raw SQL query built with f-string from request.GET",             "CWE-89"),
    _cs(119, "python.flask.security.audit.hardcoded-secret",                "Hardcoded Secret",     "medium", "Semgrep", "api/config.py",                                    8,   "Flask SECRET_KEY appears hardcoded in source",                    "CWE-798"),

    # ── Bandit ───────────────────────────────────────────────────────────────
    _cs(120, "B301",  "Pickle deserialization",           "high",   "Bandit", "scripts/cache_loader.py",              45,  "Use of pickle.loads() on potentially untrusted data",             "CWE-502"),
    _cs(121, "B108",  "Probable insecure temp file",      "medium", "Bandit", "scripts/report_export.py",             88,  "tempfile.mktemp() used — race condition possible",                "CWE-377"),
    _cs(122, "B602",  "subprocess with shell=True",       "high",   "Bandit", "scripts/deploy.py",                    17,  "Subprocess invocation with shell=True and variable input",        "CWE-78"),
    _cs(123, "B506",  "yaml.load without Loader",         "medium", "Bandit", "config/settings_loader.py",             9,  "yaml.load() called without SafeLoader — code execution possible", "CWE-20"),
    _cs(124, "B201",  "Flask debug mode",                 "medium", "Bandit", "api/app.py",                           93,  "Flask app run with debug=True in non-test context",               "CWE-94"),
    _cs(125, "B501",  "Disabled SSL certificate check",   "high",   "Bandit", "clients/http_utils.py",                56,  "requests.get called with verify=False",                          "CWE-295"),

    # ── Trivy / Snyk SAST ────────────────────────────────────────────────────
    _cs(126, "SNYK-JAVA-APACHECOMMONS-1316517", "Deserialization of Untrusted Data", "critical", "Snyk", "src/main/java/com/arm/util/SerializationHelper.java", 30, "Apache Commons Collections gadget chain allows RCE",             "CWE-502"),
    _cs(127, "TRIVY-0001", "Privileged Container in Helm chart", "high",   "Trivy", "deploy/helm/arm/templates/deployment.yaml", 44, "Container securityContext.privileged set to true",               "CWE-250"),
    _cs(128, "TRIVY-0002", "Root user in Dockerfile",             "medium", "Trivy", "docker/Dockerfile",               12,  "Dockerfile runs application process as root (no USER directive)",  "CWE-250"),
]


# ===========================================================================
# SECRET SCANNING ALERTS  (18 alerts)
# ===========================================================================

MOCK_SECRET_SCANNING_ALERTS: list[dict] = [
    _ss(201, "github_personal_access_token",      "GitHub Personal Access Token",  validity="active"),
    _ss(202, "aws_access_key_id",                 "Amazon AWS Access Key ID",      validity="active", push_protection_bypassed=True),
    _ss(203, "aws_secret_access_key",             "Amazon AWS Secret Access Key",  validity="active", push_protection_bypassed=True),
    _ss(204, "azure_storage_account_key",         "Azure Storage Account Key",     validity="active"),
    _ss(205, "azure_service_principal",            "Azure Service Principal",       validity="unknown"),
    _ss(206, "azure_devops_personal_access_token","Azure DevOps Personal Access Token", validity="active"),
    _ss(207, "slack_api_token",                   "Slack API Token",               validity="inactive", state="resolved", resolution="revoked"),
    _ss(208, "slack_incoming_webhook_url",        "Slack Incoming Webhook URL",    validity="inactive", state="resolved", resolution="revoked"),
    _ss(209, "google_api_key",                    "Google API Key",                validity="unknown"),
    _ss(210, "google_oauth_client_secret",        "Google OAuth Client Secret",    validity="active"),
    _ss(211, "npm_access_token",                  "npm Access Token",              validity="active", push_protection_bypassed=True),
    _ss(212, "pypi_api_token",                    "PyPI API Token",                validity="active"),
    _ss(213, "stripe_secret_key",                 "Stripe Secret Key",             validity="active", push_protection_bypassed=True),
    _ss(214, "sendgrid_api_key",                  "Twilio SendGrid API Key",       validity="unknown"),
    _ss(215, "jwt_high_risk_secret",              "JWT with Hardcoded High-Risk Secret", state="resolved", resolution="false_positive"),
    _ss(216, "generic_database_password",         "Generic Database Password",     validity="unknown"),
    _ss(217, "private_key",                       "RSA Private Key",               validity="active"),
    _ss(218, "terraform_cloud_api_token",         "Terraform Cloud API Token",     validity="active"),
]


# ===========================================================================
# Combined summary (for logging / assertions)
# ===========================================================================

MOCK_SUMMARY = {
    "dependabot_alerts":        len(MOCK_DEPENDABOT_ALERTS),
    "code_scanning_alerts":     len(MOCK_CODE_SCANNING_ALERTS),
    "secret_scanning_alerts":   len(MOCK_SECRET_SCANNING_ALERTS),
    "total_alerts":             (
        len(MOCK_DEPENDABOT_ALERTS)
        + len(MOCK_CODE_SCANNING_ALERTS)
        + len(MOCK_SECRET_SCANNING_ALERTS)
    ),
}
