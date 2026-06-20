"""
VEX / SBOM file store — SharePoint-backed artefact storage.

Uploads VEX and SBOM CycloneDX JSON artefacts to a SharePoint document
library via the Microsoft Graph API, inside a versioned sub-directory.

Configuration (via .env)::

    SHAREPOINT_TENANT_ID     – Azure AD tenant ID (GUID)
    SHAREPOINT_CLIENT_ID     – App registration client ID (GUID)
    SHAREPOINT_CLIENT_SECRET – App registration client secret
    SHAREPOINT_SITE_URL      – Full URL to the SharePoint site
                               e.g. https://myorg.sharepoint.com/sites/MySite
    SHAREPOINT_FOLDER_PATH   – Root folder path inside the document library
                               e.g. Shared Documents/VEX-Store
                               (defaults to "Shared Documents/VEX-Store")

Directory layout inside SharePoint::

    {SHAREPOINT_FOLDER_PATH}/{JIRA_PROJECT_KEY}/{product_version}/
        vex-{package}-{CVE}.cdx.json
        sbom-{repo}.cdx.json

The product version is read from *product_version.yaml* in the analysed
repository root (common keys tried: version, product_version, productVersion,
VERSION, PRODUCT_VERSION).  Falls back to ``unknown-version`` when absent.

Authentication uses OAuth 2.0 client-credentials flow.  The Azure AD app
registration must have the Graph API application permission
``Sites.ReadWrite.All`` (or ``Files.ReadWrite.All`` scoped to the site).
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Microsoft Graph API base URL
_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_LOGIN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

# Ordered list of YAML dictionary keys tried when reading product_version.yaml.
_VERSION_KEYS = (
    "version",
    "product_version",
    "productVersion",
    "VERSION",
    "PRODUCT_VERSION",
    "verProdVersion",
    "ProductVersionNumber",
)

# Regex fallback for raw YAML text.
_VERSION_LINE_RE = re.compile(
    r"^(?:product[_\-]?)?version\s*:\s*['\"]?([\w.\-+]+)['\"]?",
    re.IGNORECASE | re.MULTILINE,
)

# Azure DevOps runtime expression pattern — value cannot be used as-is.
_ADO_EXPR_RE = re.compile(r"^\$\[|^\$\(")


# ---------------------------------------------------------------------------
# Product-version reader
# ---------------------------------------------------------------------------

def read_product_version(repo_path: Path) -> str:
    """Read the product version from a version YAML file inside *repo_path*.

    Searches for these filenames (in priority order), starting at the repo
    root and then recursively:
      * ``product_version.yaml``
      * ``vars_product_version.yaml``

    Key resolution order:
    1. Known scalar keys (``version``, ``product_version``, ``verProdVersion``, ...)
       -- skipped when the value is an Azure DevOps pipeline expression
       (starts with ``$[`` or ``$(``)
    2. Assembled from ``verMajor`` / ``verMinor`` / ``verRelease`` (ADO pattern)
    3. Regex scan of the raw text
    4. Fall back to ``"unknown-version"``
    """
    # Collect candidate paths for both filenames, root first then recursive.
    for filename in ("product_version.yaml", "vars_product_version.yaml"):
        root_candidate = repo_path / filename
        deep_candidates: list[Path] = []
        try:
            deep_candidates = [
                p for p in repo_path.rglob(filename)
                if p != root_candidate
            ]
        except Exception:  # noqa: BLE001
            pass
        candidates = ([root_candidate] if root_candidate.is_file() else []) + deep_candidates

        for path in candidates:
            if not path.is_file():
                continue
            try:
                import yaml  # PyYAML

                raw_text = path.read_text(encoding="utf-8")
                data = yaml.safe_load(raw_text)

                # Case 1: bare scalar
                if isinstance(data, str) and data.strip() and not _ADO_EXPR_RE.match(data.strip()):
                    return data.strip()

                if isinstance(data, dict):
                    # Unwrap nested 'variables:' block (Azure DevOps YAML structure)
                    mapping = data.get("variables", data)
                    if not isinstance(mapping, dict):
                        mapping = data

                    # Case 2: known version keys (skip ADO runtime expressions)
                    for key in _VERSION_KEYS:
                        val = mapping.get(key)
                        if val and isinstance(val, str) and not _ADO_EXPR_RE.match(val.strip()):
                            return val.strip()

                    # Case 3: assemble from verMajor / verMinor / verRelease
                    major = str(mapping.get("verMajor", "")).strip().strip("'\"")
                    minor = str(mapping.get("verMinor", "")).strip().strip("'\"")
                    release = str(mapping.get("verRelease", "")).strip().strip("'\"")
                    if major and minor and release:
                        assembled = f"{major}.{minor}.{release}"
                        logger.info(
                            "Assembled product version from verMajor/verMinor/verRelease: %s",
                            assembled,
                        )
                        return assembled

                # Case 4: regex fallback on raw text
                match = _VERSION_LINE_RE.search(raw_text)
                if match:
                    return match.group(1).strip()

                logger.warning(
                    "%s found at %s but no version key recognised", filename, path
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not parse %s: %s", path, exc)

    return "unknown-version"


# ---------------------------------------------------------------------------
# SharePoint / Microsoft Graph helpers
# ---------------------------------------------------------------------------

def _get_sp_token(tenant_id: str, client_id: str, client_secret: str) -> Optional[str]:
    """Obtain an OAuth 2.0 client-credentials access token for Graph API.

    Returns the bearer token string, or ``None`` on failure.
    """
    import httpx  # available via project dependencies

    token_url = _LOGIN_URL.format(tenant_id=tenant_id)
    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
    }
    try:
        with httpx.Client(timeout=30) as client:
            resp = client.post(token_url, data=payload)
        if resp.status_code != 200:
            logger.error(
                "SharePoint token request failed (%s): %s",
                resp.status_code,
                resp.text[:300],
            )
            return None
        return resp.json().get("access_token")
    except Exception as exc:  # noqa: BLE001
        logger.error("SharePoint token request raised an exception: %s", exc)
        return None


def _get_site_id(token: str, site_url: str) -> Optional[str]:
    """Resolve a SharePoint site URL to its Graph API site ID.

    *site_url* must be of the form ``https://<tenant>.sharepoint.com/sites/<name>``.
    Returns the opaque site-ID string used by subsequent Graph calls, or
    ``None`` on failure.
    """
    import httpx

    parsed = urlparse(site_url)
    hostname = parsed.hostname or ""
    # strip leading "/" and use the rest as the site path
    site_path = parsed.path.lstrip("/")
    graph_url = f"{_GRAPH_BASE}/sites/{hostname}:/{site_path}"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        with httpx.Client(timeout=30) as client:
            resp = client.get(graph_url, headers=headers)
        if resp.status_code != 200:
            logger.error(
                "Could not resolve SharePoint site '%s' (%s): %s",
                site_url,
                resp.status_code,
                resp.text[:300],
            )
            return None
        return resp.json().get("id")
    except Exception as exc:  # noqa: BLE001
        logger.error("SharePoint site lookup raised an exception: %s", exc)
        return None


def _get_default_drive_id(token: str, site_id: str) -> Optional[str]:
    """Return the default document-library drive ID for *site_id*.

    Returns the drive-ID string, or ``None`` on failure.
    """
    import httpx

    graph_url = f"{_GRAPH_BASE}/sites/{site_id}/drive"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        with httpx.Client(timeout=30) as client:
            resp = client.get(graph_url, headers=headers)
        if resp.status_code != 200:
            logger.error(
                "Could not retrieve default drive for site '%s' (%s): %s",
                site_id,
                resp.status_code,
                resp.text[:300],
            )
            return None
        return resp.json().get("id")
    except Exception as exc:  # noqa: BLE001
        logger.error("SharePoint drive lookup raised an exception: %s", exc)
        return None


def _upload_to_sharepoint(
    token: str,
    site_id: str,
    drive_id: str,
    sp_path: str,
    content: str,
) -> Optional[str]:
    """Upload *content* (UTF-8 text) to *sp_path* inside the drive.

    *sp_path* is the full file path relative to the drive root, e.g.
    ``Shared Documents/VEX-Store/ARM/1.2.3/vex-pkg-CVE.cdx.json``.

    Returns the SharePoint web URL of the uploaded file, or ``None`` on failure.
    The Graph API will automatically create any missing intermediate folders.
    """
    import httpx

    # Encode the path but keep forward slashes
    encoded_path = sp_path.replace("#", "%23").replace("?", "%3F")
    upload_url = (
        f"{_GRAPH_BASE}/sites/{site_id}/drives/{drive_id}"
        f"/root:/{encoded_path}:/content"
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/octet-stream",
    }
    try:
        with httpx.Client(timeout=60) as client:
            resp = client.put(upload_url, headers=headers, content=content.encode("utf-8"))
        if resp.status_code not in (200, 201):
            logger.error(
                "SharePoint upload failed for '%s' (%s): %s",
                sp_path,
                resp.status_code,
                resp.text[:300],
            )
            return None
        web_url: str = resp.json().get("webUrl", sp_path)
        logger.info("Uploaded to SharePoint: %s", web_url)
        return web_url
    except Exception as exc:  # noqa: BLE001
        logger.error("SharePoint upload raised an exception for '%s': %s", sp_path, exc)
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def save_vex_and_sbom(
    *,
    vex_json_str: str,
    sbom_json: Optional[str],
    vex_filename: str,
    sbom_filename: str,
    repo_path: Optional[Path] = None,
    product_version: Optional[str] = None,
) -> list[str]:
    """Upload VEX (and optionally SBOM) JSON files to the configured SharePoint
    document library via the Microsoft Graph API.

    Directory layout inside SharePoint::

        {SHAREPOINT_FOLDER_PATH}/{JIRA_PROJECT_KEY}/{product_version}/
            {vex_filename}
            {sbom_filename}

    Version resolution order:
    1. *product_version* argument (if supplied).
    2. ``product_version.yaml`` inside *repo_path* (if supplied).
    3. ``product_version.yaml`` inside ``settings.local_repo_path``.
    4. Falls back to ``"unknown-version"``.

    Returns the list of SharePoint web-URLs for every file successfully
    uploaded.  Returns an empty list when SharePoint is not configured or a
    fatal error prevents the upload.
    """
    from config import settings  # local import to avoid circular deps at module load

    # ── Validate SharePoint configuration ────────────────────────────────
    tenant_id = (settings.sharepoint_tenant_id or "").strip()
    client_id = (settings.sharepoint_client_id or "").strip()
    client_secret = (settings.sharepoint_client_secret or "").strip()
    site_url = (settings.sharepoint_site_url or "").strip()

    if not all([tenant_id, client_id, client_secret, site_url]):
        logger.debug(
            "SharePoint not fully configured (SHAREPOINT_TENANT_ID, "
            "SHAREPOINT_CLIENT_ID, SHAREPOINT_CLIENT_SECRET, SHAREPOINT_SITE_URL "
            "must all be set) — skipping artefact store"
        )
        return []

    folder_path = (settings.sharepoint_folder_path or "Shared Documents/VEX-Store").strip()

    # ── Resolve product version ──────────────────────────────────────────
    version = product_version

    if not version and repo_path:
        version = read_product_version(repo_path)

    if not version and settings.local_repo_path:
        try:
            version = read_product_version(Path(settings.local_repo_path))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not read product version from LOCAL_REPO_PATH: %s", exc)

    if not version:
        version = "unknown-version"

    project_key = (settings.jira_project_key or "VEX").strip()

    # ── Authenticate with Microsoft Graph ────────────────────────────────
    logger.info("Authenticating with Microsoft Graph (tenant: %s) …", tenant_id)
    token = _get_sp_token(tenant_id, client_id, client_secret)
    if not token:
        logger.error("Could not obtain Graph API token — SharePoint upload aborted")
        return []

    # ── Resolve SharePoint site and drive ────────────────────────────────
    site_id = _get_site_id(token, site_url)
    if not site_id:
        logger.error("Could not resolve SharePoint site — upload aborted")
        return []

    drive_id = _get_default_drive_id(token, site_id)
    if not drive_id:
        logger.error("Could not resolve SharePoint document library — upload aborted")
        return []

    # ── Upload files ─────────────────────────────────────────────────────
    uploaded: list[str] = []
    base_sp_path = f"{folder_path}/{project_key}/{version}"

    # VEX file
    vex_sp_path = f"{base_sp_path}/{vex_filename}"
    vex_url = _upload_to_sharepoint(token, site_id, drive_id, vex_sp_path, vex_json_str)
    if vex_url:
        uploaded.append(vex_url)
    else:
        logger.error("Failed to upload VEX file '%s' to SharePoint", vex_filename)

    # SBOM file
    if sbom_json:
        sbom_sp_path = f"{base_sp_path}/{sbom_filename}"
        sbom_url = _upload_to_sharepoint(token, site_id, drive_id, sbom_sp_path, sbom_json)
        if sbom_url:
            uploaded.append(sbom_url)
        else:
            logger.error("Failed to upload SBOM file '%s' to SharePoint", sbom_filename)

    if uploaded:
        logger.info(
            "VEX/SBOM artefacts saved to SharePoint (%s/%s/%s): %d file(s)",
            folder_path,
            project_key,
            version,
            len(uploaded),
        )
    return uploaded
