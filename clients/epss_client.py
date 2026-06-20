"""
EPSS (Exploit Prediction Scoring System) API client.
Source: https://api.first.org/data/v1/epss
"""

from __future__ import annotations

import logging
from typing import Optional

import httpx

from models.vex_models import EpssScore

logger = logging.getLogger(__name__)

EPSS_API = "https://api.first.org/data/v1/epss"


class EpssClient:
    """Fetches EPSS scores from the FIRST.org public API (no auth required)."""

    def __init__(self, timeout: int = 15):
        self._timeout = timeout

    async def get_score(self, cve_id: str) -> Optional[EpssScore]:
        """
        Return the EPSS score for a single CVE.
        Returns None if the CVE is not found or the API is unavailable.
        """
        if not cve_id or not cve_id.upper().startswith("CVE-"):
            logger.debug("Skipping EPSS lookup for non-CVE identifier: %s", cve_id)
            return None

        params = {"cve": cve_id}
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(EPSS_API, params=params)
                resp.raise_for_status()
                data = resp.json()

            entries = data.get("data", [])
            if not entries:
                logger.info("No EPSS data found for %s", cve_id)
                return None

            entry = entries[0]
            score = EpssScore(
                cve=entry["cve"],
                epss=float(entry["epss"]),
                percentile=float(entry["percentile"]),
                date=data.get("timestamp", ""),
            )
            logger.info(
                "EPSS for %s: %.4f (%.1f%%ile)",
                cve_id, score.epss, score.percentile * 100,
            )
            return score

        except httpx.HTTPStatusError as exc:
            logger.warning("EPSS API HTTP error for %s: %s", cve_id, exc)
        except httpx.RequestError as exc:
            logger.warning("EPSS API request error for %s: %s", cve_id, exc)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Unexpected EPSS error for %s: %s", cve_id, exc)

        return None

    async def get_scores_bulk(self, cve_ids: list[str]) -> dict[str, EpssScore]:
        """
        Fetch EPSS scores for multiple CVEs in one API call.
        Returns a mapping of CVE-ID → EpssScore for those that were found.
        """
        valid = [c for c in cve_ids if c and c.upper().startswith("CVE-")]
        if not valid:
            return {}

        params = {"cve": ",".join(valid)}
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(EPSS_API, params=params)
                resp.raise_for_status()
                data = resp.json()

            result: dict[str, EpssScore] = {}
            for entry in data.get("data", []):
                score = EpssScore(
                    cve=entry["cve"],
                    epss=float(entry["epss"]),
                    percentile=float(entry["percentile"]),
                    date=data.get("timestamp", ""),
                )
                result[entry["cve"]] = score
            return result

        except Exception as exc:  # noqa: BLE001
            logger.warning("Bulk EPSS fetch failed: %s", exc)
            return {}

    # ------------------------------------------------------------------
    # Decision helpers
    # ------------------------------------------------------------------

    @staticmethod
    def is_high_risk(score: Optional[EpssScore], threshold: float = 0.1) -> bool:
        """Return True if the EPSS score exceeds the configured threshold."""
        if score is None:
            return False
        return score.epss > threshold
