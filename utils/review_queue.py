"""
Human review queue backed by SQLite.

When the VEX Agent is uncertain (low LLM confidence, critical severity, or
human review is always required), it stores the pending finding here and posts
a Teams card with Approve / Override / Dismiss action buttons.

A reviewer clicks one of those buttons → it calls one of the review API
endpoints → the agent finalises the ticket, attaches documents, and sends
the resolution notification.

States
------
  pending    – waiting for human action
  approved   – human confirmed the agent's decision
  overridden – human set a different decision
  dismissed  – human marked as false positive / won't fix
  timed_out  – no action taken within REVIEW_TIMEOUT_HOURS
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_DEFAULT_DB = Path(__file__).resolve().parent.parent / "review_queue.db"

REVIEW_STATES = {"pending", "approved", "overridden", "dismissed", "timed_out"}


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------

class ReviewItem:
    """One row in the review queue."""

    def __init__(self, row: dict[str, Any]):
        self.id: str = row["id"]
        self.created_at: str = row["created_at"]
        self.expires_at: str = row["expires_at"]
        self.status: str = row["status"]

        self.repo_full_name: str = row["repo_full_name"]
        self.alert_id: int = int(row["alert_id"])
        self.cve_id: Optional[str] = row.get("cve_id")
        self.package_name: str = row["package_name"]
        self.agent_decision: str = row["agent_decision"]
        self.confidence: float = float(row.get("confidence") or 0.0)
        self.trigger_reason: str = row.get("trigger_reason", "")

        # Serialised pipeline data (JSON strings)
        self.finding_json: str = row["finding_json"]
        self.epss_json: Optional[str] = row.get("epss_json")
        self.reachability_json: Optional[str] = row.get("reachability_json")
        self.hits_json: str = row.get("hits_json") or "[]"
        self.suggested_fix: str = row.get("suggested_fix") or ""
        self.sbom_json: Optional[str] = row.get("sbom_json")
        self.metadata_json: Optional[str] = row.get("metadata_json")

        # Resolution fields
        self.final_decision: Optional[str] = row.get("final_decision")
        self.reviewer_comment: Optional[str] = row.get("reviewer_comment")
        self.jira_key: Optional[str] = row.get("jira_key")
        self.resolved_at: Optional[str] = row.get("resolved_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "status": self.status,
            "repo_full_name": self.repo_full_name,
            "alert_id": self.alert_id,
            "cve_id": self.cve_id,
            "package_name": self.package_name,
            "agent_decision": self.agent_decision,
            "confidence": self.confidence,
            "trigger_reason": self.trigger_reason,
            "final_decision": self.final_decision,
            "reviewer_comment": self.reviewer_comment,
            "jira_key": self.jira_key,
            "resolved_at": self.resolved_at,
        }

    @property
    def is_expired(self) -> bool:
        try:
            expires = datetime.fromisoformat(self.expires_at)
            return datetime.now(timezone.utc) > expires
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Queue manager
# ---------------------------------------------------------------------------

class ReviewQueue:
    """
    SQLite-backed store for pending human review items.

    Thread-safe for single-process use (SQLite WAL mode).
    """

    def __init__(self, db_path: Path = _DEFAULT_DB):
        self._db_path = db_path
        self._init_db()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enqueue(
        self,
        *,
        repo_full_name: str,
        alert_id: int,
        cve_id: Optional[str],
        package_name: str,
        agent_decision: str,
        confidence: float,
        trigger_reason: str,
        finding_json: str,
        epss_json: Optional[str] = None,
        reachability_json: Optional[str] = None,
        hits_json: str = "[]",
        suggested_fix: str = "",
        sbom_json: Optional[str] = None,
        metadata_json: Optional[str] = None,
        timeout_hours: int = 24,
    ) -> str:
        """Insert a new pending review. Returns the review UUID."""
        review_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=timeout_hours)

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO review_queue (
                    id, created_at, expires_at, status,
                    repo_full_name, alert_id, cve_id, package_name,
                    agent_decision, confidence, trigger_reason,
                    finding_json, epss_json, reachability_json,
                    hits_json, suggested_fix, sbom_json, metadata_json
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    review_id, now.isoformat(), expires.isoformat(), "pending",
                    repo_full_name, alert_id, cve_id, package_name,
                    agent_decision, confidence, trigger_reason,
                    finding_json, epss_json, reachability_json,
                    hits_json, suggested_fix, sbom_json, metadata_json,
                ),
            )
        logger.info("Queued review %s for %s alert %s", review_id, repo_full_name, alert_id)
        return review_id

    def get(self, review_id: str) -> Optional[ReviewItem]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM review_queue WHERE id = ?", (review_id,)
            ).fetchone()
        return ReviewItem(dict(row)) if row else None

    def list_pending(self) -> list[ReviewItem]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM review_queue WHERE status = 'pending' ORDER BY created_at DESC"
            ).fetchall()
        return [ReviewItem(dict(r)) for r in rows]

    def list_all(self, limit: int = 100) -> list[ReviewItem]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM review_queue ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [ReviewItem(dict(r)) for r in rows]

    def resolve(
        self,
        review_id: str,
        *,
        status: str,                   # approved | overridden | dismissed
        final_decision: Optional[str] = None,
        reviewer_comment: Optional[str] = None,
        jira_key: Optional[str] = None,
    ) -> Optional[ReviewItem]:
        """Mark a review as resolved. Returns the updated item."""
        if status not in ("approved", "overridden", "dismissed"):
            raise ValueError(f"Invalid status: {status}")
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE review_queue
                   SET status = ?, final_decision = ?, reviewer_comment = ?,
                       jira_key = ?, resolved_at = ?
                 WHERE id = ? AND status = 'pending'
                """,
                (status, final_decision, reviewer_comment, jira_key, now, review_id),
            )
        return self.get(review_id)

    def expire_old(self) -> int:
        """Mark all overdue pending reviews as timed_out. Returns count updated."""
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE review_queue SET status='timed_out' WHERE status='pending' AND expires_at < ?",
                (now,),
            )
            return cur.rowcount

    def pending_for_alert(self, repo_full_name: str, alert_id: int) -> Optional[ReviewItem]:
        """Check if a pending review already exists for this alert."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM review_queue WHERE repo_full_name=? AND alert_id=? AND status='pending'",
                (repo_full_name, alert_id),
            ).fetchone()
        return ReviewItem(dict(row)) if row else None

    def clear_all(self) -> int:
        """Delete all rows from the review queue. Returns the number of rows deleted."""
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM review_queue")
            return cur.rowcount

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS review_queue (
                    id                TEXT PRIMARY KEY,
                    created_at        TEXT NOT NULL,
                    expires_at        TEXT NOT NULL,
                    status            TEXT NOT NULL DEFAULT 'pending',
                    repo_full_name    TEXT NOT NULL,
                    alert_id          INTEGER NOT NULL,
                    cve_id            TEXT,
                    package_name      TEXT NOT NULL,
                    agent_decision    TEXT NOT NULL,
                    confidence        REAL DEFAULT 0,
                    trigger_reason    TEXT DEFAULT '',
                    finding_json      TEXT NOT NULL,
                    epss_json         TEXT,
                    reachability_json TEXT,
                    hits_json         TEXT DEFAULT '[]',
                    suggested_fix     TEXT DEFAULT '',
                    sbom_json         TEXT,
                    metadata_json     TEXT,
                    final_decision    TEXT,
                    reviewer_comment  TEXT,
                    jira_key          TEXT,
                    resolved_at       TEXT
                )
                """
            )
        logger.debug("ReviewQueue initialised at %s", self._db_path)


# ---------------------------------------------------------------------------
# Module-level singleton (shared across agent + endpoints)
# ---------------------------------------------------------------------------

_queue: Optional[ReviewQueue] = None


def get_review_queue() -> ReviewQueue:
    global _queue
    if _queue is None:
        _queue = ReviewQueue()
    return _queue
