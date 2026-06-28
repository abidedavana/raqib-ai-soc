"""SQLite event store — the local SIEM index.

Every detection becomes a persisted, queryable SecurityEvent. The dashboard and
the measured red-team report both read from here; the Wazuh forwarder (Phase 6)
ships the same records on to the SIEM. Plain SQLite keeps the lab $0 and
dependency-free while still giving real query/aggregation power.
"""
from __future__ import annotations

import sqlite3
import threading
from typing import Any, Optional

from ..models import SecurityEvent

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id            TEXT PRIMARY KEY,
    timestamp     TEXT NOT NULL,
    session_id    TEXT NOT NULL,
    source_ip     TEXT,
    direction     TEXT NOT NULL,
    detector      TEXT NOT NULL,
    rule_id       TEXT NOT NULL,
    category      TEXT NOT NULL,
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL,
    confidence    REAL NOT NULL,
    owasp_llm     TEXT NOT NULL,
    mitre_atlas   TEXT NOT NULL,
    verdict       TEXT NOT NULL,
    action_taken  TEXT NOT NULL,
    evidence      TEXT,
    payload_excerpt TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts        ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_session   ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_severity  ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_owasp     ON events(owasp_llm);
"""

_COLUMNS = [
    "id", "timestamp", "session_id", "source_ip", "direction", "detector",
    "rule_id", "category", "title", "severity", "confidence", "owasp_llm",
    "mitre_atlas", "verdict", "action_taken", "evidence", "payload_excerpt",
]


class EventStore:
    def __init__(self, db_path: str = "raqib_events.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ── writes ───────────────────────────────────────────────────────────────
    def insert(self, event: SecurityEvent) -> str:
        row = event.model_dump()
        row["direction"] = event.direction.value
        row["severity"] = event.severity.value
        row["verdict"] = event.verdict.value
        with self._lock:
            self._conn.execute(
                f"INSERT OR REPLACE INTO events ({','.join(_COLUMNS)}) "
                f"VALUES ({','.join('?' for _ in _COLUMNS)})",
                [row[c] for c in _COLUMNS],
            )
            self._conn.commit()
        return event.id

    def insert_many(self, events: list[SecurityEvent]) -> list[str]:
        return [self.insert(e) for e in events]

    # ── reads ────────────────────────────────────────────────────────────────
    def query(
        self,
        *,
        limit: int = 100,
        severity: Optional[str] = None,
        session_id: Optional[str] = None,
        category: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM events"
        clauses, params = [], []
        if severity:
            clauses.append("severity = ?"); params.append(severity)
        if session_id:
            clauses.append("session_id = ?"); params.append(session_id)
        if category:
            clauses.append("category = ?"); params.append(category)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def stats(self) -> dict[str, Any]:
        """Aggregations that power the SOC dashboard."""
        with self._lock:
            c = self._conn
            by_severity = _group(c, "severity")
            by_owasp = _group(c, "owasp_llm")
            by_category = _group(c, "category")
            by_verdict = _group(c, "verdict")
            top_sessions = [
                {"session_id": r["session_id"], "events": r["n"]}
                for r in c.execute(
                    "SELECT session_id, COUNT(*) n FROM events "
                    "GROUP BY session_id ORDER BY n DESC LIMIT 10"
                ).fetchall()
            ]
            total = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        return {
            "total": total,
            "by_severity": by_severity,
            "by_owasp_llm": by_owasp,
            "by_category": by_category,
            "by_verdict": by_verdict,
            "top_sessions": top_sessions,
        }

    def session_offense_count(self, session_id: str) -> int:
        """High/critical inbound events for a session — drives quarantine."""
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) FROM events WHERE session_id = ? "
                "AND severity IN ('high','critical') AND direction = 'inbound'",
                (session_id,),
            ).fetchone()[0]

    def clear(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM events")
            self._conn.commit()

    def close(self) -> None:
        self._conn.close()


def _group(conn: sqlite3.Connection, column: str) -> dict[str, int]:
    rows = conn.execute(
        f"SELECT {column} k, COUNT(*) n FROM events GROUP BY {column} ORDER BY n DESC"
    ).fetchall()
    return {r["k"]: r["n"] for r in rows}
