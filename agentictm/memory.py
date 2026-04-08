"""Cross-Analysis Memory System — persistent episodic + semantic memory."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class MemoryManager:
    """SQLite-backed memory with episodic and semantic stores.

    Episodic memory stores outcomes from past analyses (threat patterns,
    coverage, quality). Semantic memory accumulates reusable knowledge
    such as confirmed threat patterns, effective mitigations, and
    user-flagged false positives.

    Per-system namespacing ensures analyses for different systems don't
    cross-pollinate.
    """

    def __init__(self, db_path: Path | str):
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_schema()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                str(self._db_path), check_same_thread=False,
            )
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_schema(self) -> None:
        conn = self._conn
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS episodic_memory (
                id INTEGER PRIMARY KEY,
                system_name TEXT NOT NULL,
                analysis_date TEXT NOT NULL,
                threat_count INTEGER,
                stride_coverage TEXT,
                key_threats TEXT,
                quality_score INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS semantic_memory (
                id INTEGER PRIMARY KEY,
                system_name TEXT NOT NULL,
                pattern_type TEXT,
                content TEXT NOT NULL,
                frequency INTEGER DEFAULT 1,
                last_seen TEXT DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.commit()

    def store_analysis_outcome(
        self,
        system_name: str,
        threats: list[dict[str, Any]],
        feedback: dict[str, Any] | None = None,
    ) -> None:
        """Persist post-analysis data into episodic + semantic memory."""
        conn = self._conn
        now = datetime.now().isoformat()

        stride_cats = sorted({
            (t.get("stride_category") or "").upper()
            for t in threats if t.get("stride_category")
        })
        key_descs = [
            (t.get("description") or "")[:200]
            for t in sorted(
                threats,
                key=lambda t: t.get("dread_total", 0) or 0,
                reverse=True,
            )[:5]
        ]
        quality = (feedback or {}).get("quality_score", 0)

        conn.execute(
            """INSERT INTO episodic_memory
               (system_name, analysis_date, threat_count, stride_coverage,
                key_threats, quality_score, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                system_name,
                now[:10],
                len(threats),
                json.dumps(stride_cats),
                json.dumps(key_descs),
                quality,
                now,
            ),
        )

        for t in threats:
            desc = (t.get("description") or "").strip()
            if not desc:
                continue
            mitigation = (t.get("mitigation") or "").strip()
            if mitigation:
                self._upsert_semantic(
                    conn, system_name, "effective_mitigation",
                    f"{desc} -> {mitigation}",
                )
            self._upsert_semantic(conn, system_name, "threat_pattern", desc)

        conn.commit()
        logger.info(
            "[Memory] Stored analysis outcome for '%s': %d threats, STRIDE %s",
            system_name, len(threats), stride_cats,
        )

    def store_feedback(
        self,
        system_name: str,
        threat_description: str,
        decision: str,
        reason: str,
    ) -> None:
        """Store user feedback (justification) into semantic memory."""
        conn = self._conn
        decision_upper = decision.upper()

        if decision_upper == "FALSE_POSITIVE" or decision_upper == "NOT_APPLICABLE":
            pattern_type = "false_positive"
            content = f"[{decision}] {threat_description}: {reason}"
        elif decision_upper == "MITIGATED_BY_INFRA":
            pattern_type = "effective_mitigation"
            content = f"[INFRA] {threat_description}: {reason}"
        elif decision_upper == "ACCEPTED_RISK":
            pattern_type = "threat_pattern"
            content = f"[ACCEPTED] {threat_description}: {reason}"
        else:
            pattern_type = "threat_pattern"
            content = f"[{decision}] {threat_description}: {reason}"

        self._upsert_semantic(conn, system_name, pattern_type, content)
        conn.commit()
        logger.info(
            "[Memory] Stored feedback for '%s': %s (%s)",
            system_name, decision, pattern_type,
        )

    def recall_relevant(
        self,
        system_name: str,
        system_description: str = "",
        top_k: int = 5,
    ) -> str:
        """Retrieve relevant past analysis insights for context injection.

        Combines episodic summaries with semantic patterns, prioritising
        the requested system but also surfacing cross-system patterns
        when they have high frequency.
        """
        conn = self._conn
        parts: list[str] = []

        # 1. Episodic — latest analyses for this system
        rows = conn.execute(
            """SELECT analysis_date, threat_count, stride_coverage,
                      key_threats, quality_score
               FROM episodic_memory
               WHERE system_name = ?
               ORDER BY created_at DESC LIMIT ?""",
            (system_name, top_k),
        ).fetchall()

        if rows:
            parts.append(f"## Past analyses for '{system_name}'")
            for r in rows:
                coverage = json.loads(r["stride_coverage"]) if r["stride_coverage"] else []
                key_t = json.loads(r["key_threats"]) if r["key_threats"] else []
                parts.append(
                    f"- {r['analysis_date']}: {r['threat_count']} threats, "
                    f"STRIDE {','.join(coverage)}, quality={r['quality_score']}"
                )
                if key_t:
                    for kt in key_t[:3]:
                        parts.append(f"  - {kt}")

        # 2. Semantic — false positives for this system (avoid repeating)
        fps = conn.execute(
            """SELECT content, frequency FROM semantic_memory
               WHERE system_name = ? AND pattern_type = 'false_positive'
               ORDER BY frequency DESC, last_seen DESC LIMIT ?""",
            (system_name, top_k),
        ).fetchall()
        if fps:
            parts.append(f"\n## Known false positives for '{system_name}'")
            for fp in fps:
                parts.append(f"- (freq={fp['frequency']}) {fp['content']}")

        # 3. Semantic — effective mitigations (cross-system, high frequency)
        mits = conn.execute(
            """SELECT content, frequency, system_name FROM semantic_memory
               WHERE pattern_type = 'effective_mitigation'
               ORDER BY frequency DESC, last_seen DESC LIMIT ?""",
            (top_k,),
        ).fetchall()
        if mits:
            parts.append("\n## Effective mitigations (all systems)")
            for m in mits:
                parts.append(f"- [{m['system_name']}] (freq={m['frequency']}) {m['content'][:200]}")

        if not parts:
            return ""

        context = "\n".join(parts)
        logger.info(
            "[Memory] Recalled %d lines of context for '%s'",
            len(parts), system_name,
        )
        return context

    def _upsert_semantic(
        self,
        conn: sqlite3.Connection,
        system_name: str,
        pattern_type: str,
        content: str,
    ) -> None:
        """Insert or increment frequency for a semantic pattern."""
        existing = conn.execute(
            """SELECT id, frequency FROM semantic_memory
               WHERE system_name = ? AND pattern_type = ? AND content = ?""",
            (system_name, pattern_type, content),
        ).fetchone()

        now = datetime.now().isoformat()
        if existing:
            conn.execute(
                "UPDATE semantic_memory SET frequency = ?, last_seen = ? WHERE id = ?",
                (existing["frequency"] + 1, now, existing["id"]),
            )
        else:
            conn.execute(
                """INSERT INTO semantic_memory
                   (system_name, pattern_type, content, frequency, last_seen)
                   VALUES (?, ?, ?, 1, ?)""",
                (system_name, pattern_type, content, now),
            )
