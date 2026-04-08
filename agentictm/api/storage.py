"""Persistent result storage backed by SQLite (async via aiosqlite).

Replaces the in-memory ``_results: dict`` with a durable store that
survives server restarts. Results are stored as JSON blobs alongside
indexed metadata (analysis_id, system_name, timestamp).

Usage::

    store = ResultStore("data/results.db")
    await store.init()
    await store.save("abc123", result_dict)
    result = await store.get("abc123")
    all_results = await store.list_all()
    await store.delete("abc123")
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

import aiosqlite

logger = logging.getLogger(__name__)

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS results (
    analysis_id   TEXT PRIMARY KEY,
    system_name   TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    output_dir    TEXT DEFAULT '',
    result_json   TEXT NOT NULL
);
"""

_CREATE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_results_created ON results(created_at DESC);
"""


class ResultStore:
    """Async SQLite-backed storage for analysis results."""

    def __init__(self, db_path: str | Path = "data/results.db"):
        self._db_path = Path(db_path)
        self._db: aiosqlite.Connection | None = None

    async def init(self) -> None:
        """Open the database and create tables if needed."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(str(self._db_path))
        self._db.row_factory = aiosqlite.Row
        await self._db.execute(_CREATE_TABLE)
        await self._db.execute(_CREATE_INDEX)
        await self._db.commit()
        logger.info("[Storage] SQLite store ready at %s", self._db_path)

    async def close(self) -> None:
        """Close the database connection."""
        if self._db:
            await self._db.close()
            self._db = None

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    async def save(self, analysis_id: str, result: dict[str, Any]) -> None:
        """Insert or replace a result."""
        assert self._db is not None, "Call init() first"
        now = datetime.now().isoformat()
        system_name = str(result.get("system_name", ""))
        output_dir = str(result.get("output_dir", ""))
        result_json = json.dumps(result, ensure_ascii=False, default=str)

        await self._db.execute(
            """INSERT INTO results (analysis_id, system_name, created_at, updated_at, output_dir, result_json)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(analysis_id) DO UPDATE SET
                   system_name = excluded.system_name,
                   updated_at  = excluded.updated_at,
                   output_dir  = excluded.output_dir,
                   result_json = excluded.result_json
            """,
            (analysis_id, system_name, now, now, output_dir, result_json),
        )
        await self._db.commit()

    async def get(self, analysis_id: str) -> dict[str, Any] | None:
        """Retrieve a single result by ID, or None if not found."""
        assert self._db is not None
        async with self._db.execute(
            "SELECT result_json FROM results WHERE analysis_id = ?",
            (analysis_id,),
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return None
        return json.loads(row[0])

    async def list_all(self) -> list[dict[str, Any]]:
        """Return lightweight metadata for all stored results (no full JSON)."""
        assert self._db is not None
        rows = []
        async with self._db.execute(
            "SELECT analysis_id, system_name, created_at, updated_at, output_dir FROM results ORDER BY created_at DESC",
        ) as cursor:
            async for row in cursor:
                rows.append({
                    "analysis_id": row[0],
                    "system_name": row[1],
                    "created_at": row[2],
                    "updated_at": row[3],
                    "output_dir": row[4],
                })
        return rows

    async def list_full(self) -> dict[str, dict[str, Any]]:
        """Return all results keyed by analysis_id (full JSON).

        Used to populate the in-memory cache at startup.
        """
        assert self._db is not None
        results: dict[str, dict[str, Any]] = {}
        async with self._db.execute(
            "SELECT analysis_id, result_json FROM results ORDER BY created_at DESC",
        ) as cursor:
            async for row in cursor:
                try:
                    results[row[0]] = json.loads(row[1])
                except json.JSONDecodeError:
                    logger.warning("[Storage] Corrupt JSON for analysis %s, skipping", row[0])
        return results

    async def delete(self, analysis_id: str) -> bool:
        """Delete a result. Returns True if a row was actually deleted."""
        assert self._db is not None
        cursor = await self._db.execute(
            "DELETE FROM results WHERE analysis_id = ?",
            (analysis_id,),
        )
        await self._db.commit()
        return cursor.rowcount > 0

    async def delete_many(self, analysis_ids: list[str]) -> int:
        """Delete multiple results. Returns number of rows deleted."""
        assert self._db is not None
        if not analysis_ids:
            return 0
        placeholders = ",".join("?" for _ in analysis_ids)
        cursor = await self._db.execute(
            f"DELETE FROM results WHERE analysis_id IN ({placeholders})",
            analysis_ids,
        )
        await self._db.commit()
        return cursor.rowcount

    async def list_paginated(
        self, *, page: int = 1, page_size: int = 10
    ) -> dict[str, Any]:
        """Return paginated lightweight metadata.

        Returns dict with keys: items, total, page, page_size, total_pages.
        """
        assert self._db is not None
        total = await self.count()
        total_pages = max(1, (total + page_size - 1) // page_size)
        page = max(1, min(page, total_pages))
        offset = (page - 1) * page_size

        rows = []
        async with self._db.execute(
            "SELECT analysis_id, system_name, created_at, updated_at, output_dir "
            "FROM results ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (page_size, offset),
        ) as cursor:
            async for row in cursor:
                rows.append({
                    "analysis_id": row[0],
                    "system_name": row[1],
                    "created_at": row[2],
                    "updated_at": row[3],
                    "output_dir": row[4],
                })
        return {
            "items": rows,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
        }

    async def count(self) -> int:
        """Return total number of stored results."""
        assert self._db is not None
        async with self._db.execute("SELECT COUNT(*) FROM results") as cursor:
            row = await cursor.fetchone()
        return row[0] if row else 0
