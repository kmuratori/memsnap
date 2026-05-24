#!/usr/bin/env python3
"""db.py — SQLite persistence layer for MemSnap.

All access goes through get_connection(), which opens (or creates) the DB,
enables WAL mode + foreign keys, and applies any pending migrations.

Schema lives in lib/migrations/0001.sql (and future NNNN.sql files).
Never edit a committed migration — write a new one to fix mistakes.

Public API
----------
get_connection(db_path)                            -> sqlite3.Connection

# Dump
upsert_dump(con, sha256, size_bytes, path)         -> dump_id

# Extraction
get_cached_extraction(con, dump_id)                -> extraction_id | None
insert_extraction(con, dump_id, elapsed,
                  vol_version, success, error)     -> extraction_id
insert_plugin_results(con, extraction_id, results)
insert_features(con, extraction_id, features)
load_features(con, extraction_id)                  -> dict | None

# Scan
insert_scan(con, dump_id, extraction_id, ...)      -> scan_id
finish_scan(con, scan_id, elapsed_sec,
            stage1_infected, stage1_conf, error)
insert_verdicts(con, scan_id, family_results)
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

DEFAULT_DB_PATH: Path = (
    Path.home() / ".local" / "share" / "memsnap" / "memsnap.db"
)

# Migrations live next to this file
_MIGRATIONS_DIR: Path = Path(__file__).resolve().parent / "migrations"


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

def _run_migrations(con: sqlite3.Connection) -> None:
    """Apply every pending .sql file whose 4-digit prefix > current user_version."""
    current: int = con.execute("PRAGMA user_version").fetchone()[0]

    for mf in sorted(_MIGRATIONS_DIR.glob("*.sql")):
        try:
            seq = int(mf.stem[:4])
        except (ValueError, IndexError):
            continue
        if seq <= current:
            continue
        con.executescript(mf.read_text())
        con.execute(f"PRAGMA user_version = {seq}")
        con.commit()


def get_connection(db_path: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Open (or create) the SQLite DB, run pending migrations, return connection.

    Settings applied on every connection:
      - journal_mode = WAL   (concurrent readers don't block writers)
      - foreign_keys  = ON
      - row_factory   = sqlite3.Row  (column access by name)
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(db_path))
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode = WAL")
    con.execute("PRAGMA foreign_keys = ON")
    _run_migrations(con)
    return con


def _now() -> str:
    """Current UTC time as ISO-8601 string with second precision."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# dumps
# ---------------------------------------------------------------------------

def upsert_dump(
    con: sqlite3.Connection,
    sha256: str,
    size_bytes: int,
    path: str,
) -> int:
    """Insert a new dump row or update last_seen_path for an existing one.

    Returns the dump_id (existing or newly inserted).
    """
    row = con.execute(
        "SELECT id FROM dumps WHERE sha256 = ?", (sha256,)
    ).fetchone()

    if row:
        con.execute(
            "UPDATE dumps SET last_seen_path = ? WHERE sha256 = ?",
            (path, sha256),
        )
        con.commit()
        return int(row["id"])

    cur = con.execute(
        "INSERT INTO dumps (sha256, size_bytes, first_seen_at, last_seen_path)"
        " VALUES (?, ?, ?, ?)",
        (sha256, size_bytes, _now(), path),
    )
    con.commit()
    return int(cur.lastrowid)


# ---------------------------------------------------------------------------
# extractions
# ---------------------------------------------------------------------------

def get_cached_extraction(
    con: sqlite3.Connection,
    dump_id: int,
) -> int | None:
    """Return the most-recent successful extraction_id for dump_id, or None."""
    row = con.execute(
        "SELECT id FROM extractions"
        " WHERE dump_id = ? AND success = 1"
        " ORDER BY id DESC LIMIT 1",
        (dump_id,),
    ).fetchone()
    return int(row["id"]) if row else None


def insert_extraction(
    con: sqlite3.Connection,
    dump_id: int,
    elapsed: float | None,
    vol_version: str | None,
    success: bool,
    error: str | None = None,
) -> int:
    """Record a Volatility run (successful or failed). Returns extraction_id."""
    cur = con.execute(
        "INSERT INTO extractions"
        " (dump_id, extracted_at, elapsed_sec, vol_version, success, error)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (dump_id, _now(), elapsed, vol_version, int(success), error),
    )
    con.commit()
    return int(cur.lastrowid)


def insert_plugin_results(
    con: sqlite3.Connection,
    extraction_id: int,
    results: dict[str, list],
) -> None:
    """Bulk-insert one plugin_results row per plugin in *results*.

    row_count is derived from len(rows); elapsed_sec is not tracked here
    (Volatility plugins run concurrently so individual wall-times are not
    meaningful — only total extraction elapsed_sec is stored).
    """
    rows = [
        (extraction_id, plugin, len(plugin_rows), None, 0)
        for plugin, plugin_rows in results.items()
    ]
    con.executemany(
        "INSERT OR REPLACE INTO plugin_results"
        " (extraction_id, plugin, row_count, elapsed_sec, failed)"
        " VALUES (?, ?, ?, ?, ?)",
        rows,
    )
    con.commit()


def insert_features(
    con: sqlite3.Connection,
    extraction_id: int,
    features: dict[str, Any],
) -> None:
    """Persist the 7 scalar features that the DB schema tracks.

    Extra keys in *features* (e.g. dead features, _elapsed helpers) are
    silently ignored — only the columns defined in 0001.sql are written.
    """
    COLS = [
        "hidden_proc_count",
        "masqueraded_proc_count",
        "hidden_module_count",
        "rwx_region_count",
        "total_sockets",
        "raw_socket_count",
        "unknown_lib_count",
    ]
    vals = tuple(features.get(c) for c in COLS)
    con.execute(
        "INSERT OR REPLACE INTO features"
        " (extraction_id,"
        "  hidden_proc_count, masqueraded_proc_count, hidden_module_count,"
        "  rwx_region_count, total_sockets, raw_socket_count, unknown_lib_count)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (extraction_id, *vals),
    )
    con.commit()


def load_features(
    con: sqlite3.Connection,
    extraction_id: int,
) -> dict[str, Any] | None:
    """Return the features row for *extraction_id* as a plain dict, or None."""
    row = con.execute(
        "SELECT * FROM features WHERE extraction_id = ?",
        (extraction_id,),
    ).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# scans
# ---------------------------------------------------------------------------

def insert_scan(
    con: sqlite3.Connection,
    dump_id: int,
    extraction_id: int,
    pipeline: str,
    binary_model: str | None,
    family_model: str,
    cache_hit: bool,
    elapsed_sec: float | None = None,
    stage1_infected: bool | None = None,
    stage1_conf: float | None = None,
    error: str | None = None,
) -> int:
    """Open a scan record. Returns scan_id.

    Call finish_scan() once inference completes to fill in finished_at,
    elapsed_sec, and final stage1 results — or pass them here directly
    if the scan is already complete.
    """
    cur = con.execute(
        "INSERT INTO scans"
        " (dump_id, extraction_id, started_at, pipeline,"
        "  binary_model, family_model, cache_hit,"
        "  elapsed_sec, stage1_infected, stage1_conf, error)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            dump_id,
            extraction_id,
            _now(),
            pipeline,
            binary_model,
            family_model,
            int(cache_hit),
            elapsed_sec,
            int(stage1_infected) if stage1_infected is not None else None,
            stage1_conf,
            error,
        ),
    )
    con.commit()
    return int(cur.lastrowid)


def finish_scan(
    con: sqlite3.Connection,
    scan_id: int,
    elapsed_sec: float,
    stage1_infected: bool,
    stage1_conf: float | None,
    error: str | None = None,
) -> None:
    """Update a scan row with final timing and stage-1 outcome."""
    con.execute(
        "UPDATE scans"
        " SET finished_at = ?, elapsed_sec = ?,"
        "     stage1_infected = ?, stage1_conf = ?, error = ?"
        " WHERE id = ?",
        (
            _now(),
            elapsed_sec,
            int(stage1_infected),
            stage1_conf,
            error,
            scan_id,
        ),
    )
    con.commit()


def insert_verdicts(
    con: sqlite3.Connection,
    scan_id: int,
    family_results: list[dict],
) -> None:
    """Bulk-insert one verdicts row per family in *family_results*.

    Each dict must have keys: family (str), detected (bool), confidence (float|None).
    """
    rows = [
        (
            scan_id,
            r["family"],
            int(r["detected"]),
            r.get("confidence"),
        )
        for r in family_results
    ]
    con.executemany(
        "INSERT OR REPLACE INTO verdicts (scan_id, family, detected, confidence)"
        " VALUES (?, ?, ?, ?)",
        rows,
    )
    con.commit()

