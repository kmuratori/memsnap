-- Migration 0001 — initial schema
-- Applied automatically by db.py when PRAGMA user_version = 0.
-- NEVER edit this file after it has been committed. Write 0002.sql instead.

CREATE TABLE IF NOT EXISTS dumps (
    id              INTEGER PRIMARY KEY,
    sha256          TEXT UNIQUE NOT NULL,
    size_bytes      INTEGER NOT NULL,
    first_seen_at   TEXT NOT NULL,
    last_seen_path  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS extractions (
    id            INTEGER PRIMARY KEY,
    dump_id       INTEGER NOT NULL REFERENCES dumps(id),
    extracted_at  TEXT NOT NULL,
    elapsed_sec   REAL,
    vol_version   TEXT,
    success       INTEGER NOT NULL,
    error         TEXT
);

CREATE TABLE IF NOT EXISTS plugin_results (
    extraction_id  INTEGER NOT NULL REFERENCES extractions(id),
    plugin         TEXT NOT NULL,
    row_count      INTEGER NOT NULL,
    elapsed_sec    REAL,
    failed         INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (extraction_id, plugin)
);

CREATE TABLE IF NOT EXISTS features (
    extraction_id           INTEGER PRIMARY KEY REFERENCES extractions(id),
    hidden_proc_count       INTEGER,
    masqueraded_proc_count  INTEGER,
    hidden_module_count     INTEGER,
    rwx_region_count        INTEGER,
    total_sockets           INTEGER,
    raw_socket_count        INTEGER,
    unknown_lib_count       INTEGER
);

CREATE TABLE IF NOT EXISTS scans (
    id               INTEGER PRIMARY KEY,
    dump_id          INTEGER NOT NULL REFERENCES dumps(id),
    extraction_id    INTEGER NOT NULL REFERENCES extractions(id),
    started_at       TEXT NOT NULL,
    finished_at      TEXT,
    pipeline         TEXT NOT NULL,
    binary_model     TEXT,
    family_model     TEXT NOT NULL,
    cache_hit        INTEGER NOT NULL,
    elapsed_sec      REAL,
    stage1_infected  INTEGER,
    stage1_conf      REAL,
    error            TEXT
);

CREATE TABLE IF NOT EXISTS verdicts (
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    family      TEXT NOT NULL,
    detected    INTEGER NOT NULL,
    confidence  REAL,
    PRIMARY KEY (scan_id, family)
);

CREATE INDEX IF NOT EXISTS idx_dumps_sha256       ON dumps(sha256);
CREATE INDEX IF NOT EXISTS idx_extractions_dump   ON extractions(dump_id);
CREATE INDEX IF NOT EXISTS idx_scans_dump         ON scans(dump_id);
CREATE INDEX IF NOT EXISTS idx_scans_started      ON scans(started_at);
CREATE INDEX IF NOT EXISTS idx_verdicts_family    ON verdicts(family, detected);
