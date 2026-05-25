-- Migration 0002: Add dump_name to dumps, label to scans

ALTER TABLE dumps ADD COLUMN dump_name TEXT DEFAULT NULL;
ALTER TABLE scans ADD COLUMN label TEXT DEFAULT NULL;

PRAGMA user_version = 2;
