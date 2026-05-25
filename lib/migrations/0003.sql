-- Migration 0003: Add dead-feature columns to features

ALTER TABLE features ADD COLUMN deleted_exe_count INTEGER DEFAULT 0;
ALTER TABLE features ADD COLUMN hooked_syscall_count INTEGER DEFAULT 0;
ALTER TABLE features ADD COLUMN foreign_conn_count INTEGER DEFAULT 0;
ALTER TABLE features ADD COLUMN high_port_count INTEGER DEFAULT 0;
ALTER TABLE features ADD COLUMN netfilter_hook_count INTEGER DEFAULT 0;

UPDATE features SET deleted_exe_count = 0 WHERE deleted_exe_count IS NULL;
UPDATE features SET hooked_syscall_count = 0 WHERE hooked_syscall_count IS NULL;
UPDATE features SET foreign_conn_count = 0 WHERE foreign_conn_count IS NULL;
UPDATE features SET high_port_count = 0 WHERE high_port_count IS NULL;
UPDATE features SET netfilter_hook_count = 0 WHERE netfilter_hook_count IS NULL;

PRAGMA user_version = 3;
