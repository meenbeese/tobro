-- M1 initial schema skeleton.
-- Expand with onion services, stats, etc. in later milestones.

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
);
