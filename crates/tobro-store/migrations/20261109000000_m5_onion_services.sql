-- M5: onion service hosting model and port mappings.
-- Key material lives on disk under the managed onion-services directory (0700),
-- not in the database. This schema stores metadata and desired state.

CREATE TABLE IF NOT EXISTS onion_service (
    id            TEXT PRIMARY KEY NOT NULL,
    nickname      TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1,
    onion_address TEXT,
    key_dir       TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS onion_service_port (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id  TEXT NOT NULL REFERENCES onion_service(id) ON DELETE CASCADE,
    virt_port   INTEGER NOT NULL,
    target_host TEXT NOT NULL DEFAULT '127.0.0.1',
    target_port INTEGER NOT NULL,
    UNIQUE(service_id, virt_port)
);

CREATE INDEX IF NOT EXISTS onion_service_port_service_id
    ON onion_service_port(service_id);
