-- tobro local store schema (pre-1.0, idempotent).
-- Applied on every open; uses IF NOT EXISTS so schema evolution is additive.
-- For incompatible changes pre-1.0, reset local state as needed.

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
);

-- Onion service hosting model and port mappings.
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

-- Client authorization credentials (.auth_private keypairs) and attachments to
-- hosted onion services (restricted discovery). Secret key material is stored on
-- disk under managed private directories, not in the database.
CREATE TABLE IF NOT EXISTS onion_client_auth (
    id          TEXT PRIMARY KEY NOT NULL,
    nickname    TEXT NOT NULL UNIQUE,
    key_dir     TEXT NOT NULL,
    public_key  TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS onion_service_client_auth (
    service_id      TEXT NOT NULL REFERENCES onion_service(id) ON DELETE CASCADE,
    client_auth_id  TEXT NOT NULL REFERENCES onion_client_auth(id) ON DELETE CASCADE,
    PRIMARY KEY (service_id, client_auth_id)
);

CREATE INDEX IF NOT EXISTS onion_service_client_auth_client
    ON onion_service_client_auth(client_auth_id);

-- Kindness Mode connection statistics (`kindness.stats`).
-- Single lazily-seeded row: counts of clients the proxy served. Nothing about
-- the clients themselves is recorded (no addresses, no labels, no countries).
-- `current` connections are volatile daemon state, never stored here.
CREATE TABLE IF NOT EXISTS kindness_stats (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    total_served INTEGER NOT NULL DEFAULT 0,
    week_start   TEXT NOT NULL DEFAULT '',
    week_served  INTEGER NOT NULL DEFAULT 0,
    updated_at   INTEGER NOT NULL DEFAULT 0
);

INSERT INTO kindness_stats (id) VALUES (1) ON CONFLICT DO NOTHING;
