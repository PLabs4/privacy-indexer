-- Initial schema for the privacybtc-indexer PostgreSQL state backend.
-- Applied automatically by `sqlx::migrate!()` at startup (tracked in `_sqlx_migrations`).
--
-- Manual apply:
--   createdb privacybtc
--   psql privacybtc < crates/privacybtc-indexer/migrations/0001_initial.sql
--
-- Design notes (differs from privacybtc-service, which stores DECRYPTED notes it owns):
--   * This indexer NEVER decrypts. It stores the ENCRYPTED on-chain NoteAdded data
--     (`OrchardIndexedAbiNote`) so any client with the right IVK can scan it.
--   * Multi-pool: every table is keyed by `pool_address` (the indexer can watch N pools).
--   * Hex columns are TEXT (bare hex, no 0x) for easy ad-hoc SQL inspection.
--   * `position` is BIGINT (i64 on the Rust side); the app enforces non-negative.

-- Per-pool scan checkpoint scalars (one row per watched pool).
CREATE TABLE IF NOT EXISTS indexer_meta (
    pool_address    TEXT PRIMARY KEY,
    next_block      BIGINT NOT NULL,
    active_root_hex TEXT,
    latest_seq      BIGINT NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ DEFAULT now()
);

-- Commitment-tree leaves in insertion order → drives /merkle_path (position lookup).
CREATE TABLE IF NOT EXISTS cmx_leaves (
    pool_address TEXT   NOT NULL,
    position     BIGINT NOT NULL,
    cmx_hex      TEXT   NOT NULL,
    inserted_at  TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (pool_address, position),
    UNIQUE (pool_address, cmx_hex)
);

-- One row per on-chain NoteAdded (encrypted OrchardIndexedAbiNote). The queryable data.
CREATE TABLE IF NOT EXISTS notes (
    pool_address          TEXT   NOT NULL,
    cmx_hex               TEXT   NOT NULL,
    seq                   BIGINT NOT NULL,          -- batch sequence (for /batches replay)
    block_number          BIGINT NOT NULL,
    tx_hash               TEXT   NOT NULL,
    log_index             BIGINT NOT NULL,
    position              BIGINT,                   -- tree leaf position (NULL until appended / swap-pending)
    enc_ciphertext_hex    TEXT   NOT NULL,
    epk_hex               TEXT   NOT NULL,
    out_ciphertext_hex    TEXT   NOT NULL DEFAULT '',
    cv_net_x_hex          TEXT,
    nf_old_hex            TEXT   NOT NULL,
    ack_hash_hex          TEXT   NOT NULL,
    shield_amount_sats    BIGINT,
    is_confirmed          BOOLEAN NOT NULL DEFAULT FALSE,
    inserted_at           TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (pool_address, cmx_hex)
);
CREATE INDEX IF NOT EXISTS notes_seq_idx    ON notes (pool_address, seq);
CREATE INDEX IF NOT EXISTS notes_nf_old_idx ON notes (pool_address, nf_old_hex);
CREATE INDEX IF NOT EXISTS notes_block_idx  ON notes (pool_address, block_number);

-- Relayer-notified tx hashes whose events aren't yet observed (recovery queue).
CREATE TABLE IF NOT EXISTS pending_tx (
    pool_address TEXT NOT NULL,
    tx_hash      TEXT NOT NULL,
    inserted_at  TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (pool_address, tx_hash)
);
