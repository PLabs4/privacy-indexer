-- Canonical Monad-finalized scan anchor.
--
-- Both columns are nullable for rolling compatibility with checkpoints written
-- by older indexer binaries. The first successful finalized rebuild populates
-- the pair; subsequent catch-up passes verify the hash before advancing.
ALTER TABLE indexer_meta
    ADD COLUMN IF NOT EXISTS last_finalized_block BIGINT,
    ADD COLUMN IF NOT EXISTS last_finalized_block_hash TEXT;

ALTER TABLE indexer_meta
    DROP CONSTRAINT IF EXISTS indexer_meta_finalized_cursor_pair;

ALTER TABLE indexer_meta
    ADD CONSTRAINT indexer_meta_finalized_cursor_pair CHECK (
        (last_finalized_block IS NULL AND last_finalized_block_hash IS NULL)
        OR
        (last_finalized_block IS NOT NULL
         AND last_finalized_block >= 0
         AND last_finalized_block_hash IS NOT NULL
         AND last_finalized_block_hash ~ '^0x[0-9a-f]{64}$')
    );

-- Full finalized replays are built here and swapped into `notes` only after
-- every log window and the terminal finalized block hash have been verified.
-- `rebuild_generation` keeps an interrupted or overlapping attempt isolated.
CREATE TABLE IF NOT EXISTS notes_rebuild (
    pool_address          TEXT   NOT NULL,
    rebuild_generation    TEXT   NOT NULL,
    cmx_hex               TEXT   NOT NULL,
    seq                   BIGINT NOT NULL,
    block_number          BIGINT NOT NULL,
    tx_hash               TEXT   NOT NULL,
    log_index             BIGINT NOT NULL,
    position              BIGINT,
    enc_ciphertext_hex    TEXT   NOT NULL,
    epk_hex               TEXT   NOT NULL,
    out_ciphertext_hex    TEXT   NOT NULL DEFAULT '',
    cv_net_x_hex          TEXT,
    nf_old_hex            TEXT   NOT NULL,
    ack_hash_hex          TEXT   NOT NULL,
    shield_amount_sats    BIGINT,
    is_confirmed          BOOLEAN NOT NULL DEFAULT FALSE,
    inserted_at           TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (pool_address, rebuild_generation, cmx_hex)
);
