-- Compliance frozen leaf-delta feed (frozen-tree-execution-plan PR2).
--
-- One row per ingested on-chain `FrozenRootUpdated` event, in chain order, keyed by
-- `(pool_address, position)`. `update_json` is the serialized `FrozenUpdate`
-- {block_number, log_index, tx_hash, old_root_hex, new_root_hex, cmx_changed_hex[], is_add[]}.
-- Wallets pull `GET /frozen_updates?since=cursor` and replay these deltas to rebuild their
-- local Frozen IMT. Replaces the old `frozen_cmx` table (the indexer no longer maintains the
-- IMT or serves witnesses). See `pg_load` / `pg_save`.
CREATE TABLE IF NOT EXISTS frozen_updates (
    pool_address TEXT   NOT NULL,
    position     BIGINT NOT NULL,
    update_json  TEXT   NOT NULL,
    inserted_at  TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (pool_address, position)
);

-- The old per-leaf table is superseded by the delta feed above.
DROP TABLE IF EXISTS frozen_cmx;
