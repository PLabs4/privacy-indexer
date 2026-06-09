-- Compliance frozen-set leaves for the sorted Indexed Merkle Tree.
--
-- Mirrors `cmx_leaves`: frozen `cmx` in insertion order (append-only), keyed by
-- `(pool_address, position)`. On restart the indexer replays these in order to
-- rebuild the `FrozenImt` and recompute `rt_frozen` — see `pg_load` / `pg_save`.
CREATE TABLE IF NOT EXISTS frozen_cmx (
    pool_address TEXT   NOT NULL,
    position     BIGINT NOT NULL,
    cmx_hex      TEXT   NOT NULL,
    inserted_at  TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (pool_address, position),
    UNIQUE (pool_address, cmx_hex)
);
