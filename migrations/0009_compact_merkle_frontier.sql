-- P1/P2 bounded-memory commitment-tree state.
--
-- Version 2 checkpoints keep only two 32-slot frontiers in process memory:
-- one for every ingested leaf and one for the confirmed prefix.  Complete
-- Merkle nodes live in PostgreSQL so `/merkle_path` remains compatible without
-- retaining the full witness tree in the indexer heap.

ALTER TABLE indexer_meta
    ADD COLUMN IF NOT EXISTS tree_size BIGINT,
    ADD COLUMN IF NOT EXISTS tree_root_hex TEXT,
    ADD COLUMN IF NOT EXISTS tree_frontier_hex TEXT[],
    ADD COLUMN IF NOT EXISTS confirmed_frontier_hex TEXT[],
    ADD COLUMN IF NOT EXISTS frozen_root_hex TEXT,
    ADD COLUMN IF NOT EXISTS frozen_count BIGINT,
    ADD COLUMN IF NOT EXISTS frozen_update_count BIGINT;

UPDATE indexer_meta AS meta
SET tree_size = COALESCE((
    SELECT count(*)
    FROM cmx_leaves AS leaf
    WHERE leaf.pool_address = meta.pool_address
), 0)
WHERE meta.tree_size IS NULL;

ALTER TABLE indexer_meta
    DROP CONSTRAINT IF EXISTS indexer_meta_checkpoint_version,
    DROP CONSTRAINT IF EXISTS indexer_meta_tree_size_nonnegative,
    DROP CONSTRAINT IF EXISTS indexer_meta_frontier_shape;

ALTER TABLE indexer_meta
    ADD CONSTRAINT indexer_meta_checkpoint_version CHECK (
        checkpoint_version IN (0, 1, 2)
    ),
    ADD CONSTRAINT indexer_meta_tree_size_nonnegative CHECK (
        tree_size IS NULL OR tree_size >= 0
    ),
    ADD CONSTRAINT indexer_meta_frontier_shape CHECK (
        checkpoint_version < 2
        OR (
            tree_size IS NOT NULL
            AND tree_root_hex IS NOT NULL
            AND tree_root_hex ~ '^[0-9a-f]{64}$'
            AND tree_frontier_hex IS NOT NULL
            AND cardinality(tree_frontier_hex) = 32
            AND confirmed_frontier_hex IS NOT NULL
            AND cardinality(confirmed_frontier_hex) = 32
            AND frozen_root_hex IS NOT NULL
            AND frozen_root_hex ~ '^0x[0-9a-f]{64}$'
            AND frozen_count IS NOT NULL
            AND frozen_count >= 0
            AND frozen_update_count IS NOT NULL
            AND frozen_update_count >= 0
        )
    );

CREATE TABLE IF NOT EXISTS merkle_nodes (
    pool_address TEXT NOT NULL,
    level SMALLINT NOT NULL CHECK (level BETWEEN 0 AND 32),
    node_index BIGINT NOT NULL CHECK (node_index >= 0),
    hash_hex TEXT NOT NULL CHECK (hash_hex ~ '^[0-9a-f]{64}$'),
    inserted_at TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (pool_address, level, node_index)
);

-- Isolated complete-node archive built during a finalized canonical replay.
-- It is swapped alongside notes/cmx_leaves only after the terminal finalized
-- block hash and compact frontier roots have both been verified.
CREATE TABLE IF NOT EXISTS merkle_nodes_rebuild (
    pool_address TEXT NOT NULL,
    rebuild_generation TEXT NOT NULL,
    level SMALLINT NOT NULL CHECK (level BETWEEN 0 AND 32),
    node_index BIGINT NOT NULL CHECK (node_index >= 0),
    hash_hex TEXT NOT NULL CHECK (hash_hex ~ '^[0-9a-f]{64}$'),
    inserted_at TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (pool_address, rebuild_generation, level, node_index)
);

-- The old delta table keyed rows only by a synthetic position and forced every
-- restart to deserialize the complete feed. Add its canonical chain cursor so
-- API pagination and warm-start validation stay in PostgreSQL.
ALTER TABLE frozen_updates
    ADD COLUMN IF NOT EXISTS block_number BIGINT,
    ADD COLUMN IF NOT EXISTS log_index BIGINT;

UPDATE frozen_updates
SET block_number = (update_json::jsonb ->> 'block_number')::BIGINT,
    log_index = (update_json::jsonb ->> 'log_index')::BIGINT
WHERE block_number IS NULL OR log_index IS NULL;

ALTER TABLE frozen_updates
    ALTER COLUMN block_number SET NOT NULL,
    ALTER COLUMN log_index SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS frozen_updates_chain_cursor_idx
    ON frozen_updates(pool_address, block_number, log_index);

-- Materialized current compliance set. `/frozen_leaves` reads this table with a
-- hard response cap instead of replaying every historical delta in process RAM.
CREATE TABLE IF NOT EXISTS frozen_current (
    pool_address TEXT NOT NULL,
    cmx_hex TEXT NOT NULL CHECK (cmx_hex ~ '^0x[0-9a-f]{64}$'),
    PRIMARY KEY (pool_address, cmx_hex)
);

CREATE TABLE IF NOT EXISTS frozen_updates_rebuild (
    pool_address TEXT NOT NULL,
    rebuild_generation TEXT NOT NULL,
    position BIGINT NOT NULL CHECK (position >= 0),
    block_number BIGINT NOT NULL CHECK (block_number >= 0),
    log_index BIGINT NOT NULL CHECK (log_index >= 0),
    update_json TEXT NOT NULL,
    PRIMARY KEY (pool_address, rebuild_generation, position),
    UNIQUE (pool_address, rebuild_generation, block_number, log_index)
);

CREATE TABLE IF NOT EXISTS frozen_current_rebuild (
    pool_address TEXT NOT NULL,
    rebuild_generation TEXT NOT NULL,
    cmx_hex TEXT NOT NULL CHECK (cmx_hex ~ '^0x[0-9a-f]{64}$'),
    PRIMARY KEY (pool_address, rebuild_generation, cmx_hex)
);
