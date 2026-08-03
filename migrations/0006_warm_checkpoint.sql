-- Canonical warm-start metadata.
--
-- A finalized cursor/hash proves which chain history produced the checkpoint,
-- while these fields make the in-memory confirmation watermark and append-order
-- guard exactly restorable.  They remain nullable for rolling compatibility:
-- the indexer treats any incomplete row as ineligible for warm-start.
ALTER TABLE indexer_meta
    ADD COLUMN IF NOT EXISTS confirmed_count BIGINT,
    ADD COLUMN IF NOT EXISTS last_leaf_block BIGINT,
    ADD COLUMN IF NOT EXISTS last_leaf_log_index BIGINT,
    ADD COLUMN IF NOT EXISTS checkpoint_version SMALLINT NOT NULL DEFAULT 0;

-- Bootstrap diagnostic values for existing rows. They remain checkpoint_version=0:
-- a new reader derives these scalars from the atomically-maintained note archive
-- so an old online writer cannot make them look torn. The first new-writer save
-- atomically seals checkpoint_version=1 and maintains the columns thereafter.
UPDATE indexer_meta AS meta
SET confirmed_count = COALESCE((
    SELECT max(note.position) + 1
    FROM notes AS note
    WHERE note.pool_address = meta.pool_address
      AND note.is_confirmed
      AND note.position IS NOT NULL
), 0)
WHERE meta.confirmed_count IS NULL;

UPDATE indexer_meta AS meta
SET last_leaf_block = latest.block_number,
    last_leaf_log_index = latest.log_index
FROM (
    SELECT DISTINCT ON (pool_address)
        pool_address, block_number, log_index
    FROM notes
    WHERE position IS NOT NULL
    ORDER BY pool_address, position DESC
) AS latest
WHERE latest.pool_address = meta.pool_address
  AND meta.last_leaf_block IS NULL
  AND meta.last_leaf_log_index IS NULL;

ALTER TABLE indexer_meta
    DROP CONSTRAINT IF EXISTS indexer_meta_confirmed_count_nonnegative,
    DROP CONSTRAINT IF EXISTS indexer_meta_last_leaf_pair,
    DROP CONSTRAINT IF EXISTS indexer_meta_checkpoint_version;

ALTER TABLE indexer_meta
    ADD CONSTRAINT indexer_meta_confirmed_count_nonnegative CHECK (
        confirmed_count IS NULL OR confirmed_count >= 0
    ),
    ADD CONSTRAINT indexer_meta_last_leaf_pair CHECK (
        (last_leaf_block IS NULL AND last_leaf_log_index IS NULL)
        OR
        (last_leaf_block IS NOT NULL
         AND last_leaf_block >= 0
         AND last_leaf_log_index IS NOT NULL
         AND last_leaf_log_index >= 0)
    ),
    ADD CONSTRAINT indexer_meta_checkpoint_version CHECK (
        checkpoint_version IN (0, 1)
    );
