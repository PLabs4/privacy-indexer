-- Keyset pagination for /batches/page and bounded block pagination for /txs.
-- The former `(pool_address, seq)` and `(pool_address, block_number)` indexes
-- cannot satisfy the deterministic tie-break ordering without an extra sort.

CREATE INDEX IF NOT EXISTS notes_history_seq_idx
    ON notes (pool_address, seq, cmx_hex);

CREATE INDEX IF NOT EXISTS notes_history_block_idx
    ON notes (pool_address, block_number DESC, log_index DESC, cmx_hex);
