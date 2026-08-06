-- Protocol fees collected by an ERC20Shield pool (see PERC20 docs/tx_fee_impl.md).
--
-- `shield` and `unshield` each deduct a configured fee and emit `FeeCharged`. These totals are
-- deliberately SEPARATE from the shielded-supply columns: the fee never enters custody, so
-- `current_shielded = total_shielded - total_unshielded` must not be adjusted by it.
--
-- Stored as decimal text for the same reason as the existing columns (uint256 > BIGINT).
-- Existing rows default to '0', which is correct: pools deployed before the fee release
-- charged nothing.
ALTER TABLE shield_pool_stats
    ADD COLUMN IF NOT EXISTS total_fee_units TEXT NOT NULL DEFAULT '0',
    ADD COLUMN IF NOT EXISTS total_fee_wei   TEXT NOT NULL DEFAULT '0';
