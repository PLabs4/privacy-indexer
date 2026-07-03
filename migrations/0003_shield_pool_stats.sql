-- Event-derived aggregate accounting for ERC20Shield pools.
--
-- `current_shielded = total_shielded - total_unshielded`; values are stored as
-- decimal text because Solidity uint256 / event amounts can exceed signed BIGINT.
CREATE TABLE IF NOT EXISTS shield_pool_stats (
    pool_address            TEXT PRIMARY KEY,
    total_shielded_units    TEXT NOT NULL DEFAULT '0',
    total_shielded_wei      TEXT NOT NULL DEFAULT '0',
    total_unshielded_units  TEXT NOT NULL DEFAULT '0',
    total_unshielded_wei    TEXT NOT NULL DEFAULT '0',
    updated_at              TIMESTAMPTZ DEFAULT now()
);
