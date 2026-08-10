-- Close the online-upgrade race in 0011_transaction_stats.sql.
--
-- A legacy Indexer may still append `notes` while the candidate image applies
-- 0011. Rows committed after 0011's initial aggregate snapshot but before its
-- trigger exists would not be represented in `indexed_transactions`. By the
-- time this migration runs the trigger is installed. A SHARE ROW EXCLUSIVE
-- lock briefly blocks note writers (but not readers), rebuilds the aggregate
-- from one stable archive, and then lets blocked writes proceed through the
-- trigger after commit.
LOCK TABLE notes IN SHARE ROW EXCLUSIVE MODE;

TRUNCATE TABLE indexed_transactions;

INSERT INTO indexed_transactions (tx_hash, note_count)
SELECT canonical_note_tx_hash(tx_hash), count(*)
FROM notes
GROUP BY canonical_note_tx_hash(tx_hash);
