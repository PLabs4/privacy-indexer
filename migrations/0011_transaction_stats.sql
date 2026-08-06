-- Exact durable transaction index for the public explorer's cached aggregate.
--
-- A protocol transaction can emit several notes and a swap can emit notes from
-- multiple pools, so `notes` rows cannot be counted directly. This index keeps
-- one canonical tx hash with a reference count of its live note rows. Triggers
-- make ordinary upserts, canonical rebuild activation, pool resets and deletes
-- update the aggregate in the same PostgreSQL transaction as `notes`.

CREATE OR REPLACE FUNCTION canonical_note_tx_hash(raw_hash TEXT)
RETURNS TEXT
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT CASE
        WHEN left(lower(raw_hash), 2) = '0x' THEN lower(raw_hash)
        ELSE '0x' || lower(raw_hash)
    END
$$;

CREATE TABLE IF NOT EXISTS indexed_transactions (
    tx_hash     TEXT PRIMARY KEY,
    note_count  BIGINT NOT NULL CHECK (note_count > 0)
);

-- Migrations run before the HTTP server or event loops start, so this backfill
-- sees a stable archive.
INSERT INTO indexed_transactions (tx_hash, note_count)
SELECT canonical_note_tx_hash(tx_hash), count(*)
FROM notes
GROUP BY canonical_note_tx_hash(tx_hash)
ON CONFLICT (tx_hash) DO UPDATE SET note_count = EXCLUDED.note_count;

CREATE OR REPLACE FUNCTION add_indexed_transaction_note(raw_hash TEXT)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO indexed_transactions (tx_hash, note_count)
    VALUES (canonical_note_tx_hash(raw_hash), 1)
    ON CONFLICT (tx_hash) DO UPDATE
    SET note_count = indexed_transactions.note_count + 1;
END
$$;

CREATE OR REPLACE FUNCTION remove_indexed_transaction_note(raw_hash TEXT)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    canonical_hash TEXT := canonical_note_tx_hash(raw_hash);
    updated_rows BIGINT;
    deleted_rows BIGINT;
BEGIN
    UPDATE indexed_transactions
    SET note_count = note_count - 1
    WHERE tx_hash = canonical_hash AND note_count > 1;
    GET DIAGNOSTICS updated_rows = ROW_COUNT;
    IF updated_rows = 1 THEN
        RETURN;
    END IF;

    DELETE FROM indexed_transactions
    WHERE tx_hash = canonical_hash AND note_count = 1;
    GET DIAGNOSTICS deleted_rows = ROW_COUNT;
    IF deleted_rows != 1 THEN
        RAISE EXCEPTION 'transaction note index missing or invalid for %', canonical_hash;
    END IF;

END
$$;

CREATE OR REPLACE FUNCTION maintain_indexed_transaction_stats()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM add_indexed_transaction_note(NEW.tx_hash);
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        PERFORM remove_indexed_transaction_note(OLD.tx_hash);
        RETURN OLD;
    ELSIF canonical_note_tx_hash(OLD.tx_hash) IS DISTINCT FROM canonical_note_tx_hash(NEW.tx_hash) THEN
        PERFORM remove_indexed_transaction_note(OLD.tx_hash);
        PERFORM add_indexed_transaction_note(NEW.tx_hash);
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS notes_transaction_stats_trigger ON notes;
CREATE TRIGGER notes_transaction_stats_trigger
AFTER INSERT OR DELETE OR UPDATE OF tx_hash ON notes
FOR EACH ROW EXECUTE FUNCTION maintain_indexed_transaction_stats();
