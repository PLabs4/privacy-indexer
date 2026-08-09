-- Segment-end frozen Merkle paths (docs/note-sync-indexer-frozen-merkle-path.md).
--
-- One row per confirmed cmx, written exactly once when its RootUpdated segment
-- seals. `anchor_root_hex` is that segment's `newRoot` (big-endian hex, no 0x),
-- `siblings_json` is the JSON array of 32 little-endian 0x-hex siblings exactly
-- as `/merkle_path` serves them. Rows are never updated by later appends and
-- never deleted by reads; only a canonical rebuild replaces them wholesale.
CREATE TABLE IF NOT EXISTS frozen_paths (
    pool_address    TEXT        NOT NULL,
    cmx_hex         TEXT        NOT NULL,
    position        BIGINT      NOT NULL,
    siblings_json   TEXT        NOT NULL,
    anchor_root_hex TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (pool_address, cmx_hex)
);

-- Staging generation for canonical rebuilds, mirroring notes_rebuild /
-- merkle_nodes_rebuild: the finalized replay writes here and the activation
-- transaction swaps it into frozen_paths.
CREATE TABLE IF NOT EXISTS frozen_paths_rebuild (
    pool_address       TEXT   NOT NULL,
    rebuild_generation TEXT   NOT NULL,
    cmx_hex            TEXT   NOT NULL,
    position           BIGINT NOT NULL,
    siblings_json      TEXT   NOT NULL,
    anchor_root_hex    TEXT   NOT NULL,
    PRIMARY KEY (pool_address, rebuild_generation, cmx_hex)
);
