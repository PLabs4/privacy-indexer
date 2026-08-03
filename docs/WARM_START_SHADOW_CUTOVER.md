# Indexer warm-start and shadow cutover

This runbook describes the deployment contract implemented by the indexer. It
does not authorize a production change by itself.

## Safety model

- A primary process may warm-start only from a PostgreSQL checkpoint whose
  finalized block/hash is still canonical, whose `notes` and `cmx_leaves` rows
  form the same contiguous sequence, and whose recomputed confirmed Poseidon
  root matches both the persisted root and the current contract watermark.
- The checkpoint is read in one read-only `REPEATABLE READ` transaction, so an
  online old primary cannot produce a torn shadow snapshot.
- Checkpoint version `0` supports the pre-warm-start writer by deriving the
  confirmation watermark and last-leaf cursor from the atomic note archive.
  Version `1` requires the new persisted scalars to match the archive exactly.
- A rejected checkpoint never becomes healthy. A primary falls back to the
  staged full replay; a shadow remains HTTP 503 and never replays or writes.
- `PRIVACYBTC_INDEXER_SHADOW_MODE=true` disables persistence, crank signing,
  relayer notifications, and runtime pool registration. Trusted-factory
  discovery is read-only and remains available.

## 1. Prepare the schema while the old primary remains online

Run the candidate image once with:

```text
PRIVACYBTC_INDEXER_MIGRATE_ONLY=true
PRIVACYBTC_INDEXER_SHADOW_MODE=false
PRIVACYBTC_INDEXER_CRANK=false
```

The process applies migration `0006_warm_checkpoint` and exits before starting
RPC ingestion, pool discovery, persistence, or crank work. Do not start the
shadow until this command exits successfully.

## 2. Start an isolated shadow

Start the same immutable candidate image on a different loopback port and the
same Compose network/database, overriding at least:

```text
PRIVACYBTC_INDEXER_MIGRATE_ONLY=false
PRIVACYBTC_INDEXER_SHADOW_MODE=true
PRIVACYBTC_INDEXER_CRANK=false
PRIVACYBTC_INDEXER_SIGNER_KEY=
PRIVACYBTC_INDEXER_ALLOW_RUNTIME_POOL_REGISTRATION=false
```

Keep the production trusted-factory discovery and trust-root configuration.
Do not route relayer or public traffic to the shadow.

## 3. Go/No-Go gates

For every production pool, require all of the following:

- Shadow `/healthz` is 200 for at least two catch-up intervals.
- Shadow `/status` has `canonical=true`, `shadow_mode=true`, and
  `startup_source="checkpoint"`.
- The primary and shadow pool-address sets are identical.
- `tree_size`, `confirmed_count`, `pending_cmx`, `active_root_hex`, and the
  finalized cursor match, allowing only a bounded forward lag while sampling.
- Logs contain `canonical warm-start accepted` and no startup `backfill:
  scanning logs` line.
- PostgreSQL `indexer_meta.updated_at`, note counts, and leaf counts do not
  change because of the shadow process.

Any root, pool-set, cursor, or archive mismatch is a No-Go. Do not repair it by
editing rows; retain the old primary and investigate the rejected invariant.

## 4. Replace the primary

The shadow is a read-only verifier, not a promotable writer. After the gates
pass:

1. Pause new payout preparation so the cutover has a bounded quiet window.
2. Stop the old Indexer writer/crank.
3. Recreate the normal Indexer service from the same candidate image with
   `SHADOW_MODE=false` and the reviewed crank configuration.
4. Wait for `/healthz=200` and `/status.startup_source="checkpoint"` before
   resuming payout preparation.
5. Verify the on-chain `confirmedRoot/confirmedCount/pendingCmxCount` against
   `/status`, then observe at least one successful incremental catch-up and one
   crank cycle.

The normal service still restarts, but it restores the validated checkpoint and
replays only the finalized suffix; it does not scan from the deployment block.

## Rollback limitation

Rolling back to an older image that lacks warm-start will again perform its
legacy full replay on restart. Keep the payout worker paused until that old
instance is canonical, or roll forward with the candidate after correcting a
configuration-only failure. Do not run old and new writable Indexers against
the same PostgreSQL database concurrently.
