use std::{
    collections::{HashMap, HashSet, VecDeque},
    convert::Infallible,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{Query, State},
    http::{HeaderMap, Method, StatusCode},
    response::sse::{Event, KeepAlive, Sse},
    routing::{get, post},
    Json, Router,
};
use futures_util::stream::{self, StreamExt};
use tokio::sync::{broadcast, RwLock};
use tokio_stream::wrappers::BroadcastStream;
use tokio_tungstenite::tungstenite::Message;
use futures_util::SinkExt;
use tower_http::cors::{AllowOrigin, CorsLayer};
use clap::Parser;
use k256::ecdsa::{RecoveryId, SigningKey};
use privacy_core::commitment_tree::OrchardCommitmentTree;
use privacy_core::commitment_tree::frozen::{
    fr_from_be_bytes, fr_to_be_bytes, fr_to_le_hex, FrozenImt,
};
use privacy_core::types::{
    OrchardIndexBatch, OrchardIndexedAbiNote, OrchardIndexedBundle, OrchardStoredBundle,
};
use privacy_core::ethereum::{
    bundle_actions_by_cmx, decode_note_added_log, decode_note_confirmed_log,
    decode_shield_completed_log, decode_shielded_log, decode_unshielded_log,
    shielded_topic0_hex, unshielded_topic0_hex, BundleActionCiphertexts,
    note_added_topic0_alternatives, note_confirmed_topic0_hex, shield_completed_topic0_hex,
    // WS-6: ERC20Shield pool discovery/verification + metadata (privacy-core 0.1.3).
    decode_shield_pool_created_log, shield_pool_created_topic0_hex, DecodedShieldPoolCreated,
};
use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha3::{Digest, Keccak256};

/// BN254 Poseidon incremental tree (depth 32) with **zero leaves**, matching
/// `IncrementalMerkleTree.init()` / `PrivacyBTC` constructor (`_tree.root` on-chain).
/// See `contracts/IncrementalMerkleTree.sol` (`_empty(DEPTH)`).
///
/// Stored here in EVM/on-chain byte order (big-endian as returned by `activeRoot()`).
const EVM_EMPTY_IMT_ROOT: [u8; 32] = [
    0x2c, 0xbe, 0x96, 0x7b, 0x6b, 0xa6, 0xd0, 0xfa, 0xa4, 0xe8, 0x4e, 0xa6, 0x23, 0xd1, 0x1d, 0xc7, 0x47, 0x85, 0x4f,
    0xd3, 0x2e, 0xca, 0xa4, 0x8c, 0x72, 0x16, 0x35, 0x24, 0x3d, 0x37, 0xd7, 0x9f,
];

/// Returns the Poseidon BN254 Merkle root as a LE hex string, suitable for
/// `parse_fr_le()` in the prover witness builder.
///
/// Returns the local Poseidon tree root (LE hex), which is always kept in sync
/// with the on-chain `_tree.root` as notes are appended.  This is what the prover
/// uses as the anchor, and it must match the source of Merkle paths (`/merkle_path`).
///
/// NOTE: `active_root` (from `NoteConfirmed` events) is intentionally NOT used here
/// because it can become stale when the indexer misses confirmation events across
/// restarts.  The local tree is the single source of truth for both `/root` and
/// `/merkle_path`, ensuring the two are always consistent.
fn http_root_hex(state: &SharedState) -> Option<String> {
    // Use local Poseidon tree root (LE bytes) — always consistent with /merkle_path.
    if let Some(r) = state.tree.latest_root() {
        return Some(hex::encode(r));
    }
    // Empty tree — convert hardcoded on-chain BE root to LE for prover compatibility.
    let mut le = EVM_EMPTY_IMT_ROOT;
    le.reverse();
    Some(hex::encode(le))
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Parser)]
#[command(name = "privacybtc-indexer", about = "Orchard bundle indexer for Ethereum logs")]
struct Cli {
    /// HTTP(S) JSON-RPC URL. Used for receipt fetches; the WebSocket URL is derived
    /// from it (https→wss) unless --ws-url is given.
    #[arg(long, env = "PRIVACYBTC_ETH_RPC_URL")]
    rpc_url: String,
    /// Explicit WebSocket URL for the log subscription. Needed when the provider's WS
    /// path differs from its HTTP path (e.g. Infura: HTTP /v3/<key> vs WS /ws/v3/<key>),
    /// where a naive scheme swap would produce the wrong URL.
    #[arg(long, env = "PRIVACYBTC_ETH_WS_URL")]
    ws_url: Option<String>,
    /// PostgreSQL connection URL (e.g. postgres://user:pass@host:5432/privacybtc).
    /// When set, state is persisted to PG (queryable) instead of the JSON state file;
    /// the schema in `migrations/` is applied automatically via sqlx at startup.
    #[arg(long, env = "PRIVACYBTC_INDEXER_DATABASE_URL")]
    database_url: Option<String>,
    /// Pool contract address(es). Pass the flag multiple times for multiple pools,
    /// e.g. --contract-address 0xBTC... --contract-address 0xERC...
    /// All pools are scanned by the same process on the same port; use ?pool=0x...
    /// query param on HTTP endpoints to select a specific pool.
    ///
    /// Optional: an issuance-platform indexer can start with zero CLI pools and
    /// have them registered at runtime via `POST /pools` (persisted with
    /// --pools-registry). The first pool added (CLI or runtime) becomes primary.
    #[arg(long)]
    contract_address: Vec<String>,
    /// `PrivacyBTC.sol` compatible logs: `NoteAdded`, `ShieldCompleted`, `NoteConfirmed`
    /// (topic0 OR filter). Default: on.
    #[arg(long, default_value_t = true)]
    privacybtc_abi_logs: bool,
    /// Legacy_TOPIC0: log `data` = single ABI `bytes` UTF-8 JSON [`OrchardStoredBundle`].
    #[arg(long)]
    legacy_bundle_topic0: Option<String>,
    #[arg(long, env = "PRIVACYBTC_INDEXER_BIND", default_value = "127.0.0.1:8787")]
    bind: String,
    #[arg(long, default_value_t = 512)]
    max_batches_in_memory: usize,
    /// Number of blocks before a pending note expires (default ≈ 200 blocks).
    #[arg(long, default_value_t = 200)]
    pending_timeout_blocks: u64,
    /// Path to a JSON file for persisting the last scanned block height.
    /// If the file exists on startup, `next_block` is restored from it (never
    /// going below --start-block). Updated after every successful scan chunk.
    #[arg(long, env = "PRIVACYBTC_INDEXER_STATE_FILE")]
    state_file: Option<String>,
    /// First block to scan when no checkpoint exists; resume never goes below this.
    #[arg(long, env = "PRIVACYBTC_START_BLOCK", default_value_t = 0)]
    start_block: u64,
    /// Hex-encoded secp256k1 private key for the indexer's signing account.
    /// Required to relay Phase 2 confirmations on-chain.
    #[arg(long, env = "PRIVACYBTC_INDEXER_SIGNER_KEY")]
    signer_key: Option<String>,
    #[arg(long, env = "PRIVACYBTC_CHAIN_ID", default_value_t = 1u64)]
    chain_id: u64,
    /// Gas price in wei for confirm transactions. Default: 1 Gwei.
    #[arg(long, default_value_t = 1_000_000_000u64)]
    gas_price: u64,
    /// Gas limit for confirmReceipt transactions. Default: 100_000.
    #[arg(long, default_value_t = 100_000u64)]
    gas_limit_confirm: u64,
    /// Override `NoteConfirmed(bytes32,bytes32)` topic0 (default: canonical hash).
    #[arg(long)]
    confirm_topic0: Option<String>,
    /// Path to a JSON file persisting pools registered at runtime via `POST /pools`.
    /// Re-loaded on startup so dynamically-added pools survive restarts.
    #[arg(long, env = "PRIVACYBTC_INDEXER_POOLS_REGISTRY")]
    pools_registry: Option<String>,
    /// Auto-discover pools by scanning `Perc20Created` chain-wide (no address
    /// filter) and registering each match automatically. With this on, the
    /// frontend never needs to call `POST /pools` — the indexer self-heals.
    #[arg(long, env = "PRIVACYBTC_INDEXER_DISCOVER_POOLS", default_value_t = false, value_parser = parse_bool_flag)]
    discover_pools: bool,
    /// Restrict auto-discovery to these issuer addresses (repeatable or comma-
    /// separated). Empty ⇒ discover every pERC20 on the chain.
    #[arg(long, env = "PRIVACYBTC_INDEXER_DISCOVER_ISSUER", value_delimiter = ',')]
    discover_issuer: Vec<String>,
    /// Poll interval (seconds) for the auto-discovery scan.
    #[arg(long, env = "PRIVACYBTC_INDEXER_DISCOVER_POLL_SECS", default_value_t = 12)]
    discover_poll_secs: u64,
}

/// Lenient boolean parser for env/CLI flags so deployers can use 1/0/yes/no/on/off
/// in addition to true/false (docker-compose env_file commonly uses "1").
fn parse_bool_flag(s: &str) -> Result<bool, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "" | "0" | "false" | "no" | "off" => Ok(false),
        other => Err(format!("invalid boolean '{other}' (use 1/0/true/false/yes/no)")),
    }
}

// ─── Domain types ────────────────────────────────────────────────────────────

/// Tracks a note submitted in Phase 1 but not yet confirmed by the receiver.
#[derive(Debug, Clone)]
struct PendingNote {
    /// keccak256(sharedSecret) submitted by the sender.
    ack_hash: [u8; 32],
    /// Ethereum block number when the note was submitted (Phase 1).
    submitted_block: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
struct ShieldAccounting {
    total_shielded_units: u128,
    total_shielded_wei: u128,
    total_unshielded_units: u128,
    total_unshielded_wei: u128,
}

impl ShieldAccounting {
    fn current_shielded_units(self) -> u128 {
        self.total_shielded_units.saturating_sub(self.total_unshielded_units)
    }

    fn current_shielded_wei(self) -> u128 {
        self.total_shielded_wei.saturating_sub(self.total_unshielded_wei)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BatchEnvelope {
    seq: u64,
    batch: OrchardIndexBatch,
    /// Pool contract address (0x-prefixed lowercase) that produced this batch.
    /// Allows clients querying multiple indexer instances to disambiguate batches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pool_address: Option<String>,
}

// ─── Shared state ────────────────────────────────────────────────────────────

struct SharedState {
    next_block: u64,
    latest_seq: u64,
    /// Dedup set for Phase 1 (NoteAdded) events.
    seen_event_ids: HashSet<String>,
    /// Dedup set for Phase 2 (NoteConfirmed) events.
    confirm_seen_ids: HashSet<String>,
    /// Dedup set for ShieldCompleted events (they re-emit a batch envelope, so
    /// WS/catchup overlap must not process them twice).
    shield_seen_ids: HashSet<String>,
    /// Dedup set for ERC20Shield accounting events (`Shielded` / `Unshielded`).
    accounting_seen_ids: HashSet<String>,
    /// Public aggregate totals for backed shield pools. Values are event-derived:
    /// `current = total_shielded - total_unshielded`.
    shield_accounting: ShieldAccounting,
    batches: VecDeque<BatchEnvelope>,
    max_batches: usize,
    /// Orchard note commitment tree (all cmx, pending + confirmed).
    tree: OrchardCommitmentTree,
    /// cmx → leaf position in the commitment tree.
    cmx_to_position: HashMap<[u8; 32], u64>,
    /// All cmx leaves in insertion order (big-endian bytes, as from EVM logs).
    /// Kept in sync with every `tree.append` call; serialised into the checkpoint
    /// so the tree can be rebuilt from scratch on restart without re-scanning.
    cmx_ordered: Vec<[u8; 32]>,
    /// cmx → pending note info (Phase 1 submitted, Phase 2 not yet confirmed).
    pending_notes: HashMap<[u8; 32], PendingNote>,
    /// Confirmed cmx set (Phase 2 complete).
    confirmed_cmx: HashSet<[u8; 32]>,
    /// Latest confirmed Orchard commitment tree root.
    /// Updated only when a NoteConfirmed event is processed (Phase 2).
    active_root: Option<[u8; 32]>,
    pending_timeout_blocks: u64,
    /// Tx hashes submitted by the relayer but whose events haven't been received
    /// via WebSocket yet. On WS reconnect, these are recovered via receipt lookup.
    pending_tx_hashes: VecDeque<String>,
    /// Parsed `bundle()` calldata per tx (for OVK `out_ciphertext` + `cv_net_x`).
    bundle_out_cache: HashMap<String, HashMap<[u8; 32], BundleActionCiphertexts>>,
    /// Compliance frozen-set (sorted Indexed Merkle Tree). `frozen.root()` is the
    /// `rt_frozen` / `cmxFrozenRoot()` the prover and contract must agree on. Starts
    /// as the empty-blacklist tree; admins freeze a `cmx` via `POST /frozen`.
    frozen: FrozenImt,
}

// ─── Signing (ETH transaction relay) ─────────────────────────────────────────

struct SignerConfig {
    signing_key: SigningKey,
    address: [u8; 20],
    chain_id: u64,
    gas_price: u64,
    gas_limit: u64,
}

impl SignerConfig {
    fn from_hex_key(hex_key: &str, chain_id: u64, gas_price: u64, gas_limit: u64) -> Result<Self> {
        let key_bytes = hex::decode(strip_0x(hex_key)).context("invalid signer key hex")?;
        let signing_key =
            SigningKey::from_slice(&key_bytes).map_err(|e| anyhow!("invalid signing key: {e}"))?;
        let address = eth_address_from_signing_key(&signing_key);
        Ok(Self { signing_key, address, chain_id, gas_price, gas_limit })
    }
}

// ─── App context ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppContext {
    state: Arc<RwLock<SharedState>>,
    signer: Option<Arc<SignerConfig>>,
    rpc: RpcClient,
    contract_address: String,
    persist: Persist,
    batch_tx: broadcast::Sender<BatchEnvelope>,
    /// Triggered by post_notify_tx to wake the event loop for immediate recovery.
    recover_trigger: Arc<tokio::sync::Notify>,
}

/// Everything required to construct a per-pool `AppContext` and spawn its WS
/// event loop. Shared by startup (CLI pools) and the runtime `POST /pools`
/// endpoint so both paths build pools identically.
struct PoolBuilder {
    rpc: RpcClient,
    wss_url: String,
    signer: Option<Arc<SignerConfig>>,
    pg_pool: Option<sqlx::PgPool>,
    state_file_base: Option<String>,
    /// When true, derive a unique JSON state file per pool from `state_file_base`.
    /// Always true once multiple pools exist or a runtime registry is enabled.
    derive_state_file: bool,
    max_batches: usize,
    pending_timeout_blocks: u64,
    privacybtc_abi_logs: bool,
    legacy_bundle_topic0: Option<String>,
    note_confirmed_topic0: String,
}

impl PoolBuilder {
    /// Resolve the JSON state file path for a pool (None when using PG / no file).
    fn state_file_for(&self, contract_address: &str) -> Option<String> {
        self.state_file_base.as_ref().map(|base| {
            if !self.derive_state_file {
                base.clone()
            } else {
                // e.g. /path/state.json → /path/state-0xabc....json
                let (stem, ext) = base.rsplit_once('.').unwrap_or((base.as_str(), ""));
                let short = &contract_address[..contract_address.len().min(10)];
                if ext.is_empty() {
                    format!("{stem}-{short}")
                } else {
                    format!("{stem}-{short}.{ext}")
                }
            }
        })
    }

    /// Build the pool context, rebuild its Poseidon tree from the checkpoint, and
    /// spawn the WS event loop. `attach_signer` wires the on-chain confirm signer
    /// (only the primary pool gets it, matching prior single-signer behaviour).
    async fn build(
        &self,
        contract_address: &str,
        start_block: u64,
        attach_signer: bool,
    ) -> AppContext {
        let backend = match &self.pg_pool {
            Some(p) => StateBackend::Pgsql(p.clone()),
            None => StateBackend::Json(self.state_file_for(contract_address)),
        };
        let ck = backend.load(contract_address, start_block).await;
        let (persist_tx, persist_rx) = tokio::sync::watch::channel(std::sync::Arc::new(
            CheckpointSnapshot::from_checkpoint_data(&ck),
        ));
        tokio::spawn(persist_task(backend, contract_address.to_string(), persist_rx));
        let persist = Persist { tx: persist_tx };

        // Rebuild Poseidon tree from checkpoint.
        let mut restored_tree = OrchardCommitmentTree::new();
        let mut restored_cmx_to_pos: HashMap<[u8; 32], u64> = HashMap::new();
        for cmx_be in &ck.cmx_ordered {
            if let Some(pos) = restored_tree.append(*cmx_be) {
                restored_cmx_to_pos.insert(*cmx_be, pos);
            }
        }
        if !ck.cmx_ordered.is_empty() {
            let restored_checkpoint = ck.next_block.saturating_sub(1);
            restored_tree.checkpoint(restored_checkpoint);
            println!(
                "[indexer][{}] rebuilt tree with {} leaves, checkpoint at block {}",
                &contract_address[..10.min(contract_address.len())],
                ck.cmx_ordered.len(),
                restored_checkpoint
            );
        }

        // Rebuild the compliance frozen Indexed-MT by replaying frozen cmx in order.
        let restored_frozen = FrozenImt::from_frozen_values(
            &ck.frozen_cmx.iter().filter_map(fr_from_be_bytes).collect::<Vec<_>>(),
        );

        let shared = Arc::new(RwLock::new(SharedState {
            next_block: ck.next_block,
            latest_seq: ck.latest_seq,
            seen_event_ids: HashSet::new(),
            confirm_seen_ids: HashSet::new(),
            shield_seen_ids: HashSet::new(),
            accounting_seen_ids: HashSet::new(),
            shield_accounting: ck.shield_accounting,
            batches: ck.batches,
            max_batches: self.max_batches,
            tree: restored_tree,
            cmx_to_position: restored_cmx_to_pos,
            cmx_ordered: ck.cmx_ordered,
            pending_notes: HashMap::new(),
            confirmed_cmx: HashSet::new(),
            active_root: ck.active_root,
            pending_timeout_blocks: self.pending_timeout_blocks,
            pending_tx_hashes: ck.pending_tx_hashes,
            bundle_out_cache: HashMap::new(),
            frozen: restored_frozen,
        }));

        let (batch_tx, _) = broadcast::channel::<BatchEnvelope>(256);
        let recover_trigger = Arc::new(tokio::sync::Notify::new());

        let poll_ctx = PollContext {
            rpc: self.rpc.clone(),
            wss_url: self.wss_url.clone(),
            contract_address: contract_address.to_string(),
            privacybtc_abi_logs: self.privacybtc_abi_logs,
            legacy_bundle_topic0: self.legacy_bundle_topic0.clone(),
            note_confirmed_topic0: self.note_confirmed_topic0.clone(),
            shared: Arc::clone(&shared),
            persist: persist.clone(),
            batch_tx: batch_tx.clone(),
            recover_trigger: Arc::clone(&recover_trigger),
            start_block,
            ingest_lock: Arc::new(tokio::sync::Mutex::new(())),
        };
        let addr_label = contract_address.to_string();
        tokio::spawn(async move {
            if let Err(e) = run_event_loop(poll_ctx).await {
                eprintln!("indexer event loop stopped [{addr_label}]: {e:#}");
            }
        });

        AppContext {
            state: shared,
            signer: if attach_signer { self.signer.clone() } else { None },
            rpc: self.rpc.clone(),
            contract_address: contract_address.to_string(),
            persist,
            batch_tx,
            recover_trigger,
        }
    }
}

/// Runtime-mutable multi-pool HTTP state. New pools can be added while the
/// indexer is running via `POST /pools`; reads clone the per-pool context out
/// from under a read lock so handlers never hold the lock across `.await`.
#[derive(Clone)]
struct PoolRegistry {
    pools: Arc<RwLock<HashMap<String, AppContext>>>,
    /// First pool ever added; used as the default when `?pool=` is omitted.
    primary: Arc<RwLock<Option<String>>>,
    builder: Arc<PoolBuilder>,
    registry_file: Option<String>,
    /// Cache of addresses already verified as genuine pERC20 assets (lowercase
    /// 0x). Avoids a repeat `eth_getLogs` on every re-registration attempt.
    verified_pools: Arc<RwLock<HashSet<String>>>,
    /// Cache of per-pool metadata (type/scale/underlying/name/symbol/decimals),
    /// keyed by lowercase 0x address. Populated lazily from the pool's genesis event.
    metadata: Arc<RwLock<HashMap<String, PoolMeta>>>,
}

/// Public pool metadata surfaced by the API. `Issuer` pools are PERC20 assets minted by an
/// issuer; `Wrapped` pools back a shielded balance with a custodied ERC20 (shield/unshield).
#[derive(Clone, Debug, Serialize)]
struct PoolMeta {
    pool: String,
    /// "wrapped" or "issuer".
    pool_type: String,
    /// Underlying ERC20 (wrapped pools only).
    #[serde(skip_serializing_if = "Option::is_none")]
    underlying: Option<String>,
    /// Note-unit → underlying-wei multiplier (wrapped pools only).
    #[serde(skip_serializing_if = "Option::is_none")]
    scale: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decimals: Option<u8>,
}

impl PoolMeta {
    fn from_shield_pool(pool: &str, d: &DecodedShieldPoolCreated) -> Self {
        PoolMeta {
            pool: normalize_hex_0x(pool).to_lowercase(),
            // API value kept as "wrapped" for frontend backward-compatibility (shield pools were
            // formerly WrappedPERC20); the on-chain event is now `ShieldPoolCreated`.
            pool_type: "wrapped".to_string(),
            underlying: Some(format!("0x{}", hex::encode(d.underlying))),
            scale: Some(d.scale.to_string()),
            name: Some(d.name.clone()),
            symbol: Some(d.symbol.clone()),
            decimals: Some(d.decimals),
        }
    }

    fn issuer_minimal(pool: &str) -> Self {
        PoolMeta {
            pool: normalize_hex_0x(pool).to_lowercase(),
            pool_type: "issuer".to_string(),
            underlying: None,
            scale: None,
            name: None,
            symbol: None,
            decimals: None,
        }
    }

    /// Decode `Perc20Created(address issuer, address asset?, string name, string symbol,
    /// uint8 decimals)` data (non-indexed tail) into issuer metadata. Best-effort.
    fn try_from_perc20_created(pool: &str, data_hex: &str) -> Option<Self> {
        let raw = hex::decode(strip_0x(data_hex)).ok()?;
        // Perc20Created indexes the first two address args; data holds (string,string,uint8).
        let tokens = ethabi::decode(
            &[
                ethabi::ParamType::String,
                ethabi::ParamType::String,
                ethabi::ParamType::Uint(8),
            ],
            &raw,
        )
        .ok()?;
        let name = match tokens.first()? {
            ethabi::Token::String(s) => s.clone(),
            _ => return None,
        };
        let symbol = match tokens.get(1)? {
            ethabi::Token::String(s) => s.clone(),
            _ => return None,
        };
        let decimals = match tokens.get(2)? {
            ethabi::Token::Uint(u) => u8::try_from(*u).ok()?,
            _ => return None,
        };
        Some(PoolMeta {
            pool: normalize_hex_0x(pool).to_lowercase(),
            pool_type: "issuer".to_string(),
            underlying: None,
            scale: None,
            name: Some(name),
            symbol: Some(symbol),
            decimals: Some(decimals),
        })
    }
}

impl PoolRegistry {
    /// Add a pool if not already present. Returns `Ok(true)` when newly added and
    /// `Ok(false)` when it already existed (idempotent). When `persist` is set the
    /// pool is recorded in the registry file so it is re-added on restart.
    async fn add_pool(&self, raw_addr: &str, start_block: u64, persist: bool) -> Result<bool> {
        // Pool keys are case-insensitive (Ethereum addresses), so normalise to lowercase.
        let address = normalize_hex_0x(raw_addr).to_lowercase();
        if self.pools.read().await.contains_key(&address) {
            if persist {
                if let Some(path) = &self.registry_file {
                    if let Err(e) = append_pools_registry(path, &address, start_block) {
                        eprintln!("[indexer] failed to update pools registry {path}: {e:#}");
                    }
                }
            }
            return Ok(false);
        }
        // The first pool ever added becomes primary and owns the confirm signer.
        let attach_signer = self.primary.read().await.is_none();
        let ctx = self.builder.build(&address, start_block, attach_signer).await;
        {
            let mut map = self.pools.write().await;
            // Re-check under the write lock to avoid a concurrent double-insert.
            if map.contains_key(&address) {
                return Ok(false);
            }
            map.insert(address.clone(), ctx);
        }
        {
            let mut prim = self.primary.write().await;
            if prim.is_none() {
                *prim = Some(address.clone());
            }
        }
        if persist {
            if let Some(path) = &self.registry_file {
                if let Err(e) = append_pools_registry(path, &address, start_block) {
                    eprintln!("[indexer] failed to persist pools registry {path}: {e:#}");
                }
            }
        }
        println!("[indexer] watching pool {address} (start_block={start_block})");
        Ok(true)
    }

    /// Confirm `pool_lc` (lowercase 0x) is a genuine pERC20 asset by checking it
    /// emitted `Perc20Created(pool,…)` on-chain. Cached after the first success so
    /// repeated registrations don't re-hit the RPC. Already-watched pools are
    /// trivially genuine (we indexed their logs), so they short-circuit to true.
    async fn verify_pool_genuine(&self, pool_lc: &str) -> Result<bool> {
        if self.verified_pools.read().await.contains(pool_lc) {
            return Ok(true);
        }
        if self.pools.read().await.contains_key(pool_lc) {
            return Ok(true);
        }
        // Genuine if it emitted either the issuer (`Perc20Created`) or the shield-pool
        // (`ShieldPoolCreated`) genesis event for itself.
        let genuine = self.builder.rpc.is_perc20_created(pool_lc).await?
            || self.builder.rpc.is_shield_pool_created(pool_lc).await?;
        if genuine {
            self.verified_pools.write().await.insert(pool_lc.to_string());
        }
        Ok(genuine)
    }

    /// Best-effort: fetch + cache pool metadata (issuer or wrapped) from its genesis event.
    /// Returns the cached value when already known. Never fails the caller — metadata is
    /// supplemental; `None` means the genesis event was not found / not decodable.
    async fn ensure_metadata(&self, pool_lc: &str) -> Option<PoolMeta> {
        if let Some(m) = self.metadata.read().await.get(pool_lc).cloned() {
            return Some(m);
        }
        match self.builder.rpc.fetch_pool_metadata(pool_lc).await {
            Ok(Some(meta)) => {
                self.metadata.write().await.insert(pool_lc.to_string(), meta.clone());
                Some(meta)
            }
            Ok(None) => None,
            Err(e) => {
                eprintln!("[indexer] metadata fetch for {pool_lc} failed: {e:#}");
                None
            }
        }
    }

    /// Resolve the target pool from a `?pool=0x...` query param. When `pool` is
    /// None, returns the primary pool (falling back to any pool).
    async fn resolve(&self, pool: Option<&str>) -> Result<AppContext, (StatusCode, String)> {
        let map = self.pools.read().await;
        match pool {
            Some(addr) => {
                let key = normalize_hex_0x(addr).to_lowercase();
                map.get(&key)
                    .cloned()
                    .ok_or_else(|| (StatusCode::NOT_FOUND, format!("unknown pool: {addr}")))
            }
            None => {
                if let Some(p) = self.primary.read().await.clone() {
                    if let Some(c) = map.get(&p) {
                        return Ok(c.clone());
                    }
                }
                map.values().next().cloned().ok_or_else(|| {
                    (StatusCode::INTERNAL_SERVER_ERROR, "no pools configured".to_owned())
                })
            }
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
struct PoolsRegistryFile {
    pools: Vec<PoolRegistryEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
struct PoolRegistryEntry {
    address: String,
    #[serde(default)]
    start_block: u64,
}

fn load_pools_registry(path: &str) -> Vec<PoolRegistryEntry> {
    match std::fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str::<PoolsRegistryFile>(&raw)
            .map(|f| f.pools)
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

fn append_pools_registry(path: &str, address: &str, start_block: u64) -> Result<()> {
    let mut reg = PoolsRegistryFile { pools: load_pools_registry(path) };
    let norm = normalize_hex_0x(address);
    let mut changed = false;
    if let Some(entry) = reg.pools.iter_mut().find(|e| normalize_hex_0x(&e.address) == norm) {
        if entry.address != norm {
            entry.address = norm.clone();
            changed = true;
        }
        if start_block != 0 && entry.start_block != start_block {
            entry.start_block = start_block;
            changed = true;
        }
    } else {
        reg.pools.push(PoolRegistryEntry { address: norm, start_block });
        changed = true;
    }
    if !changed {
        return Ok(());
    }
    let json = serde_json::to_string_pretty(&reg)?;
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, &json)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

// ─── HTTP request/response types ─────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct BatchesQuery {
    after_seq: Option<u64>,
    /// Contract address of the pool to query. Omit to use the primary pool.
    pool: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MerklePathQuery {
    /// cmx in hex (with or without 0x prefix).
    cmx: String,
    /// Commitment tree checkpoint (Ethereum block number).
    /// Defaults to the latest checkpoint if omitted.
    checkpoint: Option<u64>,
    /// Contract address of the pool to query. Omit to use the primary pool.
    pool: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ConfirmRequest {
    /// cmx hex (with or without 0x prefix).
    cmx_hex: String,
    /// sharedSecret (KA^Orchard ECDH output) hex — the ack_hash preimage.
    ack_preimage_hex: String,
    /// New Orchard commitment tree root hex, computed by the client after
    /// the indexer appended this cmx.
    new_root_hex: String,
}

#[derive(Debug, Serialize)]
struct ConfirmResponse {
    /// Submitted Ethereum transaction hash (0x-prefixed hex).
    tx_hash: String,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    next_block: u64,
    latest_seq: u64,
    cached_batches: usize,
    pending_notes: usize,
    confirmed_notes: usize,
    /// active_root from on-chain NoteConfirmed events (LE hex). This is what /root returns.
    active_root_hex: Option<String>,
    /// Local Poseidon tree root (LE hex). Should equal active_root if tree is complete.
    local_tree_root_hex: Option<String>,
    tree_size: u64,
    /// Pool contract address this indexer instance is watching (0x-prefixed lowercase).
    /// Allows clients querying multiple indexer instances to identify which pool each serves.
    pool_address: String,
}

#[derive(Debug, Serialize)]
struct ShieldStatsResponse {
    pools: Vec<ShieldPoolStats>,
}

#[derive(Debug, Serialize)]
struct ShieldPoolStats {
    pool_address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<PoolMeta>,
    total_shielded_units: String,
    total_shielded_wei: String,
    total_unshielded_units: String,
    total_unshielded_wei: String,
    current_shielded_units: String,
    current_shielded_wei: String,
}

#[derive(Debug, Serialize)]
struct RootResponse {
    root_hex: Option<String>,
    tree_size: u64,
}

// ─── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    // Load a local `.env` (if present) before parsing, so CLI flags with `env = …`
    // pick up values from the environment / docker-compose env_file.
    let _ = dotenvy::dotenv();
    let cli = Cli::parse();
    let bind: SocketAddr = cli.bind.parse().context("invalid --bind address")?;

    let signer = match &cli.signer_key {
        Some(key) => {
            let cfg = SignerConfig::from_hex_key(key, cli.chain_id, cli.gas_price, cli.gas_limit_confirm)?;
            let addr_hex = hex::encode(cfg.address);
            println!("indexer signer account: 0x{addr_hex}");
            Some(Arc::new(cfg))
        }
        None => {
            println!("no --signer-key provided; /confirm will validate but not relay on-chain");
            None
        }
    };

    let rpc = RpcClient::new(cli.rpc_url.clone());
    let note_confirmed = cli
        .confirm_topic0
        .as_deref()
        .map(normalize_hex_0x)
        .unwrap_or_else(note_confirmed_topic0_hex);

    // ── Persistence backend: PostgreSQL (queryable) if --database-url is set, else JSON ──
    let pg_pool: Option<sqlx::PgPool> = match &cli.database_url {
        Some(url) => {
            let pool = sqlx::PgPool::connect(url).await.context("connect PostgreSQL")?;
            sqlx::migrate!("./migrations").run(&pool).await.context("run migrations")?;
            println!("[indexer] state backend: PostgreSQL (migrations applied)");
            Some(pool)
        }
        None => {
            println!("[indexer] state backend: JSON file");
            None
        }
    };

    // ── Pool factory: shared config used by both CLI pools and POST /pools ────
    let wss_url = cli.ws_url.clone().unwrap_or_else(|| {
        cli.rpc_url
            .replacen("https://", "wss://", 1)
            .replacen("http://", "ws://", 1)
    });
    // Derive per-pool state files when there is more than one pool, or when the
    // runtime registry is enabled (so a single CLI pool and runtime pools never
    // collide on the same file).
    let derive_state_file = cli.contract_address.len() > 1 || cli.pools_registry.is_some();
    let builder = Arc::new(PoolBuilder {
        rpc: rpc.clone(),
        wss_url,
        signer: signer.clone(),
        pg_pool: pg_pool.clone(),
        state_file_base: cli.state_file.clone(),
        derive_state_file,
        max_batches: cli.max_batches_in_memory,
        pending_timeout_blocks: cli.pending_timeout_blocks,
        privacybtc_abi_logs: cli.privacybtc_abi_logs,
        legacy_bundle_topic0: cli.legacy_bundle_topic0.as_deref().map(normalize_hex_0x),
        note_confirmed_topic0: note_confirmed.clone(),
    });

    let registry = PoolRegistry {
        pools: Arc::new(RwLock::new(HashMap::new())),
        primary: Arc::new(RwLock::new(None)),
        builder,
        registry_file: cli.pools_registry.clone(),
        verified_pools: Arc::new(RwLock::new(HashSet::new())),
        metadata: Arc::new(RwLock::new(HashMap::new())),
    };

    // 1) CLI pools (the first one becomes primary and owns the confirm signer).
    for raw_addr in &cli.contract_address {
        if let Err(e) = registry.add_pool(raw_addr, cli.start_block, false).await {
            eprintln!("[indexer] add CLI pool {raw_addr} failed: {e:#}");
        }
    }
    // 2) Pools registered at runtime in a previous run.
    if let Some(path) = &cli.pools_registry {
        for entry in load_pools_registry(path) {
            let sb = if entry.start_block == 0 { cli.start_block } else { entry.start_block };
            if let Err(e) = registry.add_pool(&entry.address, sb, false).await {
                eprintln!("[indexer] re-add registry pool {} failed: {e:#}", entry.address);
            }
        }
        println!("[indexer] pools registry: {path}");
    }
    // 3) Auto-discovery: continuously scan `Perc20Created` chain-wide and register
    //    matching pools automatically (primary path; POST /pools stays as a manual
    //    fallback for e.g. pools created before --start-block).
    if cli.discover_pools {
        let issuer_topics: Vec<String> = cli
            .discover_issuer
            .iter()
            .filter(|a| parse_address20(a).is_some())
            .map(|a| address_to_topic(a))
            .collect();
        let scope = if issuer_topics.is_empty() {
            "all issuers".to_string()
        } else {
            format!("{} issuer(s)", issuer_topics.len())
        };
        println!(
            "[indexer] pool auto-discovery ON (Perc20Created, {scope}, poll {}s, from block {})",
            cli.discover_poll_secs, cli.start_block
        );
        tokio::spawn(pool_discovery_task(
            registry.clone(),
            rpc.clone(),
            perc20_created_topic0(),
            issuer_topics,
            cli.start_block,
            cli.discover_poll_secs,
        ));
    } else if registry.pools.read().await.is_empty() {
        println!(
            "[indexer] no pools configured yet — idle until a pool is registered via POST /pools"
        );
    }

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/status", get(status))
        .route("/batches", get(get_batches))
        .route("/batches/stream", get(get_batches_stream))
        .route("/root", get(get_root))
        .route("/merkle_path", get(get_merkle_path))
        .route("/note", get(get_note))
        .route("/tx", get(get_tx))
        .route("/confirm", post(post_confirm))
        .route("/notify_tx", post(post_notify_tx))
        .route("/pools", get(list_pools).post(register_pool))
        .route("/pool_meta", get(get_pool_meta))
        .route("/shield/stats", get(get_shield_stats))
        .route("/frozen_root", get(get_frozen_root))
        .route("/frozen_witness", get(get_frozen_witness))
        .route("/frozen", post(post_frozen))
        .layer(build_cors_layer())
        .with_state(registry);

    println!("privacybtc-indexer listening on http://{bind}");
    for t in note_added_topic0_alternatives() {
        println!("[indexer] NoteAdded topic0: {t}");
    }
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// topic0 of `Perc20Created(address,address,string,string,uint8)` (the pERC20
/// asset-creation event), used to verify a runtime-registered pool is genuine.
fn perc20_created_topic0() -> String {
    let hash = Keccak256::digest(b"Perc20Created(address,address,string,string,uint8)");
    format!("0x{}", hex::encode(hash))
}

/// 20-byte address → 32-byte left-padded log topic (for indexed address filters).
fn address_to_topic(addr: &str) -> String {
    let a = normalize_hex_0x(addr);
    format!("0x{:0>64}", a.trim_start_matches("0x").to_lowercase())
}

/// 32-byte indexed-address topic → 20-byte 0x address (last 20 bytes).
fn topic_to_address(topic: &str) -> Option<String> {
    let h = topic.trim_start_matches("0x");
    if h.len() < 40 {
        return None;
    }
    Some(format!("0x{}", &h[h.len() - 40..].to_lowercase()))
}

/// Background task: poll `Perc20Created` chain-wide and auto-register pools.
/// Re-scans from `start_block` on boot; `add_pool` is idempotent so already-known
/// pools are skipped. The cursor only advances past fully-scanned ranges, so a
/// transient RPC error is retried on the next tick.
async fn pool_discovery_task(
    reg: PoolRegistry,
    rpc: RpcClient,
    topic0: String,
    issuer_topics: Vec<String>,
    start_block: u64,
    poll_secs: u64,
) {
    const CHUNK: u64 = 50_000;
    let mut from = start_block;
    loop {
        if let Ok(head) = rpc.block_number().await {
            let mut lo = from;
            while lo <= head {
                let hi = (lo + CHUNK - 1).min(head);
                match rpc.fetch_created_pools(lo, hi, &topic0, &issuer_topics).await {
                    Ok(found) => {
                        for (pool, block) in found {
                            match reg.add_pool(&pool, block, false).await {
                                Ok(true) => {
                                    println!("[indexer] auto-discovered pool {pool} (block {block})")
                                }
                                Ok(false) => {}
                                Err(e) => {
                                    eprintln!("[indexer] auto-discover add_pool {pool} failed: {e:#}")
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[indexer] discovery getLogs [{lo},{hi}] failed: {e:#}");
                        break; // leave `lo` here so we retry this range next tick
                    }
                }
                lo = hi + 1;
            }
            from = lo;
        }
        tokio::time::sleep(std::time::Duration::from_secs(poll_secs.max(1))).await;
    }
}

/// Same env as relayer: comma-separated origins in `PRIVACYBTC_CORS_ORIGINS`.
/// Defaults to Vite dev server on localhost and 127.0.0.1.
fn build_cors_layer() -> CorsLayer {
    let origins_str = std::env::var("PRIVACYBTC_CORS_ORIGINS").unwrap_or_else(|_| {
        "http://localhost:5173,http://127.0.0.1:5173".to_string()
    });
    let origins: Vec<axum::http::HeaderValue> = origins_str
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(tower_http::cors::Any)
}

// ─── HTTP handlers ────────────────────────────────────────────────────────────

async fn healthz() -> &'static str {
    "ok"
}

/// `GET /pools` — list the pools currently being watched, the primary pool, and any known
/// per-pool metadata (type/scale/underlying/name/symbol/decimals). Metadata is fetched lazily
/// and best-effort; pools without a decodable genesis event simply omit it.
async fn list_pools(State(reg): State<PoolRegistry>) -> Json<serde_json::Value> {
    let addrs: Vec<String> = reg.pools.read().await.keys().cloned().collect();
    let primary = reg.primary.read().await.clone();
    let mut metas: Vec<PoolMeta> = Vec::with_capacity(addrs.len());
    for a in &addrs {
        if let Some(m) = reg.ensure_metadata(a).await {
            metas.push(m);
        }
    }
    Json(serde_json::json!({ "pools": addrs, "primary": primary, "metadata": metas }))
}

#[derive(Debug, Deserialize)]
struct PoolMetaQuery {
    pool: String,
}

/// `GET /pool_meta?pool=0x...` — metadata for a single pool (lazy fetch + cache).
async fn get_pool_meta(
    State(reg): State<PoolRegistry>,
    Query(q): Query<PoolMetaQuery>,
) -> Result<Json<PoolMeta>, (StatusCode, String)> {
    if parse_address20(&q.pool).is_none() {
        return Err((StatusCode::BAD_REQUEST, "pool must be a 20-byte hex address".to_owned()));
    }
    let key = normalize_hex_0x(&q.pool).to_lowercase();
    reg.ensure_metadata(&key)
        .await
        .map(Json)
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no metadata for pool {}", q.pool)))
}

/// `GET /shield/stats[?pool=0x...]` — event-derived ERC20Shield accounting.
async fn get_shield_stats(
    State(reg): State<PoolRegistry>,
    Query(q): Query<SimplePoolQuery>,
) -> Result<Json<ShieldStatsResponse>, (StatusCode, String)> {
    let targets: Vec<(String, AppContext)> = match q.pool.as_deref() {
        Some(pool) => {
            let ctx = reg.resolve(Some(pool)).await?;
            vec![(ctx.contract_address.clone(), ctx)]
        }
        None => reg
            .pools
            .read()
            .await
            .iter()
            .map(|(pool, ctx)| (pool.clone(), ctx.clone()))
            .collect(),
    };

    let mut pools = Vec::with_capacity(targets.len());
    for (pool, ctx) in targets {
        let stats = { ctx.state.read().await.shield_accounting };
        let metadata = reg.ensure_metadata(&pool).await;
        pools.push(ShieldPoolStats {
            pool_address: pool,
            metadata,
            total_shielded_units: stats.total_shielded_units.to_string(),
            total_shielded_wei: stats.total_shielded_wei.to_string(),
            total_unshielded_units: stats.total_unshielded_units.to_string(),
            total_unshielded_wei: stats.total_unshielded_wei.to_string(),
            current_shielded_units: stats.current_shielded_units().to_string(),
            current_shielded_wei: stats.current_shielded_wei().to_string(),
        });
    }

    pools.sort_by(|a, b| a.pool_address.cmp(&b.pool_address));
    Ok(Json(ShieldStatsResponse { pools }))
}

#[derive(Debug, Deserialize)]
struct RegisterPoolRequest {
    /// 20-byte pool contract address (0x-prefixed).
    contract_address: String,
    /// Block to start scanning from (typically the pool's deploy block). When
    /// omitted/0 the indexer falls back to its global `--start-block`.
    #[serde(default)]
    start_block: u64,
}

/// `POST /pools` — register a pool at runtime. Idempotent: returns 201 when the
/// pool is newly added and 200 when it was already being watched. Gated by
/// on-chain verification that the address is a genuine pERC20 (it emitted
/// `Perc20Created`); no shared secret is required.
async fn register_pool(
    State(reg): State<PoolRegistry>,
    Json(req): Json<RegisterPoolRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    if parse_address20(&req.contract_address).is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "contract_address must be a 20-byte hex address".to_owned(),
        ));
    }
    // The only gate for runtime registration: the address must be a genuine pERC20
    // asset — it emitted `Perc20Created(self,…)` on-chain (factory-deployed or
    // standalone, both conformant). This needs no shared secret, so the browser
    // can register pools directly; verified addresses are cached.
    let addr_lc = normalize_hex_0x(&req.contract_address).to_lowercase();
    match reg.verify_pool_genuine(&addr_lc).await {
        Ok(true) => {}
        Ok(false) => {
            return Err((
                StatusCode::FORBIDDEN,
                "address is not a pERC20 asset (no Perc20Created / ShieldPoolCreated event on-chain)".to_owned(),
            ))
        }
        Err(e) => {
            return Err((
                StatusCode::BAD_GATEWAY,
                format!("on-chain verification failed: {e:#}"),
            ))
        }
    }
    let added = reg
        .add_pool(&req.contract_address, req.start_block, true)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("add_pool failed: {e:#}")))?;
    let address = normalize_hex_0x(&req.contract_address);
    let status = if added { StatusCode::CREATED } else { StatusCode::OK };
    Ok((
        status,
        Json(serde_json::json!({
            "pool": address,
            "added": added,
            "start_block": req.start_block,
        })),
    ))
}

#[derive(Debug, Deserialize)]
struct SimplePoolQuery {
    pool: Option<String>,
}

async fn status(
    State(reg): State<PoolRegistry>,
    Query(q): Query<SimplePoolQuery>,
) -> Result<Json<StatusResponse>, (StatusCode, String)> {
    let ctx = reg.resolve(q.pool.as_deref()).await?;
    let s = ctx.state.read().await;
    let local_tree_root_hex = s.tree.latest_root().map(hex::encode);
    Ok(Json(StatusResponse {
        next_block: s.next_block,
        latest_seq: s.latest_seq,
        cached_batches: s.batches.len(),
        pending_notes: s.pending_notes.len(),
        confirmed_notes: s.confirmed_cmx.len(),
        active_root_hex: http_root_hex(&s),
        local_tree_root_hex,
        tree_size: s.tree.size(),
        pool_address: ctx.contract_address.clone(),
    }))
}

async fn get_batches(
    State(reg): State<PoolRegistry>,
    Query(q): Query<BatchesQuery>,
) -> Result<Json<Vec<BatchEnvelope>>, (StatusCode, String)> {
    let ctx = reg.resolve(q.pool.as_deref()).await?;
    let after = q.after_seq.unwrap_or(0);
    let s = ctx.state.read().await;
    let out = s
        .batches
        .iter()
        .filter(|b| b.seq > after)
        .cloned()
        .collect::<Vec<_>>();
    Ok(Json(out))
}

/// SSE endpoint: streams BatchEnvelopes to the client as they arrive.
///
/// 1. Subscribes to the broadcast channel BEFORE reading history (no race).
/// 2. Sends all historical batches with seq > after_seq first.
/// 3. Then streams live batches from the broadcast channel.
///
/// The browser's EventSource will send `Last-Event-ID` on reconnect, so the
/// client automatically resumes without missing any batches.
async fn get_batches_stream(
    State(reg): State<PoolRegistry>,
    Query(q): Query<BatchesQuery>,
    headers: HeaderMap,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>, (StatusCode, String)> {
    let ctx = reg.resolve(q.pool.as_deref()).await?;

    // Determine after_seq: Last-Event-ID (reconnect) takes priority over query param.
    let after_seq = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .or(q.after_seq)
        .unwrap_or(0);

    // Subscribe FIRST so no live batch is missed while we read history.
    let live_rx = ctx.batch_tx.subscribe();

    // Collect historical batches (seq > after_seq).
    let historical: Vec<BatchEnvelope> = {
        let s = ctx.state.read().await;
        s.batches.iter().filter(|b| b.seq > after_seq).cloned().collect()
    };
    let max_hist_seq = historical.last().map(|b| b.seq).unwrap_or(after_seq);

    // Build SSE event from a BatchEnvelope.
    fn to_event(b: BatchEnvelope) -> Result<Event, Infallible> {
        let id = b.seq.to_string();
        let data = serde_json::to_string(&b).unwrap_or_default();
        Ok(Event::default().id(id).data(data))
    }

    // Historical stream followed by live stream (deduped by seq).
    let hist_stream = stream::iter(historical).map(to_event);
    let live_stream = BroadcastStream::new(live_rx)
        .filter_map(|r| async move { r.ok() })
        .filter(move |b| futures_util::future::ready(b.seq > max_hist_seq))
        .map(to_event);

    Ok(Sse::new(hist_stream.chain(live_stream))
        .keep_alive(KeepAlive::default()))
}

async fn get_root(
    State(reg): State<PoolRegistry>,
    Query(q): Query<SimplePoolQuery>,
) -> Result<Json<RootResponse>, (StatusCode, String)> {
    let ctx = reg.resolve(q.pool.as_deref()).await?;
    let s = ctx.state.read().await;
    Ok(Json(RootResponse {
        root_hex: http_root_hex(&s),
        tree_size: s.tree.size(),
    }))
}

#[derive(Debug, Deserialize)]
struct NoteLookupQuery {
    /// cmx in hex (with or without 0x prefix).
    cmx: String,
    /// Contract address of the pool to query. Omit to use the primary pool.
    pool: Option<String>,
}

/// Return the full `NoteAdded` payload for one cmx (enc_ciphertext, epk, nf_old).
/// Used by the prover to refresh wallet note fields before witness construction.
async fn get_note(
    State(reg): State<PoolRegistry>,
    Query(q): Query<NoteLookupQuery>,
) -> Result<Json<OrchardIndexedAbiNote>, (StatusCode, String)> {
    let ctx = reg.resolve(q.pool.as_deref()).await?;
    let cmx = parse_hex32(&q.cmx)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid cmx hex".to_owned()))?;

    let s = ctx.state.read().await;
    for batch in s.batches.iter().rev() {
        for note in &batch.batch.abi_notes {
            if note.cmx == cmx {
                return Ok(Json(note.clone()));
            }
        }
    }
    Err((StatusCode::NOT_FOUND, "cmx not found in indexer batches".to_owned()))
}

#[derive(Debug, Deserialize)]
struct TxLookupQuery {
    /// Transaction hash in hex (with or without 0x prefix).
    hash: String,
    /// Contract address of the pool to query. Omit to search EVERY registered pool
    /// (so the explorer finds a tx regardless of which asset/pool it belongs to).
    pool: Option<String>,
}

/// Return every ciphertext note added by a single transaction, keyed by tx hash.
/// Powers the ciphertext explorer's "search by tx hash" so the client doesn't have
/// to download the whole pool's batch history and filter locally. One tx can carry
/// multiple notes (e.g. a transfer's recipient + change note), so this returns a list.
/// With no `pool` param it scans all registered pools — a hash for any pool resolves
/// rather than falling back to the primary pool and reporting a false "not found".
async fn get_tx(
    State(reg): State<PoolRegistry>,
    Query(q): Query<TxLookupQuery>,
) -> Result<Json<Vec<OrchardIndexedAbiNote>>, (StatusCode, String)> {
    let want = normalize_hex_0x(&q.hash).to_lowercase();
    let contexts: Vec<AppContext> = match q.pool.as_deref() {
        Some(addr) => vec![reg.resolve(Some(addr)).await?],
        None => reg.pools.read().await.values().cloned().collect(),
    };

    let mut out: Vec<OrchardIndexedAbiNote> = Vec::new();
    let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    for ctx in contexts {
        let s = ctx.state.read().await;
        for batch in s.batches.iter() {
            for note in &batch.batch.abi_notes {
                if normalize_hex_0x(&note.tx_hash).to_lowercase() == want && seen.insert(note.cmx) {
                    out.push(note.clone());
                }
            }
        }
    }
    Ok(Json(out))
}

async fn get_merkle_path(
    State(reg): State<PoolRegistry>,
    Query(q): Query<MerklePathQuery>,
) -> Result<Json<privacy_core::commitment_tree::OrchardMerklePath>, (StatusCode, String)> {
    let ctx = reg.resolve(q.pool.as_deref()).await?;
    let cmx = parse_hex32(&q.cmx)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid cmx hex".to_owned()))?;

    let s = ctx.state.read().await;
    let &position = s
        .cmx_to_position
        .get(&cmx)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "cmx not found in tree".to_owned()))?;

    let checkpoint = match q.checkpoint {
        Some(c) => c,
        None => s
            .tree
            .latest_checkpoint_id()
            .ok_or_else(|| (StatusCode::NOT_FOUND, "no checkpoint available".to_owned()))?,
    };

    s.tree
        .merkle_path(position, checkpoint)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "merkle path not available for this position/checkpoint".to_owned()))
        .map(Json)
}

// ─── Compliance frozen Indexed-MT (rt_frozen) ────────────────────────────────
#[derive(Serialize)]
struct FrozenRootResponse {
    /// `rt_frozen` as 0x-prefixed little-endian 32-byte hex (prover `parse_fr_le`).
    /// Set this on-chain via `setFrozenRoot(rt_frozen)`.
    root_hex: String,
    /// Number of frozen `cmx` (excludes the `{0,0}` sentinel).
    frozen_count: usize,
}

/// `GET /frozen_root` — current compliance root for a pool's blacklist.
async fn get_frozen_root(
    State(reg): State<PoolRegistry>,
    Query(q): Query<SimplePoolQuery>,
) -> Result<Json<FrozenRootResponse>, (StatusCode, String)> {
    let ctx = reg.resolve(q.pool.as_deref()).await?;
    let s = ctx.state.read().await;
    Ok(Json(FrozenRootResponse {
        root_hex: fr_to_le_hex(s.frozen.root()),
        frozen_count: s.frozen.len().saturating_sub(1),
    }))
}

#[derive(Serialize)]
struct FrozenWitnessResponse {
    /// Bracketing low-leaf and its `next` pointer (LE hex).
    low_val: String,
    low_next_val: String,
    /// 20 Merkle siblings + path bits (LE hex), matching `FrozenCmxNonMember`.
    siblings: Vec<String>,
    path_bits: Vec<String>,
    /// The root this witness opens to (== `/frozen_root`).
    root_hex: String,
}

/// `GET /frozen_witness?cmx=` — non-membership witness for `cmx`, or 409 if frozen.
async fn get_frozen_witness(
    State(reg): State<PoolRegistry>,
    Query(q): Query<NoteLookupQuery>,
) -> Result<Json<FrozenWitnessResponse>, (StatusCode, String)> {
    let ctx = reg.resolve(q.pool.as_deref()).await?;
    let cmx_be = parse_hex32(&q.cmx)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid cmx hex".to_owned()))?;
    let cmx = fr_from_be_bytes(&cmx_be).ok_or_else(|| {
        (StatusCode::BAD_REQUEST, "cmx is not a canonical field element".to_owned())
    })?;
    let s = ctx.state.read().await;
    let w = s.frozen.non_membership_witness(cmx).ok_or_else(|| {
        (StatusCode::CONFLICT, "cmx is frozen; no non-membership witness".to_owned())
    })?;
    Ok(Json(FrozenWitnessResponse {
        low_val: fr_to_le_hex(w.low_val),
        low_next_val: fr_to_le_hex(w.low_next_val),
        siblings: w.siblings.iter().map(|f| fr_to_le_hex(*f)).collect(),
        path_bits: w.path_bits.iter().map(|f| fr_to_le_hex(*f)).collect(),
        root_hex: fr_to_le_hex(s.frozen.root()),
    }))
}

#[derive(Deserialize)]
struct FreezeRequest {
    /// `cmx` to freeze, big-endian hex (with or without `0x`).
    cmx_hex: String,
}

/// `POST /frozen` (admin) — freeze a `cmx`: splice it into the sorted IMT
/// (update predecessor's `next` + append) and return the new root. Idempotent.
async fn post_frozen(
    State(reg): State<PoolRegistry>,
    headers: HeaderMap,
    Query(q): Query<SimplePoolQuery>,
    Json(req): Json<FreezeRequest>,
) -> Result<Json<FrozenRootResponse>, (StatusCode, String)> {
    let ctx = reg.resolve(q.pool.as_deref()).await?;
    let cmx_be = parse_hex32(&req.cmx_hex)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid cmx_hex".to_owned()))?;
    let cmx = fr_from_be_bytes(&cmx_be).ok_or_else(|| {
        (StatusCode::BAD_REQUEST, "cmx is not a canonical field element".to_owned())
    })?;
    let resp = {
        let mut s = ctx.state.write().await;
        s.frozen.insert(cmx); // no-op if already frozen or cmx == 0
        let resp = FrozenRootResponse {
            root_hex: fr_to_le_hex(s.frozen.root()),
            frozen_count: s.frozen.len().saturating_sub(1),
        };
        ctx.persist.notify(&s); // persist the updated frozen set
        resp
    };
    Ok(Json(resp))
}

async fn post_confirm(
    State(reg): State<PoolRegistry>,
    Query(q): Query<SimplePoolQuery>,
    Json(req): Json<ConfirmRequest>,
) -> Result<Json<ConfirmResponse>, (StatusCode, String)> {
    let ctx = reg.resolve(q.pool.as_deref()).await?;
    let cmx = parse_hex32(&req.cmx_hex)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid cmx_hex".to_owned()))?;
    let ack_preimage = parse_hex32(&req.ack_preimage_hex)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid ack_preimage_hex".to_owned()))?;
    let new_root = parse_hex32(&req.new_root_hex)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid new_root_hex".to_owned()))?;

    // Verify preimage against stored ack_hash.
    {
        let s = ctx.state.read().await;
        let pending = s
            .pending_notes
            .get(&cmx)
            .ok_or_else(|| (StatusCode::NOT_FOUND, "cmx not pending".to_owned()))?;

        let computed_hash: [u8; 32] = Keccak256::digest(ack_preimage).into();
        if computed_hash != pending.ack_hash {
            return Err((StatusCode::FORBIDDEN, "ack_preimage does not match ack_hash".to_owned()));
        }
    }

    // A signer is required to relay on-chain.  Without one the endpoint is not
    // operational — returning a fake tx_hash and advancing local state would
    // leave the indexer out of sync with the chain.
    let signer = ctx.signer.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "indexer has no --signer-key configured; cannot relay confirmReceipt on-chain".to_owned(),
        )
    })?;

    let nonce = ctx
        .rpc
        .get_transaction_count(&format!("0x{}", hex::encode(signer.address)))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let calldata = encode_confirm_receipt_calldata(&cmx, &ack_preimage, &new_root);
    let raw_tx = build_and_sign_raw_tx(
        nonce,
        signer.gas_price,
        signer.gas_limit,
        &ctx.contract_address,
        0u64,
        &calldata,
        signer.chain_id,
        &signer.signing_key,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let tx_hash = ctx
        .rpc
        .send_raw_transaction(&raw_tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Local state is updated by the poll loop when it observes the NoteConfirmed
    // event on-chain — do NOT update it here to avoid diverging from chain state.

    Ok(Json(ConfirmResponse { tx_hash }))
}

// ─── POST /notify_tx ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct NotifyTxRequest {
    /// Hex-encoded transaction hash (with or without 0x prefix).
    tx_hash: String,
}

/// Called by the relayer after every successful `eth_sendRawTransaction`.
/// The indexer queues the tx_hash; on WS reconnect, any still-pending hashes
/// are recovered by fetching their receipts and replaying the logs.
async fn post_notify_tx(
    State(reg): State<PoolRegistry>,
    Query(q): Query<SimplePoolQuery>,
    Json(req): Json<NotifyTxRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let ctx = reg.resolve(q.pool.as_deref()).await?;
    let tx_hash = normalize_hex_0x(&req.tx_hash);
    let mut s = ctx.state.write().await;
    if !s.pending_tx_hashes.iter().any(|h| h == &tx_hash) {
        s.pending_tx_hashes.push_back(tx_hash.clone());
        while s.pending_tx_hashes.len() > 1000 {
            s.pending_tx_hashes.pop_front();
        }
    }
    println!("[indexer] notify_tx queued: {tx_hash} (pending={} hashes)", s.pending_tx_hashes.len());
    // Persist immediately so the queue survives a restart.
    ctx.persist.notify(&s);
    drop(s);
    // Signal the event loop to run immediate HTTP recovery — don't rely solely on
    // the next WS reconnect. This ensures all logs from multi-event txs (e.g.
    // NoteAdded × N + NoteConfirmed × N in complete()) are processed even if the
    // WS delivers them partially before dropping.
    ctx.recover_trigger.notify_one();
    Ok(StatusCode::OK)
}

// ─── Checkpoint persistence ───────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct IndexerCheckpoint {
    next_block: u64,
    #[serde(default)]
    cmx_leaves_hex: Vec<String>,
    #[serde(default)]
    active_root_hex: Option<String>,
    #[serde(default)]
    latest_seq: u64,
    #[serde(default)]
    batches: Vec<BatchEnvelope>,
    /// Tx hashes notified by relayer but not yet confirmed via WS event.
    #[serde(default)]
    pending_tx_hashes: Vec<String>,
    /// Frozen `cmx` (BE hex) in insertion order — replayed to rebuild the frozen IMT.
    #[serde(default)]
    frozen_cmx_hex: Vec<String>,
    /// Event-derived ERC20Shield aggregate accounting.
    #[serde(default)]
    shield_accounting: ShieldAccounting,
}

/// Loaded result from a checkpoint file.
struct CheckpointData {
    next_block: u64,
    cmx_ordered: Vec<[u8; 32]>,
    active_root: Option<[u8; 32]>,
    latest_seq: u64,
    batches: VecDeque<BatchEnvelope>,
    pending_tx_hashes: VecDeque<String>,
    frozen_cmx: Vec<[u8; 32]>,
    shield_accounting: ShieldAccounting,
}

fn load_checkpoint(path: &str, start_block: u64) -> CheckpointData {
    match std::fs::read_to_string(path) {
        Ok(raw) => match serde_json::from_str::<IndexerCheckpoint>(&raw) {
            Ok(ck) => {
                let resumed = ck.next_block.max(start_block);
                let cmx_ordered: Vec<[u8; 32]> = ck
                    .cmx_leaves_hex
                    .iter()
                    .filter_map(|h| {
                        let bytes = hex::decode(h.trim_start_matches("0x")).ok()?;
                        if bytes.len() != 32 {
                            return None;
                        }
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        Some(arr)
                    })
                    .collect();
                let active_root: Option<[u8; 32]> =
                    ck.active_root_hex.as_deref().and_then(|h| {
                        let bytes = hex::decode(h.trim_start_matches("0x")).ok()?;
                        if bytes.len() != 32 {
                            return None;
                        }
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        Some(arr)
                    });
                println!(
                    "[indexer] resumed from checkpoint {path}: next_block={resumed}, leaves={}",
                    cmx_ordered.len()
                );
                let batches = VecDeque::from(ck.batches);
                let pending_tx_hashes = VecDeque::from(ck.pending_tx_hashes);
                let frozen_cmx: Vec<[u8; 32]> = ck
                    .frozen_cmx_hex
                    .iter()
                    .filter_map(|h| {
                        let bytes = hex::decode(h.trim_start_matches("0x")).ok()?;
                        if bytes.len() != 32 {
                            return None;
                        }
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        Some(arr)
                    })
                    .collect();
                CheckpointData { next_block: resumed, cmx_ordered, active_root, latest_seq: ck.latest_seq, batches, pending_tx_hashes, frozen_cmx, shield_accounting: ck.shield_accounting }
            }
            Err(e) => {
                eprintln!(
                    "[indexer] checkpoint parse error ({e}), starting from block {start_block}"
                );
                CheckpointData {
                    next_block: start_block,
                    cmx_ordered: vec![],
                    active_root: None,
                    latest_seq: 0,
                    batches: VecDeque::new(),
                    pending_tx_hashes: VecDeque::new(),
                    frozen_cmx: vec![],
                    shield_accounting: ShieldAccounting::default(),
                }
            }
        },
        Err(_) => CheckpointData {
            next_block: start_block,
            cmx_ordered: vec![],
            active_root: None,
            latest_seq: 0,
            batches: VecDeque::new(),
            pending_tx_hashes: VecDeque::new(),
            frozen_cmx: vec![],
            shield_accounting: ShieldAccounting::default(),
        },
    }
}

fn save_checkpoint(
    path: &str,
    next_block: u64,
    cmx_ordered: &[[u8; 32]],
    active_root: Option<[u8; 32]>,
    latest_seq: u64,
    batches: &[BatchEnvelope],
    pending_tx_hashes: &[String],
    frozen_cmx: &[[u8; 32]],
    shield_accounting: ShieldAccounting,
) {
    let ck = IndexerCheckpoint {
        next_block,
        cmx_leaves_hex: cmx_ordered.iter().map(hex::encode).collect(),
        active_root_hex: active_root.map(hex::encode),
        latest_seq,
        batches: batches.to_vec(),
        pending_tx_hashes: pending_tx_hashes.to_vec(),
        frozen_cmx_hex: frozen_cmx.iter().map(hex::encode).collect(),
        shield_accounting,
    };
    if let Ok(json) = serde_json::to_string(&ck) {
        let tmp = format!("{path}.tmp");
        if std::fs::write(&tmp, &json).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }
}

// ─── State backend (JSON file | PostgreSQL) ───────────────────────────────────

/// A point-in-time copy of the persistable state, built from `SharedState` while a
/// lock is held, then handed off (no await needed at the call site).
#[derive(Clone, Default)]
struct CheckpointSnapshot {
    next_block: u64,
    cmx_ordered: Vec<[u8; 32]>,
    active_root: Option<[u8; 32]>,
    latest_seq: u64,
    batches: Vec<BatchEnvelope>,
    pending_tx_hashes: Vec<String>,
    frozen_cmx: Vec<[u8; 32]>,
    shield_accounting: ShieldAccounting,
}

impl CheckpointSnapshot {
    fn from_state(s: &SharedState) -> Self {
        Self {
            next_block: s.next_block,
            cmx_ordered: s.cmx_ordered.clone(),
            active_root: s.active_root,
            latest_seq: s.latest_seq,
            batches: s.batches.iter().cloned().collect(),
            pending_tx_hashes: s.pending_tx_hashes.iter().cloned().collect(),
            frozen_cmx: s.frozen.frozen_values().into_iter().map(fr_to_be_bytes).collect(),
            shield_accounting: s.shield_accounting,
        }
    }
    fn from_checkpoint_data(ck: &CheckpointData) -> Self {
        Self {
            next_block: ck.next_block,
            cmx_ordered: ck.cmx_ordered.clone(),
            active_root: ck.active_root,
            latest_seq: ck.latest_seq,
            batches: ck.batches.iter().cloned().collect(),
            pending_tx_hashes: ck.pending_tx_hashes.iter().cloned().collect(),
            frozen_cmx: ck.frozen_cmx.clone(),
            shield_accounting: ck.shield_accounting,
        }
    }
}

/// Where persisted state lives. `Json` is per-pool (its own file); `Pgsql` is one shared
/// connection pool with every row keyed by `pool_address`.
#[derive(Clone)]
enum StateBackend {
    Json(Option<String>),
    Pgsql(sqlx::PgPool),
}

impl StateBackend {
    async fn load(&self, pool_address: &str, start_block: u64) -> CheckpointData {
        match self {
            StateBackend::Json(Some(path)) => load_checkpoint(path, start_block),
            StateBackend::Json(None) => empty_checkpoint(start_block),
            StateBackend::Pgsql(pool) => pg_load(pool, pool_address, start_block).await,
        }
    }
    async fn save(&self, pool_address: &str, snap: &CheckpointSnapshot) -> Result<()> {
        match self {
            StateBackend::Json(Some(path)) => {
                save_checkpoint(
                    path, snap.next_block, &snap.cmx_ordered, snap.active_root,
                    snap.latest_seq, &snap.batches, &snap.pending_tx_hashes, &snap.frozen_cmx,
                    snap.shield_accounting,
                );
                Ok(())
            }
            StateBackend::Json(None) => Ok(()),
            StateBackend::Pgsql(pool) => pg_save(pool, pool_address, snap).await,
        }
    }
}

fn empty_checkpoint(start_block: u64) -> CheckpointData {
    CheckpointData {
        next_block: start_block,
        cmx_ordered: vec![],
        active_root: None,
        latest_seq: 0,
        batches: VecDeque::new(),
        pending_tx_hashes: VecDeque::new(),
        frozen_cmx: vec![],
        shield_accounting: ShieldAccounting::default(),
    }
}

/// Clonable handle the contexts hold; `notify` coalesces saves via a watch channel so
/// call sites stay synchronous (no await while holding a lock).
#[derive(Clone)]
struct Persist {
    tx: tokio::sync::watch::Sender<std::sync::Arc<CheckpointSnapshot>>,
}

impl Persist {
    fn notify(&self, s: &SharedState) {
        let _ = self.tx.send(std::sync::Arc::new(CheckpointSnapshot::from_state(s)));
    }
    /// Persist an already-built snapshot (for sites that dropped the lock first).
    fn notify_owned(&self, snap: CheckpointSnapshot) {
        let _ = self.tx.send(std::sync::Arc::new(snap));
    }
}

/// Background task: drains the latest snapshot and persists it (JSON or PG).
async fn persist_task(
    backend: StateBackend,
    pool_address: String,
    mut rx: tokio::sync::watch::Receiver<std::sync::Arc<CheckpointSnapshot>>,
) {
    let short = pool_address[..10.min(pool_address.len())].to_string();
    while rx.changed().await.is_ok() {
        let snap = rx.borrow_and_update().clone();
        if let Err(e) = backend.save(&pool_address, &snap).await {
            eprintln!("[indexer][{short}] persist failed: {e:#}");
        }
    }
}

const NOTES_UPSERT: &str = "\
INSERT INTO notes (pool_address, cmx_hex, seq, block_number, tx_hash, log_index, position, \
  enc_ciphertext_hex, epk_hex, out_ciphertext_hex, cv_net_x_hex, nf_old_hex, ack_hash_hex, \
  shield_amount_sats, is_confirmed) \
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) \
ON CONFLICT (pool_address, cmx_hex) DO UPDATE SET \
  seq=$3, block_number=$4, tx_hash=$5, log_index=$6, position=$7, enc_ciphertext_hex=$8, \
  epk_hex=$9, out_ciphertext_hex=$10, cv_net_x_hex=$11, nf_old_hex=$12, ack_hash_hex=$13, \
  shield_amount_sats=$14, is_confirmed=$15";

async fn pg_save(pool: &sqlx::PgPool, pool_address: &str, snap: &CheckpointSnapshot) -> Result<()> {
    let mut tx = pool.begin().await.context("pg begin")?;

    sqlx::query(
        "INSERT INTO indexer_meta (pool_address, next_block, active_root_hex, latest_seq, updated_at) \
         VALUES ($1,$2,$3,$4, now()) \
         ON CONFLICT (pool_address) DO UPDATE SET next_block=$2, active_root_hex=$3, latest_seq=$4, updated_at=now()",
    )
    .bind(pool_address)
    .bind(snap.next_block as i64)
    .bind(snap.active_root.map(hex::encode))
    .bind(snap.latest_seq as i64)
    .execute(&mut *tx).await.context("upsert indexer_meta")?;

    // These are derived rows. Replace the per-pool snapshot so a repaired
    // backfill cannot leave stale leaves in PostgreSQL and resurrect a bad root
    // on the next restart.
    sqlx::query("DELETE FROM cmx_leaves WHERE pool_address=$1")
        .bind(pool_address)
        .execute(&mut *tx)
        .await
        .context("replace cmx_leaves")?;
    sqlx::query("DELETE FROM frozen_cmx WHERE pool_address=$1")
        .bind(pool_address)
        .execute(&mut *tx)
        .await
        .context("replace frozen_cmx")?;

    for (pos, cmx) in snap.cmx_ordered.iter().enumerate() {
        sqlx::query(
            "INSERT INTO cmx_leaves (pool_address, position, cmx_hex) VALUES ($1,$2,$3) \
             ON CONFLICT (pool_address, position) DO NOTHING",
        )
        .bind(pool_address).bind(pos as i64).bind(hex::encode(cmx))
        .execute(&mut *tx).await.context("insert cmx_leaves")?;
    }

    // Frozen-set leaves (append-only, insertion order) — mirrors cmx_leaves so the
    // FrozenImt can be replayed on restart to recompute the same rt_frozen.
    for (pos, cmx) in snap.frozen_cmx.iter().enumerate() {
        sqlx::query(
            "INSERT INTO frozen_cmx (pool_address, position, cmx_hex) VALUES ($1,$2,$3) \
             ON CONFLICT (pool_address, position) DO NOTHING",
        )
        .bind(pool_address).bind(pos as i64).bind(hex::encode(cmx))
        .execute(&mut *tx).await.context("insert frozen_cmx")?;
    }

    for env in &snap.batches {
        for n in &env.batch.abi_notes {
            sqlx::query(NOTES_UPSERT)
                .bind(pool_address)
                .bind(hex::encode(n.cmx))
                .bind(env.seq as i64)
                .bind(n.block_number as i64)
                .bind(&n.tx_hash)
                .bind(n.log_index as i64)
                .bind(n.cmx_position.map(|p| p as i64))
                .bind(hex::encode(&n.enc_ciphertext))
                .bind(hex::encode(n.epk))
                .bind(hex::encode(&n.out_ciphertext))
                .bind(n.cv_net_x.map(hex::encode))
                .bind(hex::encode(n.nf_old))
                .bind(hex::encode(n.ack_hash))
                .bind(n.shield_amount_sats.map(|v| v as i64))
                .bind(n.is_confirmed)
                .execute(&mut *tx).await.context("upsert notes")?;
        }
    }

    sqlx::query("DELETE FROM pending_tx WHERE pool_address=$1")
        .bind(pool_address).execute(&mut *tx).await.context("clear pending_tx")?;
    for h in &snap.pending_tx_hashes {
        sqlx::query("INSERT INTO pending_tx (pool_address, tx_hash) VALUES ($1,$2) ON CONFLICT DO NOTHING")
            .bind(pool_address).bind(h).execute(&mut *tx).await.context("insert pending_tx")?;
    }

    sqlx::query(
        "INSERT INTO shield_pool_stats \
          (pool_address, total_shielded_units, total_shielded_wei, total_unshielded_units, total_unshielded_wei, updated_at) \
         VALUES ($1,$2,$3,$4,$5, now()) \
         ON CONFLICT (pool_address) DO UPDATE SET \
          total_shielded_units=$2, total_shielded_wei=$3, total_unshielded_units=$4, total_unshielded_wei=$5, updated_at=now()",
    )
    .bind(pool_address)
    .bind(snap.shield_accounting.total_shielded_units.to_string())
    .bind(snap.shield_accounting.total_shielded_wei.to_string())
    .bind(snap.shield_accounting.total_unshielded_units.to_string())
    .bind(snap.shield_accounting.total_unshielded_wei.to_string())
    .execute(&mut *tx).await.context("upsert shield_pool_stats")?;

    tx.commit().await.context("pg commit")?;
    Ok(())
}

/// Load scan scalars + tree leaves + pending txs from PG. Batches are intentionally left
/// empty: `backfill_from_chain` rebuilds them (and the tree) from chain on startup, then
/// persistence re-populates the `notes` table.
async fn pg_load(pool: &sqlx::PgPool, pool_address: &str, start_block: u64) -> CheckpointData {
    let meta: Option<(i64, Option<String>, i64)> =
        sqlx::query_as("SELECT next_block, active_root_hex, latest_seq FROM indexer_meta WHERE pool_address=$1")
            .bind(pool_address).fetch_optional(pool).await.ok().flatten();
    let (nb, active_root_hex, latest_seq) =
        meta.map(|(n, a, l)| (n as u64, a, l as u64)).unwrap_or((start_block, None, 0));
    let next_block = nb.max(start_block);
    let active_root = active_root_hex.as_deref().and_then(parse_hex32);

    let leaf_rows: Vec<(String,)> =
        sqlx::query_as("SELECT cmx_hex FROM cmx_leaves WHERE pool_address=$1 ORDER BY position")
            .bind(pool_address).fetch_all(pool).await.unwrap_or_default();
    let cmx_ordered: Vec<[u8; 32]> = leaf_rows.iter().filter_map(|(h,)| parse_hex32(h)).collect();

    let pend_rows: Vec<(String,)> =
        sqlx::query_as("SELECT tx_hash FROM pending_tx WHERE pool_address=$1")
            .bind(pool_address).fetch_all(pool).await.unwrap_or_default();
    let pending_tx_hashes: VecDeque<String> = pend_rows.into_iter().map(|(h,)| h).collect();

    // Frozen-set leaves in insertion order → replayed to rebuild the FrozenImt.
    let frozen_rows: Vec<(String,)> =
        sqlx::query_as("SELECT cmx_hex FROM frozen_cmx WHERE pool_address=$1 ORDER BY position")
            .bind(pool_address).fetch_all(pool).await.unwrap_or_default();
    let frozen_cmx: Vec<[u8; 32]> = frozen_rows.iter().filter_map(|(h,)| parse_hex32(h)).collect();

    let stats_row: Option<(String, String, String, String)> =
        sqlx::query_as(
            "SELECT total_shielded_units, total_shielded_wei, total_unshielded_units, total_unshielded_wei \
             FROM shield_pool_stats WHERE pool_address=$1",
        )
        .bind(pool_address)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();
    let shield_accounting = stats_row
        .map(|(tsu, tsw, tuu, tuw)| ShieldAccounting {
            total_shielded_units: tsu.parse::<u128>().unwrap_or(0),
            total_shielded_wei: tsw.parse::<u128>().unwrap_or(0),
            total_unshielded_units: tuu.parse::<u128>().unwrap_or(0),
            total_unshielded_wei: tuw.parse::<u128>().unwrap_or(0),
        })
        .unwrap_or_default();

    println!(
        "[indexer] pg load: pool={} next_block={next_block} leaves={} pending={} frozen={} shielded={} unshielded={}",
        &pool_address[..10.min(pool_address.len())], cmx_ordered.len(), pending_tx_hashes.len(), frozen_cmx.len(),
        shield_accounting.total_shielded_units, shield_accounting.total_unshielded_units
    );
    CheckpointData { next_block, cmx_ordered, active_root, latest_seq, batches: VecDeque::new(), pending_tx_hashes, frozen_cmx, shield_accounting }
}

/// Load `out_ciphertext` + `cv_net_x` for one action from the tx `bundle()` calldata.
async fn lookup_bundle_out_fields(
    rpc: &RpcClient,
    cache: &mut HashMap<String, HashMap<[u8; 32], BundleActionCiphertexts>>,
    tx_hash: &str,
    cmx: [u8; 32],
) -> (Vec<u8>, Option<[u8; 32]>) {
    let key = normalize_hex_0x(tx_hash);
    if !cache.contains_key(&key) {
        match rpc.get_transaction_input(&key).await {
            Ok(Some(input)) => match bundle_actions_by_cmx(&input) {
                Ok(map) => {
                    cache.insert(key.clone(), map);
                }
                Err(e) => {
                    eprintln!("[indexer] bundle calldata decode failed for {key}: {e}");
                }
            },
            Ok(None) => {}
            Err(e) => {
                eprintln!("[indexer] eth_getTransactionByHash failed for {key}: {e}");
            }
        }
    }
    if let Some(entry) = cache.get(&key).and_then(|m| m.get(&cmx)) {
        (
            entry.out_ciphertext.clone(),
            Some(entry.cv_net_x),
        )
    } else {
        (Vec::new(), None)
    }
}

// ─── WebSocket event loop ─────────────────────────────────────────────────────

#[derive(Clone)]
struct PollContext {
    rpc: RpcClient,
    /// WebSocket URL derived from rpc_url (https→wss, http→ws).
    wss_url: String,
    contract_address: String,
    privacybtc_abi_logs: bool,
    legacy_bundle_topic0: Option<String>,
    note_confirmed_topic0: String,
    shared: Arc<RwLock<SharedState>>,
    /// Coalescing persistence handle (JSON file or PostgreSQL).
    persist: Persist,
    /// Broadcast new batches to SSE subscribers.
    batch_tx: broadcast::Sender<BatchEnvelope>,
    /// Triggered by post_notify_tx to wake the event loop for immediate recovery.
    recover_trigger: Arc<tokio::sync::Notify>,
    /// First block to scan when rebuilding the tree from chain on startup.
    start_block: u64,
    /// Serializes ALL log ingestion paths (WS, catchup, backfill, recovery).
    ///
    /// The commitment tree is append-only, so leaves MUST be appended in exact
    /// (block, log_index) order. Without this lock a catchup replay of older
    /// blocks can interleave with live WS appends of newer blocks; a single
    /// out-of-order append makes the local tree diverge from the chain and
    /// every root it produces afterwards fails `isValidAnchor` (BadAnchor).
    ingest_lock: Arc<tokio::sync::Mutex<()>>,
}

/// Rebuild the commitment tree from chain via `eth_getLogs`, in on-chain order.
///
/// This is the source of truth: it scans `[start_block, head]` in chunks and
/// replays every pool event through `process_single_log`, so leaf positions and
/// the root always match the contract — even if a prior checkpoint was empty,
/// partial, or corrupt. The live WS subscription then continues from the head.
/// (Relayer `/notify_tx` covers any tx landing in the brief gap before the
/// subscription is active; the next restart's backfill reconciles regardless.)
async fn backfill_from_chain(ctx: &PollContext) {
    let _ingest = ctx.ingest_lock.lock().await;
    let label = ctx.contract_address[..10.min(ctx.contract_address.len())].to_string();
    let head = match ctx.rpc.block_number().await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("[indexer][{label}] backfill skipped: block_number failed: {e:#}");
            return;
        }
    };
    if head < ctx.start_block {
        return;
    }

    // Every pool event topic0 the live path understands (NoteAdded variants,
    // ShieldCompleted, NoteConfirmed, SwapNotePending).
    let mut topic0s: Vec<String> = note_added_topic0_alternatives()
        .iter()
        .map(|t| normalize_hex_0x(t))
        .collect();
    topic0s.push(normalize_hex_0x(&shield_completed_topic0_hex()));
    topic0s.push(normalize_hex_0x(&ctx.note_confirmed_topic0));
    topic0s.push(normalize_hex_0x(&shielded_topic0_hex()));
    topic0s.push(normalize_hex_0x(&unshielded_topic0_hex()));

    // Reset tree state for a clean rebuild so positions match on-chain order even
    // if the restored checkpoint was partial/corrupt. (pending_tx_hashes kept.)
    {
        let mut s = ctx.shared.write().await;
        s.tree = OrchardCommitmentTree::new();
        s.cmx_to_position.clear();
        s.cmx_ordered.clear();
        s.seen_event_ids.clear();
        s.confirm_seen_ids.clear();
        s.shield_seen_ids.clear();
        s.accounting_seen_ids.clear();
        s.shield_accounting = ShieldAccounting::default();
        s.batches.clear();
        s.latest_seq = 0;
        s.pending_notes.clear();
        s.confirmed_cmx.clear();
        s.active_root = None;
    }

    const CHUNK: u64 = 5_000;
    println!("[indexer][{label}] backfill: scanning logs [{}, {head}]…", ctx.start_block);
    let mut from = ctx.start_block;
    let mut total = 0usize;
    while from <= head {
        let to = (from + CHUNK - 1).min(head);
        match ctx
            .rpc
            .fetch_logs_topic0_or(from, to, &ctx.contract_address, &topic0s)
            .await
        {
            Ok(mut logs) => {
                // Ensure strict on-chain order: (blockNumber, logIndex).
                logs.sort_by(|a, b| {
                    let ka = (
                        parse_hex_u64(&a.block_number).unwrap_or(0),
                        parse_hex_u64(&a.log_index).unwrap_or(0),
                    );
                    let kb = (
                        parse_hex_u64(&b.block_number).unwrap_or(0),
                        parse_hex_u64(&b.log_index).unwrap_or(0),
                    );
                    ka.cmp(&kb)
                });
                for log in logs {
                    total += 1;
                    if let Err(e) = process_single_log(ctx, log).await {
                        eprintln!("[indexer][{label}] backfill log error: {e:#}");
                    }
                }
            }
            Err(e) => {
                eprintln!("[indexer][{label}] backfill getLogs [{from},{to}] failed: {e:#}");
            }
        }
        from = to + 1;
    }

    // Persist the rebuilt tree and advance next_block past the scanned head.
    let mut s = ctx.shared.write().await;
    s.next_block = head + 1;
    let tree_size = s.cmx_ordered.len();
    ctx.persist.notify(&s);
    drop(s);
    println!(
        "[indexer][{label}] backfill complete: {total} log(s), tree_size={tree_size}, next_block={}",
        head + 1
    );
}

/// How often the incremental gap-filler polls the chain to reconcile logs the WebSocket
/// subscription may have silently dropped.
const CATCHUP_INTERVAL_SECS: u64 = 20;

/// Split the inclusive block range `[from, head]` into `eth_getLogs` windows of at most
/// `chunk` blocks each. Returns an empty vec when already caught up (`from > head`) or when
/// `chunk == 0` (guards against an infinite loop). Windows are contiguous and non-overlapping.
fn catchup_ranges(from: u64, head: u64, chunk: u64) -> Vec<(u64, u64)> {
    let mut ranges = Vec::new();
    if from > head || chunk == 0 {
        return ranges;
    }
    let mut cur = from;
    while cur <= head {
        let to = (cur + chunk - 1).min(head);
        ranges.push((cur, to));
        if to == u64::MAX {
            break; // avoid overflow on `to + 1`
        }
        cur = to + 1;
    }
    ranges
}

/// Monotonic cursor advance: move `next_block` to just past the reconciled `head`, but never
/// backwards (a concurrent WS log or a later backfill may have already advanced it further).
fn advance_cursor(current: u64, head: u64) -> u64 {
    current.max(head.saturating_add(1))
}

/// Incremental gap-filler. Scans `eth_getLogs` from the persisted `next_block` up to the
/// current chain head and replays any logs the live WebSocket missed, WITHOUT resetting the
/// tree. `process_single_log` dedups atomically by `(tx_hash, log_index)` under the state
/// write lock, so overlap with WS-delivered logs is a no-op.
///
/// This is the durability backstop for `run_ws_subscription`: some providers' WS endpoints
/// (notably several Monad ones) silently drop `eth_subscribe` logs or go quiet after a
/// reconnect, which used to leave a permanent gap between the one-shot startup backfill and
/// live streaming. Polling forward on an interval lets the indexer self-heal and keep
/// `next_block` advancing toward chain head instead of freezing.
async fn catchup_from_chain(ctx: &PollContext) {
    let label = ctx.contract_address[..10.min(ctx.contract_address.len())].to_string();
    let head = match ctx.rpc.block_number().await {
        Ok(h) => h,
        Err(_) => return, // transient RPC error — retry next tick from the same cursor
    };
    // Hold the ingest lock for the WHOLE pass so live WS appends of newer
    // blocks cannot interleave with this ordered replay of older ones.
    let _ingest = ctx.ingest_lock.lock().await;
    let from = { ctx.shared.read().await.next_block };
    if from > head {
        return; // already caught up
    }

    let total = match replay_range(ctx, from, head).await {
        Ok(n) => n,
        Err(()) => return, // getLogs failed mid-range; next tick retries from the same cursor
    };

    // Advance the cursor past the reconciled head (never move it backwards).
    let mut s = ctx.shared.write().await;
    s.next_block = advance_cursor(s.next_block, head);
    ctx.persist.notify(&s);
    drop(s);
    if total > 0 {
        println!(
            "[indexer][{label}] catchup: reconciled {total} log(s) up to block {head}, next_block={}",
            head + 1
        );
    }
}

/// Fetch every watched log in the inclusive block range `[from, to]` and replay
/// them through `process_single_log` in strict (block, log_index) order.
///
/// The caller MUST hold `ctx.ingest_lock`. Returns the number of logs processed,
/// or `Err(())` if a getLogs window failed (the cursor must not advance then).
async fn replay_range(ctx: &PollContext, from: u64, to: u64) -> Result<usize, ()> {
    let label = ctx.contract_address[..10.min(ctx.contract_address.len())].to_string();
    let mut topic0s: Vec<String> = note_added_topic0_alternatives()
        .iter()
        .map(|t| normalize_hex_0x(t))
        .collect();
    topic0s.push(normalize_hex_0x(&shield_completed_topic0_hex()));
    topic0s.push(normalize_hex_0x(&ctx.note_confirmed_topic0));
    topic0s.push(normalize_hex_0x(&shielded_topic0_hex()));
    topic0s.push(normalize_hex_0x(&unshielded_topic0_hex()));

    const CHUNK: u64 = 5_000;
    let mut total = 0usize;
    for (lo, hi) in catchup_ranges(from, to, CHUNK) {
        match ctx
            .rpc
            .fetch_logs_topic0_or(lo, hi, &ctx.contract_address, &topic0s)
            .await
        {
            Ok(mut logs) => {
                logs.sort_by(|a, b| {
                    let ka = (
                        parse_hex_u64(&a.block_number).unwrap_or(0),
                        parse_hex_u64(&a.log_index).unwrap_or(0),
                    );
                    let kb = (
                        parse_hex_u64(&b.block_number).unwrap_or(0),
                        parse_hex_u64(&b.log_index).unwrap_or(0),
                    );
                    ka.cmp(&kb)
                });
                for log in logs {
                    if let Err(e) = process_single_log(ctx, log).await {
                        eprintln!("[indexer][{label}] replay log error: {e:#}");
                    } else {
                        total += 1;
                    }
                }
            }
            Err(e) => {
                eprintln!("[indexer][{label}] replay getLogs [{lo},{hi}] failed: {e:#}");
                return Err(());
            }
        }
    }
    Ok(total)
}

/// Ingest a live WS log while preserving strict on-chain ordering.
///
/// The pushed log is used ONLY as a wake-up signal + coverage marker — it is
/// never processed directly. All appends flow through `replay_range`, which
/// fetches `eth_getLogs` and processes strictly in (block, log_index) order.
///
/// Two provider behaviours make direct processing unsafe:
/// - the WS can silently drop logs, so a pushed log for block B may have
///   dropped predecessors in `[next_block, B]` that must be ingested first;
/// - the provider's getLogs view can LAG its own WS push (observed on anvil
///   under load): a replay right after the push may come back empty. If we
///   then appended the pushed log directly, a later replay would insert the
///   siblings BEHIND it — out of order — permanently corrupting the tree.
///
/// So: replay the window, check whether this log's event id got ingested, and
/// if not, sleep briefly and retry until the getLogs view catches up. If it
/// never does, leave the cursor untouched and let the periodic catchup replay
/// the window in order later.
async fn ingest_ws_log(ctx: &PollContext, log: EthLog) -> Result<()> {
    let _ingest = ctx.ingest_lock.lock().await;
    let block_number = parse_hex_u64(&log.block_number)
        .with_context(|| format!("invalid blockNumber: {}", log.block_number))?;
    let event_id = format!("{}:{}", log.transaction_hash, log.log_index);

    let covered = |s: &SharedState| {
        s.seen_event_ids.contains(&event_id)
            || s.confirm_seen_ids.contains(&event_id)
            || s.shield_seen_ids.contains(&event_id)
            || s.accounting_seen_ids.contains(&event_id)
    };

    for attempt in 0u64..6 {
        {
            let s = ctx.shared.read().await;
            if covered(&s) {
                return Ok(());
            }
        }
        let cursor = { ctx.shared.read().await.next_block };
        let from = cursor.min(block_number);
        if replay_range(ctx, from, block_number).await.is_ok() {
            let mut s = ctx.shared.write().await;
            if covered(&s) {
                // Cursor moves to B (not past it): later same-block pushes
                // trigger a cheap dedup-only replay of B, never a skip.
                s.next_block = s.next_block.max(block_number);
                ctx.persist.notify(&s);
                return Ok(());
            }
        }
        // getLogs has not caught up with the WS push yet.
        tokio::time::sleep(Duration::from_millis(50 * (attempt + 1))).await;
    }
    eprintln!(
        "[indexer] WS log {event_id} (block {block_number}) still not visible via eth_getLogs; \
         deferring to the periodic catchup"
    );
    Ok(())
}

/// WebSocket event-driven loop.
///
/// 1. Subscribe: `eth_subscribe logs` on the contract address.
/// 2. Process each incoming log immediately — no block polling.
/// 3. On disconnect: recover any pending tx hashes via receipt lookup, then resubscribe.
/// 4. Also listens for recover_trigger signals from post_notify_tx for immediate recovery.
/// 5. A concurrent `catchup_from_chain` task reconciles anything the WS silently dropped.
async fn run_event_loop(ctx: PollContext) -> Result<()> {
    // Rebuild the commitment tree from chain so the indexer matches on-chain state
    // (correct leaf positions / root) even after restarts or a partial checkpoint.
    backfill_from_chain(&ctx).await;
    // On every startup, recover any pending txs persisted in the checkpoint.
    recover_pending_txs(&ctx).await;

    // Durability backstop: poll the chain forward on an interval so a flaky WS that
    // silently drops logs can no longer leave a permanent gap after go-live.
    {
        let ctx_catchup = ctx.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(CATCHUP_INTERVAL_SECS));
            // The first tick fires immediately; skip it since backfill just ran.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                catchup_from_chain(&ctx_catchup).await;
            }
        });
    }

    loop {
        let ws_future = run_ws_subscription(&ctx);
        tokio::select! {
            result = ws_future => {
                match result {
                    Ok(()) => break, // clean shutdown
                    Err(e) => {
                        eprintln!("[indexer][{}] WebSocket error: {e:#}; recovering pending txs then reconnecting in 5s…",
                            &ctx.contract_address[..10]);
                        recover_pending_txs(&ctx).await;
                        tokio::time::sleep(Duration::from_secs(300)).await;
                    }
                }
            }
            _ = ctx.recover_trigger.notified() => {
                // post_notify_tx signalled us — run HTTP recovery without waiting for WS drop.
                recover_pending_txs(&ctx).await;
            }
        }
    }
    Ok(())
}

/// On WS reconnect, fetch receipts for any tx hashes that were notified but
/// whose events were not yet observed. Replays the logs through `process_single_log`.
async fn recover_pending_txs(ctx: &PollContext) {
    let hashes: Vec<String> = {
        let s = ctx.shared.read().await;
        s.pending_tx_hashes.iter().cloned().collect()
    };
    if hashes.is_empty() {
        return;
    }
    println!("[indexer][{}] recovering {} pending tx(s)…", &ctx.contract_address[..10], hashes.len());
    for tx_hash in hashes {
        match ctx.rpc.get_transaction_receipt_logs(&tx_hash).await {
            Ok(Some((success, logs))) => {
                if success {
                    println!("[indexer] recovering tx {tx_hash}: {} log(s)", logs.len());
                    for log in logs {
                        // Ordered ingest: gap-fills any earlier dropped logs first,
                        // so recovered logs cannot be appended out of order.
                        if let Err(e) = ingest_ws_log(ctx, log).await {
                            eprintln!("[indexer] recover log error for {tx_hash}: {e:#}");
                        }
                    }
                } else {
                    eprintln!("[indexer] tx {tx_hash} reverted — removing from pending queue");
                }
                // Receipt exists (mined, success or revert) — always remove from queue.
                // process_single_log already removes it on log processing; this handles
                // the case where the tx reverted (no logs) or emitted no watched events.
                let mut s = ctx.shared.write().await;
                s.pending_tx_hashes.retain(|h| h != &tx_hash);
            }
            Ok(None) => {
                // Not yet mined — keep in queue, will retry next reconnect.
                println!("[indexer] tx {tx_hash} not yet mined, keeping in pending queue");
            }
            Err(e) => {
                eprintln!("[indexer] receipt fetch failed for {tx_hash}: {e:#}");
            }
        }
    }
    // Persist the updated (smaller) pending queue.
    let s = ctx.shared.read().await;
    ctx.persist.notify(&s);
}

/// Open a WebSocket to the WSS endpoint, subscribe to contract logs, and
/// process each log event through the same pipeline as `poll_once`.
async fn run_ws_subscription(ctx: &PollContext) -> Result<()> {
    use tokio_tungstenite::connect_async;

    let (mut ws, _) = connect_async(&ctx.wss_url)
        .await
        .with_context(|| format!("WebSocket connect failed: {}", ctx.wss_url))?;
    println!("[indexer][{}] WebSocket connected: {}", &ctx.contract_address[..10], ctx.wss_url);

    // Build topic0 OR list for subscription filter.
    let mut topics: Vec<String> = Vec::new();
    if ctx.privacybtc_abi_logs {
        for t in note_added_topic0_alternatives() {
            topics.push(norm_topic(&t));
        }
        topics.push(norm_topic(&shield_completed_topic0_hex()));
        topics.push(norm_topic(&ctx.note_confirmed_topic0));
        topics.push(norm_topic(&shielded_topic0_hex()));
        topics.push(norm_topic(&unshielded_topic0_hex()));
    }
    if let Some(ref leg) = ctx.legacy_bundle_topic0 {
        topics.push(norm_topic(leg));
    }

    let sub_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_subscribe",
        "params": ["logs", {
            "address": ctx.contract_address,
            "topics": [topics]
        }]
    });
    ws.send(Message::Text(sub_req.to_string().into())).await
        .context("failed to send eth_subscribe")?;

    // Expect subscription confirmation — with timeout to avoid hanging forever.
    let sub_id = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(txt))) => {
                    let v: serde_json::Value = serde_json::from_str(&txt)
                        .context("invalid JSON from WebSocket")?;
                    if v.get("id") == Some(&serde_json::Value::Number(1.into())) {
                        if let Some(id) = v["result"].as_str() {
                            println!("[indexer][{}] subscribed id={id}", &ctx.contract_address[..10]);
                            return Ok::<_, anyhow::Error>(id.to_string());
                        }
                        return Err(anyhow!("eth_subscribe error: {}", v["error"]));
                    }
                }
                Some(Ok(Message::Ping(d))) => { ws.send(Message::Pong(d)).await.ok(); }
                Some(Err(e)) => return Err(e.into()),
                None => return Err(anyhow!("WebSocket closed before subscription confirmed")),
                _ => {}
            }
        }
    })
    .await
    .context("eth_subscribe timed out after 15s")??;

    println!("[indexer][{}] listening for events (sub={sub_id})", &ctx.contract_address[..10]);

    // Process incoming events.
    while let Some(msg) = ws.next().await {
        match msg {
            Ok(Message::Text(txt)) => {
                let v: serde_json::Value = match serde_json::from_str(&txt) {
                    Ok(v) => v,
                    Err(e) => { eprintln!("[indexer] JSON parse error: {e}"); continue; }
                };
                if v["method"].as_str() != Some("eth_subscription") { continue; }
                if v["params"]["subscription"].as_str() != Some(&sub_id) { continue; }
                let log_val = &v["params"]["result"];
                if let Ok(log) = serde_json::from_value::<EthLog>(log_val.clone()) {
                    if let Err(e) = ingest_ws_log(ctx, log).await {
                        eprintln!("[indexer] ingest_ws_log error: {e:#}");
                    }
                }
            }
            Ok(Message::Ping(d)) => { ws.send(Message::Pong(d)).await.ok(); }
            Ok(Message::Close(_)) => {
                println!("[indexer][{}] WebSocket closed by server", &ctx.contract_address[..10]);
                return Err(anyhow!("server closed connection"));
            }
            Err(e) => return Err(e.into()),
            _ => {}
        }
    }
    Err(anyhow!("WebSocket stream ended"))
}

/// Process a single `EthLog` event received from the WebSocket subscription.
///
/// Key differences from `poll_once`:
/// - Each event arrives as a separate WebSocket message, so `NoteAdded` and
///   `SwapNotePending` (same tx) are two separate calls.
/// - We look up the existing note in `state.batches` when `SwapNotePending` or
///   `ShieldCompleted` arrives after `NoteAdded`.
/// - Batches are persisted to `state.batches` + `state.latest_seq` so reconnecting
///   SSE clients receive a consistent sequence.
async fn process_single_log(ctx: &PollContext, log: EthLog) -> Result<()> {
    // Only process events emitted by the pool contract we are watching.
    // Without this guard, a multi-pool transaction (e.g. complete() touching
    // both pBTC and pUSDC pools) would cause each pool's handler to process
    // the other pool's events, corrupting the local Merkle tree and producing
    // expensive spurious Poseidon hash computations in debug builds.
    let log_addr = log.address.trim_start_matches("0x").to_ascii_lowercase();
    let pool_addr = ctx.contract_address.trim_start_matches("0x").to_ascii_lowercase();
    if !log_addr.is_empty() && log_addr != pool_addr {
        return Ok(());
    }

    let na_topics: Vec<String> = note_added_topic0_alternatives()
        .iter()
        .map(|t| norm_topic(t))
        .collect();
    let sc = norm_topic(&shield_completed_topic0_hex());
    let nc = norm_topic(&ctx.note_confirmed_topic0);
    let shielded_topic = norm_topic(&shielded_topic0_hex());
    let unshielded_topic = norm_topic(&unshielded_topic0_hex());

    let event_id = format!("{}:{}", log.transaction_hash, log.log_index);
    let block_number = parse_hex_u64(&log.block_number)
        .with_context(|| format!("invalid blockNumber: {}", log.block_number))?;
    let log_index = parse_hex_u64(&log.log_index)
        .with_context(|| format!("invalid logIndex: {}", log.log_index))?;
    let t0 = log.topics.as_ref().and_then(|x| x.first()).map(|s| norm_topic(s));

    let mut state = ctx.shared.write().await;

    // Do NOT remove from pending_tx_hashes here. A tx can emit multiple logs
    // (e.g. NoteAdded + SwapNotePending + NoteConfirmed × N). Removing on the
    // first WS log means a WS drop before all logs arrive permanently loses the
    // later events (the tx is gone from pending when recover_pending_txs runs).
    // Only recover_pending_txs (which fetches the full receipt) removes from queue.

    if na_topics.iter().any(|na| t0.as_deref() == Some(na.as_str())) {
        // ── NoteAdded ────────────────────────────────────────────────────────
        if state.seen_event_ids.contains(&event_id) { return Ok(()); }
        let d = match decode_note_added_log(log.topics.as_deref().unwrap_or(&[]), &log.data) {
            Ok(d) => d,
            Err(e) => { eprintln!("[indexer] NoteAdded decode FAILED: {e}"); return Ok(()); }
        };
        let cmx_position = if let Some(&existing_pos) = state.cmx_to_position.get(&d.cmx) {
            Some(existing_pos)
        } else {
            state.tree.append(d.cmx).map(|pos| {
                state.cmx_to_position.insert(d.cmx, pos);
                state.cmx_ordered.push(d.cmx);
                pos
            })
        };
        state.seen_event_ids.insert(event_id);
        let is_confirmed = state.confirmed_cmx.contains(&d.cmx);
        const OUT_LEN: usize = 80;
        let (out_ciphertext, cv_net_x) = if d.out_ciphertext.len() == OUT_LEN && d.cv_net_x.is_some() {
            (d.out_ciphertext, d.cv_net_x)
        } else {
            lookup_bundle_out_fields(
                &ctx.rpc,
                &mut state.bundle_out_cache,
                &log.transaction_hash,
                d.cmx,
            )
            .await
        };
        let note = OrchardIndexedAbiNote {
            block_number,
            tx_hash: log.transaction_hash.clone(),
            log_index,
            cmx: d.cmx,
            enc_ciphertext: d.enc_ciphertext,
            epk: d.epk,
            out_ciphertext,
            cv_net_x,
            nf_old: d.nf_old,
            ack_hash: [0u8; 32],
            cmx_position,
            shield_amount_sats: None,
            is_confirmed,
        };
        let seq = state.latest_seq.saturating_add(1);
        state.latest_seq = seq;
        let batch = OrchardIndexBatch {
            from_block: block_number,
            to_block: block_number,
            abi_notes: vec![note],
            bundles: vec![],
            latest_root: state.tree.latest_root(),
        };
        let envelope = BatchEnvelope { seq, pool_address: Some(ctx.contract_address.clone()), batch };
        state.batches.push_back(envelope.clone());
        while state.batches.len() > state.max_batches { state.batches.pop_front(); }
        let next_block = block_number.saturating_add(1).max(state.next_block);
        state.next_block = next_block;
        let cmx_snap = state.cmx_ordered.clone();
        let root_snap = state.active_root;
        let seq_snap = state.latest_seq;
        let batches_snap: Vec<BatchEnvelope> = state.batches.iter().cloned().collect();
        let pending_snap: Vec<String> = state.pending_tx_hashes.iter().cloned().collect();
        let frozen_snap: Vec<[u8; 32]> =
            state.frozen.frozen_values().into_iter().map(fr_to_be_bytes).collect();
        let accounting_snap = state.shield_accounting;
        drop(state);
        ctx.batch_tx.send(envelope).ok();
        ctx.persist.notify_owned(CheckpointSnapshot {
            next_block,
            cmx_ordered: cmx_snap,
            active_root: root_snap,
            latest_seq: seq_snap,
            batches: batches_snap,
            pending_tx_hashes: pending_snap,
            frozen_cmx: frozen_snap,
            shield_accounting: accounting_snap,
        });

    } else if t0.as_deref() == Some(nc.as_str()) {
        // ── NoteConfirmed ────────────────────────────────────────────────────
        if !state.confirm_seen_ids.insert(event_id) { return Ok(()); }
        if let Ok((cmx, new_root, position)) =
            decode_note_confirmed_log(log.topics.as_deref().unwrap_or(&[]), &log.data)
        {
            state.pending_notes.remove(&cmx);
            state.confirmed_cmx.insert(cmx);
            state.active_root = Some(new_root);

            // Find the shield/transfer note in batches history and mark it confirmed.
            let maybe_note: Option<OrchardIndexedAbiNote> = {
                let found = state.batches.iter().rev()
                    .flat_map(|env| env.batch.abi_notes.iter())
                    .find(|n| n.cmx == cmx)
                    .cloned();
                if let Some(mut note) = found {
                    note.is_confirmed = true;
                    note.cmx_position = Some(position);
                    println!("[indexer] note confirmed: cmx={} pos={}", hex::encode(cmx), position);
                    Some(note)
                } else {
                    println!("[indexer] NoteConfirmed cmx={} not found in batches, skipping re-emit", hex::encode(cmx));
                    None
                }
            };

            // Add a tree checkpoint so /merkle_path works after this confirmation.
            state.tree.checkpoint(block_number);

            if let Some(note) = maybe_note {
                let seq = state.latest_seq.saturating_add(1);
                state.latest_seq = seq;
                let batch = OrchardIndexBatch {
                    from_block: block_number,
                    to_block: block_number,
                    abi_notes: vec![note],
                    bundles: vec![],
                    latest_root: state.tree.latest_root(),
                };
                let envelope = BatchEnvelope { seq, pool_address: Some(ctx.contract_address.clone()), batch };
                state.batches.push_back(envelope.clone());
                while state.batches.len() > state.max_batches { state.batches.pop_front(); }
                let cmx_snap = state.cmx_ordered.clone();
                let root_snap = state.active_root;
                let seq_snap  = state.latest_seq;
                let next_block = state.next_block;
                let batches_snap: Vec<BatchEnvelope> = state.batches.iter().cloned().collect();
                let pending_snap: Vec<String> = state.pending_tx_hashes.iter().cloned().collect();
                let frozen_snap: Vec<[u8; 32]> =
                    state.frozen.frozen_values().into_iter().map(fr_to_be_bytes).collect();
                let accounting_snap = state.shield_accounting;
                drop(state);
                ctx.batch_tx.send(envelope).ok();
                ctx.persist.notify_owned(CheckpointSnapshot {
                    next_block,
                    cmx_ordered: cmx_snap,
                    active_root: root_snap,
                    latest_seq: seq_snap,
                    batches: batches_snap,
                    pending_tx_hashes: pending_snap,
                    frozen_cmx: frozen_snap,
                    shield_accounting: accounting_snap,
                });
                return Ok(());
            }
        }

    } else if t0.as_deref() == Some(sc.as_str()) {
        // ── ShieldCompleted ──────────────────────────────────────────────────
        // NoteAdded was already processed; update shield_amount_sats on the
        // existing batch entry and re-emit.
        if !state.shield_seen_ids.insert(event_id) { return Ok(()); }
        if let Ok((cmx, amt)) =
            decode_shield_completed_log(log.topics.as_deref().unwrap_or(&[]), &log.data)
        {
            let maybe_note = state.batches.iter().rev()
                .flat_map(|env| env.batch.abi_notes.iter())
                .find(|n| n.cmx == cmx && n.tx_hash == log.transaction_hash)
                .cloned();
            if let Some(mut note) = maybe_note {
                note.shield_amount_sats = u64::try_from(amt).ok();
                let seq = state.latest_seq.saturating_add(1);
                state.latest_seq = seq;
                let batch = OrchardIndexBatch {
                    from_block: block_number,
                    to_block: block_number,
                    abi_notes: vec![note],
                    bundles: vec![],
                    latest_root: state.tree.latest_root(),
                };
                let envelope = BatchEnvelope { seq, pool_address: Some(ctx.contract_address.clone()), batch };
                state.batches.push_back(envelope.clone());
                while state.batches.len() > state.max_batches { state.batches.pop_front(); }
                drop(state);
                ctx.batch_tx.send(envelope).ok();
                return Ok(());
            }
        }
    } else if t0.as_deref() == Some(shielded_topic.as_str()) {
        // ── Shielded accounting ───────────────────────────────────────────────
        if state.accounting_seen_ids.contains(&event_id) { return Ok(()); }
        match decode_shielded_log(log.topics.as_deref().unwrap_or(&[]), &log.data) {
            Ok(d) => {
                state.accounting_seen_ids.insert(event_id);
                state.shield_accounting.total_shielded_units =
                    state.shield_accounting.total_shielded_units.saturating_add(d.amount_units);
                state.shield_accounting.total_shielded_wei =
                    state.shield_accounting.total_shielded_wei.saturating_add(d.wei_amount);
                state.next_block = block_number.saturating_add(1).max(state.next_block);
                ctx.persist.notify(&state);
            }
            Err(e) => eprintln!("[indexer] Shielded decode FAILED: {e}"),
        }
    } else if t0.as_deref() == Some(unshielded_topic.as_str()) {
        // ── Unshielded accounting ─────────────────────────────────────────────
        if state.accounting_seen_ids.contains(&event_id) { return Ok(()); }
        match decode_unshielded_log(log.topics.as_deref().unwrap_or(&[]), &log.data) {
            Ok(d) => {
                state.accounting_seen_ids.insert(event_id);
                state.shield_accounting.total_unshielded_units =
                    state.shield_accounting.total_unshielded_units.saturating_add(d.amount_units);
                state.shield_accounting.total_unshielded_wei =
                    state.shield_accounting.total_unshielded_wei.saturating_add(d.wei_amount);
                state.next_block = block_number.saturating_add(1).max(state.next_block);
                ctx.persist.notify(&state);
            }
            Err(e) => eprintln!("[indexer] Unshielded decode FAILED: {e}"),
        }
    }

    Ok(())
}

fn norm_topic(s: &str) -> String {
    let t = strip_0x(s).to_lowercase();
    format!("0x{t}")
}

// ─── RPC client ───────────────────────────────────────────────────────────────

#[derive(Clone)]
struct RpcClient {
    http: Client,
    urls: Vec<String>,
}

impl RpcClient {
    fn new(url: String) -> Self {
        // HTTP RPC calls must use https:// / http://, not wss:// / ws://.
        let http_url = url
            .replacen("wss://", "https://", 1)
            .replacen("ws://", "http://", 1);
        let urls = vec![http_url];
        // Read proxy from env: HTTPS_PROXY / ALL_PROXY (case-insensitive).
        // reqwest reads these by default, but we also add it explicitly so the
        // proxy is used even when Clash/system-proxy is only configured at the
        // OS level (not in environment variables).
        let proxy_url = std::env::var("HTTPS_PROXY")
            .or_else(|_| std::env::var("https_proxy"))
            .or_else(|_| std::env::var("ALL_PROXY"))
            .or_else(|_| std::env::var("all_proxy"))
            .ok();
        let no_proxy = std::env::var("NO_PROXY")
            .or_else(|_| std::env::var("no_proxy"))
            .unwrap_or_default();

        let mut builder = Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            // Expire idle proxy-tunnel connections after 30 s so reqwest never
            // tries to reuse a stale keep-alive connection that the proxy already
            // closed (which produces spurious "error sending request" failures).
            .pool_idle_timeout(std::time::Duration::from_secs(30))
            .tcp_keepalive(std::time::Duration::from_secs(20));

        if let Some(ref p) = proxy_url {
            match reqwest::Proxy::all(p) {
                Ok(proxy) => {
                    // Apply no-proxy exclusions.
                    let proxy = if no_proxy.is_empty() {
                        proxy
                    } else {
                        proxy.no_proxy(reqwest::NoProxy::from_string(&no_proxy))
                    };
                    builder = builder.proxy(proxy);
                    println!("[indexer] RPC using proxy: {p} (no_proxy={no_proxy:?})");
                }
                Err(e) => eprintln!("[indexer] invalid proxy URL {p}: {e}"),
            }
        }

        let http = builder.build().expect("reqwest client");
        Self { http, urls }
    }

    async fn block_number(&self) -> Result<u64> {
        let hex_num: String = self.rpc_call("eth_blockNumber", serde_json::json!([])).await?;
        parse_hex_u64(&hex_num).context("invalid eth_blockNumber")
    }

    async fn get_transaction_count(&self, address: &str) -> Result<u64> {
        let hex_num: String = self
            .rpc_call("eth_getTransactionCount", serde_json::json!([address, "latest"]))
            .await?;
        parse_hex_u64(&hex_num).context("invalid eth_getTransactionCount")
    }

    async fn send_raw_transaction(&self, raw_tx: &[u8]) -> Result<String> {
        let hex_tx = format!("0x{}", hex::encode(raw_tx));
        self.rpc_call("eth_sendRawTransaction", serde_json::json!([hex_tx])).await
    }

    /// Returns `None` if tx not yet mined, `Some(true)` if success, `Some(false)` if reverted.
    async fn get_transaction_receipt_status(&self, tx_hash: &str) -> Result<Option<bool>> {
        #[derive(Deserialize)]
        struct Receipt { status: Option<String> }
        let hash = if tx_hash.starts_with("0x") || tx_hash.starts_with("0X") {
            tx_hash.to_string()
        } else {
            format!("0x{tx_hash}")
        };
        let receipt: Option<Receipt> = self.rpc_call(
            "eth_getTransactionReceipt",
            serde_json::json!([hash]),
        ).await?;
        Ok(receipt.map(|r| r.status.as_deref().unwrap_or("0x1") == "0x1"))
    }

    /// Returns the raw EthLog entries from a mined transaction receipt.
    /// Returns `None` if the transaction is not yet mined.
    async fn get_transaction_input(&self, tx_hash: &str) -> Result<Option<Vec<u8>>> {
        #[derive(Deserialize)]
        struct Tx { input: String }
        let hash = normalize_hex_0x(tx_hash);
        let tx: Option<Tx> = self
            .rpc_call("eth_getTransactionByHash", serde_json::json!([hash]))
            .await?;
        Ok(tx.map(|t| {
            hex::decode(t.input.strip_prefix("0x").unwrap_or(&t.input))
                .unwrap_or_default()
        }))
    }

    async fn get_transaction_receipt_logs(&self, tx_hash: &str) -> Result<Option<(bool, Vec<EthLog>)>> {
        #[derive(Deserialize)]
        struct ReceiptLog {
            #[serde(default)]
            address: String,
            #[serde(rename = "blockNumber")]
            block_number: String,
            #[serde(rename = "transactionHash")]
            transaction_hash: String,
            #[serde(rename = "logIndex")]
            log_index: String,
            #[serde(default)]
            topics: Option<Vec<String>>,
            data: String,
        }
        #[derive(Deserialize)]
        struct Receipt {
            /// "0x1" = success, "0x0" = revert. None if legacy pre-Byzantium.
            status: Option<String>,
            logs: Vec<ReceiptLog>,
        }
        let hash = normalize_hex_0x(tx_hash);
        let receipt: Option<Receipt> = self
            .rpc_call("eth_getTransactionReceipt", serde_json::json!([hash]))
            .await?;
        Ok(receipt.map(|r| {
            let success = r.status.as_deref().unwrap_or("0x1") == "0x1";
            let logs = r.logs
                .into_iter()
                .map(|l| EthLog {
                    address: l.address,
                    block_number: l.block_number,
                    transaction_hash: l.transaction_hash,
                    log_index: l.log_index,
                    topics: l.topics,
                    data: l.data,
                })
                .collect();
            (success, logs)
        }))
    }

    async fn fetch_logs_topic0_or(
        &self,
        from_block: u64,
        to_block: u64,
        contract_address: &str,
        topic0_alternatives: &[String],
    ) -> Result<Vec<EthLog>> {
        let alt: Vec<serde_json::Value> = topic0_alternatives.iter().cloned().map(Into::into).collect();
        let filter = serde_json::json!({
            "fromBlock": format!("0x{:x}", from_block),
            "toBlock":   format!("0x{:x}", to_block),
            "address":   contract_address,
            "topics":    [ alt ],
        });
        self.rpc_call("eth_getLogs", serde_json::json!([filter]))
            .await
            .with_context(|| format!("eth_getLogs failed for [{from_block}, {to_block}]"))
    }

    /// True if `pool` (0x-prefixed) emitted `Perc20Created(pool,…)` at construction
    /// — i.e. it is a genuine pERC20 asset (factory-deployed or standalone, both
    /// conformant). The event's indexed `pool` arg equals the emitting contract,
    /// so we filter by both `address` and `topics[1]` for a precise, cheap lookup.
    async fn is_perc20_created(&self, pool: &str) -> Result<bool> {
        let addr = normalize_hex_0x(pool);
        let topic1 = format!("0x{:0>64}", addr.trim_start_matches("0x"));
        let filter = serde_json::json!({
            "fromBlock": "0x0",
            "toBlock":   "latest",
            "address":   addr,
            "topics":    [perc20_created_topic0(), topic1],
        });
        let logs: Vec<EthLog> = self
            .rpc_call("eth_getLogs", serde_json::json!([filter]))
            .await
            .context("eth_getLogs (Perc20Created verification) failed")?;
        Ok(!logs.is_empty())
    }

    /// True if `pool` emitted `ShieldPoolCreated(pool,…)` at construction — i.e. it is a genuine
    /// `ERC20Shield` backed pool. Mirrors `is_perc20_created` but for the shield-pool event.
    async fn is_shield_pool_created(&self, pool: &str) -> Result<bool> {
        let addr = normalize_hex_0x(pool);
        let topic1 = format!("0x{:0>64}", addr.trim_start_matches("0x"));
        let filter = serde_json::json!({
            "fromBlock": "0x0",
            "toBlock":   "latest",
            "address":   addr,
            "topics":    [shield_pool_created_topic0_hex(), topic1],
        });
        let logs: Vec<EthLog> = self
            .rpc_call("eth_getLogs", serde_json::json!([filter]))
            .await
            .context("eth_getLogs (ShieldPoolCreated verification) failed")?;
        Ok(!logs.is_empty())
    }

    /// Fetch pool metadata by reading the pool's genesis event. Returns shield-pool metadata
    /// (scale/underlying/name/symbol/decimals) when `ShieldPoolCreated` is present, else issuer
    /// metadata (name/symbol/decimals) from `Perc20Created`, else `None`.
    async fn fetch_pool_metadata(&self, pool: &str) -> Result<Option<PoolMeta>> {
        let addr = normalize_hex_0x(pool);
        let topic1 = format!("0x{:0>64}", addr.trim_start_matches("0x"));
        // Prefer the shield-pool genesis event (carries scale + underlying).
        let shield_filter = serde_json::json!({
            "fromBlock": "0x0",
            "toBlock":   "latest",
            "address":   addr,
            "topics":    [shield_pool_created_topic0_hex(), topic1],
        });
        let logs: Vec<EthLog> = self
            .rpc_call("eth_getLogs", serde_json::json!([shield_filter]))
            .await
            .context("eth_getLogs (ShieldPoolCreated metadata) failed")?;
        if let Some(l) = logs.first() {
            if let Some(topics) = l.topics.as_ref() {
                if let Ok(d) = decode_shield_pool_created_log(topics, &l.data) {
                    return Ok(Some(PoolMeta::from_shield_pool(&addr, &d)));
                }
            }
        }
        // Fall back to issuer genesis (name/symbol/decimals only).
        let issuer_filter = serde_json::json!({
            "fromBlock": "0x0",
            "toBlock":   "latest",
            "address":   addr,
            "topics":    [perc20_created_topic0(), topic1],
        });
        let logs: Vec<EthLog> = self
            .rpc_call("eth_getLogs", serde_json::json!([issuer_filter]))
            .await
            .context("eth_getLogs (Perc20Created metadata) failed")?;
        if let Some(l) = logs.first() {
            if let Some(meta) = PoolMeta::try_from_perc20_created(&addr, &l.data) {
                return Ok(Some(meta));
            }
            // Event present but body not decodable — still a known issuer pool.
            return Ok(Some(PoolMeta::issuer_minimal(&addr)));
        }
        Ok(None)
    }

    /// Scan `Perc20Created` chain-wide (no address filter) over [from, to] and
    /// return `(pool_address, block_number)` for each match. When `issuer_topics`
    /// is non-empty, only those issuers (indexed topic[2]) are returned.
    async fn fetch_created_pools(
        &self,
        from_block: u64,
        to_block: u64,
        topic0: &str,
        issuer_topics: &[String],
    ) -> Result<Vec<(String, u64)>> {
        let topics = if issuer_topics.is_empty() {
            serde_json::json!([topic0])
        } else {
            let issuers: Vec<serde_json::Value> =
                issuer_topics.iter().cloned().map(Into::into).collect();
            // [topic0, null(pool, any), [issuer…]]
            serde_json::json!([topic0, serde_json::Value::Null, issuers])
        };
        let filter = serde_json::json!({
            "fromBlock": format!("0x{:x}", from_block),
            "toBlock":   format!("0x{:x}", to_block),
            "topics":    topics,
        });
        let logs: Vec<EthLog> = self
            .rpc_call("eth_getLogs", serde_json::json!([filter]))
            .await
            .with_context(|| format!("eth_getLogs (Perc20Created discovery) [{from_block},{to_block}]"))?;
        let mut out = Vec::new();
        for l in logs {
            let pool = l
                .topics
                .as_ref()
                .and_then(|t| t.get(1))
                .and_then(|t| topic_to_address(t));
            let block = parse_hex_u64(&l.block_number).ok();
            if let (Some(p), Some(b)) = (pool, block) {
                out.push((p, b));
            }
        }
        Ok(out)
    }

    async fn rpc_call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T> {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1u64,
            "method": method,
            "params": params,
        });
        let mut last_err = anyhow::anyhow!("no rpc urls");
        for url in &self.urls {
            // Try up to 2 times per URL: the first attempt may fail with
            // "error sending request" if the proxy recycled a keep-alive
            // connection.  A single immediate retry with a fresh connection
            // fixes that without adding noticeable latency.
            'attempts: for attempt in 0u8..2 {
                match self.http.post(url).json(&req).send().await {
                    Ok(resp) => match resp.json::<JsonRpcResponse<T>>().await {
                        Ok(r) => match (r.result, r.error) {
                            (Some(v), None) => return Ok(v),
                            (None, Some(e)) => {
                                last_err = anyhow!("eth_{} failed for {url}: rpc error {}: {}", method, e.code, e.message);
                                return Err(last_err);
                            }
                            _ => { last_err = anyhow!("malformed rpc response for method {method} from {url}"); break 'attempts; }
                        },
                        Err(e) => { last_err = anyhow!("eth_{} rpc decode failed: {}", method, e); break 'attempts; }
                    },
                    Err(e) => {
                        last_err = anyhow!("eth_{} send failed from {url}: {}", method, e);
                        if attempt == 0 {
                            // First failure — may be a stale connection; retry once silently.
                            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                            continue 'attempts;
                        }
                        eprintln!("[indexer] rpc {url} failed ({e}), trying fallback…");
                    }
                }
            }
        }
        Err(last_err)
    }
}

// ─── Ethereum raw transaction ─────────────────────────────────────────────────

/// Encodes calldata for `confirmReceipt(bytes32,bytes32,bytes32)`.
/// Function selector = keccak256("confirmReceipt(bytes32,bytes32,bytes32)")[0:4]
fn encode_confirm_receipt_calldata(
    cmx: &[u8; 32],
    ack_preimage: &[u8; 32],
    new_root: &[u8; 32],
) -> Vec<u8> {
    let selector: [u8; 4] =
        Keccak256::digest(b"confirmReceipt(bytes32,bytes32,bytes32)")[..4]
            .try_into()
            .expect("keccak digest is 32 bytes");
    let mut calldata = Vec::with_capacity(4 + 32 + 32 + 32);
    calldata.extend_from_slice(&selector);
    calldata.extend_from_slice(cmx);
    calldata.extend_from_slice(ack_preimage);
    calldata.extend_from_slice(new_root);
    calldata
}

/// Builds and signs an EIP-155 legacy raw transaction.
fn build_and_sign_raw_tx(
    nonce: u64,
    gas_price: u64,
    gas_limit: u64,
    to: &str,
    value: u64,
    data: &[u8],
    chain_id: u64,
    signing_key: &SigningKey,
) -> Result<Vec<u8>> {
    let to_bytes = hex::decode(strip_0x(to)).context("invalid contract address hex")?;
    if to_bytes.len() != 20 {
        return Err(anyhow!("contract address must be 20 bytes"));
    }

    // Pre-signing hash: keccak256(RLP([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]))
    let pre_sign_rlp = rlp_list(vec![
        rlp_uint(nonce as u128),
        rlp_uint(gas_price as u128),
        rlp_uint(gas_limit as u128),
        rlp_bytes(&to_bytes),
        rlp_uint(value as u128),
        rlp_bytes(data),
        rlp_uint(chain_id as u128),
        rlp_bytes(&[]),
        rlp_bytes(&[]),
    ]);
    let tx_hash: [u8; 32] = Keccak256::digest(&pre_sign_rlp).into();

    // Sign prehash (secp256k1, EIP-155).
    let (sig, recid): (k256::ecdsa::Signature, RecoveryId) = signing_key
        .sign_prehash_recoverable(&tx_hash)
        .map_err(|e| anyhow!("signing failed: {e}"))?;

    let r: [u8; 32] = sig.r().to_bytes().into();
    let s: [u8; 32] = sig.s().to_bytes().into();
    let v = chain_id * 2 + 35 + recid.to_byte() as u64;

    // Final signed transaction.
    let signed_rlp = rlp_list(vec![
        rlp_uint(nonce as u128),
        rlp_uint(gas_price as u128),
        rlp_uint(gas_limit as u128),
        rlp_bytes(&to_bytes),
        rlp_uint(value as u128),
        rlp_bytes(data),
        rlp_uint(v as u128),
        rlp_bytes(&r),
        rlp_bytes(&s),
    ]);

    Ok(signed_rlp)
}

/// Derives the Ethereum address from a SigningKey.
fn eth_address_from_signing_key(signing_key: &SigningKey) -> [u8; 20] {
    let vk = signing_key.verifying_key();
    let encoded = vk.to_encoded_point(false); // uncompressed (65 bytes: 0x04 + x + y)
    let pubkey_bytes = &encoded.as_bytes()[1..]; // drop 0x04 prefix → 64 bytes
    let hash: [u8; 32] = Keccak256::digest(pubkey_bytes).into();
    hash[12..].try_into().expect("20 bytes from last 12 of keccak")
}

// ─── Minimal RLP encoder ─────────────────────────────────────────────────────
//
// Only the subset needed for EIP-155 legacy transactions.

fn rlp_uint(n: u128) -> Vec<u8> {
    if n == 0 {
        return vec![0x80]; // RLP empty bytes = integer 0
    }
    let bytes = n.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(15);
    let trimmed = &bytes[start..];
    rlp_bytes(trimmed)
}

fn rlp_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.is_empty() {
        return vec![0x80];
    }
    if bytes.len() == 1 && bytes[0] < 0x80 {
        return bytes.to_vec();
    }
    if bytes.len() <= 55 {
        let mut out = vec![0x80u8 + bytes.len() as u8];
        out.extend_from_slice(bytes);
        return out;
    }
    let len_be = (bytes.len() as u64).to_be_bytes();
    let len_start = len_be.iter().position(|&b| b != 0).unwrap_or(7);
    let len_bytes = &len_be[len_start..];
    let mut out = vec![0xb7u8 + len_bytes.len() as u8];
    out.extend_from_slice(len_bytes);
    out.extend_from_slice(bytes);
    out
}

fn rlp_list(items: Vec<Vec<u8>>) -> Vec<u8> {
    let payload: Vec<u8> = items.into_iter().flatten().collect();
    if payload.len() <= 55 {
        let mut out = vec![0xc0u8 + payload.len() as u8];
        out.extend_from_slice(&payload);
        return out;
    }
    let len_be = (payload.len() as u64).to_be_bytes();
    let len_start = len_be.iter().position(|&b| b != 0).unwrap_or(7);
    let len_bytes = &len_be[len_start..];
    let mut out = vec![0xf7u8 + len_bytes.len() as u8];
    out.extend_from_slice(len_bytes);
    out.extend_from_slice(&payload);
    out
}

// ─── Log parsing ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct EthLog {
    /// Contract address that emitted this log.
    #[serde(default)]
    address: String,
    #[serde(rename = "blockNumber")]
    block_number: String,
    #[serde(rename = "transactionHash")]
    transaction_hash: String,
    #[serde(rename = "logIndex")]
    log_index: String,
    /// Indexed topics: topics[0] = event signature hash, topics[1..] = indexed params.
    #[serde(default)]
    topics: Option<Vec<String>>,
    data: String,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

fn decode_orchard_bundle_from_log_data(data_hex: &str) -> Result<OrchardStoredBundle> {
    let raw = hex::decode(strip_0x(data_hex)).context("log data is not valid hex")?;

    // Preferred format: ABI-encoded single `bytes` parameter containing UTF-8 JSON.
    if let Ok(tokens) = ethabi::decode(&[ethabi::ParamType::Bytes], &raw) {
        if let Some(ethabi::Token::Bytes(payload)) = tokens.first() {
            if let Ok(bundle) = serde_json::from_slice::<OrchardStoredBundle>(payload) {
                return Ok(bundle);
            }
        }
    }

    // Fallback format: raw UTF-8 JSON bytes directly in log data.
    serde_json::from_slice::<OrchardStoredBundle>(&raw)
        .context("log data is neither ABI(bytes-json) nor raw-json for OrchardStoredBundle")
}

// ─── Utilities ────────────────────────────────────────────────────────────────

fn parse_hex_u64(hex_str: &str) -> Result<u64> {
    u64::from_str_radix(strip_0x(hex_str), 16).map_err(|e| anyhow!(e))
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(strip_0x(s)).ok()?;
    bytes.try_into().ok()
}

fn parse_address20(s: &str) -> Option<[u8; 20]> {
    let bytes = hex::decode(strip_0x(s)).ok()?;
    bytes.try_into().ok()
}

fn normalize_hex_0x(s: &str) -> String {
    if s.starts_with("0x") || s.starts_with("0X") {
        s.to_owned()
    } else {
        format!("0x{s}")
    }
}

fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{
        advance_cursor, catchup_ranges, decode_orchard_bundle_from_log_data,
        encode_confirm_receipt_calldata, normalize_hex_0x, rlp_bytes, rlp_list, rlp_uint,
    };
    use privacy_core::types::OrchardStoredBundle;
    use sha3::{Digest, Keccak256};

    /// The indexer's empty frozen tree must publish the same `rt_frozen` the PERC20
    /// circuit/prover expect, and a freeze must change the root while the witness for
    /// a non-frozen cmx still opens to the live root.
    #[test]
    fn frozen_imt_root_matches_perc20_and_updates_on_freeze() {
        use privacy_core::commitment_tree::frozen::{
            fr_from_be_bytes, fr_to_le_hex, FrozenImt,
        };

        // Empty-blacklist root == poseidon_merkle_bn254::frozen_empty_tree_root.
        const EMPTY_ROOT_DEC: &str =
            "9079151408671112139333676443195611613776084922747126087146403043120709007371";
        let empty_be = primitive_u256_dec_to_be32(EMPTY_ROOT_DEC);
        let empty_fr = fr_from_be_bytes(&empty_be).unwrap();
        let mut t = FrozenImt::new();
        assert_eq!(fr_to_le_hex(t.root()), fr_to_le_hex(empty_fr));

        // A non-frozen cmx has a witness that opens to the current root.
        let cmx = fr_from_be_bytes(&primitive_u256_dec_to_be32("12345")).unwrap();
        assert!(t.non_membership_witness(cmx).is_some());

        // Freezing changes the root; the frozen cmx no longer has a witness.
        let root_before = t.root();
        assert!(t.insert(cmx));
        assert_ne!(t.root(), root_before);
        assert!(t.non_membership_witness(cmx).is_none());
    }

    /// Minimal decimal-uint256 → big-endian 32-byte parser for the test vector.
    fn primitive_u256_dec_to_be32(dec: &str) -> [u8; 32] {
        let mut bytes = vec![0u8; 32];
        for ch in dec.bytes() {
            let d = (ch - b'0') as u16;
            let mut carry = d;
            for b in bytes.iter_mut().rev() {
                let v = (*b as u16) * 10 + carry;
                *b = (v & 0xff) as u8;
                carry = v >> 8;
            }
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    fn sample_bundle() -> OrchardStoredBundle {
        OrchardStoredBundle {
            flags_orchard: 3,
            value_balance_orchard: 0,
            anchor_orchard: [0u8; 32],
            proofs_orchard: vec![1, 2, 3],
            actions: vec![],
            binding_sig_orchard: vec![0u8; 64],
            proof_bn254: None,
            pub_fields_bn254: None,
            binding_sig_bn254: None,
            value_balance_bn254: 0,
        }
    }

    #[test]
    fn normalize_hex_keeps_or_adds_prefix() {
        assert_eq!(normalize_hex_0x("abcd"), "0xabcd");
        assert_eq!(normalize_hex_0x("0xabcd"), "0xabcd");
    }

    #[test]
    fn decode_raw_json_log_data() {
        let bundle = sample_bundle();
        let raw_json = serde_json::to_vec(&bundle).expect("bundle should serialize");
        let data_hex = format!("0x{}", hex::encode(raw_json));
        let decoded =
            decode_orchard_bundle_from_log_data(&data_hex).expect("raw json bytes should decode");
        assert_eq!(decoded.flags_orchard, 3);
    }

    #[test]
    fn decode_abi_wrapped_json_log_data() {
        let bundle = sample_bundle();
        let json = serde_json::to_vec(&bundle).expect("bundle should serialize");
        let encoded = ethabi::encode(&[ethabi::Token::Bytes(json)]);
        let data_hex = format!("0x{}", hex::encode(encoded));
        let decoded = decode_orchard_bundle_from_log_data(&data_hex)
            .expect("abi wrapped json should decode");
        assert_eq!(decoded.flags_orchard, 3);
    }

    #[test]
    fn confirm_receipt_calldata_length_and_selector() {
        let cmx = [1u8; 32];
        let preimage = [2u8; 32];
        let root = [3u8; 32];
        let cd = encode_confirm_receipt_calldata(&cmx, &preimage, &root);
        assert_eq!(cd.len(), 4 + 32 + 32 + 32, "calldata should be 100 bytes");

        let expected_selector: [u8; 4] =
            Keccak256::digest(b"confirmReceipt(bytes32,bytes32,bytes32)")[..4]
                .try_into()
                .unwrap();
        assert_eq!(&cd[..4], &expected_selector, "selector mismatch");
        assert_eq!(&cd[4..36], &cmx, "cmx not encoded");
        assert_eq!(&cd[36..68], &preimage, "preimage not encoded");
        assert_eq!(&cd[68..100], &root, "root not encoded");
    }

    #[test]
    fn rlp_uint_zero_is_empty() {
        assert_eq!(rlp_uint(0), vec![0x80]);
    }

    #[test]
    fn rlp_uint_single_byte() {
        assert_eq!(rlp_uint(1), vec![0x01]);
        assert_eq!(rlp_uint(0x7f), vec![0x7f]);
    }

    #[test]
    fn rlp_uint_two_bytes() {
        // 0x100 = 256: big-endian [0x01, 0x00], length 2 → 0x82 0x01 0x00
        assert_eq!(rlp_uint(256), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn rlp_list_short() {
        // empty list → [0xc0]
        assert_eq!(rlp_list(vec![]), vec![0xc0]);
    }

    #[test]
    fn rlp_bytes_empty() {
        assert_eq!(rlp_bytes(&[]), vec![0x80]);
    }

    #[test]
    fn ack_hash_verification_roundtrip() {
        let secret = [42u8; 32];
        let hash: [u8; 32] = Keccak256::digest(secret).into();
        let recomputed: [u8; 32] = Keccak256::digest(secret).into();
        assert_eq!(hash, recomputed);
    }

    // ── Incremental catch-up gap-filler ─────────────────────────────────────
    //
    // Regression for "indexer stops advancing after backfill→WS live": the periodic
    // gap-filler must chunk `[next_block, head]` correctly and advance the cursor
    // monotonically so a flaky WS can no longer freeze `next_block`.

    #[test]
    fn catchup_ranges_already_caught_up_is_empty() {
        assert!(catchup_ranges(101, 100, 5_000).is_empty());
        assert!(catchup_ranges(1, 0, 5_000).is_empty());
    }

    #[test]
    fn catchup_ranges_single_block() {
        assert_eq!(catchup_ranges(0, 0, 5_000), vec![(0, 0)]);
        assert_eq!(catchup_ranges(42, 42, 5_000), vec![(42, 42)]);
    }

    #[test]
    fn catchup_ranges_chunks_are_contiguous_and_cover_everything() {
        let ranges = catchup_ranges(1, 12_000, 5_000);
        assert_eq!(ranges, vec![(1, 5_000), (5_001, 10_000), (10_001, 12_000)]);
        // Contiguous, non-overlapping, and fully covering [1, 12_000].
        assert_eq!(ranges.first().unwrap().0, 1);
        assert_eq!(ranges.last().unwrap().1, 12_000);
        for w in ranges.windows(2) {
            assert_eq!(w[0].1 + 1, w[1].0, "windows must be contiguous with no gap/overlap");
        }
    }

    #[test]
    fn catchup_ranges_zero_chunk_does_not_loop_forever() {
        // Guard: a misconfigured chunk of 0 returns empty instead of hanging.
        assert!(catchup_ranges(1, 100, 0).is_empty());
    }

    #[test]
    fn advance_cursor_moves_forward_never_backward() {
        // Normal advance: cursor jumps to head+1.
        assert_eq!(advance_cursor(50, 100), 101);
        // Never regress: a concurrent WS log / later backfill already moved it past head.
        assert_eq!(advance_cursor(200, 100), 200);
        // Idempotent at the boundary.
        assert_eq!(advance_cursor(101, 100), 101);
    }
}
