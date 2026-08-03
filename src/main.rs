use std::{
    collections::{HashMap, HashSet, VecDeque},
    convert::Infallible,
    net::SocketAddr,
    sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use axum::{
    extract::{DefaultBodyLimit, Query, State},
    http::{HeaderMap, Method, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    response::sse::{Event, KeepAlive, Sse},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use ff::{Field, PrimeField};
use futures_util::stream::{self, StreamExt};
use futures_util::SinkExt;
use halo2curves::bn256::Fr;
use k256::ecdsa::{RecoveryId, SigningKey};
use privacy_core::commitment_tree::frontier::{
    CmxConfirmWitnessInput, FrontierTree, CMX_CONFIRM_MAX_BATCH, CMX_CONFIRM_MAX_PROOFS_PER_TX,
};
use privacy_core::commitment_tree::frozen::{fr_from_be_bytes, fr_to_be_bytes};
use privacy_core::commitment_tree::poseidon::{merkle_compress, MERKLE_DEPTH_EVM};
use privacy_core::commitment_tree::OrchardCommitmentTree;
use privacy_core::ethereum::{
    bundle_actions_by_cmx,
    decode_note_added_log,
    decode_note_confirmed_log,
    // Batch-update model (off-chain tree): RootUpdated watermark + updateRoot crank calldata.
    decode_root_updated_log,
    decode_shield_completed_log,
    // WS-6: ERC20Shield pool discovery/verification + metadata (privacy-core 0.1.3).
    decode_shield_pool_created_log,
    decode_shielded_log,
    // Swap plan A (call-on-chain): initiate/join tx calldata is the canonical DA source for
    // swap legs; the indexer decodes it so wallets can trial-decrypt BEFORE joining.
    decode_swap_initiate_calldata,
    decode_swap_initiated_log,
    decode_swap_join_calldata,
    decode_swap_joined_log,
    decode_unshielded_log,
    encode_update_root_calldata,
    encode_update_roots_calldata,
    note_added_topic0_alternatives,
    note_confirmed_topic0_hex,
    root_updated_topic0_hex,
    shield_completed_topic0_hex,
    shield_pool_created_topic0_hex,
    shielded_topic0_hex,
    swap_cancelled_topic0_hex,
    swap_initiate_selector,
    swap_initiated_topic0_hex,
    swap_join_selector,
    swap_joined_topic0_hex,
    swap_settled_topic0_hex,
    unshielded_topic0_hex,
    BundleActionCiphertexts,
    DecodedShieldPoolCreated,
    PrivacyCallArgs,
    RootUpdateArgs,
};
use privacy_core::types::{OrchardIndexBatch, OrchardIndexedAbiNote};
use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use tokio::sync::{broadcast, RwLock, Semaphore};
use tokio_stream::wrappers::BroadcastStream;
use tokio_tungstenite::tungstenite::Message;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::timeout::TimeoutLayer;

/// BN254 Poseidon incremental tree (depth 32) with **zero leaves**, matching
/// `IncrementalMerkleTree.init()` / `PrivacyBTC` constructor (`_tree.root` on-chain).
/// See `contracts/IncrementalMerkleTree.sol` (`_empty(DEPTH)`).
///
/// Stored here in EVM/on-chain byte order (big-endian as returned by `activeRoot()`).
const EVM_EMPTY_IMT_ROOT: [u8; 32] = [
    0x2c, 0xbe, 0x96, 0x7b, 0x6b, 0xa6, 0xd0, 0xfa, 0xa4, 0xe8, 0x4e, 0xa6, 0x23, 0xd1, 0x1d, 0xc7,
    0x47, 0x85, 0x4f, 0xd3, 0x2e, 0xca, 0xa4, 0x8c, 0x72, 0x16, 0x35, 0x24, 0x3d, 0x37, 0xd7, 0x9f,
];

/// Returns the Poseidon BN254 Merkle root as a LE hex string, suitable for
/// `parse_fr_le()` in the prover witness builder.
///
/// Batch-update model (off-chain tree): the pool's `bundle()` only ENQUEUES new cmx;
/// a permissionless `updateRoot` crank folds them into the on-chain `confirmedRoot`
/// later. Anchors are Strategy A (`anchor == confirmedRoot`), so the root served to
/// provers MUST be the root of the CONFIRMED prefix of the local tree — leaves at
/// positions `>= confirmed_count` are still pending on-chain and must not be folded
/// into anchors or witness paths yet.
///
/// The watermark `confirmed_count` is event-derived (`NoteConfirmed` / `RootUpdated`,
/// replayed by the startup backfill), and the prefix root is computed from the SAME
/// local tree that serves `/merkle_path`, so the two stay mutually consistent.
fn http_root_hex(state: &SharedState) -> Option<String> {
    if state.tree_out_of_order {
        return None;
    }
    if state.confirmed_count > 0 {
        // Prefix root at the confirmed watermark (LE bytes, consistent with /merkle_path).
        // `None` here means the local tree has fewer leaves than the chain has confirmed
        // (mid-backfill or out-of-order): serve nothing rather than a wrong anchor.
        return state.tree.root_at(state.confirmed_count).map(hex::encode);
    }
    // Nothing confirmed — the on-chain confirmedRoot is the empty-tree root.
    let mut le = EVM_EMPTY_IMT_ROOT;
    le.reverse();
    Some(hex::encode(le))
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

const DEFAULT_MAX_BATCHES_IN_MEMORY: usize = 4_096;
const MAX_INCREMENTAL_REPLAY_MUTATIONS: usize = 8_192;

#[derive(Debug, Parser)]
#[command(
    name = "privacybtc-indexer",
    about = "Orchard bundle indexer for Ethereum logs"
)]
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
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_BIND",
        default_value = "127.0.0.1:8787"
    )]
    bind: String,
    #[arg(long, default_value_t = DEFAULT_MAX_BATCHES_IN_MEMORY)]
    max_batches_in_memory: usize,
    /// Path to a JSON file for persisting the last scanned block height.
    /// If the file exists on startup, `next_block` is restored from it (never
    /// going below --start-block). Updated after every successful scan chunk.
    #[arg(long, env = "PRIVACYBTC_INDEXER_STATE_FILE")]
    state_file: Option<String>,
    /// Start as a read-only shadow instance. The process must restore a fully
    /// validated PostgreSQL checkpoint; it never applies migrations, persists
    /// state, cranks roots, accepts runtime pool registration, or relayer writes.
    /// Trusted-factory discovery remains available so the shadow can mirror the
    /// production pool set without a separate address list.
    /// If warm-start validation fails, health remains 503 instead of replaying.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_SHADOW_MODE",
        default_value_t = false,
        value_parser = parse_bool_flag
    )]
    shadow_mode: bool,
    /// Apply PostgreSQL migrations and exit before constructing RPC, pool, or
    /// signer state. Used to prepare schema 0006 while the old primary remains
    /// online, before starting a read-only shadow.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_MIGRATE_ONLY",
        default_value_t = false,
        value_parser = parse_bool_flag
    )]
    migrate_only: bool,
    /// First block to scan when no checkpoint exists; resume never goes below this.
    #[arg(long, env = "PRIVACYBTC_START_BLOCK", default_value_t = 0)]
    start_block: u64,
    /// Hex-encoded secp256k1 private key for the indexer's crank signing account.
    /// Required when --crank is enabled.
    #[arg(long, env = "PRIVACYBTC_INDEXER_SIGNER_KEY")]
    signer_key: Option<String>,
    /// Run the permissionless `updateRoot` crank: watch every pool's pending cmx
    /// queue, generate `cmxconfirm_evm` batch proofs via the prover service, and
    /// submit `updateRoot` transactions. Requires --signer-key.
    #[arg(long, env = "PRIVACYBTC_INDEXER_CRANK", default_value_t = false, value_parser = parse_bool_flag)]
    crank: bool,
    /// Base URL of the privacy-prover service exposing POST /cmxconfirm/prove.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_CRANK_PROVER_URL",
        default_value = "http://127.0.0.1:8791"
    )]
    crank_prover_url: String,
    /// Bearer token for the shared generic prover's /cmxconfirm/prove endpoint.
    #[arg(long, env = "PRIVACYBTC_INDEXER_CRANK_PROVER_API_TOKEN")]
    crank_prover_api_token: Option<String>,
    /// Seconds between crank passes over the pools.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_CRANK_INTERVAL_SECS",
        default_value_t = 15
    )]
    crank_interval_secs: u64,
    /// Maximum unchanged CmxConfirm proofs folded into one `updateRoots`
    /// transaction. Each proof handles up to 8 queued commitments; valid range
    /// is 1..=4, so one transaction confirms at most 32 leaves.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_CRANK_MAX_PROOFS_PER_TX",
        default_value_t = 4usize
    )]
    crank_max_proofs_per_tx: usize,
    /// Hard gas cap for `updateRoot` (Groth16 verify + up to 8 confirms) and
    /// `updateRoots` (RLC verify + up to 32 confirms), and `syncBatchModel`
    /// (32 Poseidon folds). Every exact transaction is first estimated and
    /// padded; the signer fails closed above this cap.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_CRANK_GAS_LIMIT",
        default_value_t = 4_000_000u64
    )]
    gas_limit_update_root: u64,
    /// Safety margin applied to the exact crank `eth_estimateGas`, in basis
    /// points. Bounded to 10% at startup.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_CRANK_GAS_MARGIN_BPS",
        default_value_t = 200u64
    )]
    crank_gas_margin_bps: u64,
    /// Pools the signer may crank. Required and non-empty when --crank is enabled.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_CRANK_ALLOWED_POOLS",
        value_delimiter = ','
    )]
    crank_allowed_pool: Vec<String>,
    /// Maximum signed crank transactions in any rolling one-hour window.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_CRANK_MAX_TX_PER_HOUR",
        default_value_t = 0u64
    )]
    crank_max_tx_per_hour: u64,
    #[arg(long, env = "PRIVACYBTC_CHAIN_ID", default_value_t = 1u64)]
    chain_id: u64,
    /// Wire/storage protocol expected from every admitted pool. Protocol 3 is the
    /// Binding-Groth16 cutover and must never be mixed with protocol-2 calldata.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_EXPECTED_PROTOCOL_VERSION",
        default_value_t = 3u64
    )]
    expected_protocol_version: u64,
    /// Exact verifier-set fingerprint returned by `verifierSetId()` on every pool.
    /// This is release-bound and therefore intentionally has no default.
    #[arg(long, env = "PRIVACYBTC_INDEXER_EXPECTED_VERIFIER_SET_ID")]
    expected_verifier_set_id: String,
    /// Gas price in wei for crank transactions. Default: 1 Gwei.
    /// Networks with a higher minimum gas price must set this explicitly.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_GAS_PRICE",
        default_value_t = 1_000_000_000u64
    )]
    gas_price: u64,
    /// Override `NoteConfirmed(bytes32,bytes32)` topic0 (default: canonical hash).
    #[arg(long)]
    confirm_topic0: Option<String>,
    /// Path to a JSON file persisting pools registered at runtime via `POST /pools`.
    /// Re-loaded on startup so dynamically-added pools survive restarts.
    #[arg(long, env = "PRIVACYBTC_INDEXER_POOLS_REGISTRY")]
    pools_registry: Option<String>,
    /// Allow POST /pools. Production deployments normally disable this and rely
    /// on trusted-factory discovery plus explicit startup pools.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_ALLOW_RUNTIME_POOL_REGISTRATION",
        default_value_t = false,
        value_parser = parse_bool_flag
    )]
    allow_runtime_pool_registration: bool,
    /// Hard cap across startup, persisted and discovered pools.
    #[arg(long, env = "PRIVACYBTC_INDEXER_MAX_POOLS", default_value_t = 100usize)]
    max_pools: usize,
    /// Auto-discover pools by scanning `Perc20Created` chain-wide (no address
    /// filter) and registering each match automatically. With this on, the
    /// frontend never needs to call `POST /pools` — the indexer self-heals.
    #[arg(long, env = "PRIVACYBTC_INDEXER_DISCOVER_POOLS", default_value_t = false, value_parser = parse_bool_flag)]
    discover_pools: bool,
    /// Restrict auto-discovery to these issuer addresses (repeatable or comma-
    /// separated). Empty ⇒ discover every pERC20 on the chain.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_DISCOVER_ISSUER",
        value_delimiter = ','
    )]
    discover_issuer: Vec<String>,
    /// Trusted PERC20Factory addresses. Dynamic issuer-pool admission must be
    /// proven by a Perc20Deployed log emitted by one of these factories.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_TRUSTED_PERC20_FACTORIES",
        value_delimiter = ','
    )]
    trusted_perc20_factory: Vec<String>,
    /// Trusted ERC20ShieldFactory addresses. Dynamic shield-pool admission must
    /// be proven by a ShieldPoolDeployed log emitted by one of these factories.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_TRUSTED_SHIELD_FACTORIES",
        value_delimiter = ','
    )]
    trusted_shield_factory: Vec<String>,
    /// Explicitly trusted standalone pools that are not factory-deployed.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_TRUSTED_STATIC_POOLS",
        value_delimiter = ','
    )]
    trusted_static_pool: Vec<String>,
    /// Allowed keccak256 runtime code hashes for trusted factories.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_TRUSTED_FACTORY_CODEHASHES",
        value_delimiter = ','
    )]
    trusted_factory_codehash: Vec<String>,
    /// Allowed keccak256 runtime code hashes for admitted pools/proxies.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_TRUSTED_POOL_CODEHASHES",
        value_delimiter = ','
    )]
    trusted_pool_codehash: Vec<String>,
    /// Allowed runtime code hashes for implementations referenced by trusted beacons.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_TRUSTED_IMPLEMENTATION_CODEHASHES",
        value_delimiter = ','
    )]
    trusted_implementation_codehash: Vec<String>,
    /// Poll interval (seconds) for the auto-discovery scan.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_DISCOVER_POLL_SECS",
        default_value_t = 12
    )]
    discover_poll_secs: u64,
}

/// Lenient boolean parser for env/CLI flags so deployers can use 1/0/yes/no/on/off
/// in addition to true/false (docker-compose env_file commonly uses "1").
fn parse_bool_flag(s: &str) -> Result<bool, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "" | "0" | "false" | "no" | "off" => Ok(false),
        other => Err(format!(
            "invalid boolean '{other}' (use 1/0/true/false/yes/no)"
        )),
    }
}

// ─── Domain types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
struct ShieldAccounting {
    total_shielded_units: u128,
    total_shielded_wei: u128,
    total_unshielded_units: u128,
    total_unshielded_wei: u128,
}

impl ShieldAccounting {
    fn current_shielded_units(self) -> u128 {
        self.total_shielded_units
            .saturating_sub(self.total_unshielded_units)
    }

    fn current_shielded_wei(self) -> u128 {
        self.total_shielded_wei
            .saturating_sub(self.total_unshielded_wei)
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
    /// Last fully scanned Monad-finalized block and its canonical hash.
    ///
    /// Older checkpoints have neither field; startup performs a full finalized
    /// rebuild and writes them before incremental scanning resumes.
    last_finalized_block: Option<u64>,
    last_finalized_block_hash: Option<String>,
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
    /// (block, log_index) of the most recently appended leaf. Appends MUST be
    /// monotonic in this key — the tree is append-only and must match on-chain
    /// insertion order exactly, or every root it produces is invalid.
    last_leaf_key: Option<(u64, u64)>,
    /// True only when the loaded PostgreSQL checkpoint passed relational
    /// integrity checks and contains all fields required for warm-start.
    warm_start_candidate: bool,
    /// Observable startup path for shadow-cutover readiness checks.
    startup_source: String,
    /// Set when an out-of-order append was rejected: the tree is missing a
    /// leaf in the middle and must be rebuilt from chain (see catchup task).
    tree_out_of_order: bool,
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
    /// Confirmed cmx set (Phase 2 complete).
    confirmed_cmx: HashSet<[u8; 32]>,
    /// Batch-update watermark: number of leaves folded into the on-chain
    /// `confirmedRoot` (event-derived from `NoteConfirmed` positions and
    /// `RootUpdated.to_count`; rebuilt by the startup backfill replay).
    /// Leaves at positions `>= confirmed_count` are pending — excluded from
    /// `/root` anchors and `/merkle_path` witnesses.
    confirmed_count: u64,
    /// Restored confirmed frontier. This is populated by warm-start validation
    /// so the crank need not replay every confirmed leaf on the async runtime.
    confirmed_frontier: Option<FrontierTree>,
    /// Latest confirmed Orchard commitment tree root.
    /// Updated only when a NoteConfirmed event is processed (Phase 2).
    active_root: Option<[u8; 32]>,
    /// Tx hashes submitted by the relayer but whose events haven't been received
    /// via WebSocket yet. On WS reconnect, these are recovered via receipt lookup.
    pending_tx_hashes: VecDeque<String>,
    /// Parsed `bundle()` calldata per tx (for OVK `out_ciphertext` + `cv_net_x`).
    bundle_out_cache: HashMap<String, HashMap<[u8; 32], BundleActionCiphertexts>>,
    /// Ordered feed of compliance blacklist leaf deltas, ingested from on-chain
    /// `FrozenRootUpdated` events (frozen-tree-execution-plan PR2). The indexer no longer
    /// maintains the Frozen IMT or serves witnesses — wallets pull this feed and rebuild the
    /// tree locally. Append-only, in `(block_number, log_index)` order.
    frozen_updates: Vec<FrozenUpdate>,
}

// ─── Signing (ETH transaction relay) ─────────────────────────────────────────

struct SignerConfig {
    signing_key: SigningKey,
    address: [u8; 20],
    chain_id: u64,
    gas_price: u64,
}

impl SignerConfig {
    fn from_hex_key(hex_key: &str, chain_id: u64, gas_price: u64) -> Result<Self> {
        let key_bytes = hex::decode(strip_0x(hex_key)).context("invalid signer key hex")?;
        let signing_key =
            SigningKey::from_slice(&key_bytes).map_err(|e| anyhow!("invalid signing key: {e}"))?;
        let address = eth_address_from_signing_key(&signing_key);
        Ok(Self {
            signing_key,
            address,
            chain_id,
            gas_price,
        })
    }
}

// ─── App context ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppContext {
    state: Arc<RwLock<SharedState>>,
    contract_address: String,
    persist: Persist,
    /// Shared ordering lock used by chain replay and persistence-relevant HTTP writes.
    ingest_lock: Arc<tokio::sync::Mutex<()>>,
    batch_tx: broadcast::Sender<BatchEnvelope>,
    /// Triggered by post_notify_tx to wake the event loop for immediate recovery.
    recover_trigger: Arc<tokio::sync::Notify>,
    /// Persistent backend, used by `/batches` to serve history evicted from the
    /// in-memory ring (the ring is a hot cache, NOT the source of truth).
    backend: StateBackend,
    shadow_mode: bool,
}

/// Everything required to construct a per-pool `AppContext` and spawn its WS
/// event loop. Shared by startup (CLI pools) and the runtime `POST /pools`
/// endpoint so both paths build pools identically.
struct PoolBuilder {
    rpc: RpcClient,
    wss_url: String,
    pg_pool: Option<sqlx::PgPool>,
    state_file_base: Option<String>,
    /// When true, derive a unique JSON state file per pool from `state_file_base`.
    /// Always true once multiple pools exist or a runtime registry is enabled.
    derive_state_file: bool,
    max_batches: usize,
    note_confirmed_topic0: String,
    shadow_mode: bool,
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
    /// spawn the WS event loop.
    async fn build(&self, contract_address: &str, start_block: u64) -> AppContext {
        let backend = match &self.pg_pool {
            Some(p) => StateBackend::Pgsql(p.clone()),
            None => StateBackend::Json(self.state_file_for(contract_address)),
        };
        let mut ck = backend.load(contract_address, start_block).await;
        if matches!(&backend, StateBackend::Pgsql(_))
            && ck.last_finalized_block.is_some()
            && !ck.warm_start_candidate
        {
            // A pre-v1 writer commits archive mutations and its coalesced
            // checkpoint in separate transactions. Retry a few read-only
            // snapshots so a busy but healthy old primary is not rejected only
            // because the first sample landed inside that short tail window.
            for attempt in 1..=5 {
                tokio::time::sleep(Duration::from_millis(250)).await;
                ck = backend.load(contract_address, start_block).await;
                if ck.warm_start_candidate {
                    println!(
                        "[indexer][{}] checkpoint became consistent on snapshot retry {attempt}",
                        &contract_address[..10.min(contract_address.len())]
                    );
                    break;
                }
            }
        }
        // A fresh checkpoint restarts sequence numbers from 0; a leftover batch
        // archive from an earlier run would collide with re-issued seqs.
        if ck.latest_seq == 0 {
            backend.reset_archive();
        }
        let persist_paused = Arc::new(AtomicBool::new(false));
        let persist_epoch = Arc::new(AtomicU64::new(0));
        let backend_write_lock = Arc::new(tokio::sync::Mutex::new(()));
        let (persist_tx, persist_rx) =
            tokio::sync::watch::channel(std::sync::Arc::new(PersistRequest {
                epoch: 0,
                snapshot: CheckpointSnapshot::from_checkpoint_data(&ck),
            }));
        if !self.shadow_mode {
            tokio::spawn(persist_task(
                backend.clone(),
                contract_address.to_string(),
                persist_rx,
                Arc::clone(&persist_paused),
                Arc::clone(&persist_epoch),
                Arc::clone(&backend_write_lock),
            ));
        }
        let persist = Persist {
            tx: persist_tx,
            paused: Arc::clone(&persist_paused),
            epoch: persist_epoch,
            read_only: self.shadow_mode,
        };

        // Rebuild the in-memory tree. A warm candidate is pre-hashed in a
        // blocking worker so root/path caches and the crank frontier are hot
        // before canonical health can turn green.
        let mut restored_frontier = None;
        let mut restored_tree = OrchardCommitmentTree::new();
        if ck.warm_start_candidate {
            let leaves = ck.cmx_ordered.clone();
            let confirmed_count = ck.confirmed_count;
            match tokio::task::spawn_blocking(move || {
                checkpoint_tree_and_frontier(&leaves, confirmed_count)
            })
            .await
            {
                Ok(Ok((tree, frontier))) => {
                    restored_tree = tree;
                    restored_frontier = Some(frontier);
                }
                Ok(Err(error)) => {
                    eprintln!(
                        "[indexer][{}] checkpoint tree prewarm rejected: {error:#}",
                        &contract_address[..10.min(contract_address.len())]
                    );
                    ck.warm_start_candidate = false;
                }
                Err(error) => {
                    eprintln!(
                        "[indexer][{}] checkpoint tree worker failed: {error}",
                        &contract_address[..10.min(contract_address.len())]
                    );
                    ck.warm_start_candidate = false;
                }
            }
        }
        if restored_frontier.is_none() {
            for cmx_be in &ck.cmx_ordered {
                restored_tree.append(*cmx_be);
            }
        }
        let restored_cmx_to_pos: HashMap<[u8; 32], u64> = ck
            .cmx_ordered
            .iter()
            .enumerate()
            .map(|(position, cmx)| (*cmx, position as u64))
            .collect();
        if !ck.cmx_ordered.is_empty() {
            println!(
                "[indexer][{}] rebuilt tree with {} leaves through block {}",
                &contract_address[..10.min(contract_address.len())],
                ck.cmx_ordered.len(),
                ck.next_block.saturating_sub(1)
            );
        }

        let shared = Arc::new(RwLock::new(SharedState {
            next_block: ck.next_block,
            last_finalized_block: ck.last_finalized_block,
            last_finalized_block_hash: ck.last_finalized_block_hash,
            latest_seq: ck.latest_seq,
            seen_event_ids: HashSet::new(),
            confirm_seen_ids: HashSet::new(),
            shield_seen_ids: HashSet::new(),
            accounting_seen_ids: HashSet::new(),
            shield_accounting: ck.shield_accounting,
            last_leaf_key: ck.last_leaf_key,
            warm_start_candidate: ck.warm_start_candidate,
            startup_source: "pending".to_string(),
            // Startup state is untrusted until the persisted finalized cursor
            // has been checked and the finalized replay completes.
            tree_out_of_order: true,
            batches: ck.batches,
            max_batches: self.max_batches,
            tree: restored_tree,
            cmx_to_position: restored_cmx_to_pos,
            cmx_ordered: ck.cmx_ordered,
            confirmed_cmx: ck.confirmed_cmx,
            confirmed_count: ck.confirmed_count,
            confirmed_frontier: restored_frontier,
            active_root: ck.active_root,
            pending_tx_hashes: ck.pending_tx_hashes,
            bundle_out_cache: HashMap::new(),
            frozen_updates: ck.frozen_updates,
        }));

        let (batch_tx, _) = broadcast::channel::<BatchEnvelope>(256);
        let recover_trigger = Arc::new(tokio::sync::Notify::new());

        let ingest_lock = Arc::new(tokio::sync::Mutex::new(()));
        let poll_ctx = PollContext {
            rpc: self.rpc.clone(),
            wss_url: self.wss_url.clone(),
            contract_address: contract_address.to_string(),
            note_confirmed_topic0: self.note_confirmed_topic0.clone(),
            shared: Arc::clone(&shared),
            persist: persist.clone(),
            batch_tx: batch_tx.clone(),
            recover_trigger: Arc::clone(&recover_trigger),
            start_block,
            ingest_lock: Arc::clone(&ingest_lock),
            backend: backend.clone(),
            backend_write_lock,
            rebuild_generation: Arc::new(RwLock::new(None)),
            rebuild_mutations: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            incremental_replay_mutations: Arc::new(tokio::sync::Mutex::new(None)),
            broadcast_paused: Arc::new(AtomicBool::new(false)),
            shadow_mode: self.shadow_mode,
        };
        let addr_label = contract_address.to_string();
        tokio::spawn(async move {
            if let Err(e) = run_event_loop(poll_ctx).await {
                eprintln!("indexer event loop stopped [{addr_label}]: {e:#}");
            }
        });

        AppContext {
            state: shared,
            contract_address: contract_address.to_string(),
            persist,
            ingest_lock,
            batch_tx,
            recover_trigger,
            backend,
            shadow_mode: self.shadow_mode,
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
    admission: Arc<PoolAdmissionPolicy>,
    add_lock: Arc<tokio::sync::Mutex<()>>,
    max_pools: usize,
    allow_runtime_pool_registration: bool,
    /// Fail health until at least one configured/discovered pool is ready.
    require_pool: bool,
    registry_file: Option<String>,
    /// Cache of addresses already verified as genuine pERC20 assets (lowercase
    /// 0x). Avoids a repeat `eth_getLogs` on every re-registration attempt.
    verified_pools: Arc<RwLock<HashSet<String>>>,
    verified_pool_provenance: Arc<RwLock<HashMap<String, PoolProvenance>>>,
    /// Cache of per-pool metadata (type/scale/underlying/name/symbol/decimals),
    /// keyed by lowercase 0x address. Populated lazily from the pool's genesis event.
    metadata: Arc<RwLock<HashMap<String, PoolMeta>>>,
    /// Chain-global cache of block number → unix timestamp (seconds). Block
    /// timestamps are immutable, so entries never expire. Populated lazily when
    /// `/txs` ages a transaction; shared across all pools (one chain per indexer).
    block_time: Arc<RwLock<HashMap<u64, u64>>>,
    /// Cache of tx hash (lowercase 0x) → public tx facts (op type + shield/unshield
    /// amount + unshield recipient), derived from immutable calldata. Cached forever;
    /// populated lazily when `/txs` classifies a page.
    tx_meta: Arc<RwLock<HashMap<String, TxMeta>>>,
    /// Bearer token required by admin-only write endpoints such as POST /frozen.
    admin_token: Option<Arc<str>>,
    /// Separate token used only by the relayer to wake receipt recovery.
    relayer_token: Option<Arc<str>>,
    /// Bounds expensive runtime registration RPC work.
    write_semaphore: Arc<Semaphore>,
}

#[derive(Clone, Debug)]
struct PoolAdmissionPolicy {
    perc20_factories: HashSet<String>,
    shield_factories: HashSet<String>,
    static_pools: HashSet<String>,
    factory_codehashes: HashSet<String>,
    pool_codehashes: HashSet<String>,
    implementation_codehashes: HashSet<String>,
    expected_protocol_version: u64,
    expected_verifier_set_id: [u8; 32],
}

#[derive(Clone, Debug)]
enum PoolProvenance {
    Static,
    Factory(String),
}

impl PoolAdmissionPolicy {
    fn from_cli(cli: &Cli) -> Result<Self> {
        if !cli.discover_issuer.is_empty() {
            return Err(anyhow!(
                "PRIVACYBTC_INDEXER_DISCOVER_ISSUER is no longer an admission control; configure trusted factories instead"
            ));
        }
        let addresses = |name: &str, values: &[String]| -> Result<HashSet<String>> {
            values
                .iter()
                .filter(|v| !v.trim().is_empty())
                .map(|v| {
                    if parse_address20(v).is_none() {
                        return Err(anyhow!("{name} contains invalid address: {v}"));
                    }
                    Ok(normalize_hex_0x(v).to_lowercase())
                })
                .collect()
        };
        let hashes = |name: &str, values: &[String]| -> Result<HashSet<String>> {
            values
                .iter()
                .filter(|v| !v.trim().is_empty())
                .map(|v| {
                    let clean = strip_0x(v);
                    if clean.len() != 64 || !clean.bytes().all(|b| b.is_ascii_hexdigit()) {
                        return Err(anyhow!("{name} contains invalid bytes32 hash: {v}"));
                    }
                    Ok(format!("0x{}", clean.to_ascii_lowercase()))
                })
                .collect()
        };
        let policy = Self {
            perc20_factories: addresses(
                "PRIVACYBTC_INDEXER_TRUSTED_PERC20_FACTORIES",
                &cli.trusted_perc20_factory,
            )?,
            shield_factories: addresses(
                "PRIVACYBTC_INDEXER_TRUSTED_SHIELD_FACTORIES",
                &cli.trusted_shield_factory,
            )?,
            static_pools: addresses(
                "PRIVACYBTC_INDEXER_TRUSTED_STATIC_POOLS",
                &cli.trusted_static_pool,
            )?,
            factory_codehashes: hashes(
                "PRIVACYBTC_INDEXER_TRUSTED_FACTORY_CODEHASHES",
                &cli.trusted_factory_codehash,
            )?,
            pool_codehashes: hashes(
                "PRIVACYBTC_INDEXER_TRUSTED_POOL_CODEHASHES",
                &cli.trusted_pool_codehash,
            )?,
            implementation_codehashes: hashes(
                "PRIVACYBTC_INDEXER_TRUSTED_IMPLEMENTATION_CODEHASHES",
                &cli.trusted_implementation_codehash,
            )?,
            expected_protocol_version: cli.expected_protocol_version,
            expected_verifier_set_id: parse_bytes32_strict(
                "PRIVACYBTC_INDEXER_EXPECTED_VERIFIER_SET_ID",
                &cli.expected_verifier_set_id,
            )?,
        };
        if policy.expected_protocol_version != 3 {
            return Err(anyhow!(
                "PRIVACYBTC_INDEXER_EXPECTED_PROTOCOL_VERSION must be 3 for Binding Groth16"
            ));
        }
        if (!policy.perc20_factories.is_empty() || !policy.shield_factories.is_empty())
            && policy.factory_codehashes.is_empty()
        {
            return Err(anyhow!(
                "trusted factories require PRIVACYBTC_INDEXER_TRUSTED_FACTORY_CODEHASHES"
            ));
        }
        if (!policy.perc20_factories.is_empty()
            || !policy.shield_factories.is_empty()
            || !policy.static_pools.is_empty())
            && policy.pool_codehashes.is_empty()
        {
            return Err(anyhow!(
                "trusted pools require PRIVACYBTC_INDEXER_TRUSTED_POOL_CODEHASHES"
            ));
        }
        if (!policy.perc20_factories.is_empty() || !policy.shield_factories.is_empty())
            && policy.implementation_codehashes.is_empty()
        {
            return Err(anyhow!(
                "trusted factories require PRIVACYBTC_INDEXER_TRUSTED_IMPLEMENTATION_CODEHASHES"
            ));
        }
        Ok(policy)
    }

    fn discovery_sources(&self) -> Vec<(String, String)> {
        self.perc20_factories
            .iter()
            .map(|f| (f.clone(), perc20_deployed_topic0()))
            .chain(
                self.shield_factories
                    .iter()
                    .map(|f| (f.clone(), shield_pool_deployed_topic0())),
            )
            .collect()
    }
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
    async fn validate_trust_roots(&self) -> Result<()> {
        for factory in self
            .admission
            .perc20_factories
            .iter()
            .chain(self.admission.shield_factories.iter())
        {
            let hash = self.builder.rpc.runtime_codehash(factory).await?;
            if !self.admission.factory_codehashes.contains(&hash) {
                return Err(anyhow!(
                    "trusted factory {factory} has unapproved runtime codehash {hash}"
                ));
            }
        }
        Ok(())
    }

    /// Validate every admission path before constructing an AppContext. This is
    /// deliberately separate from `add_pool`, which only mutates the registry.
    async fn add_admitted_pool(
        &self,
        raw_addr: &str,
        start_block: u64,
        persist: bool,
    ) -> Result<bool> {
        let address = normalize_hex_0x(raw_addr).to_lowercase();
        if !self.verify_pool_admitted(&address).await? {
            return Err(anyhow!(
                "pool {address} is not from a trusted factory or explicit static allowlist"
            ));
        }
        self.add_pool(&address, start_block, persist).await
    }

    /// Add a pool if not already present. Returns `Ok(true)` when newly added and
    /// `Ok(false)` when it already existed (idempotent). When `persist` is set the
    /// pool is recorded in the registry file so it is re-added on restart.
    async fn add_pool(&self, raw_addr: &str, start_block: u64, persist: bool) -> Result<bool> {
        let _add_guard = self.add_lock.lock().await;
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
        if self.pools.read().await.len() >= self.max_pools {
            return Err(anyhow!(
                "pool registry limit reached (max={})",
                self.max_pools
            ));
        }
        let ctx = self.builder.build(&address, start_block).await;
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

    /// Confirm pool provenance from a trusted factory event or the explicit
    /// standalone allowlist, and pin its runtime bytecode hash. A pool's own
    /// self-emitted genesis event is supplemental metadata, never trust evidence.
    async fn verify_pool_admitted(&self, pool_lc: &str) -> Result<bool> {
        if self.verified_pools.read().await.contains(pool_lc) {
            return Ok(true);
        }
        if let Some(provenance) = self.resolve_pool_provenance(pool_lc).await? {
            self.ensure_pool_protocol(pool_lc).await?;
            self.verified_pools
                .write()
                .await
                .insert(pool_lc.to_string());
            self.verified_pool_provenance
                .write()
                .await
                .insert(pool_lc.to_string(), provenance);
            return Ok(true);
        }
        Ok(false)
    }

    /// Re-evaluate mutable trust facts (especially beacon implementation) without
    /// consulting the admission cache. The signer calls this before every crank.
    async fn verify_pool_current(&self, pool_lc: &str) -> Result<bool> {
        let codehash = self.builder.rpc.runtime_codehash(pool_lc).await?;
        if !self.admission.pool_codehashes.contains(&codehash) {
            return Ok(false);
        }
        self.ensure_pool_protocol(pool_lc).await?;
        let provenance = match self
            .verified_pool_provenance
            .read()
            .await
            .get(pool_lc)
            .cloned()
        {
            Some(value) => value,
            None => match self.resolve_pool_provenance(pool_lc).await? {
                Some(value) => value,
                None => return Ok(false),
            },
        };
        match provenance {
            PoolProvenance::Static => Ok(true),
            PoolProvenance::Factory(factory) => {
                self.builder
                    .rpc
                    .pool_uses_factory_beacon(
                        &factory,
                        pool_lc,
                        &self.admission.implementation_codehashes,
                    )
                    .await
            }
        }
    }

    async fn resolve_pool_provenance(&self, pool_lc: &str) -> Result<Option<PoolProvenance>> {
        let codehash = self.builder.rpc.runtime_codehash(pool_lc).await?;
        if !self.admission.pool_codehashes.contains(&codehash) {
            return Ok(None);
        }
        if self.admission.static_pools.contains(pool_lc) {
            return Ok(Some(PoolProvenance::Static));
        }
        for (factory, topic0) in self.admission.discovery_sources() {
            if self
                .builder
                .rpc
                .was_pool_deployed_by(&factory, pool_lc, &topic0)
                .await?
                && self
                    .builder
                    .rpc
                    .pool_uses_factory_beacon(
                        &factory,
                        pool_lc,
                        &self.admission.implementation_codehashes,
                    )
                    .await?
            {
                return Ok(Some(PoolProvenance::Factory(factory)));
            }
        }
        Ok(None)
    }

    /// Bind every ingestion/crank target to the exact protocol/verifier set in
    /// the coordinated release. A codehash allowlist alone cannot distinguish a
    /// pool initialized with different immutable verifier addresses.
    async fn ensure_pool_protocol(&self, pool_lc: &str) -> Result<()> {
        let version_word = self
            .builder
            .rpc
            .eth_call_word(pool_lc, eth_selector(b"protocolVersion()"))
            .await
            .with_context(|| format!("read protocolVersion() from pool {pool_lc}"))?;
        if version_word[..24].iter().any(|b| *b != 0) {
            return Err(anyhow!(
                "pool {pool_lc} returned a non-canonical protocolVersion word"
            ));
        }
        let version = u64::from_be_bytes(version_word[24..].try_into().expect("8-byte suffix"));
        if version != self.admission.expected_protocol_version {
            return Err(anyhow!(
                "pool {pool_lc} protocolVersion mismatch: expected {}, got {version}",
                self.admission.expected_protocol_version
            ));
        }

        let verifier_set_id = self
            .builder
            .rpc
            .eth_call_word(pool_lc, eth_selector(b"verifierSetId()"))
            .await
            .with_context(|| format!("read verifierSetId() from pool {pool_lc}"))?;
        if verifier_set_id != self.admission.expected_verifier_set_id {
            return Err(anyhow!(
                "pool {pool_lc} verifierSetId mismatch: expected 0x{}, got 0x{}",
                hex::encode(self.admission.expected_verifier_set_id),
                hex::encode(verifier_set_id)
            ));
        }
        Ok(())
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
                self.metadata
                    .write()
                    .await
                    .insert(pool_lc.to_string(), meta.clone());
                Some(meta)
            }
            Ok(None) => None,
            Err(e) => {
                eprintln!("[indexer] metadata fetch for {pool_lc} failed: {e:#}");
                None
            }
        }
    }

    /// Resolve unix timestamps (seconds) for a set of block numbers, using the
    /// immutable block-time cache and fetching any misses from the chain once.
    /// Missing/unfetchable blocks are simply absent from the returned map, so the
    /// explorer degrades to showing the block number rather than failing.
    async fn block_times(&self, blocks: &[u64]) -> HashMap<u64, u64> {
        // Which blocks aren't cached yet?
        let missing: Vec<u64> = {
            let cache = self.block_time.read().await;
            blocks
                .iter()
                .copied()
                .filter(|b| !cache.contains_key(b))
                .collect()
        };
        if !missing.is_empty() {
            // Fetch misses concurrently (bounded), so a cold page doesn't serialize
            // one round-trip per block. Failures are left uncached to retry later
            // (a block's timestamp is transient-fetchable, not a permanent "no").
            let fetched: Vec<(u64, u64)> = stream::iter(missing.into_iter().map(|b| async move {
                self.builder
                    .rpc
                    .get_block_timestamp(b)
                    .await
                    .ok()
                    .map(|ts| (b, ts))
            }))
            .buffer_unordered(8)
            .filter_map(|x| async move { x })
            .collect()
            .await;
            if !fetched.is_empty() {
                let mut cache = self.block_time.write().await;
                for (b, ts) in fetched {
                    cache.insert(b, ts);
                }
                // Build this page's result BEFORE bounding, so eviction can't drop a
                // block we just fetched. Bound after: the servable window is the batch
                // ring, but this cache would otherwise keep every block ever served;
                // values are immutable so evicting is free — a re-served block re-fetches.
                let result = blocks
                    .iter()
                    .filter_map(|b| cache.get(b).map(|ts| (*b, *ts)))
                    .collect();
                bound_cache(&mut cache, BLOCK_TIME_CACHE_CAP);
                return result;
            }
        }
        let cache = self.block_time.read().await;
        blocks
            .iter()
            .filter_map(|b| cache.get(b).map(|ts| (*b, *ts)))
            .collect()
    }

    /// Classify tx op types by function selector, using the immutable per-tx cache
    /// and fetching any misses once. Unrecognized/unfetchable txs are absent from
    /// the map, so the explorer shows "unknown" rather than a wrong label.
    async fn tx_metas(&self, hashes: &[String]) -> HashMap<String, TxMeta> {
        let missing: Vec<String> = {
            let cache = self.tx_meta.read().await;
            hashes
                .iter()
                .filter(|h| !cache.contains_key(*h))
                .cloned()
                .collect()
        };
        if !missing.is_empty() {
            // Fetch inputs concurrently (bounded) and parse public facts from calldata.
            // A mined tx's calldata is immutable, so cache the result — INCLUDING an
            // unrecognized default (op=None) — so it's never re-fetched. Un-mined
            // (`Ok(None)`) and transient RPC errors are left uncached, so only they retry.
            let fetched: Vec<(String, TxMeta)> =
                stream::iter(missing.into_iter().map(|h| async move {
                    match self.builder.rpc.get_transaction_input_from(&h).await {
                        Ok(Some((input, from))) => {
                            let mut m = parse_tx_meta(&input);
                            // The depositor/issuer is public for shield & mint (they add
                            // value from a public balance); a hidden note funds the others.
                            if matches!(m.op, Some("shield") | Some("mint")) {
                                m.sender = Some(from);
                            }
                            Some((h, m))
                        }
                        _ => None,
                    }
                }))
                .buffer_unordered(8)
                .filter_map(|x| async move { x })
                .collect()
                .await;
            if !fetched.is_empty() {
                let mut cache = self.tx_meta.write().await;
                for (h, m) in fetched {
                    cache.insert(h, m);
                }
                // Build the result BEFORE bounding so a just-fetched key can't be
                // evicted out of this page's response.
                let result = hashes
                    .iter()
                    .filter_map(|h| cache.get(h).map(|m| (h.clone(), m.clone())))
                    .collect();
                bound_cache(&mut cache, TX_META_CACHE_CAP);
                return result;
            }
        }
        let cache = self.tx_meta.read().await;
        hashes
            .iter()
            .filter_map(|h| cache.get(h).map(|m| (h.clone(), m.clone())))
            .collect()
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
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "no pools configured".to_owned(),
                    )
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
    let mut reg = PoolsRegistryFile {
        pools: load_pools_registry(path),
    };
    let norm = normalize_hex_0x(address);
    let mut changed = false;
    if let Some(entry) = reg
        .pools
        .iter_mut()
        .find(|e| normalize_hex_0x(&e.address) == norm)
    {
        if entry.address != norm {
            entry.address = norm.clone();
            changed = true;
        }
        if start_block != 0 && entry.start_block != start_block {
            entry.start_block = start_block;
            changed = true;
        }
    } else {
        reg.pools.push(PoolRegistryEntry {
            address: norm,
            start_block,
        });
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
    /// Contract address of the pool to query. Omit to use the primary pool.
    pool: Option<String>,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    next_block: u64,
    canonical: bool,
    /// `pending`, `checkpoint`, `full_replay`, or a fail-closed rejection state.
    startup_source: String,
    shadow_mode: bool,
    last_finalized_block: Option<u64>,
    last_finalized_block_hash: Option<String>,
    latest_seq: u64,
    cached_batches: usize,
    confirmed_notes: usize,
    /// Confirmed root (LE hex) at the batch-update watermark. This is what /root returns.
    active_root_hex: Option<String>,
    /// Local Poseidon tree root over ALL ingested leaves, pending included (LE hex).
    /// Equals active_root only when nothing is pending.
    local_tree_root_hex: Option<String>,
    tree_size: u64,
    /// Leaves folded into the on-chain `confirmedRoot` (batch-update watermark).
    confirmed_count: u64,
    /// Leaves ingested locally but not yet confirmed on-chain (`tree_size - confirmed_count`).
    pending_cmx: u64,
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
    /// CONFIRMED root (LE hex) — the only valid Strategy A anchor.
    root_hex: Option<String>,
    /// Total ingested leaves (confirmed + pending).
    tree_size: u64,
    /// Leaves folded into the on-chain `confirmedRoot`; `root_hex` covers exactly these.
    confirmed_count: u64,
}

// ─── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    // Load a local `.env` (if present) before parsing, so CLI flags with `env = …`
    // pick up values from the environment / docker-compose env_file.
    let _ = dotenvy::dotenv();
    let cli = Cli::parse();
    let bind: SocketAddr = cli.bind.parse().context("invalid --bind address")?;
    if cli.migrate_only && cli.shadow_mode {
        return Err(anyhow!(
            "migrate-only and shadow mode are mutually exclusive"
        ));
    }
    if cli.migrate_only && cli.database_url.is_none() {
        return Err(anyhow!(
            "migrate-only requires PRIVACYBTC_INDEXER_DATABASE_URL"
        ));
    }
    if cli.shadow_mode {
        if cli.database_url.is_none() {
            return Err(anyhow!(
                "shadow mode requires PRIVACYBTC_INDEXER_DATABASE_URL"
            ));
        }
        if cli.crank || cli.signer_key.is_some() {
            return Err(anyhow!(
                "shadow mode forbids crank and signer configuration"
            ));
        }
        if cli.allow_runtime_pool_registration {
            return Err(anyhow!("shadow mode forbids runtime pool registration"));
        }
    }

    let signer = if cli.migrate_only {
        None
    } else {
        match &cli.signer_key {
            Some(key) => {
                let cfg = SignerConfig::from_hex_key(key, cli.chain_id, cli.gas_price)?;
                let addr_hex = hex::encode(cfg.address);
                println!("indexer signer account: 0x{addr_hex}");
                Some(Arc::new(cfg))
            }
            None => None,
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
            let pool = sqlx::PgPool::connect(url)
                .await
                .context("connect PostgreSQL")?;
            if cli.shadow_mode {
                sqlx::query(
                    "SELECT confirmed_count, last_leaf_block, last_leaf_log_index, checkpoint_version \
                     FROM indexer_meta LIMIT 0",
                )
                .execute(&pool)
                .await
                .context("shadow mode requires migration 0006_warm_checkpoint")?;
                println!(
                    "[indexer] state backend: PostgreSQL read-only shadow (migrations not applied)"
                );
            } else {
                sqlx::migrate!("./migrations")
                    .run(&pool)
                    .await
                    .context("run migrations")?;
                println!("[indexer] state backend: PostgreSQL (migrations applied)");
            }
            Some(pool)
        }
        None => {
            println!("[indexer] state backend: JSON file");
            None
        }
    };
    if cli.migrate_only {
        println!("[indexer] migrations complete; exiting migrate-only mode");
        return Ok(());
    }

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
        pg_pool: pg_pool.clone(),
        state_file_base: cli.state_file.clone(),
        derive_state_file,
        max_batches: cli.max_batches_in_memory,
        note_confirmed_topic0: note_confirmed.clone(),
        shadow_mode: cli.shadow_mode,
    });

    let admission = Arc::new(PoolAdmissionPolicy::from_cli(&cli)?);
    if cli.max_pools == 0 {
        return Err(anyhow!(
            "PRIVACYBTC_INDEXER_MAX_POOLS must be greater than zero"
        ));
    }
    if cli.crank {
        if cli.crank_allowed_pool.is_empty() {
            return Err(anyhow!(
                "--crank requires PRIVACYBTC_INDEXER_CRANK_ALLOWED_POOLS"
            ));
        }
        if cli.crank_max_tx_per_hour == 0 {
            return Err(anyhow!(
                "--crank requires PRIVACYBTC_INDEXER_CRANK_MAX_TX_PER_HOUR > 0"
            ));
        }
        if cli.gas_limit_update_root == 0 {
            return Err(anyhow!(
                "--crank requires PRIVACYBTC_INDEXER_CRANK_GAS_LIMIT > 0"
            ));
        }
        if !(1..=CMX_CONFIRM_MAX_PROOFS_PER_TX).contains(&cli.crank_max_proofs_per_tx) {
            return Err(anyhow!(
                "PRIVACYBTC_INDEXER_CRANK_MAX_PROOFS_PER_TX must be 1..={CMX_CONFIRM_MAX_PROOFS_PER_TX}"
            ));
        }
        if cli.crank_gas_margin_bps > MAX_CRANK_GAS_MARGIN_BPS {
            return Err(anyhow!(
                "PRIVACYBTC_INDEXER_CRANK_GAS_MARGIN_BPS must be <= {MAX_CRANK_GAS_MARGIN_BPS}"
            ));
        }
        if cli
            .crank_prover_api_token
            .as_deref()
            .map(str::len)
            .unwrap_or(0)
            < 32
        {
            return Err(anyhow!(
                "--crank requires PRIVACYBTC_INDEXER_CRANK_PROVER_API_TOKEN with at least 32 characters"
            ));
        }
    }
    let registry = PoolRegistry {
        pools: Arc::new(RwLock::new(HashMap::new())),
        primary: Arc::new(RwLock::new(None)),
        builder,
        admission,
        add_lock: Arc::new(tokio::sync::Mutex::new(())),
        max_pools: cli.max_pools,
        allow_runtime_pool_registration: cli.allow_runtime_pool_registration,
        require_pool: cli.shadow_mode || cli.discover_pools || !cli.contract_address.is_empty(),
        registry_file: cli.pools_registry.clone(),
        verified_pools: Arc::new(RwLock::new(HashSet::new())),
        verified_pool_provenance: Arc::new(RwLock::new(HashMap::new())),
        metadata: Arc::new(RwLock::new(HashMap::new())),
        block_time: Arc::new(RwLock::new(HashMap::new())),
        tx_meta: Arc::new(RwLock::new(HashMap::new())),
        admin_token: std::env::var("PRIVACYBTC_INDEXER_ADMIN_TOKEN")
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .map(Arc::<str>::from),
        relayer_token: std::env::var("PRIVACYBTC_INDEXER_RELAYER_TOKEN")
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .map(Arc::<str>::from),
        write_semaphore: Arc::new(Semaphore::new(2)),
    };
    registry.validate_trust_roots().await?;

    // 1) CLI pools (the first one becomes the default query target).
    for raw_addr in &cli.contract_address {
        if let Err(e) = registry
            .add_admitted_pool(raw_addr, cli.start_block, false)
            .await
        {
            eprintln!("[indexer] add CLI pool {raw_addr} failed: {e:#}");
        }
    }
    // 2) Pools registered at runtime in a previous run.
    if let Some(path) = &cli.pools_registry {
        for entry in load_pools_registry(path) {
            let sb = if entry.start_block == 0 {
                cli.start_block
            } else {
                entry.start_block
            };
            if let Err(e) = registry.add_admitted_pool(&entry.address, sb, false).await {
                eprintln!(
                    "[indexer] re-add registry pool {} failed: {e:#}",
                    entry.address
                );
            }
        }
        println!("[indexer] pools registry: {path}");
    }
    // 3) Auto-discovery: continuously scan `Perc20Created` chain-wide and register
    //    matching pools automatically (primary path; POST /pools stays as a manual
    //    fallback for e.g. pools created before --start-block).
    if cli.discover_pools {
        let sources = registry.admission.discovery_sources();
        if sources.is_empty() {
            return Err(anyhow!(
                "pool discovery requires at least one trusted PERC20 or shield factory"
            ));
        }
        println!(
            "[indexer] trusted factory discovery ON ({} factories, poll {}s, from block {})",
            sources.len(),
            cli.discover_poll_secs,
            cli.start_block
        );
        tokio::spawn(pool_discovery_task(
            registry.clone(),
            rpc.clone(),
            sources,
            cli.start_block,
            cli.discover_poll_secs,
        ));
    } else if registry.pools.read().await.is_empty() {
        println!(
            "[indexer] no pools configured yet — idle until a pool is registered via POST /pools"
        );
    }

    // 4) updateRoot crank: batch-confirm pending cmx for every pool (batch model).
    if cli.crank {
        match &signer {
            Some(s) => {
                tokio::spawn(crank_task(
                    registry.clone(),
                    rpc.clone(),
                    CrankConfig {
                        signer: Arc::clone(s),
                        prover_url: cli.crank_prover_url.clone(),
                        prover_api_token: cli.crank_prover_api_token.clone().unwrap_or_default(),
                        interval_secs: cli.crank_interval_secs,
                        max_proofs_per_tx: cli.crank_max_proofs_per_tx,
                        gas_limit_cap: cli.gas_limit_update_root,
                        gas_margin_bps: cli.crank_gas_margin_bps,
                        allowed_pools: parse_address_set(
                            "PRIVACYBTC_INDEXER_CRANK_ALLOWED_POOLS",
                            &cli.crank_allowed_pool,
                        )?,
                        max_tx_per_hour: cli.crank_max_tx_per_hour,
                    },
                ));
            }
            None => eprintln!("[indexer] --crank requires --signer-key; crank disabled"),
        }
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
        .route("/txs", get(get_txs))
        .route("/swap", get(get_swap))
        .route("/swap/leg", get(get_swap_leg))
        .route("/notify_tx", post(post_notify_tx))
        .route("/pools", get(list_pools).post(register_pool))
        .route("/pool_meta", get(get_pool_meta))
        .route("/shield/stats", get(get_shield_stats))
        .route("/frozen_root", get(get_frozen_root))
        .route("/frozen_updates", get(get_frozen_updates))
        .route("/frozen_leaves", get(get_frozen_leaves))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .layer(build_cors_layer())
        .layer(middleware::from_fn_with_state(
            registry.clone(),
            canonical_api_gate,
        ))
        .with_state(registry);

    println!("privacybtc-indexer listening on http://{bind}");
    for t in note_added_topic0_alternatives() {
        println!("[indexer] NoteAdded topic0: {t}");
    }
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn event_topic0(signature: &[u8]) -> String {
    let hash = Keccak256::digest(signature);
    format!("0x{}", hex::encode(hash))
}

fn perc20_created_topic0() -> String {
    event_topic0(b"Perc20Created(address,address,string,string,uint8)")
}

fn perc20_deployed_topic0() -> String {
    event_topic0(b"Perc20Deployed(address,address)")
}

fn shield_pool_deployed_topic0() -> String {
    event_topic0(b"ShieldPoolDeployed(address,address,address,uint256)")
}

/// topic0 of `FrozenRootUpdated(uint256 oldRoot, uint256 newRoot, uint256[] cmxChanged,
/// bool[] isAdd)` — the compliance blacklist leaf-delta disclosure (frozen-tree-execution-plan).
fn frozen_root_updated_topic0() -> String {
    event_topic0(b"FrozenRootUpdated(uint256,uint256,uint256[],bool[])")
}

fn eip1967_beacon_slot() -> [u8; 32] {
    let mut slot: [u8; 32] = Keccak256::digest(b"eip1967.proxy.beacon").into();
    for byte in slot.iter_mut().rev() {
        if *byte > 0 {
            *byte -= 1;
            break;
        }
        *byte = 0xff;
    }
    slot
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

fn factory_log_matches(log: &EthLog, factory: &str, topic0: &str, pool: &str) -> bool {
    let topics = match log.topics.as_ref() {
        Some(topics) => topics,
        None => return false,
    };
    normalize_hex_0x(&log.address).to_lowercase() == normalize_hex_0x(factory).to_lowercase()
        && topics.first().map(|v| v.to_lowercase()) == Some(topic0.to_lowercase())
        && topics.get(1).map(|v| v.to_lowercase()) == Some(address_to_topic(pool))
}

fn beacon_words_match(factory_beacon: &[u8; 32], pool_slot: &[u8; 32]) -> bool {
    factory_beacon[12..] == pool_slot[12..] && factory_beacon[12..].iter().any(|byte| *byte != 0)
}

/// Background task: poll deployment events emitted by explicitly trusted factories.
/// Re-scans from `start_block` on boot; `add_pool` is idempotent so already-known
/// pools are skipped. The cursor only advances past fully-scanned ranges, so a
/// transient RPC error is retried on the next tick.
async fn pool_discovery_task(
    reg: PoolRegistry,
    rpc: RpcClient,
    sources: Vec<(String, String)>,
    start_block: u64,
    poll_secs: u64,
) {
    let mut from = start_block;
    loop {
        if let Ok((head, _)) = rpc.finalized_block().await {
            let mut lo = from;
            while lo <= head {
                let hi = getlogs_window_end(lo, head, rpc.getlogs_span());
                let mut found = Vec::new();
                let mut failed = None;
                for (factory, topic0) in &sources {
                    match rpc
                        .fetch_factory_deployed_pools(lo, hi, factory, topic0)
                        .await
                    {
                        Ok(mut pools) => found.append(&mut pools),
                        Err(e) => {
                            failed = Some(e);
                            break;
                        }
                    }
                }
                match failed {
                    None => {
                        for (pool, block) in found {
                            match reg.add_admitted_pool(&pool, block, false).await {
                                Ok(true) => {
                                    println!(
                                        "[indexer] auto-discovered pool {pool} (block {block})"
                                    )
                                }
                                Ok(false) => {}
                                Err(e) => {
                                    eprintln!(
                                        "[indexer] auto-discover add_pool {pool} failed: {e:#}"
                                    )
                                }
                            }
                        }
                        lo = hi + 1;
                    }
                    Some(e) if hi > lo && is_getlogs_range_error(&e) => {
                        // Window too large for this provider: shrink and retry
                        // the same offset within this tick.
                        rpc.shrink_getlogs_span(hi - lo + 1);
                    }
                    Some(e) => {
                        eprintln!("[indexer] discovery getLogs [{lo},{hi}] failed: {e:#}");
                        break; // leave `lo` here so we retry this range next tick
                    }
                }
            }
            from = lo;
        }
        tokio::time::sleep(std::time::Duration::from_secs(poll_secs.max(1))).await;
    }
}

// ─── updateRoot crank ─────────────────────────────────────────────────────────

/// First 4 bytes of `keccak256(sig)` — Solidity function selector.
fn eth_selector(sig: &[u8]) -> [u8; 4] {
    let d = Keccak256::digest(sig);
    [d[0], d[1], d[2], d[3]]
}

/// Last 8 bytes of a 32-byte ABI word as u64 (values here are small counters).
fn word_to_u64(w: &[u8; 32]) -> u64 {
    u64::from_be_bytes(w[24..32].try_into().unwrap())
}

const GAS_BPS_DENOMINATOR: u64 = 10_000;
const MAX_CRANK_GAS_MARGIN_BPS: u64 = 1_000;

fn crank_gas_limit(estimate: u64, margin_bps: u64, cap: u64) -> Result<u64> {
    if estimate == 0 {
        return Err(anyhow!("crank gas estimate must be greater than zero"));
    }
    if cap == 0 {
        return Err(anyhow!("crank gas cap must be greater than zero"));
    }
    if margin_bps > MAX_CRANK_GAS_MARGIN_BPS {
        return Err(anyhow!(
            "crank gas margin must be <= {MAX_CRANK_GAS_MARGIN_BPS} basis points"
        ));
    }
    let numerator = u128::from(estimate)
        .checked_mul(u128::from(GAS_BPS_DENOMINATOR + margin_bps))
        .ok_or_else(|| anyhow!("crank gas margin calculation overflow"))?;
    let padded = numerator
        .checked_add(u128::from(GAS_BPS_DENOMINATOR - 1))
        .ok_or_else(|| anyhow!("crank gas margin calculation overflow"))?
        / u128::from(GAS_BPS_DENOMINATOR);
    let padded = u64::try_from(padded).context("padded crank gas does not fit u64")?;
    if padded > cap {
        return Err(anyhow!(
            "crank estimate {estimate} with {margin_bps}bps margin requires {padded} gas, above cap {cap}"
        ));
    }
    Ok(padded)
}

struct CrankConfig {
    signer: Arc<SignerConfig>,
    prover_url: String,
    prover_api_token: String,
    interval_secs: u64,
    max_proofs_per_tx: usize,
    gas_limit_cap: u64,
    gas_margin_bps: u64,
    allowed_pools: HashSet<String>,
    max_tx_per_hour: u64,
}

struct HourlyTxBudget {
    limit: u64,
    submitted_at: VecDeque<u64>,
}

impl HourlyTxBudget {
    fn new(limit: u64) -> Self {
        Self {
            limit,
            submitted_at: VecDeque::new(),
        }
    }

    fn prune(&mut self, now_seconds: u64) {
        while self
            .submitted_at
            .front()
            .is_some_and(|at| now_seconds.saturating_sub(*at) >= 3600)
        {
            self.submitted_at.pop_front();
        }
    }

    fn retry_after_seconds(&mut self, now_seconds: u64) -> Option<u64> {
        self.prune(now_seconds);
        if (self.submitted_at.len() as u64) < self.limit {
            return None;
        }
        self.submitted_at
            .front()
            .map(|at| at.saturating_add(3600).saturating_sub(now_seconds).max(1))
    }

    fn try_take(&mut self, now_seconds: u64) -> bool {
        self.prune(now_seconds);
        if self.submitted_at.len() as u64 >= self.limit {
            return false;
        }
        self.submitted_at.push_back(now_seconds);
        true
    }
}

/// `None` keeps the crank hot: a successful batch is followed by an immediate
/// chain re-read so a non-empty queue drains continuously. Empty/no-progress
/// passes use the normal poll interval, while an exhausted rolling budget sleeps
/// exactly until its oldest slot becomes available.
fn crank_next_delay_secs(
    made_progress: bool,
    budget_retry_after_secs: Option<u64>,
    interval_secs: u64,
) -> Option<u64> {
    match budget_retry_after_secs {
        Some(wait) => Some(wait.max(1)),
        None if made_progress => None,
        None => Some(interval_secs.max(1)),
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Permissionless batch-confirm crank. Every tick, for every pool:
///
///   1. Read the on-chain batch state (`confirmedRoot` / `confirmedCount` /
///      `pendingCmxCount`). Pools on the pre-batch implementation are skipped.
///   2. If the pool is a freshly-upgraded legacy pool (`confirmedRoot == 0`),
///      submit the one-time `syncBatchModel()` migration.
///   3. Otherwise, take up to `8 * max_proofs_per_tx` locally-indexed leaves at
///      the chain watermark, plan consecutive unchanged-circuit segments with
///      the shared `FrontierTree`, request their proofs concurrently, and submit
///      `updateRoots`. A single-segment tail retains the `updateRoot` fallback.
///
/// The chain is the source of truth for the watermark: local state is only used
/// for the leaf values (which the contract itself cross-checks — the queue
/// segment is part of the proof's public inputs, read from contract storage).
/// A failed/raced tx therefore burns a little gas at worst; it can never
/// corrupt the tree.
async fn crank_task(reg: PoolRegistry, rpc: RpcClient, cfg: CrankConfig) {
    let sel_confirmed_root = eth_selector(b"confirmedRoot()");
    let sel_confirmed_count = eth_selector(b"confirmedCount()");
    let sel_pending_count = eth_selector(b"pendingCmxCount()");
    let sel_sync = eth_selector(b"syncBatchModel()");
    // Proofs take tens of seconds; a dedicated client with a generous timeout.
    let prover_http = Client::builder()
        .timeout(std::time::Duration::from_secs(600))
        .build()
        .expect("reqwest client");
    // Confirmed-state frontier per pool (advanced only after an on-chain success).
    let mut frontiers: HashMap<String, FrontierTree> = HashMap::new();
    let mut tx_budget = HourlyTxBudget::new(cfg.max_tx_per_hour);

    println!(
        "[crank] root crank ON (prover={}, interval={}s, max_proofs_per_tx={}, max_leaves_per_tx={}, max_tx_per_hour={}, account=0x{})",
        cfg.prover_url,
        cfg.interval_secs,
        cfg.max_proofs_per_tx,
        CMX_CONFIRM_MAX_BATCH * cfg.max_proofs_per_tx,
        cfg.max_tx_per_hour,
        hex::encode(cfg.signer.address)
    );

    loop {
        let mut made_progress = false;
        let pools: Vec<AppContext> = { reg.pools.read().await.values().cloned().collect() };
        for ctx in pools {
            let pool = ctx.contract_address.clone();
            let label = pool[..10.min(pool.len())].to_string();
            if !cfg.allowed_pools.contains(&pool.to_lowercase()) {
                continue;
            }
            if ctx.state.read().await.tree_out_of_order {
                continue;
            }
            if let Some(wait) = tx_budget.retry_after_seconds(unix_seconds()) {
                println!(
                    "[crank] rolling hourly transaction budget exhausted; retrying in {wait}s"
                );
                break;
            }
            match reg.verify_pool_current(&pool).await {
                Ok(true) => {}
                Ok(false) => {
                    eprintln!("[crank][{label}] pool trust validation failed; refusing to sign");
                    continue;
                }
                Err(e) => {
                    eprintln!(
                        "[crank][{label}] pool trust validation unavailable; refusing to sign: {e:#}"
                    );
                    continue;
                }
            }

            // 1. On-chain batch state. A revert/empty result ⇒ pre-batch
            //    implementation (or RPC hiccup) — skip quietly.
            let chain_root = match rpc.eth_call_word(&pool, sel_confirmed_root).await {
                Ok(w) => w,
                Err(_) => continue,
            };

            // 2. Legacy pool freshly upgraded to the batch implementation: its new
            //    storage fields are zero until the one-time migration runs.
            if chain_root == [0u8; 32] {
                println!("[crank][{label}] legacy pool detected — submitting syncBatchModel()");
                match submit_crank_tx(
                    &rpc,
                    &cfg,
                    &mut tx_budget,
                    &pool,
                    &sel_sync,
                    "syncBatchModel",
                )
                .await
                {
                    Ok(true) => made_progress = true,
                    Ok(false) => eprintln!("[crank][{label}] syncBatchModel reverted"),
                    Err(e) => eprintln!("[crank][{label}] syncBatchModel failed: {e:#}"),
                }
                continue; // watermark reads are meaningless until the sync lands
            }

            let chain_count = match rpc.eth_call_word(&pool, sel_confirmed_count).await {
                Ok(w) => word_to_u64(&w),
                Err(_) => continue,
            };
            let chain_pending = match rpc.eth_call_word(&pool, sel_pending_count).await {
                Ok(w) => word_to_u64(&w),
                Err(_) => continue,
            };
            if chain_pending == 0 {
                continue;
            }

            // 3. Local leaves at the chain watermark.
            let (leaves, local_len) = {
                let s = ctx.state.read().await;
                let take =
                    (chain_pending as usize).min(CMX_CONFIRM_MAX_BATCH * cfg.max_proofs_per_tx);
                let end = ((chain_count as usize) + take).min(s.cmx_ordered.len());
                let leaves: Vec<[u8; 32]> = s
                    .cmx_ordered
                    .get(chain_count as usize..end)
                    .map(|x| x.to_vec())
                    .unwrap_or_default();
                (leaves, s.cmx_ordered.len() as u64)
            };
            if leaves.is_empty() {
                // Indexer has not ingested the pending NoteAdded events yet.
                println!(
                    "[crank][{label}] chain has {chain_pending} pending at count {chain_count}, \
                     local tree only {local_len} leaves — waiting for ingest"
                );
                continue;
            }

            // Restore the exact confirmed-state frontier without monopolising a
            // Tokio worker. Warm-start supplies it directly when counts match;
            // otherwise derive it in a blocking worker from one final-leaf path
            // (O(n), rather than replaying 32 hashes per historical leaf).
            let frontier_matches = frontiers
                .get(&pool)
                .is_some_and(|frontier| frontier.next_index() == chain_count);
            if !frontier_matches {
                let (restored, confirmed_prefix): (Option<FrontierTree>, Option<Vec<[u8; 32]>>) = {
                    let s = ctx.state.read().await;
                    let restored = s
                        .confirmed_frontier
                        .as_ref()
                        .filter(|frontier| frontier.next_index() == chain_count)
                        .cloned();
                    let prefix = s
                        .cmx_ordered
                        .get(..chain_count as usize)
                        .map(ToOwned::to_owned);
                    (restored, prefix)
                };
                let rebuilt = if let Some(frontier) = restored {
                    Ok(frontier)
                } else if let Some(prefix) = confirmed_prefix {
                    println!(
                        "[crank][{label}] deriving confirmed frontier at count {chain_count} in blocking worker"
                    );
                    match tokio::task::spawn_blocking(move || frontier_from_ordered_leaves(&prefix))
                        .await
                    {
                        Ok(result) => result,
                        Err(error) => Err(anyhow!("frontier worker failed: {error}")),
                    }
                } else {
                    Err(anyhow!("local tree behind chain watermark"))
                };
                match rebuilt {
                    Ok(frontier) => {
                        frontiers.insert(pool.clone(), frontier);
                    }
                    Err(error) => {
                        eprintln!("[crank][{label}] cannot restore frontier: {error:#}");
                        continue;
                    }
                }
            }
            let frontier = frontiers
                .get_mut(&pool)
                .expect("frontier inserted after successful restore");
            // Byte-identity guard: local frontier must reproduce the chain root.
            let local_root = fr_to_be_bytes(frontier.root());
            if local_root != chain_root {
                eprintln!(
                    "[crank][{label}] DESYNC: local confirmed root {} != chain {} at count {chain_count} — resetting frontier",
                    hex::encode(local_root),
                    hex::encode(chain_root)
                );
                frontiers.remove(&pool);
                continue;
            }

            // 4. Plan consecutive unchanged-circuit segments on a clone (commit
            //    only after aggregate on-chain success), prove all segments
            //    concurrently, and submit one updateRoot/updateRoots transaction.
            let mut planned = frontier.clone();
            let inputs = planned.plan_batches(&leaves, cfg.max_proofs_per_tx);
            let total_j: u64 = inputs.iter().map(CmxConfirmWitnessInput::batch_size).sum();
            println!(
                "[crank][{label}] confirming {} proof segment(s), leaves={total_j}, count={chain_count}, chain_pending={chain_pending}",
                inputs.len()
            );

            let proof_results = stream::iter(inputs.clone().into_iter().enumerate())
                .map(|(segment, input)| {
                    let http = prover_http.clone();
                    let prover_url = cfg.prover_url.clone();
                    let prover_api_token = cfg.prover_api_token.clone();
                    async move {
                        prove_cmxconfirm(&http, &prover_url, &prover_api_token, &input)
                            .await
                            .with_context(|| format!("proof segment {}", segment + 1))
                    }
                })
                .buffered(inputs.len())
                .collect::<Vec<_>>()
                .await;
            let proofs: Vec<Vec<u8>> = match proof_results.into_iter().collect::<Result<Vec<_>>>() {
                Ok(proofs) => proofs,
                Err(e) => {
                    eprintln!("[crank][{label}] concurrent proof generation failed: {e:#}");
                    continue;
                }
            };
            let (calldata, method) = match encode_crank_root_calldata(&inputs, &proofs) {
                Ok(encoded) => encoded,
                Err(e) => {
                    eprintln!("[crank][{label}] aggregate calldata build failed: {e:#}");
                    continue;
                }
            };
            match submit_crank_tx(&rpc, &cfg, &mut tx_budget, &pool, &calldata, method).await {
                Ok(true) => {
                    let final_input = inputs.last().expect("non-empty root update plan");
                    println!(
                        "[crank][{label}] {method} confirmed: count {chain_count} → {} root={}",
                        chain_count + total_j,
                        hex::encode(final_input.new_root_be())
                    );
                    *frontier = planned;
                    made_progress = true;
                }
                Ok(false) => {
                    // Raced by another cranker or state changed under us — the next
                    // tick re-reads chain state and replans.
                    eprintln!("[crank][{label}] {method} reverted (raced?); will replan");
                }
                Err(e) => eprintln!("[crank][{label}] {method} submit failed: {e:#}"),
            }
        }
        let budget_retry_after_secs = tx_budget.retry_after_seconds(unix_seconds());
        match crank_next_delay_secs(made_progress, budget_retry_after_secs, cfg.interval_secs) {
            None => {
                // Re-read the chain immediately while a backlog remains. This
                // removes the fixed interval from the hot path without
                // pipelining dependent root transactions or nonces.
                tokio::task::yield_now().await;
            }
            Some(delay) => {
                tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            }
        }
    }
}

fn encode_crank_root_calldata(
    inputs: &[CmxConfirmWitnessInput],
    proofs: &[Vec<u8>],
) -> Result<(Vec<u8>, &'static str)> {
    if inputs.is_empty()
        || inputs.len() > CMX_CONFIRM_MAX_PROOFS_PER_TX
        || inputs.len() != proofs.len()
    {
        return Err(anyhow!(
            "root update plan/proof cardinality must match in 1..={CMX_CONFIRM_MAX_PROOFS_PER_TX}"
        ));
    }
    if proofs.iter().any(|proof| proof.len() != 256) {
        return Err(anyhow!("each CmxConfirm proof must be exactly 256 bytes"));
    }
    if inputs.len() == 1 {
        let input = &inputs[0];
        return Ok((
            encode_update_root_calldata(
                &input.new_root_be(),
                &input.new_frontier_commit_be(),
                input.batch_size(),
                &proofs[0],
            ),
            "updateRoot",
        ));
    }
    let updates: Vec<RootUpdateArgs> = inputs
        .iter()
        .zip(proofs)
        .map(|(input, proof)| RootUpdateArgs {
            new_root: input.new_root_be(),
            new_frontier_commit: input.new_frontier_commit_be(),
            j: input.batch_size(),
            proof: proof.clone(),
        })
        .collect();
    Ok((encode_update_roots_calldata(&updates), "updateRoots"))
}

/// POST the circom witness input to the prover's `/cmxconfirm/prove`; returns the
/// ABI-encoded Groth16 proof bytes (`updateRoot`'s `proof` argument).
async fn prove_cmxconfirm(
    http: &Client,
    prover_url: &str,
    prover_api_token: &str,
    input: &privacy_core::commitment_tree::frontier::CmxConfirmWitnessInput,
) -> Result<Vec<u8>> {
    let url = format!("{}/cmxconfirm/prove", prover_url.trim_end_matches('/'));
    let resp = http
        .post(&url)
        .bearer_auth(prover_api_token)
        .json(input)
        .send()
        .await
        .context("prover request")?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow!("prover {status}: {body}"));
    }
    #[derive(Deserialize)]
    struct ProveResponse {
        proof_hex: String,
    }
    let out: ProveResponse = serde_json::from_str(&body).context("prover response JSON")?;
    let proof = hex::decode(out.proof_hex.trim_start_matches("0x")).context("proof hex")?;
    if proof.len() != 256 {
        return Err(anyhow!(
            "prover returned {} proof bytes; expected 256",
            proof.len()
        ));
    }
    Ok(proof)
}

/// Simulate (`eth_call`), estimate and submit one crank transaction, then wait
/// for its receipt. Estimation is mandatory: there is no fixed-limit fallback.
/// `Ok(true)` = mined successfully, `Ok(false)` = reverted (simulation or on-chain).
async fn submit_crank_tx(
    rpc: &RpcClient,
    cfg: &CrankConfig,
    budget: &mut HourlyTxBudget,
    pool: &str,
    calldata: &[u8],
    what: &str,
) -> Result<bool> {
    let from_hex = format!("0x{}", hex::encode(cfg.signer.address));

    // Dry-run first: a revert here costs nothing (vs. burning gas on-chain).
    if let Err(e) = rpc.eth_call(pool, calldata, Some(&from_hex)).await {
        eprintln!("[crank] {what} simulation reverted: {e:#}");
        return Ok(false);
    }
    let estimated_gas = rpc
        .estimate_gas(pool, calldata, Some(&from_hex))
        .await
        .with_context(|| format!("{what} gas estimation failed; refusing fixed-limit fallback"))?;
    let gas_limit = crank_gas_limit(estimated_gas, cfg.gas_margin_bps, cfg.gas_limit_cap)?;
    println!(
        "[crank] {what} gas: estimate={estimated_gas} margin_bps={} signed_limit={gas_limit} cap={}",
        cfg.gas_margin_bps, cfg.gas_limit_cap
    );
    if !budget.try_take(unix_seconds()) {
        return Err(anyhow!(
            "hourly crank transaction budget exhausted (limit={})",
            cfg.max_tx_per_hour
        ));
    }

    let nonce = rpc.get_transaction_count(&from_hex).await?;
    let raw = build_and_sign_raw_tx(
        nonce,
        cfg.signer.gas_price,
        gas_limit,
        pool,
        0u64,
        calldata,
        cfg.signer.chain_id,
        &cfg.signer.signing_key,
    )?;
    let tx_hash = rpc.send_raw_transaction(&raw).await?;
    println!("[crank] {what} submitted: {tx_hash}");

    // Wait for the receipt so ticks never pipeline conflicting txs.
    for _ in 0..45 {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        match rpc.get_transaction_receipt_status(&tx_hash).await {
            Ok(Some(ok)) => return Ok(ok),
            Ok(None) => continue,
            Err(_) => continue,
        }
    }
    Err(anyhow!("{what} tx {tx_hash} not mined within 90s"))
}

/// Same env as relayer: comma-separated origins in `PRIVACYBTC_CORS_ORIGINS`.
/// Defaults to Vite dev server on localhost and 127.0.0.1.
fn build_cors_layer() -> CorsLayer {
    let origins_str = std::env::var("PRIVACYBTC_CORS_ORIGINS")
        .unwrap_or_else(|_| "http://localhost:5173,http://127.0.0.1:5173".to_string());
    let origins: Vec<axum::http::HeaderValue> = origins_str
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(tower_http::cors::Any)
}

fn require_admin(
    headers: &HeaderMap,
    token: Option<&Arc<str>>,
) -> Result<(), (StatusCode, String)> {
    let Some(expected) = token else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "admin writes are disabled; set PRIVACYBTC_INDEXER_ADMIN_TOKEN".to_owned(),
        ));
    };
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let supplied = auth.strip_prefix("Bearer ").unwrap_or_default();
    if supplied.is_empty() || supplied != expected.as_ref() {
        return Err((StatusCode::UNAUTHORIZED, "invalid admin token".to_owned()));
    }
    Ok(())
}

fn require_relayer(
    headers: &HeaderMap,
    token: Option<&Arc<str>>,
) -> Result<(), (StatusCode, String)> {
    let Some(expected) = token else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "relayer notifications are disabled; set PRIVACYBTC_INDEXER_RELAYER_TOKEN".to_owned(),
        ));
    };
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let supplied = auth.strip_prefix("Bearer ").unwrap_or_default();
    if supplied.is_empty() || supplied != expected.as_ref() {
        return Err((StatusCode::UNAUTHORIZED, "invalid relayer token".to_owned()));
    }
    Ok(())
}

// ─── HTTP handlers ────────────────────────────────────────────────────────────

fn canonical_guard(tree_out_of_order: bool) -> Result<(), (StatusCode, String)> {
    if tree_out_of_order {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "indexer canonical finalized replay is not ready".to_owned(),
        ))
    } else {
        Ok(())
    }
}

async fn require_canonical_context(
    ctx: &AppContext,
) -> Result<(), (StatusCode, String)> {
    canonical_guard(ctx.state.read().await.tree_out_of_order)
}

async fn canonical_api_gate(
    State(reg): State<PoolRegistry>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if path == "/status" || path == "/healthz" {
        return next.run(request).await;
    }
    let contexts: Vec<AppContext> = reg.pools.read().await.values().cloned().collect();
    for ctx in contexts {
        if let Err(error) = require_canonical_context(&ctx).await {
            return error.into_response();
        }
    }
    next.run(request).await
}

async fn healthz(
    State(reg): State<PoolRegistry>,
) -> Result<&'static str, (StatusCode, String)> {
    let contexts: Vec<AppContext> = reg.pools.read().await.values().cloned().collect();
    if contexts.is_empty() && reg.require_pool {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "no required pool has been configured or discovered".to_owned(),
        ));
    }
    for ctx in contexts {
        require_canonical_context(&ctx).await.map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "pool {} canonical finalized replay is not ready",
                    ctx.contract_address
                ),
            )
        })?;
    }
    Ok("ok")
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
        return Err((
            StatusCode::BAD_REQUEST,
            "pool must be a 20-byte hex address".to_owned(),
        ));
    }
    let key = normalize_hex_0x(&q.pool).to_lowercase();
    reg.ensure_metadata(&key).await.map(Json).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("no metadata for pool {}", q.pool),
        )
    })
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
/// trusted-factory provenance or the explicit standalone allowlist, plus a
/// pinned runtime codehash; no self-emitted event can grant admission.
async fn register_pool(
    State(reg): State<PoolRegistry>,
    headers: HeaderMap,
    Json(req): Json<RegisterPoolRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    require_admin(&headers, reg.admin_token.as_ref())?;
    if !reg.allow_runtime_pool_registration {
        return Err((
            StatusCode::FORBIDDEN,
            "runtime pool registration is disabled; use factory discovery".to_owned(),
        ));
    }
    if reg.pools.read().await.len() >= reg.max_pools {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "maximum watched pool count reached".to_owned(),
        ));
    }
    let _permit = reg
        .write_semaphore
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            (
                StatusCode::TOO_MANY_REQUESTS,
                "indexer write capacity is busy; retry later".to_owned(),
            )
        })?;
    if parse_address20(&req.contract_address).is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "contract_address must be a 20-byte hex address".to_owned(),
        ));
    }
    let addr_lc = normalize_hex_0x(&req.contract_address).to_lowercase();
    match reg.verify_pool_admitted(&addr_lc).await {
        Ok(true) => {}
        Ok(false) => {
            return Err((
                StatusCode::FORBIDDEN,
                "pool is not from a trusted factory/static allowlist or has an unapproved codehash"
                    .to_owned(),
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
        .add_admitted_pool(&req.contract_address, req.start_block, true)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("add_pool failed: {e:#}"),
            )
        })?;
    let address = normalize_hex_0x(&req.contract_address);
    let status = if added {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
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
        canonical: !s.tree_out_of_order,
        startup_source: s.startup_source.clone(),
        shadow_mode: ctx.shadow_mode,
        last_finalized_block: s.last_finalized_block,
        last_finalized_block_hash: s.last_finalized_block_hash.clone(),
        latest_seq: s.latest_seq,
        cached_batches: s.batches.len(),
        confirmed_notes: s.confirmed_cmx.len(),
        active_root_hex: http_root_hex(&s),
        local_tree_root_hex,
        tree_size: s.tree.size(),
        confirmed_count: s.confirmed_count,
        pending_cmx: s.tree.size().saturating_sub(s.confirmed_count),
        pool_address: ctx.contract_address.clone(),
    }))
}

async fn get_batches(
    State(reg): State<PoolRegistry>,
    Query(q): Query<BatchesQuery>,
) -> Result<Json<Vec<BatchEnvelope>>, (StatusCode, String)> {
    let ctx = reg.resolve(q.pool.as_deref()).await?;
    let after = q.after_seq.unwrap_or(0);
    let out = collect_batches_since(&ctx, after).await?;
    Ok(Json(out))
}

/// All batch envelopes with `seq > after`, oldest first. Recent envelopes come
/// from the in-memory ring; anything older than the ring's front (evicted) is
/// loaded from the persistent backend, so full-history scans never silently
/// miss notes regardless of `--max-batches-in-memory`.
async fn collect_batches_since(
    ctx: &AppContext,
    after: u64,
) -> Result<Vec<BatchEnvelope>, (StatusCode, String)> {
    let (ring, ring_front, latest_seq) = {
        let s = ctx.state.read().await;
        canonical_guard(s.tree_out_of_order)?;
        let ring: Vec<BatchEnvelope> = s
            .batches
            .iter()
            .filter(|b| b.seq > after)
            .cloned()
            .collect();
        (ring, s.batches.front().map(|b| b.seq), s.latest_seq)
    };
    // The ring covers (front..=latest); anything in (after..front) was evicted.
    let missing_before = match ring_front {
        Some(front) if front > after.saturating_add(1) => Some(front),
        None if latest_seq > after => Some(u64::MAX),
        _ => None,
    };
    let Some(before) = missing_before else {
        return Ok(ring);
    };
    let mut out = ctx
        .backend
        .load_archived_batches(&ctx.contract_address, after, before)
        .await;
    out.extend(ring);
    // A cursor mismatch may be detected while the archive query is in flight.
    // Recheck before returning any historical rows.
    require_canonical_context(ctx).await?;
    Ok(out)
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
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>, (StatusCode, String)>
{
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

    // Collect historical batches (seq > after_seq), including archived ones the
    // in-memory ring has already evicted.
    let historical: Vec<BatchEnvelope> = collect_batches_since(&ctx, after_seq).await?;
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

    require_canonical_context(&ctx).await?;
    Ok(Sse::new(hist_stream.chain(live_stream)).keep_alive(KeepAlive::default()))
}

async fn get_root(
    State(reg): State<PoolRegistry>,
    Query(q): Query<SimplePoolQuery>,
) -> Result<Json<RootResponse>, (StatusCode, String)> {
    let ctx = reg.resolve(q.pool.as_deref()).await?;
    let s = ctx.state.read().await;
    if s.tree_out_of_order {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "indexer canonical cursor is not verified".to_owned(),
        ));
    }
    Ok(Json(RootResponse {
        root_hex: http_root_hex(&s),
        tree_size: s.tree.size(),
        confirmed_count: s.confirmed_count,
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
    if s.tree_out_of_order {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "indexer canonical cursor is not verified".to_owned(),
        ));
    }
    for batch in s.batches.iter().rev() {
        for note in &batch.batch.abi_notes {
            if note.cmx == cmx {
                return Ok(Json(note.clone()));
            }
        }
    }
    Err((
        StatusCode::NOT_FOUND,
        "cmx not found in indexer batches".to_owned(),
    ))
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
) -> Result<Json<Vec<TxNote>>, (StatusCode, String)> {
    let want = normalize_hex_0x(&q.hash).to_lowercase();
    let contexts: Vec<AppContext> = match q.pool.as_deref() {
        Some(addr) => vec![reg.resolve(Some(addr)).await?],
        None => reg.pools.read().await.values().cloned().collect(),
    };

    // Per-note pool attribution (address + unit): a swap settle's two legs live in
    // different pools and the explorer renders each in its own symbol/decimals.
    let mut out: Vec<TxNote> = Vec::new();
    let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    for ctx in contexts {
        let pool_lc = ctx.contract_address.to_lowercase();
        let s = ctx.state.read().await;
        canonical_guard(s.tree_out_of_order)?;
        for batch in s.batches.iter() {
            for note in &batch.batch.abi_notes {
                if normalize_hex_0x(&note.tx_hash).to_lowercase() == want && seen.insert(note.cmx) {
                    out.push(TxNote {
                        note: note.clone(),
                        pool: pool_lc.clone(),
                        symbol: None,
                        decimals: None,
                    });
                }
            }
        }
    }
    let pools: std::collections::HashSet<String> = out.iter().map(|n| n.pool.clone()).collect();
    for pool in pools {
        if let Some(meta) = reg.ensure_metadata(&pool).await {
            for n in out.iter_mut().filter(|n| n.pool == pool) {
                n.symbol = meta.symbol.clone();
                n.decimals = meta.decimals;
            }
        }
    }
    Ok(Json(out))
}

/// Upper bound on the lazily-filled `/txs` enrichment caches. Far exceeds the
/// servable batch ring, so hot entries are never thrashed, while capping lifetime
/// memory. ~50k tx metas ≈ 20MB; ~100k block times ≈ 5MB.
const TX_META_CACHE_CAP: usize = 50_000;
const BLOCK_TIME_CACHE_CAP: usize = 100_000;

/// Cap a lazily-filled immutable cache: when it exceeds `cap`, drop entries down to
/// ~90% of `cap`. Eviction is arbitrary (values are immutable, so a re-served key
/// just re-fetches) — no per-entry LRU bookkeeping needed on the request path.
fn bound_cache<K: Clone + std::hash::Hash + Eq, V>(cache: &mut HashMap<K, V>, cap: usize) {
    if cache.len() <= cap {
        return;
    }
    let target = cap * 9 / 10;
    let drop_keys: Vec<K> = cache.keys().take(cache.len() - target).cloned().collect();
    for k in drop_keys {
        cache.remove(&k);
    }
}

/// Map a tx's 4-byte function selector to an explorer op type. Public info (the
/// selector is on-chain), so this is safe to expose pre-decrypt. Mirrors the pool
/// entrypoints; unknown selectors return None (shown as "unknown", never mislabeled).
fn classify_selector(input: &[u8]) -> Option<&'static str> {
    if input.len() < 4 {
        return None;
    }
    match &input[0..4] {
        // Protocol 3 (Binding Groth16, PrivacyCall = (bytes,uint256[8])).
        [0x33, 0xb8, 0x54, 0xb0] => Some("shield"),
        [0x19, 0x52, 0xce, 0x65] => Some("unshield"),
        [0x14, 0x1f, 0x64, 0x1d] => Some("mint"),
        [0xb7, 0x45, 0x34, 0xe9] => Some("burn"),
        [0xb2, 0xd4, 0x79, 0x7b] => Some("transfer"),
        [0x5e, 0x09, 0xe2, 0xb1] => Some("transfer"),
        [0xd4, 0x1e, 0x4a, 0x7a] => Some("swap"),
        [0x74, 0xda, 0x02, 0xc8] => Some("swap"),
        [0xe3, 0xb3, 0xfa, 0xe4] => Some("swap"),
        // Historical protocol-2 selectors remain classified for read-only
        // explorer compatibility; current calldata emission never uses them.
        // Wrapped ERC20Shield pools: deposit/withdraw a public ERC20 balance.
        [0x04, 0x11, 0xcb, 0xab] => Some("shield"),
        [0x53, 0x64, 0x4c, 0x61] => Some("unshield"), // has a public `recipient`
        // Issuer pERC20 pools: create/destroy supply (no public recipient).
        [0x12, 0x92, 0x3a, 0x62] => Some("mint"), // mint(uint256,(bytes,uint256[3]))
        [0xe7, 0x66, 0x0f, 0xf5] => Some("burn"), // burn(uint256,(bytes,uint256[3]))
        [0xed, 0xa1, 0xa0, 0xac] => Some("transfer"),
        [0xc7, 0xb9, 0x21, 0xd3] => Some("transfer"),
        [0xe3, 0xb9, 0x2d, 0xfd] => Some("swap"), // initiateSwap (plan A: full callA in calldata)
        [0x43, 0xfa, 0x07, 0x47] => Some("swap"), // joinSwap (plan A: full callB in calldata)
        [0x6d, 0xb7, 0x97, 0x4d] => Some("swap"), // initiateSwap (legacy commit-only)
        [0x8b, 0xbe, 0x82, 0x1a] => Some("swap"), // joinSwap (legacy commit-only)
        [0xc7, 0xec, 0xe1, 0x5f] => Some("swap"), // settle
        _ => None,
    }
}

/// Public (pre-decrypt) facts about a tx, derived from its calldata. Shield/Unshield
/// move funds between the pool and a PUBLIC ERC20 balance, so their amount — and an
/// unshield's recipient — are on-chain public, not part of the encrypted note.
#[derive(Clone, Default)]
struct TxMeta {
    /// Op type ("shield"/"transfer"/"unshield"/"swap"), None if unrecognized.
    op: Option<&'static str>,
    /// Public amount as a 0x 32-byte hex word (client formats with pool decimals).
    /// Present for shield/mint/unshield/burn (arg0 `uint256`); None otherwise.
    amount_hex: Option<String>,
    /// Public recipient (0x address) — unshield only (its arg1 `address`).
    recipient: Option<String>,
    /// Public sender (0x address = tx `from`) — the depositor/issuer for shield/mint.
    /// None for private-source ops (unshield/burn/transfer/swap spend a hidden note).
    sender: Option<String>,
}

/// Parse the public tx facts from raw calldata. `shield`/`mint`/`unshield`/`burn`
/// all take the amount as arg0 (`uint256` at calldata[4..36]); `unshield` also takes
/// a public `recipient` as arg1 (`address` at calldata[36..68], low 20 bytes).
fn parse_tx_meta(input: &[u8]) -> TxMeta {
    let op = classify_selector(input);
    // shield/mint/unshield/burn all take the public amount as arg0 (`uint256`).
    let amount_hex = match op {
        Some("shield") | Some("unshield") | Some("mint") | Some("burn") if input.len() >= 36 => {
            Some(format!("0x{}", hex::encode(&input[4..36])))
        }
        _ => None,
    };
    // Recipient is public ONLY for unshield. Burn has no recipient, so match the
    // exact v3 or historical v2 selector here.
    let recipient = if input.len() >= 68
        && (input[0..4] == [0x19, 0x52, 0xce, 0x65] || input[0..4] == [0x53, 0x64, 0x4c, 0x61])
    {
        Some(format!("0x{}", hex::encode(&input[48..68])))
    } else {
        None
    };
    // `sender` is filled by the resolver (it needs the tx's `from`, not the calldata).
    TxMeta {
        op,
        amount_hex,
        recipient,
        sender: None,
    }
}

#[derive(Debug, Deserialize)]
struct TxsListQuery {
    /// Max transactions per page (default 25, capped at 100).
    limit: Option<usize>,
    /// Cursor: return only transactions in a block strictly below this number.
    /// Omit for the newest page; pass the previous response's `next_before_block`
    /// to page backwards in time. Block number is the global chronological order
    /// across all pools (per-pool `seq` is not comparable between pools).
    before_block: Option<u64>,
    /// Optional pool filter; omit to span every registered pool.
    pool: Option<String>,
}

/// A note plus its POOL attribution. A swap settle's two legs land in DIFFERENT
/// pools, so per-note pool/symbol/decimals are required for the explorer to render
/// each leg in its own unit (the tx-level symbol only reflects the first note's
/// pool). Additive: the note's own fields are flattened, so consumers parsing a
/// plain `OrchardIndexedAbiNote` keep working and just ignore the extras.
#[derive(Clone, Serialize)]
struct TxNote {
    #[serde(flatten)]
    note: OrchardIndexedAbiNote,
    /// Pool address (lowercase 0x) that emitted this note's `NoteAdded`.
    pool: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decimals: Option<u8>,
}

/// One transaction, aggregating every ciphertext note it produced. A single tx can
/// carry several notes (a transfer's recipient + change, a swap settle's two legs).
#[derive(Serialize)]
struct TxSummary {
    tx_hash: String,
    block_number: u64,
    /// Block header unix timestamp (seconds); `null` if not yet resolvable. The
    /// client renders relative age from this and falls back to the block number.
    #[serde(skip_serializing_if = "Option::is_none")]
    block_time: Option<u64>,
    /// Op type from the tx's function selector ("shield"/"transfer"/"unshield"/
    /// "swap"); omitted when unrecognized (client shows "unknown"). Public info.
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_type: Option<String>,
    /// Public shield/unshield amount as a 0x 32-byte hex word — visible pre-decrypt
    /// (funds move to/from a public ERC20 balance). Omitted for private ops.
    #[serde(skip_serializing_if = "Option::is_none")]
    public_amount: Option<String>,
    /// Public unshield recipient (0x address); omitted for other ops.
    #[serde(skip_serializing_if = "Option::is_none")]
    public_recipient: Option<String>,
    /// Public sender (0x address) — shield/mint depositor; omitted for private ops.
    #[serde(skip_serializing_if = "Option::is_none")]
    public_sender: Option<String>,
    /// Symbol of the pool this tx's notes belong to (for the amount's unit).
    #[serde(skip_serializing_if = "Option::is_none")]
    symbol: Option<String>,
    /// Decimals of that pool — the client scales `public_amount` (and the decrypted
    /// note value) by this instead of assuming the active asset's decimals.
    #[serde(skip_serializing_if = "Option::is_none")]
    decimals: Option<u8>,
    /// Pool address (lowercase 0x) the tx's first note came from — the metadata key.
    #[serde(skip)]
    pool_address: String,
    /// Highest batch `seq` among this tx's notes (kept for debugging; not the sort
    /// key — ordering is by `block_number`, which is comparable across pools).
    seq: u64,
    /// Max `log_index` of this tx's notes — used to order txs within a block.
    #[serde(skip)]
    max_log_index: u64,
    notes: Vec<TxNote>,
}

#[derive(Serialize)]
struct TxsListResponse {
    items: Vec<TxSummary>,
    /// Pass as `before_block` for the next (older) page; `null` when none remain.
    next_before_block: Option<u64>,
}

/// List ciphertext transactions newest-first with cursor pagination — powers the
/// explorer's default "show everything" view (search is only quick-locate). Groups
/// notes by tx hash and orders by `block_number` descending (the global chronological
/// order across pools — per-pool `seq` is NOT comparable between pools). The newest
/// page reads the in-memory ring (cheap, hot poll path); older pages (cursor set)
/// read FULL history (ring + persisted archive) so deep pagination doesn't dead-end
/// at the ring's edge. The cursor never splits a block across pages, so callers can't
/// skip or double-count boundary txs.
async fn get_txs(
    State(reg): State<PoolRegistry>,
    Query(q): Query<TxsListQuery>,
) -> Result<Json<TxsListResponse>, (StatusCode, String)> {
    let limit = q.limit.unwrap_or(25).clamp(1, 100);
    let before = q.before_block.unwrap_or(u64::MAX);
    let contexts: Vec<AppContext> = match q.pool.as_deref() {
        Some(addr) => vec![reg.resolve(Some(addr)).await?],
        None => reg.pools.read().await.values().cloned().collect(),
    };

    // Aggregate notes into per-tx buckets. A tx can appear across pools (a swap
    // settle emits a note in each leg's pool), so key by hash and merge.
    // Newest page (no cursor) reads only the in-memory ring — cheap, and it's the
    // hot path the live poll hits every few seconds. Any older page (cursor set)
    // pulls FULL history (ring + persisted archive) via collect_batches_since, so
    // deep pagination reaches beyond the ring instead of dead-ending at its edge.
    let full_history = q.before_block.is_some();
    let mut by_tx: HashMap<String, TxSummary> = HashMap::new();
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    // On the newest (ring-only) page, track the safe cutoff for excluding blocks
    // that might be split across the ring/archive boundary. Notes are stored one
    // per batch and evicted per-note, so each evicted pool's OLDEST retained block
    // can be half-evicted. A block is guaranteed complete across all pools only if
    // it sits ABOVE every evicted pool's floor — so the cutoff is the MAX of those
    // floors. Blocks at/below it are deferred to the next (full-history) page.
    let mut ring_has_older = false;
    let mut ring_cutoff: Option<u64> = None;
    for ctx in &contexts {
        let pool_lc = ctx.contract_address.to_lowercase();
        let batches: Vec<BatchEnvelope> = if full_history {
            collect_batches_since(ctx, 0).await?
        } else {
            let s = ctx.state.read().await;
            canonical_guard(s.tree_out_of_order)?;
            // seq starts at 1; a ring front seq > 1 means this pool evicted batches.
            if s.batches.front().map(|b| b.seq).unwrap_or(1) > 1 {
                ring_has_older = true;
                // This pool's ring-floor block = its oldest retained note's block.
                if let Some(fb) = s
                    .batches
                    .front()
                    .and_then(|b| b.batch.abi_notes.first())
                    .map(|n| n.block_number)
                {
                    ring_cutoff = Some(ring_cutoff.map_or(fb, |c| c.max(fb)));
                }
            }
            s.batches.iter().cloned().collect()
        };
        for batch in &batches {
            for note in &batch.batch.abi_notes {
                if !seen.insert(note.cmx) {
                    continue;
                }
                let key = normalize_hex_0x(&note.tx_hash).to_lowercase();
                let entry = by_tx.entry(key.clone()).or_insert_with(|| TxSummary {
                    tx_hash: key,
                    block_number: note.block_number,
                    block_time: None,
                    tx_type: None,
                    public_amount: None,
                    public_recipient: None,
                    public_sender: None,
                    symbol: None,
                    decimals: None,
                    // The pool of the tx's FIRST note. shield/unshield (the ops with a
                    // public amount) touch a single pool, so this is unambiguous there.
                    pool_address: pool_lc.clone(),
                    seq: 0,
                    max_log_index: 0,
                    notes: Vec::new(),
                });
                entry.seq = entry.seq.max(batch.seq);
                entry.block_number = entry.block_number.max(note.block_number);
                entry.max_log_index = entry.max_log_index.max(note.log_index);
                entry.notes.push(TxNote {
                    note: note.clone(),
                    pool: pool_lc.clone(),
                    symbol: None,
                    decimals: None,
                });
            }
        }
    }

    // Keep notes within a tx ordered by log_index — that ordering is the "action
    // index" the explorer shows to tell apart a tx's individual note details.
    let mut txs: Vec<TxSummary> = by_tx.into_values().collect();
    for tx in &mut txs {
        tx.notes.sort_by_key(|n| n.note.log_index);
    }

    // Newest first by BLOCK (the only clock comparable across pools; per-pool `seq`
    // is not). Within a block, order by log_index; tx_hash breaks any final tie.
    txs.sort_by(|a, b| {
        b.block_number
            .cmp(&a.block_number)
            .then_with(|| b.max_log_index.cmp(&a.max_log_index))
            .then_with(|| b.tx_hash.cmp(&a.tx_hash))
    });

    // Newest (ring) page: drop any block at/below the safe cutoff — it may be split
    // across the ring/archive boundary. It's re-served complete by the next
    // full-history page, preserving "a block is never split across a cursor boundary".
    let mut items: Vec<TxSummary> = Vec::new();
    let mut last_block: Option<u64> = None;
    let mut truncated = false;
    for tx in txs
        .into_iter()
        .filter(|t| t.block_number < before && ring_cutoff.is_none_or(|c| t.block_number > c))
    {
        // Fill the page, then keep going while the block matches the last included
        // one so a block's txs are never split across a cursor boundary.
        if items.len() >= limit && Some(tx.block_number) != last_block {
            truncated = true;
            break;
        }
        last_block = Some(tx.block_number);
        items.push(tx);
    }
    // Advertise a cursor when older txs remain. `last_block` (min block shown, always
    // above the cutoff) is a clean boundary: paging below it loads full history
    // (archive included), which re-serves the cutoff block and everything under it,
    // complete. If the cutoff emptied the page, page into it via `cutoff + 1`.
    // None only when the ring holds everything.
    let next_before_block = match last_block {
        Some(lb) if truncated || (!full_history && ring_has_older) => Some(lb),
        Some(_) => None,
        None => ring_cutoff.map(|c| c + 1),
    };

    // Enrich this page (cost bounded by `limit`, both caches immutable):
    //  • age  — resolve each distinct block's header timestamp
    //  • type — classify each tx by its function selector (public info)
    let blocks: Vec<u64> = {
        let mut b: Vec<u64> = items.iter().map(|t| t.block_number).collect();
        b.sort_unstable();
        b.dedup();
        b
    };
    let hashes: Vec<String> = items.iter().map(|t| t.tx_hash.clone()).collect();
    // Resolve ages and tx facts concurrently — they hit disjoint RPC methods.
    let (times, metas) = tokio::join!(reg.block_times(&blocks), reg.tx_metas(&hashes));
    // Per-pool symbol/decimals so amounts render in each pool's own unit (cached).
    // Covers every NOTE's pool, not just each tx's first pool — a swap settle's two
    // legs sit in different pools and each must carry its own unit.
    let mut pool_meta: HashMap<String, PoolMeta> = HashMap::new();
    let all_pools: HashSet<String> = items
        .iter()
        .flat_map(|t| {
            t.notes
                .iter()
                .map(|n| n.pool.clone())
                .chain([t.pool_address.clone()])
        })
        .collect();
    for pool in all_pools {
        if let Some(meta) = reg.ensure_metadata(&pool).await {
            pool_meta.insert(pool, meta);
        }
    }
    for tx in &mut items {
        tx.block_time = times.get(&tx.block_number).copied();
        if let Some(m) = metas.get(&tx.tx_hash) {
            tx.tx_type = m.op.map(|s| s.to_string());
            tx.public_amount = m.amount_hex.clone();
            tx.public_recipient = m.recipient.clone();
            tx.public_sender = m.sender.clone();
        }
        if let Some(meta) = pool_meta.get(&tx.pool_address) {
            tx.symbol = meta.symbol.clone();
            tx.decimals = meta.decimals;
        }
        for n in &mut tx.notes {
            if let Some(meta) = pool_meta.get(&n.pool) {
                n.symbol = meta.symbol.clone();
                n.decimals = meta.decimals;
            }
        }
    }

    for ctx in &contexts {
        require_canonical_context(ctx).await?;
    }
    Ok(Json(TxsListResponse {
        items,
        next_before_block,
    }))
}

// ─── Swap plan A: on-chain leg lookup (calldata is the canonical DA source) ───
//
// With plan A the FULL `PrivacyCall` of each swap leg rides in the SwapCoordinator
// initiate/join tx calldata. These endpoints let a wallet fetch and trial-decrypt the
// counterparty leg from chain BEFORE signing the join challenge (and let the LP bot
// cross-check the joiner leg before settle):
//
//   GET /swap/leg?tx_hash=0x…                 — decode one initiate/join tx (stateless)
//   GET /swap?swap_id=0x…&coordinator=0x…     — event-driven summary + both decoded legs
//
// Both are stateless (straight RPC reads), so they survive indexer restarts with no
// backfill and work for any coordinator address.

/// Hex-encoded JSON form of a `PrivacyCall` (mirrors `IPERC20.PrivacyCall`).
#[derive(Serialize)]
struct SwapCallActionJson {
    cmx: String,
    enc_ciphertext: String,
    out_ciphertext: String,
    epk: String,
    nf_old: String,
    anchor: String,
    proof: String,
    /// 8 BN254 pub fields: [anchor, cv_x, cv_y, nf, rk_x, rk_y, cmx, rt_frozen].
    pub_fields: Vec<String>,
}

#[derive(Serialize)]
struct SwapCallJson {
    actions: Vec<SwapCallActionJson>,
    binding_proof: Vec<String>,
}

fn swap_call_json(call: &PrivacyCallArgs) -> SwapCallJson {
    fn hx(b: &[u8]) -> String {
        format!("0x{}", hex::encode(b))
    }
    SwapCallJson {
        actions: call
            .actions
            .iter()
            .map(|a| SwapCallActionJson {
                cmx: hx(&a.cmx),
                enc_ciphertext: hx(&a.enc_ciphertext),
                out_ciphertext: hx(&a.out_ciphertext),
                epk: hx(&a.epk),
                nf_old: hx(&a.nf_old),
                anchor: hx(&a.anchor),
                proof: hx(&a.proof),
                pub_fields: a.pub_fields.iter().map(|f| hx(f)).collect(),
            })
            .collect(),
        binding_proof: call.binding_proof.iter().map(|f| hx(f)).collect(),
    }
}

fn hex32_0x(b: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(b))
}

fn hex20_0x(b: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(b))
}

#[derive(Debug, Deserialize)]
struct SwapLegQuery {
    /// initiate/join transaction hash (with or without 0x prefix).
    tx_hash: String,
}

/// Decode a SwapCoordinator initiate/join tx: full leg from calldata + swap id / mining
/// status from the receipt. The wallet MUST check `mined && tx_success` and that `swap_id`
/// matches the swap it intends to join before trusting the decoded leg.
async fn get_swap_leg(
    State(reg): State<PoolRegistry>,
    Query(q): Query<SwapLegQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let rpc = reg.builder.rpc.clone();
    let tx_hash = normalize_hex_0x(&q.tx_hash).to_lowercase();
    let input = rpc
        .get_transaction_input(&tx_hash)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("eth_getTransactionByHash: {e:#}"),
            )
        })?
        .ok_or((StatusCode::NOT_FOUND, "transaction not found".to_owned()))?;
    if input.len() < 4 {
        return Err((StatusCode::BAD_REQUEST, "tx input too short".to_owned()));
    }

    let mut out = serde_json::json!({ "tx_hash": tx_hash });
    if input[..4] == swap_initiate_selector() {
        let d = decode_swap_initiate_calldata(&input).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("initiate calldata decode: {e}"),
            )
        })?;
        out["kind"] = "initiate".into();
        out["pool_a"] = hex20_0x(&d.pool_a).into();
        out["pool_b"] = hex20_0x(&d.pool_b).into();
        out["htlc_hash"] = hex32_0x(&d.htlc_hash).into();
        out["rk_bx"] = hex32_0x(&d.rk_bx).into();
        out["rk_by"] = hex32_0x(&d.rk_by).into();
        out["deadline"] = d.deadline.into();
        out["commit_a"] = hex32_0x(&d.commit_a()).into();
        out["call_a"] = serde_json::to_value(swap_call_json(&d.call_a)).unwrap_or_default();
    } else if input[..4] == swap_join_selector() {
        let d = decode_swap_join_calldata(&input).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("join calldata decode: {e}"),
            )
        })?;
        out["kind"] = "join".into();
        out["swap_id_calldata"] = hex32_0x(&d.swap_id).into();
        out["commit_b"] = hex32_0x(&d.commit_b()).into();
        out["call_b"] = serde_json::to_value(swap_call_json(&d.call_b)).unwrap_or_default();
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            "not a SwapCoordinator initiateSwap/joinSwap transaction".to_owned(),
        ));
    }

    // Receipt: mining status + the authoritative swap id from the coordinator's event.
    let receipt = rpc
        .get_transaction_receipt_logs(&tx_hash)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("eth_getTransactionReceipt: {e:#}"),
            )
        })?;
    match receipt {
        Some(receipt) => {
            out["mined"] = true.into();
            out["tx_success"] = receipt.success.into();
            out["block_number"] = receipt.block_number.into();
            out["block_hash"] = receipt.block_hash.clone().into();
            let want_init = swap_initiated_topic0_hex().to_lowercase();
            let want_join = swap_joined_topic0_hex().to_lowercase();
            for log in &receipt.logs {
                let Some(topics) = &log.topics else { continue };
                let Some(t0) = topics.first() else { continue };
                let t0 = t0.to_lowercase();
                if t0 == want_init || t0 == want_join {
                    if let Some(sid) = topics.get(1) {
                        out["swap_id"] = normalize_hex_0x(sid).to_lowercase().into();
                    }
                    out["coordinator"] = normalize_hex_0x(&log.address).to_lowercase().into();
                }
            }
        }
        None => {
            out["mined"] = false.into();
            out["tx_success"] = serde_json::Value::Null;
        }
    }
    Ok(Json(out))
}

#[derive(Debug, Deserialize)]
struct SwapLookupQuery {
    /// Swap id (bytes32 hex).
    swap_id: String,
    /// SwapCoordinator contract address.
    coordinator: String,
    /// First block of the `eth_getLogs` scan. Defaults to 0; pass the coordinator's
    /// deploy block (or a recent lower bound) on providers that reject wide ranges.
    from_block: Option<u64>,
    /// When false, skip fetching/decoding the initiate/join tx calldata (summary only).
    include_calls: Option<bool>,
}

/// Event-driven view of one swap: lifecycle status, both commits, and (by default) both
/// decoded legs pulled from the initiate/join tx calldata.
async fn get_swap(
    State(reg): State<PoolRegistry>,
    Query(q): Query<SwapLookupQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let rpc = reg.builder.rpc.clone();
    let swap_id = parse_hex32(&q.swap_id)
        .ok_or((StatusCode::BAD_REQUEST, "invalid swap_id hex".to_owned()))?;
    let coordinator = normalize_hex_0x(&q.coordinator).to_lowercase();
    let finalized = rpc
        .finalized_block()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("eth_getBlockByNumber(finalized): {e:#}"),
            )
        })?
        .0;
    let topic0s = vec![
        swap_initiated_topic0_hex(),
        swap_joined_topic0_hex(),
        swap_settled_topic0_hex(),
        swap_cancelled_topic0_hex(),
    ];
    let mut logs = rpc
        .fetch_logs_topic0_or_with_topic1(
            q.from_block.unwrap_or(0),
            finalized,
            &coordinator,
            &topic0s,
            &hex32_0x(&swap_id),
        )
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("eth_getLogs: {e:#}")))?;
    rpc.validate_canonical_logs(&logs)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("canonical log validation: {e:#}"),
            )
        })?;
    if logs.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            "no events for this swap id".to_owned(),
        ));
    }
    logs.sort_by_key(|l| {
        (
            parse_hex_u64(&l.block_number).unwrap_or(u64::MAX),
            parse_hex_u64(&l.log_index).unwrap_or(u64::MAX),
        )
    });

    let t_init = swap_initiated_topic0_hex().to_lowercase();
    let t_join = swap_joined_topic0_hex().to_lowercase();
    let t_settle = swap_settled_topic0_hex().to_lowercase();
    let t_cancel = swap_cancelled_topic0_hex().to_lowercase();

    let mut out = serde_json::json!({
        "swap_id": hex32_0x(&swap_id),
        "coordinator": coordinator,
        "status": "unknown",
    });
    let mut initiate_tx: Option<String> = None;
    let mut join_tx: Option<String> = None;
    for log in &logs {
        let Some(t0) = log.topics.as_ref().and_then(|t| t.first()) else {
            continue;
        };
        let t0 = t0.to_lowercase();
        let tx = normalize_hex_0x(&log.transaction_hash).to_lowercase();
        let data = &log.data;
        let topics = log.topics.clone().unwrap_or_default();
        if t0 == t_init {
            if let Ok(d) = decode_swap_initiated_log(&topics, data) {
                out["initiator"] = hex20_0x(&d.initiator).into();
                out["pool_a"] = hex20_0x(&d.pool_a).into();
                out["pool_b"] = hex20_0x(&d.pool_b).into();
                out["htlc_hash"] = hex32_0x(&d.htlc_hash).into();
                out["deadline"] = d.deadline.into();
                out["commit_a"] = hex32_0x(&d.commit_a).into();
                out["rk_bx"] = hex32_0x(&d.rk_bx).into();
                out["rk_by"] = hex32_0x(&d.rk_by).into();
            }
            out["initiate_tx"] = tx.clone().into();
            out["status"] = "initiated".into();
            initiate_tx = Some(tx);
        } else if t0 == t_join {
            if let Ok(d) = decode_swap_joined_log(&topics, data) {
                out["joiner"] = hex20_0x(&d.joiner).into();
                out["commit_b"] = hex32_0x(&d.commit_b).into();
            }
            out["join_tx"] = tx.clone().into();
            out["status"] = "joined".into();
            join_tx = Some(tx);
        } else if t0 == t_settle {
            out["settle_tx"] = tx.into();
            out["status"] = "settled".into();
        } else if t0 == t_cancel {
            out["cancel_tx"] = tx.into();
            out["status"] = "cancelled".into();
        }
    }

    // Pull the full legs out of the initiate/join tx calldata (plan A DA path) and
    // re-derive each commitment so the caller can see it matches the event commit.
    if q.include_calls.unwrap_or(true) {
        if let Some(tx) = initiate_tx {
            if let Ok(Some(input)) = rpc.get_transaction_input(&tx).await {
                if let Ok(d) = decode_swap_initiate_calldata(&input) {
                    out["call_a"] =
                        serde_json::to_value(swap_call_json(&d.call_a)).unwrap_or_default();
                    out["commit_a_from_calldata"] = hex32_0x(&d.commit_a()).into();
                }
            }
        }
        if let Some(tx) = join_tx {
            if let Ok(Some(input)) = rpc.get_transaction_input(&tx).await {
                if let Ok(d) = decode_swap_join_calldata(&input) {
                    out["call_b"] =
                        serde_json::to_value(swap_call_json(&d.call_b)).unwrap_or_default();
                    out["commit_b_from_calldata"] = hex32_0x(&d.commit_b()).into();
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
    if s.tree_out_of_order {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "indexer canonical cursor is not verified".to_owned(),
        ));
    }
    let &position = s
        .cmx_to_position
        .get(&cmx)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "cmx not found in tree".to_owned()))?;

    // Batch-update model: witnesses must open to the CONFIRMED root (`/root`), so they
    // are computed over the confirmed prefix only. A pending note (position >= watermark)
    // has no anchor that includes it yet — it becomes spendable after the next updateRoot.
    if position >= s.confirmed_count {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "note is pending batch confirmation (position {position}, confirmed {}); retry after the next updateRoot",
                s.confirmed_count
            ),
        ));
    }

    s.tree
        .merkle_path_at(position, s.confirmed_count)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                "merkle path not available for this position".to_owned(),
            )
        })
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

// ─── Frozen leaf-delta feed (frozen-tree-execution-plan PR2) ──────────────────
//
// The indexer stays DUMB: it ingests `FrozenRootUpdated` events and appends the raw
// leaf delta to an ordered per-pool feed. It does NOT rebuild a Frozen IMT or recompute
// roots — that is the wallet's job (§2/§4). Wallets pull `GET /frozen_updates?since=cursor`
// and replay the deltas to maintain their own tree, asserting `localRoot == cmxFrozenRoot()`
// on-chain before proving. The `(block_number, log_index)` pair is the cursor and preserves
// on-chain order. Reorg safety is intentionally NOT handled here: a reverted delta is caught
// downstream by the wallet's `eth_call cmxFrozenRoot()` vs local-root check (fail-closed), so
// do NOT add indexer-side reorg logic for this feature (see ENG-03/PRO-14 scope).

/// One ingested `FrozenRootUpdated` leaf delta.
#[derive(Clone, Serialize, Deserialize)]
struct FrozenUpdate {
    /// Cursor components (strictly increasing in on-chain order).
    block_number: u64,
    log_index: u64,
    tx_hash: String,
    /// `oldRoot` / `newRoot` as 0x big-endian 32-byte hex (the on-chain `uint256` words).
    old_root_hex: String,
    new_root_hex: String,
    /// `cmx` leaves changed this update, 0x big-endian hex, in IMT-apply order.
    cmx_changed_hex: Vec<String>,
    /// Per-leaf op: `true` (=1) added, `false` (=0) removed. Same length as `cmx_changed_hex`.
    is_add: Vec<bool>,
}

#[derive(Serialize)]
struct FrozenUpdatesResponse {
    /// Deltas strictly AFTER the requested cursor, in on-chain order.
    updates: Vec<FrozenUpdate>,
    /// Opaque cursor to pass as `since` next time (the last returned entry's cursor, or the
    /// caller's `since` when nothing new). Format: `"<block>:<logIndex>"`.
    cursor: String,
}

/// Decoded `FrozenRootUpdated(uint256,uint256,uint256[],bool[])` payload (all non-indexed,
/// so the entire tuple lives in `log.data`).
struct FrozenDelta {
    old_root: [u8; 32],
    new_root: [u8; 32],
    cmx_changed: Vec<[u8; 32]>,
    is_add: Vec<bool>,
}

/// Manually ABI-decode `FrozenRootUpdated` log `data` (head/tail dynamic-array encoding).
/// Pinned to a `cast abi-encode` fixture in the unit tests below.
fn decode_frozen_root_updated_log(data_hex: &str) -> Result<FrozenDelta> {
    let bytes = hex::decode(data_hex.trim_start_matches("0x"))
        .context("FrozenRootUpdated: data is not valid hex")?;
    let word = |byte_off: usize| -> Result<[u8; 32]> {
        bytes
            .get(byte_off..byte_off + 32)
            .map(|s| {
                let mut w = [0u8; 32];
                w.copy_from_slice(s);
                w
            })
            .ok_or_else(|| anyhow!("FrozenRootUpdated: data too short at byte offset {byte_off}"))
    };
    // A 32-byte word → usize, rejecting absurd sizes (guards a malformed/huge length or offset).
    let word_to_usize = |w: &[u8; 32]| -> Result<usize> {
        if w[..24].iter().any(|&b| b != 0) {
            bail!("FrozenRootUpdated: value exceeds usize");
        }
        Ok(u64::from_be_bytes(w[24..].try_into().unwrap()) as usize)
    };
    let read_array = |head_word_idx: usize| -> Result<Vec<[u8; 32]>> {
        let off = word_to_usize(&word(head_word_idx * 32)?)?;
        let len = word_to_usize(&word(off)?)?;
        // Sanity bound: an update carries a small compliance delta, never megabytes.
        if len > 100_000 {
            bail!("FrozenRootUpdated: array length {len} implausibly large");
        }
        let mut out = Vec::with_capacity(len);
        for i in 0..len {
            out.push(word(off + 32 + i * 32)?);
        }
        Ok(out)
    };

    let old_root = word(0)?;
    let new_root = word(32)?;
    let cmx_changed = read_array(2)?;
    let is_add_words = read_array(3)?;
    if cmx_changed.len() != is_add_words.len() {
        bail!(
            "FrozenRootUpdated: cmxChanged ({}) / isAdd ({}) length mismatch",
            cmx_changed.len(),
            is_add_words.len()
        );
    }
    let is_add = is_add_words
        .iter()
        .map(|w| w.iter().any(|&b| b != 0))
        .collect();
    Ok(FrozenDelta {
        old_root,
        new_root,
        cmx_changed,
        is_add,
    })
}

/// Replay the ingested delta feed into the current frozen leaf set (0x big-endian hex). Add
/// inserts (idempotent); remove deletes. Ordering here is the most-recent-add order and is only
/// cosmetic — the prover re-sorts the set when rebuilding the IMT (`frozen_populated_tree_root`).
fn replay_frozen_set(updates: &[FrozenUpdate]) -> Vec<String> {
    let mut set: Vec<String> = Vec::new();
    for u in updates {
        for (cmx, &add) in u.cmx_changed_hex.iter().zip(u.is_add.iter()) {
            if add {
                if !set.iter().any(|c| c == cmx) {
                    set.push(cmx.clone());
                }
            } else {
                set.retain(|c| c != cmx);
            }
        }
    }
    set
}

/// Latest `newRoot` disclosed on-chain (from the feed), or the all-zero placeholder if no
/// update has been ingested yet. The AUTHORITATIVE root is always the pool's on-chain
/// `cmxFrozenRoot()`; this is a feed-derived convenience.
fn latest_frozen_root_hex(updates: &[FrozenUpdate]) -> String {
    updates
        .last()
        .map(|u| u.new_root_hex.clone())
        .unwrap_or_else(|| format!("0x{}", "00".repeat(32)))
}

/// `GET /frozen_root` — latest compliance root disclosed on-chain (feed-derived, PR2). The
/// admin sets this via `setFrozenRoot`; the authoritative source is the pool's on-chain
/// `cmxFrozenRoot()`. Returns the last ingested `newRoot` as 0x big-endian hex; `frozen_count`
/// is the net leaf count after replaying the delta feed (adds − removes).
async fn get_frozen_root(
    State(reg): State<PoolRegistry>,
    Query(q): Query<SimplePoolQuery>,
) -> Result<Json<FrozenRootResponse>, (StatusCode, String)> {
    let ctx = reg.resolve(q.pool.as_deref()).await?;
    let s = ctx.state.read().await;
    Ok(Json(FrozenRootResponse {
        root_hex: latest_frozen_root_hex(&s.frozen_updates),
        frozen_count: replay_frozen_set(&s.frozen_updates).len(),
    }))
}

#[derive(Serialize)]
struct FrozenLeavesResponse {
    /// Current frozen `cmx` set (`cm_old.x` values, 0x big-endian hex). Feed this directly to the
    /// prover's `frozen_blacklist`; the prover re-sorts and rebuilds the Frozen IMT.
    leaves: Vec<String>,
    /// The latest on-chain `newRoot` these leaves SHOULD reproduce. The wallet MUST still read the
    /// authoritative `cmxFrozenRoot()` from chain itself and pass it as `expected_frozen_root` so
    /// the prover fail-closes on a stale/incorrect set — do NOT trust this value alone.
    root_hex: String,
    count: usize,
}

/// `GET /frozen_leaves?pool=` — the CURRENT compliance blacklist as a full leaf set (PR2, the
/// simplified wallet path). The indexer replays its ingested `FrozenRootUpdated` deltas into the
/// live set so the wallet can read it directly (no local tree). Safety still comes from the
/// wallet passing the on-chain `cmxFrozenRoot()` as `expected_frozen_root`: the prover verifies
/// `frozen_populated_tree_root(leaves) == cmxFrozenRoot()` and rejects a mismatch. The
/// append-only `/frozen_updates` feed remains for auditing / trustless cold-start.
async fn get_frozen_leaves(
    State(reg): State<PoolRegistry>,
    Query(q): Query<SimplePoolQuery>,
) -> Result<Json<FrozenLeavesResponse>, (StatusCode, String)> {
    let ctx = reg.resolve(q.pool.as_deref()).await?;
    let s = ctx.state.read().await;
    let leaves = replay_frozen_set(&s.frozen_updates);
    Ok(Json(FrozenLeavesResponse {
        count: leaves.len(),
        root_hex: latest_frozen_root_hex(&s.frozen_updates),
        leaves,
    }))
}

#[derive(Deserialize)]
struct FrozenUpdatesQuery {
    #[serde(default)]
    pool: Option<String>,
    /// Cursor `"<block>:<logIndex>"`; only deltas strictly after it are returned. Omit for all.
    #[serde(default)]
    since: Option<String>,
}

/// `GET /frozen_updates?pool=&since=cursor` — the compliance leaf-delta feed (PR2 main path).
/// Wallets replay these deltas to maintain their local Frozen IMT, then assert
/// `localRoot == cmxFrozenRoot()` on-chain before proving. The indexer stays dumb: it does not
/// rebuild the tree or serve witnesses.
async fn get_frozen_updates(
    State(reg): State<PoolRegistry>,
    Query(q): Query<FrozenUpdatesQuery>,
) -> Result<Json<FrozenUpdatesResponse>, (StatusCode, String)> {
    let ctx = reg.resolve(q.pool.as_deref()).await?;
    // Parse the cursor into (block, logIndex); malformed/absent = from the beginning.
    let after = q.since.as_deref().and_then(|s| {
        let (b, l) = s.split_once(':')?;
        Some((b.parse::<u64>().ok()?, l.parse::<u64>().ok()?))
    });
    let s = ctx.state.read().await;
    let updates: Vec<FrozenUpdate> = s
        .frozen_updates
        .iter()
        .filter(|u| match after {
            Some((b, l)) => (u.block_number, u.log_index) > (b, l),
            None => true,
        })
        .cloned()
        .collect();
    let cursor = updates
        .last()
        .map(|u| format!("{}:{}", u.block_number, u.log_index))
        .or_else(|| q.since.clone())
        .unwrap_or_default();
    Ok(Json(FrozenUpdatesResponse { updates, cursor }))
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
    headers: HeaderMap,
    Query(q): Query<SimplePoolQuery>,
    Json(req): Json<NotifyTxRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let ctx = reg.resolve(q.pool.as_deref()).await?;
    if ctx.shadow_mode {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "relayer notifications are disabled in shadow mode".to_owned(),
        ));
    }
    require_relayer(&headers, reg.relayer_token.as_ref())?;
    if parse_hex32(&req.tx_hash).is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "tx_hash must be a 32-byte hex value".to_owned(),
        ));
    }
    let tx_hash = normalize_hex_0x(&req.tx_hash);
    let ingest_guard = ctx.ingest_lock.lock().await;
    let mut s = ctx.state.write().await;
    if !s.pending_tx_hashes.iter().any(|h| h == &tx_hash) {
        s.pending_tx_hashes.push_back(tx_hash.clone());
        while s.pending_tx_hashes.len() > 1000 {
            s.pending_tx_hashes.pop_front();
        }
    }
    println!(
        "[indexer] notify_tx queued: {tx_hash} (pending={} hashes)",
        s.pending_tx_hashes.len()
    );
    // Persist immediately so the queue survives a restart.
    ctx.persist.notify(&s);
    drop(s);
    drop(ingest_guard);
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
    last_finalized_block: Option<u64>,
    #[serde(default)]
    last_finalized_block_hash: Option<String>,
    #[serde(default)]
    cmx_leaves_hex: Vec<String>,
    #[serde(default)]
    active_root_hex: Option<String>,
    #[serde(default)]
    confirmed_count: Option<u64>,
    #[serde(default)]
    last_leaf_block: Option<u64>,
    #[serde(default)]
    last_leaf_log_index: Option<u64>,
    #[serde(default)]
    latest_seq: u64,
    #[serde(default)]
    batches: Vec<BatchEnvelope>,
    /// Tx hashes notified by relayer but not yet confirmed via WS event.
    #[serde(default)]
    pending_tx_hashes: Vec<String>,
    /// Frozen leaf-delta feed ingested from `FrozenRootUpdated` events (PR2). Persisted verbatim
    /// so the feed survives restarts and wallets can pull from any cursor.
    #[serde(default)]
    frozen_updates: Vec<FrozenUpdate>,
    /// Event-derived ERC20Shield aggregate accounting.
    #[serde(default)]
    shield_accounting: ShieldAccounting,
}

/// Loaded result from a checkpoint file.
struct CheckpointData {
    next_block: u64,
    last_finalized_block: Option<u64>,
    last_finalized_block_hash: Option<String>,
    cmx_ordered: Vec<[u8; 32]>,
    active_root: Option<[u8; 32]>,
    confirmed_count: u64,
    confirmed_cmx: HashSet<[u8; 32]>,
    last_leaf_key: Option<(u64, u64)>,
    warm_start_candidate: bool,
    latest_seq: u64,
    batches: VecDeque<BatchEnvelope>,
    pending_tx_hashes: VecDeque<String>,
    frozen_updates: Vec<FrozenUpdate>,
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
                let active_root: Option<[u8; 32]> = ck.active_root_hex.as_deref().and_then(|h| {
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
                CheckpointData {
                    next_block: resumed,
                    last_finalized_block: ck.last_finalized_block,
                    last_finalized_block_hash: ck
                        .last_finalized_block_hash
                        .and_then(|hash| normalize_block_hash(&hash).ok()),
                    cmx_ordered,
                    active_root,
                    confirmed_count: ck.confirmed_count.unwrap_or(0),
                    confirmed_cmx: HashSet::new(),
                    last_leaf_key: ck.last_leaf_block.zip(ck.last_leaf_log_index),
                    // JSON checkpoints do not have a transactional note archive,
                    // so they deliberately retain the full-replay startup path.
                    warm_start_candidate: false,
                    latest_seq: ck.latest_seq,
                    batches,
                    pending_tx_hashes,
                    frozen_updates: ck.frozen_updates,
                    shield_accounting: ck.shield_accounting,
                }
            }
            Err(e) => {
                eprintln!(
                    "[indexer] checkpoint parse error ({e}), starting from block {start_block}"
                );
                CheckpointData {
                    next_block: start_block,
                    last_finalized_block: None,
                    last_finalized_block_hash: None,
                    cmx_ordered: vec![],
                    active_root: None,
                    confirmed_count: 0,
                    confirmed_cmx: HashSet::new(),
                    last_leaf_key: None,
                    warm_start_candidate: false,
                    latest_seq: 0,
                    batches: VecDeque::new(),
                    pending_tx_hashes: VecDeque::new(),
                    frozen_updates: vec![],
                    shield_accounting: ShieldAccounting::default(),
                }
            }
        },
        Err(_) => CheckpointData {
            next_block: start_block,
            last_finalized_block: None,
            last_finalized_block_hash: None,
            cmx_ordered: vec![],
            active_root: None,
            confirmed_count: 0,
            confirmed_cmx: HashSet::new(),
            last_leaf_key: None,
            warm_start_candidate: false,
            latest_seq: 0,
            batches: VecDeque::new(),
            pending_tx_hashes: VecDeque::new(),
            frozen_updates: vec![],
            shield_accounting: ShieldAccounting::default(),
        },
    }
}

fn save_checkpoint(path: &str, snap: &CheckpointSnapshot) -> Result<()> {
    let ck = IndexerCheckpoint {
        next_block: snap.next_block,
        last_finalized_block: snap.last_finalized_block,
        last_finalized_block_hash: snap.last_finalized_block_hash.clone(),
        cmx_leaves_hex: snap.cmx_ordered.iter().map(hex::encode).collect(),
        active_root_hex: snap.active_root.map(hex::encode),
        confirmed_count: Some(snap.confirmed_count),
        last_leaf_block: snap.last_leaf_key.map(|(block, _)| block),
        last_leaf_log_index: snap.last_leaf_key.map(|(_, log_index)| log_index),
        latest_seq: snap.latest_seq,
        batches: snap.batches.clone(),
        pending_tx_hashes: snap.pending_tx_hashes.clone(),
        frozen_updates: snap.frozen_updates.clone(),
        shield_accounting: snap.shield_accounting,
    };
    let json = serde_json::to_string(&ck).context("serialize indexer checkpoint")?;
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, &json).with_context(|| format!("write checkpoint {tmp}"))?;
    std::fs::rename(&tmp, path).with_context(|| format!("replace checkpoint {path}"))?;
    Ok(())
}

// ─── State backend (JSON file | PostgreSQL) ───────────────────────────────────

/// A point-in-time copy of the persistable state, built from `SharedState` while a
/// lock is held, then handed off (no await needed at the call site).
#[derive(Clone, Default)]
struct CheckpointSnapshot {
    next_block: u64,
    last_finalized_block: Option<u64>,
    last_finalized_block_hash: Option<String>,
    cmx_ordered: Vec<[u8; 32]>,
    active_root: Option<[u8; 32]>,
    confirmed_count: u64,
    last_leaf_key: Option<(u64, u64)>,
    latest_seq: u64,
    batches: Vec<BatchEnvelope>,
    pending_tx_hashes: Vec<String>,
    frozen_updates: Vec<FrozenUpdate>,
    shield_accounting: ShieldAccounting,
}

impl CheckpointSnapshot {
    fn from_state(s: &SharedState) -> Self {
        Self {
            next_block: s.next_block,
            last_finalized_block: s.last_finalized_block,
            last_finalized_block_hash: s.last_finalized_block_hash.clone(),
            cmx_ordered: s.cmx_ordered.clone(),
            active_root: s.active_root,
            confirmed_count: s.confirmed_count,
            last_leaf_key: s.last_leaf_key,
            latest_seq: s.latest_seq,
            batches: s.batches.iter().cloned().collect(),
            pending_tx_hashes: s.pending_tx_hashes.iter().cloned().collect(),
            frozen_updates: s.frozen_updates.clone(),
            shield_accounting: s.shield_accounting,
        }
    }
    fn from_checkpoint_data(ck: &CheckpointData) -> Self {
        Self {
            next_block: ck.next_block,
            last_finalized_block: ck.last_finalized_block,
            last_finalized_block_hash: ck.last_finalized_block_hash.clone(),
            cmx_ordered: ck.cmx_ordered.clone(),
            active_root: ck.active_root,
            confirmed_count: ck.confirmed_count,
            last_leaf_key: ck.last_leaf_key,
            latest_seq: ck.latest_seq,
            batches: ck.batches.iter().cloned().collect(),
            pending_tx_hashes: ck.pending_tx_hashes.iter().cloned().collect(),
            frozen_updates: ck.frozen_updates.clone(),
            shield_accounting: ck.shield_accounting,
        }
    }
}

/// Where persisted state lives. `Json` is per-pool (its own file); `Pgsql` is one shared
/// connection pool with every row keyed by `pool_address`.
#[derive(Clone, Debug)]
enum NoteArchiveMutation {
    Upsert(BatchEnvelope),
    Confirm {
        cmx: [u8; 32],
        position: u64,
    },
    ShieldAmount {
        cmx: [u8; 32],
        amount: u64,
    },
}

fn push_incremental_replay_mutation(
    buffered: &mut Vec<NoteArchiveMutation>,
    mutation: NoteArchiveMutation,
    limit: usize,
) -> Result<()> {
    if buffered.len() >= limit {
        return Err(anyhow!(
            "incremental replay mutation limit exceeded: {limit}"
        ));
    }
    buffered.push(mutation);
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "record_type", rename_all = "snake_case")]
enum JsonNoteArchiveUpdate {
    Confirm {
        cmx_hex: String,
        position: u64,
    },
    ShieldAmount {
        cmx_hex: String,
        amount: u64,
    },
}

#[derive(Clone)]
enum StateBackend {
    Json(Option<String>),
    Pgsql(sqlx::PgPool),
}

impl StateBackend {
    /// Sidecar JSONL file holding every batch envelope ever emitted (JSON mode).
    /// The in-memory ring only caches the most recent `max_batches`; this archive
    /// is what lets `/batches?after_seq=0` serve full history after eviction.
    fn json_archive_path(state_path: &str) -> String {
        format!("{state_path}.batches.jsonl")
    }

    fn json_rebuild_archive_path(state_path: &str) -> String {
        format!("{state_path}.batches.rebuild.jsonl")
    }

    fn append_json_line<T: Serialize>(path: &str, value: &T) -> Result<()> {
        use std::io::Write;
        let line = serde_json::to_string(value).context("serialize note archive record")?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("open note archive {path}"))?;
        writeln!(file, "{line}").with_context(|| format!("append note archive {path}"))
    }

    /// Persist note-history mutations. During a full finalized replay they are
    /// written to an isolated staging generation; ordinary catch-up writes the
    /// canonical archive directly.
    async fn apply_note_mutations(
        &self,
        pool_address: &str,
        rebuild_generation: Option<&str>,
        mutations: &[NoteArchiveMutation],
    ) -> Result<()> {
        if mutations.is_empty() {
            return Ok(());
        }
        match self {
            StateBackend::Json(Some(path)) => {
                let archive_path = if rebuild_generation.is_some() {
                    Self::json_rebuild_archive_path(path)
                } else {
                    Self::json_archive_path(path)
                };
                for mutation in mutations {
                    match mutation {
                        NoteArchiveMutation::Upsert(env) => {
                            Self::append_json_line(&archive_path, env)?;
                        }
                        NoteArchiveMutation::Confirm { cmx, position } => {
                            Self::append_json_line(
                                &archive_path,
                                &JsonNoteArchiveUpdate::Confirm {
                                    cmx_hex: hex::encode(cmx),
                                    position: *position,
                                },
                            )?;
                        }
                        NoteArchiveMutation::ShieldAmount { cmx, amount } => {
                            Self::append_json_line(
                                &archive_path,
                                &JsonNoteArchiveUpdate::ShieldAmount {
                                    cmx_hex: hex::encode(cmx),
                                    amount: *amount,
                                },
                            )?;
                        }
                    }
                }
                Ok(())
            }
            StateBackend::Json(None) => Ok(()),
            StateBackend::Pgsql(pool) => {
                pg_apply_note_mutations(
                    pool,
                    pool_address,
                    rebuild_generation,
                    mutations,
                )
                .await
            }
        }
    }

    /// Atomically publish one canonical incremental replay in PostgreSQL.
    /// JSON mode preserves the same ordering but cannot provide a cross-file transaction.
    async fn commit_incremental_replay(
        &self,
        pool_address: &str,
        mutations: &[NoteArchiveMutation],
        snap: &CheckpointSnapshot,
    ) -> Result<()> {
        match self {
            StateBackend::Pgsql(pool) => {
                pg_commit_incremental_replay(pool, pool_address, mutations, snap).await
            }
            StateBackend::Json(_) => {
                self.apply_note_mutations(pool_address, None, mutations)
                    .await?;
                self.save(pool_address, snap).await
            }
        }
    }

    async fn begin_canonical_rebuild(
        &self,
        pool_address: &str,
        generation: &str,
    ) -> Result<()> {
        match self {
            StateBackend::Json(Some(path)) => {
                std::fs::write(Self::json_rebuild_archive_path(path), [])
                    .with_context(|| format!("initialize rebuild archive for {pool_address}"))?;
                Ok(())
            }
            StateBackend::Json(None) => Ok(()),
            StateBackend::Pgsql(pool) => {
                pg_begin_canonical_rebuild(pool, pool_address, generation).await
            }
        }
    }

    async fn finish_canonical_rebuild(
        &self,
        pool_address: &str,
        generation: &str,
        snap: &CheckpointSnapshot,
    ) -> Result<()> {
        match self {
            StateBackend::Json(Some(path)) => {
                let rebuild_path = Self::json_rebuild_archive_path(path);
                let staged_raw = std::fs::read_to_string(&rebuild_path)
                    .with_context(|| format!("read staged note archive for {pool_address}"))?;
                let staged_notes =
                    decode_json_note_archive(&staged_raw, pool_address).len();
                if staged_notes != snap.cmx_ordered.len() {
                    return Err(anyhow!(
                        "canonical note activation mismatch: staged={staged_notes}, tree_leaves={}",
                        snap.cmx_ordered.len()
                    ));
                }
                save_checkpoint(path, snap)?;
                std::fs::rename(
                    rebuild_path,
                    Self::json_archive_path(path),
                )
                .with_context(|| format!("activate finalized note archive for {pool_address}"))?;
                Ok(())
            }
            StateBackend::Json(None) => Ok(()),
            StateBackend::Pgsql(pool) => {
                pg_finish_canonical_rebuild(pool, pool_address, generation, snap).await
            }
        }
    }

    /// Drop the archive. Called when the batch history restarts from seq 0
    /// (full rebuild via `backfill_from_chain`, or a fresh checkpoint), so stale
    /// lines can never collide with re-issued sequence numbers.
    fn reset_archive(&self) {
        if let StateBackend::Json(Some(path)) = self {
            let _ = std::fs::remove_file(Self::json_archive_path(path));
            let _ = std::fs::remove_file(Self::json_rebuild_archive_path(path));
        }
    }

    /// Load archived envelopes with `after_seq < seq < before_seq`, oldest first.
    /// Complements the in-memory ring when a client asks for history that has
    /// already been evicted from it.
    async fn load_archived_batches(
        &self,
        pool_address: &str,
        after_seq: u64,
        before_seq: u64,
    ) -> Vec<BatchEnvelope> {
        match self {
            StateBackend::Json(Some(path)) => {
                let raw = match std::fs::read_to_string(Self::json_archive_path(path)) {
                    Ok(r) => r,
                    Err(_) => return Vec::new(),
                };
                decode_json_note_archive(&raw, pool_address)
                    .into_iter()
                    .filter(|env| env.seq > after_seq && env.seq < before_seq)
                    .collect()
            }
            StateBackend::Json(None) => Vec::new(),
            StateBackend::Pgsql(pool) => {
                type NoteRow = (
                    String,         // cmx_hex
                    i64,            // seq
                    i64,            // block_number
                    String,         // tx_hash
                    i64,            // log_index
                    Option<i64>,    // position
                    String,         // enc_ciphertext_hex
                    String,         // epk_hex
                    String,         // out_ciphertext_hex
                    Option<String>, // cv_net_x_hex
                    String,         // nf_old_hex
                    String,         // ack_hash_hex
                    Option<i64>,    // shield_amount_sats
                    bool,           // is_confirmed
                );
                let rows: Vec<NoteRow> = sqlx::query_as(
                    "SELECT cmx_hex, seq, block_number, tx_hash, log_index, position, \
                       enc_ciphertext_hex, epk_hex, out_ciphertext_hex, cv_net_x_hex, \
                       nf_old_hex, ack_hash_hex, shield_amount_sats, is_confirmed \
                     FROM notes WHERE pool_address=$1 AND seq > $2 AND seq < $3 ORDER BY seq",
                )
                .bind(pool_address)
                .bind(after_seq as i64)
                .bind(before_seq as i64)
                .fetch_all(pool)
                .await
                .unwrap_or_default();

                rows.into_iter()
                    .filter_map(|r| {
                        let (
                            cmx_hex,
                            seq,
                            block_number,
                            tx_hash,
                            log_index,
                            position,
                            enc_hex,
                            epk_hex,
                            out_hex,
                            cv_hex,
                            nf_hex,
                            ack_hex,
                            shield,
                            confirmed,
                        ) = r;
                        let note = OrchardIndexedAbiNote {
                            block_number: block_number as u64,
                            tx_hash,
                            log_index: log_index as u64,
                            cmx: parse_hex32(&cmx_hex)?,
                            enc_ciphertext: hex::decode(strip_0x(&enc_hex)).ok()?,
                            epk: parse_hex32(&epk_hex)?,
                            out_ciphertext: hex::decode(strip_0x(&out_hex)).unwrap_or_default(),
                            cv_net_x: cv_hex.as_deref().and_then(parse_hex32),
                            nf_old: parse_hex32(&nf_hex)?,
                            ack_hash: parse_hex32(&ack_hex)?,
                            cmx_position: position.map(|p| p as u64),
                            shield_amount_sats: shield.map(|v| v as u64),
                            is_confirmed: confirmed,
                        };
                        Some(BatchEnvelope {
                            seq: seq as u64,
                            pool_address: Some(pool_address.to_string()),
                            batch: OrchardIndexBatch {
                                from_block: note.block_number,
                                to_block: note.block_number,
                                abi_notes: vec![note],
                                bundles: vec![],
                                latest_root: None,
                            },
                        })
                    })
                    .collect()
            }
        }
    }

    async fn load(&self, pool_address: &str, start_block: u64) -> CheckpointData {
        match self {
            StateBackend::Json(Some(path)) => load_checkpoint(path, start_block),
            StateBackend::Json(None) => empty_checkpoint(start_block),
            StateBackend::Pgsql(pool) => pg_load(pool, pool_address, start_block).await,
        }
    }
    async fn save(&self, pool_address: &str, snap: &CheckpointSnapshot) -> Result<()> {
        match self {
            StateBackend::Json(Some(path)) => save_checkpoint(path, snap),
            StateBackend::Json(None) => Ok(()),
            StateBackend::Pgsql(pool) => pg_save(pool, pool_address, snap).await,
        }
    }
}

fn decode_json_note_archive(raw: &str, pool_address: &str) -> Vec<BatchEnvelope> {
    let mut by_cmx: HashMap<[u8; 32], BatchEnvelope> = HashMap::new();
    for line in raw.lines() {
        // Tolerate a torn final line from a crash mid-append and legacy archives
        // that contain plain BatchEnvelope records only.
        if let Ok(env) = serde_json::from_str::<BatchEnvelope>(line) {
            for note in &env.batch.abi_notes {
                let mut single = env.clone();
                single.pool_address = Some(pool_address.to_string());
                single.batch.abi_notes = vec![note.clone()];
                by_cmx.insert(note.cmx, single);
            }
            continue;
        }
        let Ok(update) = serde_json::from_str::<JsonNoteArchiveUpdate>(line) else {
            continue;
        };
        match update {
            JsonNoteArchiveUpdate::Confirm { cmx_hex, position } => {
                if let Some(env) = parse_hex32(&cmx_hex).and_then(|cmx| by_cmx.get_mut(&cmx)) {
                    if let Some(note) = env.batch.abi_notes.first_mut() {
                        note.cmx_position = Some(position);
                        note.is_confirmed = true;
                    }
                }
            }
            JsonNoteArchiveUpdate::ShieldAmount { cmx_hex, amount } => {
                if let Some(env) = parse_hex32(&cmx_hex).and_then(|cmx| by_cmx.get_mut(&cmx)) {
                    if let Some(note) = env.batch.abi_notes.first_mut() {
                        note.shield_amount_sats = Some(amount);
                    }
                }
            }
        }
    }
    let mut out: Vec<BatchEnvelope> = by_cmx.into_values().collect();
    out.sort_by_key(|env| env.seq);
    out
}

fn empty_checkpoint(start_block: u64) -> CheckpointData {
    CheckpointData {
        next_block: start_block,
        last_finalized_block: None,
        last_finalized_block_hash: None,
        cmx_ordered: vec![],
        active_root: None,
        confirmed_count: 0,
        confirmed_cmx: HashSet::new(),
        last_leaf_key: None,
        warm_start_candidate: false,
        latest_seq: 0,
        batches: VecDeque::new(),
        pending_tx_hashes: VecDeque::new(),
        frozen_updates: vec![],
        shield_accounting: ShieldAccounting::default(),
    }
}

/// Clonable handle the contexts hold; `notify` coalesces saves via a watch channel so
/// call sites stay synchronous (no await while holding a lock).
#[derive(Clone)]
struct Persist {
    tx: tokio::sync::watch::Sender<std::sync::Arc<PersistRequest>>,
    paused: Arc<AtomicBool>,
    /// Invalidates snapshots queued before a staged rebuild or incremental replay.
    epoch: Arc<AtomicU64>,
    read_only: bool,
}

#[derive(Clone)]
struct PersistRequest {
    epoch: u64,
    snapshot: CheckpointSnapshot,
}

impl Persist {
    fn is_paused(&self) -> bool {
        self.paused.load(AtomicOrdering::Acquire)
    }

    fn notify(&self, s: &SharedState) {
        if self.read_only || self.is_paused() {
            return;
        }
        let epoch = self.epoch.load(AtomicOrdering::Acquire);
        let snapshot = CheckpointSnapshot::from_state(s);
        if self.is_paused() || epoch != self.epoch.load(AtomicOrdering::Acquire) {
            return;
        }
        let _ = self
            .tx
            .send(std::sync::Arc::new(PersistRequest { epoch, snapshot }));
    }
    /// Persist an already-built snapshot (for sites that dropped the lock first).
    fn notify_owned(&self, snap: CheckpointSnapshot) {
        if self.read_only || self.is_paused() {
            return;
        }
        let epoch = self.epoch.load(AtomicOrdering::Acquire);
        if self.is_paused() || epoch != self.epoch.load(AtomicOrdering::Acquire) {
            return;
        }
        let _ = self.tx.send(std::sync::Arc::new(PersistRequest {
            epoch,
            snapshot: snap,
        }));
    }

    fn pause_and_invalidate_queued(&self) {
        self.paused.store(true, AtomicOrdering::Release);
        self.epoch.fetch_add(1, AtomicOrdering::AcqRel);
    }

    fn resume(&self) {
        self.paused.store(false, AtomicOrdering::Release);
    }
}

fn persist_request_is_current(paused: bool, current_epoch: u64, request_epoch: u64) -> bool {
    !paused && current_epoch == request_epoch
}

/// Background task: drains the latest snapshot and persists it (JSON or PG).
async fn persist_task(
    backend: StateBackend,
    pool_address: String,
    mut rx: tokio::sync::watch::Receiver<std::sync::Arc<PersistRequest>>,
    paused: Arc<AtomicBool>,
    epoch: Arc<AtomicU64>,
    backend_write_lock: Arc<tokio::sync::Mutex<()>>,
) {
    let short = pool_address[..10.min(pool_address.len())].to_string();
    while rx.changed().await.is_ok() {
        let request = rx.borrow_and_update().clone();
        if !persist_request_is_current(
            paused.load(AtomicOrdering::Acquire),
            epoch.load(AtomicOrdering::Acquire),
            request.epoch,
        ) {
            continue;
        }
        let _write_guard = backend_write_lock.lock().await;
        if !persist_request_is_current(
            paused.load(AtomicOrdering::Acquire),
            epoch.load(AtomicOrdering::Acquire),
            request.epoch,
        ) {
            continue;
        }
        if let Err(e) = backend.save(&pool_address, &request.snapshot).await {
            eprintln!("[indexer][{short}] persist failed: {e:#}");
        }
    }
}

#[derive(Clone, Debug)]
struct ArchivedNoteRow {
    seq: u64,
    note: OrchardIndexedAbiNote,
}

#[derive(Default)]
struct CompactedNoteMutations {
    upserts: Vec<ArchivedNoteRow>,
    confirmations: Vec<([u8; 32], u64)>,
    shield_amounts: Vec<([u8; 32], u64)>,
}

fn compact_note_mutations(mutations: &[NoteArchiveMutation]) -> CompactedNoteMutations {
    let mut upserts: HashMap<[u8; 32], ArchivedNoteRow> = HashMap::new();
    let mut confirmations: HashMap<[u8; 32], u64> = HashMap::new();
    let mut shield_amounts: HashMap<[u8; 32], u64> = HashMap::new();
    for mutation in mutations {
        match mutation {
            NoteArchiveMutation::Upsert(env) => {
                for note in &env.batch.abi_notes {
                    upserts.insert(
                        note.cmx,
                        ArchivedNoteRow {
                            seq: env.seq,
                            note: note.clone(),
                        },
                    );
                }
            }
            NoteArchiveMutation::Confirm { cmx, position } => {
                confirmations.insert(*cmx, *position);
            }
            NoteArchiveMutation::ShieldAmount { cmx, amount } => {
                shield_amounts.insert(*cmx, *amount);
            }
        }
    }
    let mut upserts: Vec<ArchivedNoteRow> = upserts.into_values().collect();
    upserts.sort_by_key(|row| row.seq);
    let mut confirmations: Vec<([u8; 32], u64)> = confirmations.into_iter().collect();
    confirmations.sort_by_key(|(cmx, _)| *cmx);
    let mut shield_amounts: Vec<([u8; 32], u64)> = shield_amounts.into_iter().collect();
    shield_amounts.sort_by_key(|(cmx, _)| *cmx);
    CompactedNoteMutations {
        upserts,
        confirmations,
        shield_amounts,
    }
}

const NOTE_COLUMNS: &str = "\
pool_address, cmx_hex, seq, block_number, tx_hash, log_index, position, \
enc_ciphertext_hex, epk_hex, out_ciphertext_hex, cv_net_x_hex, nf_old_hex, ack_hash_hex, \
shield_amount_sats, is_confirmed";

const NOTE_UPDATE_FROM_EXCLUDED: &str = "\
seq=EXCLUDED.seq, block_number=EXCLUDED.block_number, tx_hash=EXCLUDED.tx_hash, \
log_index=EXCLUDED.log_index, position=EXCLUDED.position, \
enc_ciphertext_hex=EXCLUDED.enc_ciphertext_hex, epk_hex=EXCLUDED.epk_hex, \
out_ciphertext_hex=EXCLUDED.out_ciphertext_hex, cv_net_x_hex=EXCLUDED.cv_net_x_hex, \
nf_old_hex=EXCLUDED.nf_old_hex, ack_hash_hex=EXCLUDED.ack_hash_hex, \
shield_amount_sats=EXCLUDED.shield_amount_sats, is_confirmed=EXCLUDED.is_confirmed";

async fn pg_bulk_upsert_notes(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pool_address: &str,
    rebuild_generation: Option<&str>,
    rows: &[ArchivedNoteRow],
) -> Result<()> {
    for chunk in rows.chunks(250) {
        let prefix = if rebuild_generation.is_some() {
            format!(
                "INSERT INTO notes_rebuild (pool_address, rebuild_generation, {}) ",
                NOTE_COLUMNS.trim_start_matches("pool_address, ")
            )
        } else {
            format!("INSERT INTO notes ({NOTE_COLUMNS}) ")
        };
        let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(prefix);
        query.push_values(chunk, |mut row_builder, row| {
            let note = &row.note;
            row_builder.push_bind(pool_address);
            if let Some(generation) = rebuild_generation {
                row_builder.push_bind(generation);
            }
            row_builder
                .push_bind(hex::encode(note.cmx))
                .push_bind(row.seq as i64)
                .push_bind(note.block_number as i64)
                .push_bind(&note.tx_hash)
                .push_bind(note.log_index as i64)
                .push_bind(note.cmx_position.map(|position| position as i64))
                .push_bind(hex::encode(&note.enc_ciphertext))
                .push_bind(hex::encode(note.epk))
                .push_bind(hex::encode(&note.out_ciphertext))
                .push_bind(note.cv_net_x.map(hex::encode))
                .push_bind(hex::encode(note.nf_old))
                .push_bind(hex::encode(note.ack_hash))
                .push_bind(note.shield_amount_sats.map(|amount| amount as i64))
                .push_bind(note.is_confirmed);
        });
        if rebuild_generation.is_some() {
            query.push(
                " ON CONFLICT (pool_address, rebuild_generation, cmx_hex) DO UPDATE SET ",
            );
        } else {
            query.push(" ON CONFLICT (pool_address, cmx_hex) DO UPDATE SET ");
        }
        query.push(NOTE_UPDATE_FROM_EXCLUDED);
        query
            .build()
            .execute(&mut **tx)
            .await
            .context("bulk upsert note archive")?;
    }
    Ok(())
}

async fn pg_apply_compacted_note_mutations_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pool_address: &str,
    rebuild_generation: Option<&str>,
    compacted: &CompactedNoteMutations,
) -> Result<()> {
    pg_bulk_upsert_notes(tx, pool_address, rebuild_generation, &compacted.upserts).await?;

    if !compacted.confirmations.is_empty() {
        let cmx_values: Vec<String> = compacted
            .confirmations
            .iter()
            .map(|(cmx, _)| hex::encode(cmx))
            .collect();
        let positions: Vec<i64> = compacted
            .confirmations
            .iter()
            .map(|(_, position)| *position as i64)
            .collect();
        let affected = if let Some(generation) = rebuild_generation {
            sqlx::query(
                "UPDATE notes_rebuild AS n \
                 SET position=u.position, is_confirmed=TRUE \
                 FROM UNNEST($3::text[], $4::bigint[]) AS u(cmx_hex, position) \
                 WHERE n.pool_address=$1 AND n.rebuild_generation=$2 AND n.cmx_hex=u.cmx_hex",
            )
            .bind(pool_address)
            .bind(generation)
            .bind(&cmx_values)
            .bind(&positions)
            .execute(&mut **tx)
            .await?
            .rows_affected()
        } else {
            sqlx::query(
                "UPDATE notes AS n \
                 SET position=u.position, is_confirmed=TRUE \
                 FROM UNNEST($2::text[], $3::bigint[]) AS u(cmx_hex, position) \
                 WHERE n.pool_address=$1 AND n.cmx_hex=u.cmx_hex",
            )
            .bind(pool_address)
            .bind(&cmx_values)
            .bind(&positions)
            .execute(&mut **tx)
            .await?
            .rows_affected()
        };
        if affected != compacted.confirmations.len() as u64 {
            return Err(anyhow!(
                "note confirmation archive mismatch: expected {} row(s), updated {affected}",
                compacted.confirmations.len()
            ));
        }
    }

    if !compacted.shield_amounts.is_empty() {
        let cmx_values: Vec<String> = compacted
            .shield_amounts
            .iter()
            .map(|(cmx, _)| hex::encode(cmx))
            .collect();
        let amounts: Vec<i64> = compacted
            .shield_amounts
            .iter()
            .map(|(_, amount)| *amount as i64)
            .collect();
        let affected = if let Some(generation) = rebuild_generation {
            sqlx::query(
                "UPDATE notes_rebuild AS n \
                 SET shield_amount_sats=u.amount \
                 FROM UNNEST($3::text[], $4::bigint[]) AS u(cmx_hex, amount) \
                 WHERE n.pool_address=$1 AND n.rebuild_generation=$2 AND n.cmx_hex=u.cmx_hex",
            )
            .bind(pool_address)
            .bind(generation)
            .bind(&cmx_values)
            .bind(&amounts)
            .execute(&mut **tx)
            .await?
            .rows_affected()
        } else {
            sqlx::query(
                "UPDATE notes AS n \
                 SET shield_amount_sats=u.amount \
                 FROM UNNEST($2::text[], $3::bigint[]) AS u(cmx_hex, amount) \
                 WHERE n.pool_address=$1 AND n.cmx_hex=u.cmx_hex",
            )
            .bind(pool_address)
            .bind(&cmx_values)
            .bind(&amounts)
            .execute(&mut **tx)
            .await?
            .rows_affected()
        };
        if affected != compacted.shield_amounts.len() as u64 {
            return Err(anyhow!(
                "shield amount archive mismatch: expected {} row(s), updated {affected}",
                compacted.shield_amounts.len()
            ));
        }
    }
    Ok(())
}

async fn pg_apply_note_mutations(
    pool: &sqlx::PgPool,
    pool_address: &str,
    rebuild_generation: Option<&str>,
    mutations: &[NoteArchiveMutation],
) -> Result<()> {
    let compacted = compact_note_mutations(mutations);
    let mut tx = pool
        .begin()
        .await
        .context("begin note archive transaction")?;
    pg_apply_compacted_note_mutations_tx(&mut tx, pool_address, rebuild_generation, &compacted)
        .await?;
    tx.commit().await.context("commit note archive transaction")
}

async fn pg_begin_canonical_rebuild(
    pool: &sqlx::PgPool,
    pool_address: &str,
    generation: &str,
) -> Result<()> {
    if generation.is_empty() {
        return Err(anyhow!("canonical rebuild generation must not be empty"));
    }
    sqlx::query("DELETE FROM notes_rebuild WHERE pool_address=$1")
        .bind(pool_address)
        .execute(pool)
        .await
        .context("clear stale note rebuild generations")?;
    Ok(())
}

#[derive(Clone, Copy)]
enum SnapshotSaveMode {
    ReplaceDerivedState,
    AppendOnly,
}

async fn pg_existing_cmx_prefix_len(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pool_address: &str,
    snap: &CheckpointSnapshot,
) -> Result<usize> {
    let (count, max_position): (i64, Option<i64>) =
        sqlx::query_as("SELECT count(*), max(position) FROM cmx_leaves WHERE pool_address=$1")
            .bind(pool_address)
            .fetch_one(&mut **tx)
            .await
            .context("inspect persisted cmx prefix")?;
    let count = usize::try_from(count).context("negative persisted cmx count")?;
    let expected_max = count.checked_sub(1).map(|position| position as i64);
    if max_position != expected_max {
        return Err(anyhow!(
            "persisted cmx positions are not contiguous: count={count}, max={max_position:?}"
        ));
    }
    if count > snap.cmx_ordered.len() {
        return Err(anyhow!(
            "append-only cmx checkpoint would shrink persisted state: persisted={count}, snapshot={}",
            snap.cmx_ordered.len()
        ));
    }
    if count > 0 {
        let last_hex: String = sqlx::query_scalar(
            "SELECT cmx_hex FROM cmx_leaves WHERE pool_address=$1 AND position=$2",
        )
        .bind(pool_address)
        .bind((count - 1) as i64)
        .fetch_one(&mut **tx)
        .await
        .context("load persisted cmx prefix boundary")?;
        let expected = hex::encode(snap.cmx_ordered[count - 1]);
        if !last_hex.eq_ignore_ascii_case(&expected) {
            return Err(anyhow!(
                "append-only cmx checkpoint prefix mismatch at position {}",
                count - 1
            ));
        }
    }
    Ok(count)
}

async fn pg_save_snapshot_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pool_address: &str,
    snap: &CheckpointSnapshot,
    mode: SnapshotSaveMode,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO indexer_meta \
           (pool_address, next_block, active_root_hex, latest_seq, last_finalized_block, last_finalized_block_hash, \
            confirmed_count, last_leaf_block, last_leaf_log_index, checkpoint_version, updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,1, now()) \
         ON CONFLICT (pool_address) DO UPDATE SET \
           next_block=$2, active_root_hex=$3, latest_seq=$4, \
           last_finalized_block=$5, last_finalized_block_hash=$6, confirmed_count=$7, \
           last_leaf_block=$8, last_leaf_log_index=$9, checkpoint_version=1, updated_at=now()",
    )
    .bind(pool_address)
    .bind(snap.next_block as i64)
    .bind(snap.active_root.map(hex::encode))
    .bind(snap.latest_seq as i64)
    .bind(snap.last_finalized_block.map(|block| block as i64))
    .bind(&snap.last_finalized_block_hash)
    .bind(snap.confirmed_count as i64)
    .bind(snap.last_leaf_key.map(|(block, _)| block as i64))
    .bind(snap.last_leaf_key.map(|(_, log_index)| log_index as i64))
    .execute(&mut **tx)
    .await
    .context("upsert indexer_meta")?;

    let cmx_start = match mode {
        SnapshotSaveMode::ReplaceDerivedState => {
            sqlx::query("DELETE FROM cmx_leaves WHERE pool_address=$1")
                .bind(pool_address)
                .execute(&mut **tx)
                .await
                .context("replace cmx_leaves")?;
            0
        }
        SnapshotSaveMode::AppendOnly => pg_existing_cmx_prefix_len(tx, pool_address, snap).await?,
    };
    sqlx::query("DELETE FROM frozen_updates WHERE pool_address=$1")
        .bind(pool_address)
        .execute(&mut **tx)
        .await
        .context("replace frozen_updates")?;

    for (chunk_number, chunk) in snap.cmx_ordered[cmx_start..].chunks(1_000).enumerate() {
        let base = cmx_start + chunk_number * 1_000;
        let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "INSERT INTO cmx_leaves (pool_address, position, cmx_hex) ",
        );
        query.push_values(chunk.iter().enumerate(), |mut row, (offset, cmx)| {
            row.push_bind(pool_address)
                .push_bind((base + offset) as i64)
                .push_bind(hex::encode(cmx));
        });
        query
            .build()
            .execute(&mut **tx)
            .await
            .context("bulk insert cmx_leaves")?;
    }

    // Frozen leaf-delta feed (append-only, on-chain order) — one JSON row per ingested
    // `FrozenRootUpdated`, replayed by wallets to rebuild the Frozen IMT (PR2). Note persistence
    // moved out of the snapshot in origin's canonical-rebuild refactor (`pg_load` leaves batches
    // empty and `backfill_from_chain` re-derives notes from the finalized chain), so this function
    // no longer inlines a notes upsert.
    for (pos, upd) in snap.frozen_updates.iter().enumerate() {
        let json = serde_json::to_string(upd).context("serialize frozen_update")?;
        sqlx::query(
            "INSERT INTO frozen_updates (pool_address, position, update_json) VALUES ($1,$2,$3) \
             ON CONFLICT (pool_address, position) DO NOTHING",
        )
        .bind(pool_address)
        .bind(pos as i64)
        .bind(json)
        .execute(&mut **tx)
        .await
        .context("insert frozen_updates")?;
    }

    sqlx::query("DELETE FROM pending_tx WHERE pool_address=$1")
        .bind(pool_address)
        .execute(&mut **tx)
        .await
        .context("clear pending_tx")?;
    for chunk in snap.pending_tx_hashes.chunks(1_000) {
        let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "INSERT INTO pending_tx (pool_address, tx_hash) ",
        );
        query.push_values(chunk, |mut row, hash| {
            row.push_bind(pool_address).push_bind(hash);
        });
        query
            .push(" ON CONFLICT DO NOTHING")
            .build()
            .execute(&mut **tx)
            .await
            .context("bulk insert pending_tx")?;
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
    .execute(&mut **tx)
    .await
    .context("upsert shield_pool_stats")?;
    Ok(())
}

async fn pg_finish_canonical_rebuild(
    pool: &sqlx::PgPool,
    pool_address: &str,
    generation: &str,
    snap: &CheckpointSnapshot,
) -> Result<()> {
    let mut tx = pool.begin().await.context("begin canonical rebuild activation")?;
    let staged: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM notes_rebuild \
         WHERE pool_address=$1 AND rebuild_generation=$2",
    )
    .bind(pool_address)
    .bind(generation)
    .fetch_one(&mut *tx)
    .await
    .context("count staged canonical notes")?;
    if staged as usize != snap.cmx_ordered.len() {
        return Err(anyhow!(
            "canonical note activation mismatch: staged={staged}, tree_leaves={}",
            snap.cmx_ordered.len()
        ));
    }

    sqlx::query("DELETE FROM notes WHERE pool_address=$1")
        .bind(pool_address)
        .execute(&mut *tx)
        .await
        .context("clear previous canonical notes")?;
    let inserted = sqlx::query(
        "INSERT INTO notes \
           (pool_address, cmx_hex, seq, block_number, tx_hash, log_index, position, \
            enc_ciphertext_hex, epk_hex, out_ciphertext_hex, cv_net_x_hex, nf_old_hex, \
            ack_hash_hex, shield_amount_sats, is_confirmed) \
         SELECT pool_address, cmx_hex, seq, block_number, tx_hash, log_index, position, \
            enc_ciphertext_hex, epk_hex, out_ciphertext_hex, cv_net_x_hex, nf_old_hex, \
            ack_hash_hex, shield_amount_sats, is_confirmed \
         FROM notes_rebuild \
         WHERE pool_address=$1 AND rebuild_generation=$2",
    )
    .bind(pool_address)
    .bind(generation)
    .execute(&mut *tx)
    .await
    .context("activate staged canonical notes")?
    .rows_affected();
    if inserted != staged as u64 {
        return Err(anyhow!(
            "canonical note activation mismatch: staged={staged}, inserted={inserted}"
        ));
    }

    pg_save_snapshot_tx(
        &mut tx,
        pool_address,
        snap,
        SnapshotSaveMode::ReplaceDerivedState,
    )
    .await?;
    sqlx::query("DELETE FROM notes_rebuild WHERE pool_address=$1")
        .bind(pool_address)
        .execute(&mut *tx)
        .await
        .context("clear activated note staging rows")?;
    tx.commit()
        .await
        .context("commit canonical rebuild activation")
}

async fn pg_save(pool: &sqlx::PgPool, pool_address: &str, snap: &CheckpointSnapshot) -> Result<()> {
    let mut tx = pool.begin().await.context("pg begin")?;
    pg_save_snapshot_tx(&mut tx, pool_address, snap, SnapshotSaveMode::AppendOnly).await?;
    tx.commit().await.context("pg commit")
}

async fn pg_commit_incremental_replay(
    pool: &sqlx::PgPool,
    pool_address: &str,
    mutations: &[NoteArchiveMutation],
    snap: &CheckpointSnapshot,
) -> Result<()> {
    let compacted = compact_note_mutations(mutations);
    let mut tx = pool
        .begin()
        .await
        .context("begin incremental replay transaction")?;
    pg_apply_compacted_note_mutations_tx(&mut tx, pool_address, None, &compacted).await?;
    pg_save_snapshot_tx(&mut tx, pool_address, snap, SnapshotSaveMode::AppendOnly).await?;
    tx.commit()
        .await
        .context("commit incremental replay transaction")
}

/// Load a transactional PostgreSQL checkpoint and prove its relational shape is
/// sufficient for warm-start.  Cryptographic/root and finalized-hash validation
/// happen later against the rebuilt in-memory tree and live RPC.
async fn pg_load(pool: &sqlx::PgPool, pool_address: &str, start_block: u64) -> CheckpointData {
    type MetaRow = (
        i64,
        Option<String>,
        i64,
        Option<i64>,
        Option<String>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        i16,
    );
    let label = &pool_address[..10.min(pool_address.len())];
    let mut warm_rejection: Option<String> = None;
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(error) => {
            eprintln!("[indexer][{label}] cannot open checkpoint snapshot: {error}");
            return empty_checkpoint(start_block);
        }
    };
    if let Err(error) = sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await
    {
        eprintln!("[indexer][{label}] cannot pin checkpoint snapshot: {error}");
        return empty_checkpoint(start_block);
    }
    let meta = match sqlx::query_as::<_, MetaRow>(
        "SELECT next_block, active_root_hex, latest_seq, last_finalized_block, \
                last_finalized_block_hash, confirmed_count, last_leaf_block, last_leaf_log_index, \
                checkpoint_version \
         FROM indexer_meta WHERE pool_address=$1",
    )
    .bind(pool_address)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(row) => row,
        Err(error) => {
            warm_rejection = Some(format!("load indexer_meta: {error}"));
            None
        }
    };
    let meta_present = meta.is_some();
    let (
        raw_next_block,
        active_root_hex,
        raw_latest_seq,
        raw_finalized_block,
        raw_finalized_hash,
        raw_confirmed_count,
        raw_last_leaf_block,
        raw_last_leaf_log_index,
        checkpoint_version,
    ) = meta.unwrap_or((start_block as i64, None, 0, None, None, None, None, None, 0));
    if !matches!(checkpoint_version, 0 | 1) {
        warm_rejection.get_or_insert_with(|| "unsupported checkpoint version".to_string());
    }

    if raw_next_block < 0 || raw_latest_seq < 0 {
        warm_rejection.get_or_insert_with(|| "negative checkpoint scalar".to_string());
    }
    let next_block = u64::try_from(raw_next_block)
        .unwrap_or(start_block)
        .max(start_block);
    let latest_seq = u64::try_from(raw_latest_seq).unwrap_or(0);
    let last_finalized_block = raw_finalized_block.and_then(|value| u64::try_from(value).ok());
    let last_finalized_block_hash = raw_finalized_hash
        .as_deref()
        .and_then(|value| normalize_block_hash(value).ok());
    if raw_finalized_block.is_some() != raw_finalized_hash.is_some()
        || raw_finalized_block.is_some() != last_finalized_block.is_some()
        || raw_finalized_hash.is_some() != last_finalized_block_hash.is_some()
    {
        warm_rejection.get_or_insert_with(|| "invalid finalized cursor pair".to_string());
    }
    let persisted_confirmed_count = raw_confirmed_count.and_then(|value| u64::try_from(value).ok());
    if checkpoint_version == 1 && persisted_confirmed_count.is_none() {
        warm_rejection.get_or_insert_with(|| "missing confirmed_count".to_string());
    }
    let persisted_last_leaf_key = match (raw_last_leaf_block, raw_last_leaf_log_index) {
        (Some(block), Some(log_index)) => match (u64::try_from(block), u64::try_from(log_index)) {
            (Ok(block), Ok(log_index)) => Some((block, log_index)),
            _ => {
                if checkpoint_version == 1 {
                    warm_rejection.get_or_insert_with(|| "negative last-leaf cursor".to_string());
                }
                None
            }
        },
        (None, None) => None,
        _ => {
            if checkpoint_version == 1 {
                warm_rejection.get_or_insert_with(|| "incomplete last-leaf cursor".to_string());
            }
            None
        }
    };
    let active_root = match active_root_hex.as_deref() {
        Some(value) => match parse_hex32(value) {
            Some(root) => Some(root),
            None => {
                warm_rejection.get_or_insert_with(|| "invalid active_root_hex".to_string());
                None
            }
        },
        None => None,
    };

    let leaf_rows: Vec<(i64, String)> = match sqlx::query_as(
        "SELECT position, cmx_hex FROM cmx_leaves WHERE pool_address=$1 ORDER BY position",
    )
    .bind(pool_address)
    .fetch_all(&mut *tx)
    .await
    {
        Ok(rows) => rows,
        Err(error) => {
            warm_rejection.get_or_insert_with(|| format!("load cmx leaves: {error}"));
            Vec::new()
        }
    };
    let mut cmx_ordered = Vec::with_capacity(leaf_rows.len());
    for (expected, (position, cmx_hex)) in leaf_rows.iter().enumerate() {
        if *position != expected as i64 {
            warm_rejection.get_or_insert_with(|| "non-contiguous cmx positions".to_string());
        }
        match parse_hex32(cmx_hex) {
            Some(cmx) => cmx_ordered.push(cmx),
            None => {
                warm_rejection.get_or_insert_with(|| "invalid persisted cmx".to_string());
            }
        }
    }

    type NoteIntegrityRow = (String, Option<i64>, i64, i64, bool);
    let note_rows: Vec<NoteIntegrityRow> = match sqlx::query_as(
        "SELECT cmx_hex, position, block_number, log_index, is_confirmed \
         FROM notes WHERE pool_address=$1 ORDER BY position NULLS LAST, cmx_hex",
    )
    .bind(pool_address)
    .fetch_all(&mut *tx)
    .await
    {
        Ok(rows) => rows,
        Err(error) => {
            warm_rejection.get_or_insert_with(|| format!("load note integrity rows: {error}"));
            Vec::new()
        }
    };
    if note_rows.len() != cmx_ordered.len() {
        warm_rejection.get_or_insert_with(|| "note/leaf cardinality mismatch".to_string());
    }
    let mut confirmed_cmx = HashSet::new();
    let mut derived_confirmed_count = 0u64;
    let mut saw_unconfirmed = false;
    for (expected, (cmx_hex, position, block, log_index, is_confirmed)) in
        note_rows.iter().enumerate()
    {
        let parsed = parse_hex32(cmx_hex);
        if *position != Some(expected as i64)
            || parsed != cmx_ordered.get(expected).copied()
            || *block < 0
            || *log_index < 0
        {
            warm_rejection.get_or_insert_with(|| "note/leaf position mismatch".to_string());
        }
        if *is_confirmed {
            if saw_unconfirmed {
                warm_rejection.get_or_insert_with(|| "confirmed note prefix mismatch".to_string());
            }
            derived_confirmed_count = derived_confirmed_count.saturating_add(1);
            if let Some(cmx) = parsed {
                confirmed_cmx.insert(cmx);
            }
        } else {
            saw_unconfirmed = true;
        }
    }
    let confirmed_count = if checkpoint_version == 1 {
        let persisted = persisted_confirmed_count.unwrap_or(0);
        if persisted != derived_confirmed_count {
            warm_rejection.get_or_insert_with(|| "persisted confirmed_count mismatch".to_string());
        }
        persisted
    } else {
        derived_confirmed_count
    };
    if confirmed_count > cmx_ordered.len() as u64 {
        warm_rejection.get_or_insert_with(|| "confirmed_count exceeds tree size".to_string());
    }
    let archive_last_leaf = note_rows
        .last()
        .and_then(|(_, position, block, log_index, _)| {
            position.map(|_| (*block as u64, *log_index as u64))
        });
    let last_leaf_key = if checkpoint_version == 1 {
        if archive_last_leaf != persisted_last_leaf_key
            || cmx_ordered.is_empty() != persisted_last_leaf_key.is_none()
        {
            warm_rejection.get_or_insert_with(|| "last-leaf cursor mismatch".to_string());
        }
        persisted_last_leaf_key
    } else {
        archive_last_leaf
    };
    match (last_finalized_block, last_finalized_block_hash.as_ref()) {
        (Some(block), Some(_)) if next_block == block.saturating_add(1) => {}
        _ => {
            warm_rejection.get_or_insert_with(|| {
                "checkpoint is not at a complete finalized boundary".to_string()
            });
        }
    }
    if last_leaf_key
        .zip(last_finalized_block)
        .is_some_and(|((leaf_block, _), finalized_block)| leaf_block > finalized_block)
    {
        warm_rejection
            .get_or_insert_with(|| "last leaf is beyond finalized checkpoint".to_string());
    }

    let pending_tx_hashes: VecDeque<String> = match sqlx::query_as::<_, (String,)>(
        "SELECT tx_hash FROM pending_tx WHERE pool_address=$1 ORDER BY inserted_at, tx_hash",
    )
    .bind(pool_address)
    .fetch_all(&mut *tx)
    .await
    {
        Ok(rows) => rows.into_iter().map(|(hash,)| hash).collect(),
        Err(error) => {
            warm_rejection.get_or_insert_with(|| format!("load pending txs: {error}"));
            VecDeque::new()
        }
    };

    let frozen_rows: Vec<(String,)> = match sqlx::query_as(
        "SELECT update_json FROM frozen_updates WHERE pool_address=$1 ORDER BY position",
    )
    .bind(pool_address)
    .fetch_all(&mut *tx)
    .await
    {
        Ok(rows) => rows,
        Err(error) => {
            warm_rejection.get_or_insert_with(|| format!("load frozen updates: {error}"));
            Vec::new()
        }
    };
    let mut frozen_updates = Vec::with_capacity(frozen_rows.len());
    for (json,) in frozen_rows {
        match serde_json::from_str(&json) {
            Ok(update) => frozen_updates.push(update),
            Err(error) => {
                warm_rejection.get_or_insert_with(|| format!("decode frozen update: {error}"));
            }
        }
    }

    let stats_row: Option<(String, String, String, String)> = match sqlx::query_as(
        "SELECT total_shielded_units, total_shielded_wei, total_unshielded_units, total_unshielded_wei \
         FROM shield_pool_stats WHERE pool_address=$1",
    )
    .bind(pool_address)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(row) => row,
        Err(error) => {
            warm_rejection.get_or_insert_with(|| format!("load shield stats: {error}"));
            None
        }
    };
    let shield_accounting = match stats_row {
        Some((tsu, tsw, tuu, tuw)) => match (
            tsu.parse::<u128>(),
            tsw.parse::<u128>(),
            tuu.parse::<u128>(),
            tuw.parse::<u128>(),
        ) {
            (Ok(tsu), Ok(tsw), Ok(tuu), Ok(tuw)) => ShieldAccounting {
                total_shielded_units: tsu,
                total_shielded_wei: tsw,
                total_unshielded_units: tuu,
                total_unshielded_wei: tuw,
            },
            _ => {
                warm_rejection.get_or_insert_with(|| "invalid persisted shield stats".to_string());
                ShieldAccounting::default()
            }
        },
        None => ShieldAccounting::default(),
    };

    if let Err(error) = tx.commit().await {
        warm_rejection.get_or_insert_with(|| format!("close checkpoint snapshot: {error}"));
    }

    let warm_start_candidate = meta_present && warm_rejection.is_none();
    if let Some(reason) = &warm_rejection {
        eprintln!("[indexer][{label}] checkpoint is not warm-start eligible: {reason}");
    }
    println!(
        "[indexer] pg load: pool={label} next_block={next_block} leaves={} confirmed={} pending={} frozen_updates={} warm_candidate={warm_start_candidate}",
        cmx_ordered.len(), confirmed_count, pending_tx_hashes.len(), frozen_updates.len()
    );
    CheckpointData {
        next_block,
        last_finalized_block,
        last_finalized_block_hash,
        cmx_ordered,
        active_root,
        confirmed_count,
        confirmed_cmx,
        last_leaf_key,
        warm_start_candidate,
        latest_seq,
        batches: VecDeque::new(),
        pending_tx_hashes,
        frozen_updates,
        shield_accounting,
    }
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
        (entry.out_ciphertext.clone(), Some(entry.cv_net_x))
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
    /// Persistent backend: batch envelopes are archived here as they are emitted
    /// so `/batches` can serve history after in-memory ring eviction.
    backend: StateBackend,
    /// Serializes snapshot writes with staged note-history activation. Combined
    /// with `Persist::paused`, this prevents an old coalesced snapshot from
    /// overwriting the just-activated finalized rebuild.
    backend_write_lock: Arc<tokio::sync::Mutex<()>>,
    /// Active full-rebuild generation. `None` during ordinary finalized catch-up.
    rebuild_generation: Arc<RwLock<Option<String>>>,
    /// Per-getLogs-window note mutations. This bounds rebuild memory while
    /// avoiding a PostgreSQL round-trip for every historical event.
    rebuild_mutations: Arc<tokio::sync::Mutex<Vec<NoteArchiveMutation>>>,
    /// Ordinary catch-up/WS replay mutations, committed only after the terminal
    /// finalized hash check. `None` means there is no active incremental replay.
    incremental_replay_mutations: Arc<tokio::sync::Mutex<Option<Vec<NoteArchiveMutation>>>>,
    /// Incremental replay buffers SSE publication until its terminal finalized
    /// hash check succeeds, preventing partial/non-canonical history leakage.
    broadcast_paused: Arc<AtomicBool>,
    /// Read-only warm-start probe used for blue/green shadow validation.
    shadow_mode: bool,
}

impl PollContext {
    async fn begin_canonical_rebuild(&self, generation: &str) -> Result<()> {
        if self.shadow_mode {
            return Err(anyhow!("canonical rebuild is disabled in shadow mode"));
        }
        self.persist.pause_and_invalidate_queued();
        *self.rebuild_generation.write().await = Some(generation.to_string());
        self.rebuild_mutations.lock().await.clear();
        let _write_guard = self.backend_write_lock.lock().await;
        self.backend
            .begin_canonical_rebuild(&self.contract_address, generation)
            .await
    }

    async fn archive_note_mutation(&self, mutation: NoteArchiveMutation) -> Result<()> {
        let generation = self.rebuild_generation.read().await.clone();
        if generation.is_some() {
            self.rebuild_mutations.lock().await.push(mutation);
            return Ok(());
        }
        {
            let mut slot = self.incremental_replay_mutations.lock().await;
            if let Some(buffered) = slot.as_mut() {
                return push_incremental_replay_mutation(
                    buffered,
                    mutation,
                    MAX_INCREMENTAL_REPLAY_MUTATIONS,
                );
            }
        }
        if self.shadow_mode {
            return Ok(());
        }
        let _write_guard = self.backend_write_lock.lock().await;
        self.backend
            .apply_note_mutations(&self.contract_address, None, &[mutation])
            .await
    }

    async fn begin_incremental_replay(&self) -> Result<()> {
        if self.rebuild_generation.read().await.is_some() {
            return Err(anyhow!(
                "incremental replay cannot start during canonical rebuild"
            ));
        }
        if self.persist.paused.load(AtomicOrdering::Acquire) {
            return Err(anyhow!("checkpoint persistence is already paused"));
        }
        let mut slot = self.incremental_replay_mutations.lock().await;
        if slot.is_some() {
            return Err(anyhow!("incremental replay is already active"));
        }
        *slot = Some(Vec::new());
        self.persist.pause_and_invalidate_queued();
        Ok(())
    }

    async fn finish_incremental_replay(&self, snap: &CheckpointSnapshot) -> Result<usize> {
        let mutations = self.incremental_replay_mutations.lock().await.take();
        let Some(mutations) = mutations else {
            self.persist.resume();
            return Err(anyhow!("no active incremental replay"));
        };
        let mutation_count = mutations.len();
        if self.shadow_mode {
            self.persist.resume();
            return Ok(mutation_count);
        }
        let result = {
            let _write_guard = self.backend_write_lock.lock().await;
            self.backend
                .commit_incremental_replay(&self.contract_address, &mutations, snap)
                .await
        };
        self.persist.resume();
        result.map(|()| mutation_count)
    }

    async fn abort_incremental_replay(&self) {
        self.incremental_replay_mutations.lock().await.take();
        self.persist.resume();
    }

    async fn flush_rebuild_note_mutations(&self) -> Result<()> {
        let generation = self
            .rebuild_generation
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow!("no active canonical rebuild generation"))?;
        let mutations = {
            let mut buffered = self.rebuild_mutations.lock().await;
            std::mem::take(&mut *buffered)
        };
        if mutations.is_empty() {
            return Ok(());
        }
        let _write_guard = self.backend_write_lock.lock().await;
        self.backend
            .apply_note_mutations(
                &self.contract_address,
                Some(&generation),
                &mutations,
            )
            .await
    }

    async fn finish_canonical_rebuild(
        &self,
        generation: &str,
        snap: &CheckpointSnapshot,
    ) -> Result<()> {
        self.flush_rebuild_note_mutations().await?;
        let _write_guard = self.backend_write_lock.lock().await;
        self.backend
            .finish_canonical_rebuild(&self.contract_address, generation, snap)
            .await
    }

    async fn mark_canonical_rebuild_ready(&self) {
        *self.rebuild_generation.write().await = None;
        self.persist.resume();
    }

    async fn mark_canonical_unready(&self) {
        let mut state = self.shared.write().await;
        state.tree_out_of_order = true;
        state.confirmed_frontier = None;
    }

    async fn broadcast_batches_after(&self, after_seq: u64) {
        if self.broadcast_paused.load(AtomicOrdering::Acquire) {
            return;
        }
        let batches = {
            let state = self.shared.read().await;
            if state.tree_out_of_order {
                return;
            }
            state
                .batches
                .iter()
                .filter(|batch| batch.seq > after_seq)
                .cloned()
                .collect::<Vec<_>>()
        };
        for batch in batches {
            self.batch_tx.send(batch).ok();
        }
    }
}

/// Rebuild the commitment tree from chain via `eth_getLogs`, in on-chain order.
///
/// This is the source of truth: it scans `[start_block, finalized_head]` in chunks and
/// replays every pool event through `process_single_log`, so leaf positions and
/// the root always match the contract — even if a prior checkpoint was empty,
/// partial, or corrupt. WebSocket notifications are wake-up hints; only the
/// canonical finalized replay is authoritative.
async fn persisted_finalized_cursor_matches(
    ctx: &PollContext,
    current_finalized_head: u64,
) -> Result<bool> {
    let (block, expected_hash) = {
        let state = ctx.shared.read().await;
        (
            state.last_finalized_block,
            state.last_finalized_block_hash.clone(),
        )
    };
    match (block, expected_hash) {
        (None, None) => Ok(true),
        (Some(block), Some(expected_hash)) if block <= current_finalized_head => {
            let canonical = ctx.rpc.block_hash(block).await?;
            Ok(canonical == expected_hash)
        }
        (Some(_), Some(_)) => Ok(false),
        _ => Ok(false),
    }
}

fn fr_from_le_hex(value: &str) -> Result<Fr> {
    let bytes = hex::decode(strip_0x(value)).context("invalid little-endian field hex")?;
    let repr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("field element must be 32 bytes"))?;
    Option::from(Fr::from_repr(repr.into()))
        .ok_or_else(|| anyhow!("non-canonical BN254 field element"))
}

/// Reconstruct the exact O(1) on-chain frontier from the authentication path of
/// the final leaf. This performs O(n) Poseidon work once, rather than replaying
/// 32 hashes for every historical leaf (O(32n)).
fn frontier_from_tree_prefix(
    tree: &OrchardCommitmentTree,
    leaves: &[[u8; 32]],
    confirmed_count: u64,
) -> Result<FrontierTree> {
    if confirmed_count == 0 {
        return Ok(FrontierTree::new());
    }
    let confirmed_count =
        usize::try_from(confirmed_count).context("confirmed_count does not fit in usize")?;
    if confirmed_count > leaves.len() {
        return Err(anyhow!("confirmed_count exceeds checkpoint leaves"));
    }
    let final_position = (confirmed_count - 1) as u64;
    let path = tree
        .merkle_path_at(final_position, confirmed_count as u64)
        .ok_or_else(|| anyhow!("cannot derive final-leaf Merkle path"))?;
    if path.siblings.len() != MERKLE_DEPTH_EVM {
        return Err(anyhow!(
            "unexpected Merkle path depth: {}",
            path.siblings.len()
        ));
    }
    let mut filled = [Fr::ZERO; MERKLE_DEPTH_EVM];
    let mut node = fr_from_be_bytes(&leaves[final_position as usize])
        .ok_or_else(|| anyhow!("non-canonical confirmed cmx"))?;
    for (level, sibling_hex) in path.siblings.iter().enumerate() {
        let sibling = fr_from_le_hex(sibling_hex)?;
        if (final_position >> level) & 1 == 0 {
            filled[level] = node;
            node = merkle_compress(level as u8, node, sibling);
        } else {
            filled[level] = sibling;
            node = merkle_compress(level as u8, sibling, node);
        }
    }
    Ok(FrontierTree::from_parts(
        filled,
        confirmed_count as u64,
        node,
    ))
}

fn checkpoint_tree_and_frontier(
    leaves: &[[u8; 32]],
    confirmed_count: u64,
) -> Result<(OrchardCommitmentTree, FrontierTree)> {
    let mut tree = OrchardCommitmentTree::new();
    for leaf in leaves {
        tree.append(*leaf);
    }
    let frontier = frontier_from_tree_prefix(&tree, leaves, confirmed_count)?;
    // The prefix path above warms the confirmed subtree cache. Warm the small
    // pending suffix too so /status, /root, and the first witness request do not
    // pay another O(n) Poseidon pass after health turns green.
    let _ = tree.latest_root();
    Ok((tree, frontier))
}

fn frontier_from_ordered_leaves(leaves: &[[u8; 32]]) -> Result<FrontierTree> {
    checkpoint_tree_and_frontier(leaves, leaves.len() as u64).map(|(_, frontier)| frontier)
}

/// Returns the finalized head that the initial incremental catch-up must cover
/// before health may turn green.
async fn try_warm_start(ctx: &PollContext) -> Result<Option<u64>> {
    let label = ctx.contract_address[..10.min(ctx.contract_address.len())].to_string();
    let (candidate, next_block, confirmed_count, active_root, frontier) = {
        let state = ctx.shared.read().await;
        (
            state.warm_start_candidate,
            state.next_block,
            state.confirmed_count,
            state.active_root,
            state.confirmed_frontier.clone(),
        )
    };
    if !candidate {
        return Ok(None);
    }
    let Some(frontier) = frontier else {
        ctx.shared.write().await.startup_source = "checkpoint_rejected".to_string();
        return Ok(None);
    };
    let (finalized_head, _) = ctx
        .rpc
        .finalized_block()
        .await
        .context("resolve finalized head for warm-start")?;
    if !persisted_finalized_cursor_matches(ctx, finalized_head).await? {
        ctx.shared.write().await.startup_source = "checkpoint_rejected".to_string();
        return Err(anyhow!(
            "persisted finalized cursor is not canonical; reviewed recovery is required"
        ));
    }

    let local_root = fr_to_be_bytes(frontier.root());
    let expected_root = match (confirmed_count, active_root) {
        (0, None) => EVM_EMPTY_IMT_ROOT,
        (0, Some(root)) if root == EVM_EMPTY_IMT_ROOT => root,
        (0, Some(_)) => {
            ctx.shared.write().await.startup_source = "checkpoint_rejected".to_string();
            return Ok(None);
        }
        (_, Some(root)) => root,
        (_, None) => {
            ctx.shared.write().await.startup_source = "checkpoint_rejected".to_string();
            return Ok(None);
        }
    };
    if local_root != expected_root {
        eprintln!(
            "[indexer][{label}] warm checkpoint root mismatch: local={} persisted={} count={confirmed_count}",
            hex::encode(local_root),
            hex::encode(expected_root)
        );
        ctx.shared.write().await.startup_source = "checkpoint_rejected".to_string();
        return Ok(None);
    }

    let chain_count_before = word_to_u64(
        &ctx.rpc
            .eth_call_word(&ctx.contract_address, eth_selector(b"confirmedCount()"))
            .await
            .context("read confirmedCount for warm-start")?,
    );
    let chain_root = ctx
        .rpc
        .eth_call_word(&ctx.contract_address, eth_selector(b"confirmedRoot()"))
        .await
        .context("read confirmedRoot for warm-start")?;
    let chain_count = word_to_u64(
        &ctx.rpc
            .eth_call_word(&ctx.contract_address, eth_selector(b"confirmedCount()"))
            .await
            .context("re-read confirmedCount for warm-start")?,
    );
    if chain_count != chain_count_before {
        return Err(anyhow!(
            "confirmed watermark changed during warm-start validation: {chain_count_before} -> {chain_count}"
        ));
    }
    if chain_count < confirmed_count || (chain_count == confirmed_count && chain_root != local_root)
    {
        eprintln!(
            "[indexer][{label}] warm checkpoint is ahead of or divergent from chain: checkpoint_count={confirmed_count}, chain_count={chain_count}"
        );
        ctx.shared.write().await.startup_source = "checkpoint_rejected".to_string();
        return Ok(None);
    }

    let mut state = ctx.shared.write().await;
    if !state.warm_start_candidate
        || state.next_block != next_block
        || state.confirmed_count != confirmed_count
    {
        state.startup_source = "checkpoint_rejected".to_string();
        return Ok(None);
    }
    state.confirmed_frontier = Some(frontier);
    // Stay fail-closed until the incremental suffix reaches `finalized_head`.
    state.tree_out_of_order = true;
    state.startup_source = "checkpoint_validated".to_string();
    println!(
        "[indexer][{label}] canonical warm-start accepted: next_block={next_block}, confirmed={confirmed_count}, chain_confirmed={chain_count}"
    );
    Ok(Some(finalized_head))
}

async fn backfill_from_chain(ctx: &PollContext) -> Result<()> {
    let _ingest = ctx.ingest_lock.lock().await;
    let label = ctx.contract_address[..10.min(ctx.contract_address.len())].to_string();
    let (head, finalized_hash) = ctx
        .rpc
        .finalized_block()
        .await
        .context("resolve finalized head for backfill")?;
    if !persisted_finalized_cursor_matches(ctx, head).await? {
        let mut state = ctx.shared.write().await;
        state.tree_out_of_order = true;
        drop(state);
        eprintln!(
            "[indexer][{label}] persisted finalized cursor is not canonical; \
             refusing automatic mutation of persisted derived history"
        );
        return Err(anyhow!(
            "persisted finalized cursor mismatch; manual recovery from a reviewed checkpoint is required"
        ));
    }
    let generation = format!(
        "{head:x}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    ctx.begin_canonical_rebuild(&generation).await?;
    if head < ctx.start_block {
        let mut state = ctx.shared.write().await;
        // A legacy checkpoint may contain derived state but no finalized
        // marker. A finalized head below the configured deployment block
        // proves there are no canonical pool events to retain.
        state.tree = OrchardCommitmentTree::new();
        state.cmx_to_position.clear();
        state.cmx_ordered.clear();
        state.seen_event_ids.clear();
        state.confirm_seen_ids.clear();
        state.shield_seen_ids.clear();
        state.accounting_seen_ids.clear();
        state.shield_accounting = ShieldAccounting::default();
        state.last_leaf_key = None;
        state.batches.clear();
        state.latest_seq = 0;
        state.confirmed_cmx.clear();
        state.confirmed_count = 0;
        state.confirmed_frontier = Some(FrontierTree::new());
        state.active_root = None;
        state.next_block = ctx.start_block;
        state.last_finalized_block = Some(head);
        state.last_finalized_block_hash = Some(finalized_hash);
        // Remain fail-closed until the empty canonical snapshot and archive are
        // durably activated.
        state.tree_out_of_order = true;
        let snap = CheckpointSnapshot::from_state(&state);
        drop(state);
        ctx.finish_canonical_rebuild(&generation, &snap).await?;
        {
            let mut state = ctx.shared.write().await;
            state.tree_out_of_order = false;
            state.startup_source = "full_replay".to_string();
        }
        ctx.mark_canonical_rebuild_ready().await;
        return Ok(());
    }

    // Every pool event topic0 the live path understands (NoteAdded variants,
    // ShieldCompleted, NoteConfirmed, SwapNotePending).
    let mut topic0s: Vec<String> = note_added_topic0_alternatives()
        .iter()
        .map(|t| normalize_hex_0x(t))
        .collect();
    topic0s.push(normalize_hex_0x(&shield_completed_topic0_hex()));
    topic0s.push(normalize_hex_0x(&ctx.note_confirmed_topic0));
    topic0s.push(normalize_hex_0x(&root_updated_topic0_hex()));
    topic0s.push(normalize_hex_0x(&frozen_root_updated_topic0()));
    topic0s.push(normalize_hex_0x(&shielded_topic0_hex()));
    topic0s.push(normalize_hex_0x(&unshielded_topic0_hex()));

    // Reset tree state for a clean rebuild so positions match on-chain order even
    // if the restored checkpoint was partial/corrupt. (pending_tx_hashes kept.)
    {
        let mut s = ctx.shared.write().await;
        // Public root endpoints fail closed until the complete finalized replay
        // and its terminal block-hash check have both succeeded.
        s.tree_out_of_order = true;
        s.tree = OrchardCommitmentTree::new();
        s.cmx_to_position.clear();
        s.cmx_ordered.clear();
        s.seen_event_ids.clear();
        s.confirm_seen_ids.clear();
        s.shield_seen_ids.clear();
        s.accounting_seen_ids.clear();
        s.shield_accounting = ShieldAccounting::default();
        s.last_leaf_key = None;
        s.batches.clear();
        s.latest_seq = 0;
        s.confirmed_cmx.clear();
        s.confirmed_count = 0;
        s.confirmed_frontier = None;
        s.active_root = None;
    }
    println!(
        "[indexer][{label}] backfill: scanning logs [{}, {head}]…",
        ctx.start_block
    );
    let mut from = ctx.start_block;
    let mut total = 0usize;
    while from <= head {
        let to = getlogs_window_end(from, head, ctx.rpc.getlogs_span());
        match ctx
            .rpc
            .fetch_logs_topic0_or(from, to, &ctx.contract_address, &topic0s)
            .await
        {
            Ok(mut logs) => {
                ctx.rpc
                    .validate_canonical_logs(&logs)
                    .await
                    .with_context(|| format!("canonical log validation [{from},{to}]"))?;
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
                    process_single_log(ctx, log)
                        .await
                        .with_context(|| format!("backfill log processing [{from},{to}]"))?;
                }
                ctx.flush_rebuild_note_mutations()
                    .await
                    .with_context(|| format!("stage finalized notes [{from},{to}]"))?;
            }
            Err(e) if to > from && is_getlogs_range_error(&e) => {
                // Provider rejected the window size: shrink and retry the same
                // offset so the rebuilt tree cannot silently skip a range.
                ctx.rpc.shrink_getlogs_span(to - from + 1);
                continue;
            }
            Err(e) => {
                return Err(e).with_context(|| format!("backfill getLogs [{from},{to}]"));
            }
        }
        from = to + 1;
    }

    let canonical_hash = ctx.rpc.block_hash(head).await?;
    if canonical_hash != finalized_hash {
        return Err(anyhow!(
            "finalized head changed during backfill at block {head}: \
             before={finalized_hash} after={canonical_hash}"
        ));
    }

    // A finalized block is complete. Keep every derived endpoint fail-closed
    // until the full note staging generation and scan snapshot are atomically
    // activated.
    let mut s = ctx.shared.write().await;
    s.next_block = advance_cursor(ctx.start_block, head);
    s.last_finalized_block = Some(head);
    s.last_finalized_block_hash = Some(finalized_hash);
    let tree_size = s.cmx_ordered.len();
    let snap = CheckpointSnapshot::from_state(&s);
    drop(s);
    ctx.finish_canonical_rebuild(&generation, &snap).await?;
    {
        let mut state = ctx.shared.write().await;
        state.tree_out_of_order = false;
        state.startup_source = "full_replay".to_string();
    }
    ctx.mark_canonical_rebuild_ready().await;
    println!(
        "[indexer][{label}] finalized backfill complete: {total} log(s), \
         tree_size={tree_size}, next_block={}",
        advance_cursor(ctx.start_block, head)
    );
    Ok(())
}

/// How often the incremental gap-filler polls the chain to reconcile logs the WebSocket
/// subscription may have silently dropped.
const CATCHUP_INTERVAL_SECS: u64 = 20;

/// Monotonic cursor advance: move `next_block` to just past the reconciled `head`, but never
/// backwards (a concurrent WS log or a later backfill may have already advanced it further).
fn advance_cursor(current: u64, head: u64) -> u64 {
    current.max(head.saturating_add(1))
}

/// Incremental gap-filler. Scans `eth_getLogs` from the persisted `next_block` up to the
/// current finalized head and replays any logs the live WebSocket hinted at, WITHOUT
/// resetting the tree. `process_single_log` dedups atomically by `(tx_hash, log_index)`
/// under the state write lock.
///
/// This is the durability backstop for `run_ws_subscription`: some providers' WS endpoints
/// (notably several Monad ones) silently drop `eth_subscribe` logs or go quiet after a
/// reconnect, which used to leave a permanent gap between the one-shot startup backfill and
/// live streaming. Polling forward on an interval lets the indexer self-heal and keep
/// `next_block` advancing toward the finalized head instead of freezing.
async fn catchup_from_chain(ctx: &PollContext) {
    let label = ctx.contract_address[..10.min(ctx.contract_address.len())].to_string();
    let (head, finalized_hash) = match ctx.rpc.finalized_block().await {
        Ok(value) => value,
        Err(_) => return, // transient RPC error — retry next tick from the same cursor
    };
    match persisted_finalized_cursor_matches(ctx, head).await {
        Ok(true) => {}
        Ok(false) => {
            let mut state = ctx.shared.write().await;
            state.tree_out_of_order = true;
            state.confirmed_frontier = None;
            ctx.persist.notify(&state);
            drop(state);
            eprintln!(
                "[indexer][{label}] canonical cursor mismatch detected; \
                 index-derived roots are disabled pending reviewed recovery"
            );
            return;
        }
        Err(e) => {
            eprintln!("[indexer][{label}] cursor hash check failed closed: {e:#}");
            return;
        }
    }
    // Hold the ingest lock for the WHOLE pass so live WS appends of newer
    // blocks cannot interleave with this ordered replay of older ones.
    let _ingest = ctx.ingest_lock.lock().await;
    let from = { ctx.shared.read().await.next_block };
    if from > head {
        return; // already caught up
    }

    let starting_seq = ctx.shared.read().await.latest_seq;
    if let Err(e) = ctx.begin_incremental_replay().await {
        eprintln!("[indexer][{label}] cannot begin incremental catchup: {e:#}");
        ctx.mark_canonical_unready().await;
        return;
    }
    ctx.broadcast_paused.store(true, AtomicOrdering::Release);
    let total = match replay_range(ctx, from, head).await {
        Ok(n) => n,
        Err(()) => {
            // A prior window may already have mutated derived state. Never
            // expose that partial pass; the dirty path performs a full staged
            // rebuild on the next tick.
            ctx.abort_incremental_replay().await;
            ctx.mark_canonical_unready().await;
            ctx.broadcast_paused.store(false, AtomicOrdering::Release);
            return;
        }
    };

    let canonical_hash = match ctx.rpc.block_hash(head).await {
        Ok(hash) if hash == finalized_hash => hash,
        Ok(hash) => {
            eprintln!(
                "[indexer][{label}] finalized head hash changed during catchup at block {head}: \
                 before={finalized_hash} after={hash}; cursor not advanced"
            );
            ctx.abort_incremental_replay().await;
            ctx.mark_canonical_unready().await;
            ctx.broadcast_paused.store(false, AtomicOrdering::Release);
            return;
        }
        Err(e) => {
            eprintln!("[indexer][{label}] finalized head recheck failed: {e:#}");
            ctx.abort_incremental_replay().await;
            ctx.mark_canonical_unready().await;
            ctx.broadcast_paused.store(false, AtomicOrdering::Release);
            return;
        }
    };

    let mut s = ctx.shared.write().await;
    s.next_block = advance_cursor(s.next_block, head);
    s.last_finalized_block = Some(head);
    s.last_finalized_block_hash = Some(canonical_hash);
    let snap = CheckpointSnapshot::from_state(&s);
    drop(s);
    let mutation_count = match ctx.finish_incremental_replay(&snap).await {
        Ok(count) => count,
        Err(e) => {
            eprintln!("[indexer][{label}] incremental catchup commit failed: {e:#}");
            ctx.mark_canonical_unready().await;
            ctx.broadcast_paused.store(false, AtomicOrdering::Release);
            return;
        }
    };
    ctx.broadcast_paused.store(false, AtomicOrdering::Release);
    ctx.broadcast_batches_after(starting_seq).await;
    if total > 0 {
        println!(
            "[indexer][{label}] catchup: reconciled {total} log(s), committed \
             {mutation_count} note mutation(s) up to block {head}, next_block={}",
            head.saturating_add(1)
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
    topic0s.push(normalize_hex_0x(&root_updated_topic0_hex()));
    topic0s.push(normalize_hex_0x(&frozen_root_updated_topic0()));
    topic0s.push(normalize_hex_0x(&shielded_topic0_hex()));
    topic0s.push(normalize_hex_0x(&unshielded_topic0_hex()));

    let mut total = 0usize;
    let mut lo = from;
    while lo <= to {
        let hi = getlogs_window_end(lo, to, ctx.rpc.getlogs_span());
        match ctx
            .rpc
            .fetch_logs_topic0_or(lo, hi, &ctx.contract_address, &topic0s)
            .await
        {
            Ok(mut logs) => {
                if let Err(e) = ctx.rpc.validate_canonical_logs(&logs).await {
                    eprintln!(
                        "[indexer][{label}] canonical log validation [{lo},{hi}] failed: {e:#}"
                    );
                    return Err(());
                }
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
                        return Err(());
                    }
                    total += 1;
                }
                if hi == u64::MAX {
                    break;
                }
                lo = hi + 1;
            }
            Err(e) if hi > lo && is_getlogs_range_error(&e) => {
                // Window too large for this provider: shrink and retry the same
                // offset instead of failing the whole replay (which would freeze
                // the cursor and wedge the indexer permanently).
                ctx.rpc.shrink_getlogs_span(hi - lo + 1);
            }
            Err(e) => {
                eprintln!("[indexer][{label}] replay getLogs [{lo},{hi}] failed: {e:#}");
                return Err(());
            }
        }
    }
    Ok(total)
}

fn is_watched_pool_log(ctx: &PollContext, log: &EthLog) -> bool {
    if normalize_hex_0x(&log.address).to_lowercase()
        != normalize_hex_0x(&ctx.contract_address).to_lowercase()
    {
        return false;
    }
    let Some(topic0) = log
        .topics
        .as_ref()
        .and_then(|topics| topics.first())
        .map(|topic| norm_topic(topic))
    else {
        return false;
    };
    note_added_topic0_alternatives()
        .iter()
        .any(|topic| norm_topic(topic) == topic0)
        || [
            norm_topic(&shield_completed_topic0_hex()),
            norm_topic(&ctx.note_confirmed_topic0),
            norm_topic(&root_updated_topic0_hex()),
            norm_topic(&shielded_topic0_hex()),
            norm_topic(&unshielded_topic0_hex()),
        ]
        .contains(&topic0)
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
    if log.removed {
        return Err(anyhow!(
            "removed WS log {}:{} rejected",
            log.transaction_hash,
            log.log_index
        ));
    }
    let _ingest = ctx.ingest_lock.lock().await;
    let block_number = parse_hex_u64(&log.block_number)
        .with_context(|| format!("invalid blockNumber: {}", log.block_number))?;
    let (finalized_head, finalized_hash) = ctx.rpc.finalized_block().await?;
    if block_number > finalized_head {
        // Monad publishes Voted logs before finalization. The push remains a
        // wake-up hint only; periodic catch-up will ingest it once finalized.
        return Ok(());
    }
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
        let starting_seq = ctx.shared.read().await.latest_seq;
        ctx.begin_incremental_replay()
            .await
            .context("begin canonical WS replay")?;
        ctx.broadcast_paused.store(true, AtomicOrdering::Release);
        if replay_range(ctx, from, block_number).await.is_err() {
            ctx.abort_incremental_replay().await;
            ctx.mark_canonical_unready().await;
            ctx.broadcast_paused.store(false, AtomicOrdering::Release);
            return Err(anyhow!(
                "canonical replay failed while ingesting WS hint {event_id}"
            ));
        }
        match ctx.rpc.block_hash(finalized_head).await {
            Ok(hash) if hash == finalized_hash => {}
            Ok(hash) => {
                ctx.abort_incremental_replay().await;
                ctx.mark_canonical_unready().await;
                ctx.broadcast_paused.store(false, AtomicOrdering::Release);
                return Err(anyhow!(
                    "finalized boundary changed during WS replay: head={finalized_head}, \
                     before={finalized_hash}, after={hash}"
                ));
            }
            Err(error) => {
                ctx.abort_incremental_replay().await;
                ctx.mark_canonical_unready().await;
                ctx.broadcast_paused.store(false, AtomicOrdering::Release);
                return Err(error).context("recheck finalized boundary during WS replay");
            }
        }
        let mut s = ctx.shared.write().await;
        let is_covered = covered(&s);
        if is_covered {
            // Cursor moves to B (not past it): later same-block pushes trigger
            // a cheap dedup-only replay of B, never a skip.
            s.next_block = s.next_block.max(block_number);
        }
        let snap = CheckpointSnapshot::from_state(&s);
        drop(s);
        if let Err(e) = ctx.finish_incremental_replay(&snap).await {
            ctx.mark_canonical_unready().await;
            ctx.broadcast_paused.store(false, AtomicOrdering::Release);
            return Err(e).context("commit canonical WS replay");
        }
        ctx.broadcast_paused.store(false, AtomicOrdering::Release);
        ctx.broadcast_batches_after(starting_seq).await;
        if is_covered {
            return Ok(());
        }
        // getLogs has not caught up with the WS push yet.
        tokio::time::sleep(Duration::from_millis(50 * (attempt + 1))).await;
    }
    eprintln!(
        "[indexer] WS log {event_id} (block {block_number}) still not visible via eth_getLogs; \
         deferring to the periodic catchup"
    );
    Err(anyhow!(
        "WS hint {event_id} was not visible through canonical eth_getLogs"
    ))
}

/// WebSocket event-driven loop.
///
/// 1. Subscribe: `eth_subscribe logs` on the contract address.
/// 2. Treat each incoming log as a hint; ingest only via finalized canonical replay.
/// 3. On disconnect: recover any pending tx hashes via receipt lookup, then resubscribe.
/// 4. Also listens for recover_trigger signals from post_notify_tx for immediate recovery.
/// 5. A concurrent `catchup_from_chain` task reconciles anything the WS silently dropped.
async fn run_event_loop(ctx: PollContext) -> Result<()> {
    let label = &ctx.contract_address[..10.min(ctx.contract_address.len())];
    let warm_target = loop {
        match try_warm_start(&ctx).await {
            Ok(Some(target)) => break Some(target),
            Ok(None) if ctx.shadow_mode => {
                return Err(anyhow!(
                    "shadow checkpoint rejected; health remains 503 until the shadow is restarted from a reviewed checkpoint"
                ));
            }
            Ok(None) => break None,
            Err(error) => {
                eprintln!(
                    "[indexer][{label}] warm-start validation failed closed: {error:#}; retrying in 5s"
                );
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };
    let mut full_replay_required = warm_target.is_none();
    if let Some(target) = warm_target {
        // Reconcile only the post-checkpoint finalized suffix. The checkpoint
        // remains fail-closed until the captured finalized head is covered.
        catchup_from_chain(&ctx).await;
        let caught_up = {
            let state = ctx.shared.read().await;
            state
                .last_finalized_block
                .is_some_and(|block| block >= target)
                && state.next_block > target
        };
        if caught_up {
            let mut state = ctx.shared.write().await;
            state.tree_out_of_order = false;
            state.startup_source = "checkpoint".to_string();
            // Primary instances immediately seal a version-1 checkpoint even
            // when no suffix block needed replay; shadow persistence is a no-op.
            ctx.persist.notify(&state);
            println!(
                "[indexer][{label}] warm-start suffix caught up through finalized block {target}"
            );
        } else if ctx.shadow_mode {
            return Err(anyhow!(
                "shadow warm-start suffix did not reach finalized block {target}; health remains 503"
            ));
        } else {
            full_replay_required = true;
        }
    }
    if full_replay_required {
        // A primary instance may bootstrap/repair a legacy checkpoint by doing
        // the staged full replay. A shadow is never allowed down this path.
        loop {
            match backfill_from_chain(&ctx).await {
                Ok(()) => break,
                Err(e) => {
                    eprintln!(
                        "[indexer][{label}] finalized startup backfill failed closed: {e:#}; retrying in 5s"
                    );
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }
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
                // Disaster recovery: if an out-of-order append was rejected the
                // tree is missing a middle leaf — rebuild it from chain (ordered
                // getLogs replay) instead of running the incremental catchup.
                let dirty = { ctx_catchup.shared.read().await.tree_out_of_order };
                if dirty {
                    if ctx_catchup.shadow_mode {
                        eprintln!(
                            "[indexer] shadow commitment tree is unready; full replay is disabled"
                        );
                    } else {
                        eprintln!(
                            "[indexer] commitment tree flagged out-of-order — rebuilding from chain"
                        );
                        if let Err(e) = backfill_from_chain(&ctx_catchup).await {
                            eprintln!("[indexer] finalized rebuild failed closed: {e:#}");
                        }
                    }
                } else {
                    catchup_from_chain(&ctx_catchup).await;
                }
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
    println!(
        "[indexer][{}] recovering {} pending tx(s)…",
        &ctx.contract_address[..10],
        hashes.len()
    );
    for tx_hash in hashes {
        match ctx.rpc.get_transaction_receipt_logs(&tx_hash).await {
            Ok(Some(receipt)) => {
                let finalized = match ctx.rpc.finalized_block().await {
                    Ok(value) => value,
                    Err(e) => {
                        eprintln!(
                            "[indexer] cannot finalize pending tx {tx_hash}: finalized head failed: {e:#}"
                        );
                        continue;
                    }
                };
                if receipt.block_number > finalized.0 {
                    println!(
                        "[indexer] tx {tx_hash} is mined at {} but not finalized (head={}); keeping pending",
                        receipt.block_number, finalized.0
                    );
                    continue;
                }
                let canonical = match ctx.rpc.block_hash(receipt.block_number).await {
                    Ok(hash) => hash,
                    Err(e) => {
                        eprintln!(
                            "[indexer] cannot verify receipt block for {tx_hash}: {e:#}"
                        );
                        continue;
                    }
                };
                if canonical != receipt.block_hash {
                    eprintln!(
                        "[indexer] receipt block hash mismatch for {tx_hash} at {}: receipt={} canonical={canonical}; keeping pending",
                        receipt.block_number, receipt.block_hash
                    );
                    continue;
                }
                if receipt.success {
                    println!(
                        "[indexer] recovering finalized tx {tx_hash}: {} log(s)",
                        receipt.logs.len()
                    );
                    let mut replayed = true;
                    for log in receipt
                        .logs
                        .into_iter()
                        .filter(|log| is_watched_pool_log(ctx, log))
                    {
                        // Ordered ingest: gap-fills any earlier dropped logs first,
                        // so recovered logs cannot be appended out of order.
                        if let Err(e) = ingest_ws_log(ctx, log).await {
                            eprintln!("[indexer] recover log error for {tx_hash}: {e:#}");
                            replayed = false;
                            break;
                        }
                    }
                    if !replayed {
                        // The canonical replay is incomplete. Keep the tx in the
                        // durable queue so a later finalized rebuild can retry it.
                        continue;
                    }
                } else {
                    eprintln!(
                        "[indexer] tx {tx_hash} finalized reverted — removing from pending queue"
                    );
                }
                // Only a canonical finalized receipt (success or revert) can leave
                // the recovery queue.
                let _ingest = ctx.ingest_lock.lock().await;
                let mut s = ctx.shared.write().await;
                s.pending_tx_hashes.retain(|h| h != &tx_hash);
                ctx.persist.notify(&s);
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
    println!(
        "[indexer][{}] WebSocket connected: {}",
        &ctx.contract_address[..10],
        ctx.wss_url
    );

    // Build topic0 OR list for subscription filter.
    let mut topics: Vec<String> = note_added_topic0_alternatives()
        .iter()
        .map(|topic| norm_topic(topic))
        .collect();
    topics.push(norm_topic(&shield_completed_topic0_hex()));
    topics.push(norm_topic(&ctx.note_confirmed_topic0));
    topics.push(norm_topic(&root_updated_topic0_hex()));
    topics.push(norm_topic(&frozen_root_updated_topic0()));
    topics.push(norm_topic(&shielded_topic0_hex()));
    topics.push(norm_topic(&unshielded_topic0_hex()));

    let sub_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_subscribe",
        "params": ["logs", {
            "address": ctx.contract_address,
            "topics": [topics]
        }]
    });
    ws.send(Message::Text(sub_req.to_string().into()))
        .await
        .context("failed to send eth_subscribe")?;

    // Expect subscription confirmation — with timeout to avoid hanging forever.
    let sub_id = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(txt))) => {
                    let v: serde_json::Value =
                        serde_json::from_str(&txt).context("invalid JSON from WebSocket")?;
                    if v.get("id") == Some(&serde_json::Value::Number(1.into())) {
                        if let Some(id) = v["result"].as_str() {
                            println!(
                                "[indexer][{}] subscribed id={id}",
                                &ctx.contract_address[..10]
                            );
                            return Ok::<_, anyhow::Error>(id.to_string());
                        }
                        return Err(anyhow!("eth_subscribe error: {}", v["error"]));
                    }
                }
                Some(Ok(Message::Ping(d))) => {
                    ws.send(Message::Pong(d)).await.ok();
                }
                Some(Err(e)) => return Err(e.into()),
                None => return Err(anyhow!("WebSocket closed before subscription confirmed")),
                _ => {}
            }
        }
    })
    .await
    .context("eth_subscribe timed out after 15s")??;

    println!(
        "[indexer][{}] listening for events (sub={sub_id})",
        &ctx.contract_address[..10]
    );

    // Process incoming events.
    while let Some(msg) = ws.next().await {
        match msg {
            Ok(Message::Text(txt)) => {
                let v: serde_json::Value = match serde_json::from_str(&txt) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("[indexer] JSON parse error: {e}");
                        continue;
                    }
                };
                if v["method"].as_str() != Some("eth_subscription") {
                    continue;
                }
                if v["params"]["subscription"].as_str() != Some(&sub_id) {
                    continue;
                }
                let log_val = &v["params"]["result"];
                if let Ok(log) = serde_json::from_value::<EthLog>(log_val.clone()) {
                    if let Err(e) = ingest_ws_log(ctx, log).await {
                        eprintln!("[indexer] ingest_ws_log error: {e:#}");
                    }
                }
            }
            Ok(Message::Ping(d)) => {
                ws.send(Message::Pong(d)).await.ok();
            }
            Ok(Message::Close(_)) => {
                println!(
                    "[indexer][{}] WebSocket closed by server",
                    &ctx.contract_address[..10]
                );
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
    let pool_addr = ctx
        .contract_address
        .trim_start_matches("0x")
        .to_ascii_lowercase();
    if !log_addr.is_empty() && log_addr != pool_addr {
        return Ok(());
    }

    let na_topics: Vec<String> = note_added_topic0_alternatives()
        .iter()
        .map(|t| norm_topic(t))
        .collect();
    let sc = norm_topic(&shield_completed_topic0_hex());
    let nc = norm_topic(&ctx.note_confirmed_topic0);
    let ru = norm_topic(&root_updated_topic0_hex());
    let fru = norm_topic(&frozen_root_updated_topic0());
    let shielded_topic = norm_topic(&shielded_topic0_hex());
    let unshielded_topic = norm_topic(&unshielded_topic0_hex());

    let event_id = format!("{}:{}", log.transaction_hash, log.log_index);
    let block_number = parse_hex_u64(&log.block_number)
        .with_context(|| format!("invalid blockNumber: {}", log.block_number))?;
    let log_index = parse_hex_u64(&log.log_index)
        .with_context(|| format!("invalid logIndex: {}", log.log_index))?;
    let t0 = log
        .topics
        .as_ref()
        .and_then(|x| x.first())
        .map(|s| norm_topic(s));

    let mut state = ctx.shared.write().await;

    // Do NOT remove from pending_tx_hashes here. A tx can emit multiple logs
    // (e.g. NoteAdded + SwapNotePending + NoteConfirmed × N). Removing on the
    // first WS log means a WS drop before all logs arrive permanently loses the
    // later events (the tx is gone from pending when recover_pending_txs runs).
    // Only recover_pending_txs (which fetches the full receipt) removes from queue.

    if na_topics
        .iter()
        .any(|na| t0.as_deref() == Some(na.as_str()))
    {
        // ── NoteAdded ────────────────────────────────────────────────────────
        if state.seen_event_ids.contains(&event_id) {
            return Ok(());
        }
        let d = match decode_note_added_log(log.topics.as_deref().unwrap_or(&[]), &log.data) {
            Ok(d) => d,
            Err(e) => {
                return Err(anyhow!("NoteAdded decode failed: {e}"));
            }
        };
        // Monotonicity guard: an append-only tree must receive leaves in exact
        // (block, log_index) order. If this leaf is OLDER than the newest one
        // appended, some path raced ahead of it — appending now would put it at
        // the wrong position and permanently desync every future root from the
        // chain. Reject the append and flag a full rebuild instead; do NOT mark
        // the event seen, so the rebuild replays it at the right position.
        let key = (block_number, log_index);
        if !state.cmx_to_position.contains_key(&d.cmx) {
            if let Some(last) = state.last_leaf_key {
                if key <= last {
                    eprintln!(
                        "[indexer] OUT-OF-ORDER leaf rejected: event {event_id} key={key:?} <= last appended {last:?}; scheduling tree rebuild"
                    );
                    state.tree_out_of_order = true;
                    state.confirmed_frontier = None;
                    return Ok(());
                }
            }
        }
        let cmx_position = if let Some(&existing_pos) = state.cmx_to_position.get(&d.cmx) {
            Some(existing_pos)
        } else {
            state.tree.append(d.cmx).map(|pos| {
                state.cmx_to_position.insert(d.cmx, pos);
                state.cmx_ordered.push(d.cmx);
                state.last_leaf_key = Some(key);
                pos
            })
        };
        state.seen_event_ids.insert(event_id);
        let is_confirmed = state.confirmed_cmx.contains(&d.cmx);
        const OUT_LEN: usize = 80;
        let (out_ciphertext, cv_net_x) =
            if d.out_ciphertext.len() == OUT_LEN && d.cv_net_x.is_some() {
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
        let envelope = BatchEnvelope {
            seq,
            pool_address: Some(ctx.contract_address.clone()),
            batch,
        };
        state.batches.push_back(envelope.clone());
        while state.batches.len() > state.max_batches {
            state.batches.pop_front();
        }
        // Advance the cursor only TO this block, never past it: this log alone
        // does not prove the rest of the block's logs were ingested (getLogs
        // can lag the WS push), so the block must stay inside the replay
        // window until a full ordered window pass moves the cursor beyond it.
        state.next_block = block_number.max(state.next_block);
        let persist_snap =
            (!ctx.persist.is_paused()).then(|| CheckpointSnapshot::from_state(&state));
        let canonical_ready = !state.tree_out_of_order;
        drop(state);
        ctx.archive_note_mutation(NoteArchiveMutation::Upsert(envelope.clone()))
            .await?;
        if canonical_ready && !ctx.broadcast_paused.load(AtomicOrdering::Acquire) {
            ctx.batch_tx.send(envelope).ok();
        }
        if let Some(snap) = persist_snap {
            ctx.persist.notify_owned(snap);
        }
    } else if t0.as_deref() == Some(nc.as_str()) {
        // ── NoteConfirmed ────────────────────────────────────────────────────
        if !state.confirm_seen_ids.insert(event_id) {
            return Ok(());
        }
        let (cmx, new_root, position) =
            decode_note_confirmed_log(log.topics.as_deref().unwrap_or(&[]), &log.data)
                .map_err(|e| anyhow!("NoteConfirmed decode failed: {e}"))?;
        state.confirmed_cmx.insert(cmx);
        state.active_root = Some(new_root);
        state.confirmed_count = state.confirmed_count.max(position.saturating_add(1));

        let maybe_note = state
            .batches
            .iter()
            .rev()
            .flat_map(|env| env.batch.abi_notes.iter())
            .find(|note| note.cmx == cmx)
            .cloned()
            .map(|mut note| {
                note.is_confirmed = true;
                note.cmx_position = Some(position);
                note
            });
        let envelope = maybe_note.map(|note| {
            let seq = state.latest_seq.saturating_add(1);
            state.latest_seq = seq;
            BatchEnvelope {
                seq,
                pool_address: Some(ctx.contract_address.clone()),
                batch: OrchardIndexBatch {
                    from_block: block_number,
                    to_block: block_number,
                    abi_notes: vec![note],
                    bundles: vec![],
                    latest_root: state.tree.latest_root(),
                },
            }
        });
        if let Some(envelope) = &envelope {
            state.batches.push_back(envelope.clone());
            while state.batches.len() > state.max_batches {
                state.batches.pop_front();
            }
        }
        let canonical_ready = !state.tree_out_of_order;
        let persist_snap =
            (!ctx.persist.is_paused()).then(|| CheckpointSnapshot::from_state(&state));
        drop(state);

        if let Some(envelope) = &envelope {
            ctx.archive_note_mutation(NoteArchiveMutation::Upsert(envelope.clone()))
                .await?;
        }
        ctx.archive_note_mutation(NoteArchiveMutation::Confirm { cmx, position })
            .await?;
        if canonical_ready && !ctx.broadcast_paused.load(AtomicOrdering::Acquire) {
            if let Some(envelope) = envelope {
                ctx.batch_tx.send(envelope).ok();
            }
        }
        if let Some(snap) = persist_snap {
            ctx.persist.notify_owned(snap);
        }
        return Ok(());
    } else if t0.as_deref() == Some(ru.as_str()) {
        // ── RootUpdated (batch confirm) ──────────────────────────────────────
        // One verified `updateRoot` batch: authoritative watermark advance. The
        // per-note NoteConfirmed events of the same tx also advance it; this
        // branch makes the watermark robust if any of them fails to decode.
        if !state.confirm_seen_ids.insert(event_id) {
            return Ok(());
        }
        match decode_root_updated_log(log.topics.as_deref().unwrap_or(&[]), &log.data) {
            Ok(d) => {
                state.confirmed_count = state.confirmed_count.max(d.to_count);
                state.active_root = Some(d.new_root);
                println!(
                    "[indexer] root updated: confirmed [{}, {}) root={} batch={}",
                    d.from_count,
                    d.to_count,
                    hex::encode(d.new_root),
                    d.batch_size
                );
                ctx.persist.notify(&state);
            }
            Err(e) => return Err(anyhow!("RootUpdated decode failed: {e}")),
        }
    } else if t0.as_deref() == Some(fru.as_str()) {
        // ── FrozenRootUpdated (compliance leaf delta) ────────────────────────
        // Append the disclosed delta to the per-pool feed (frozen-tree-execution-plan PR2).
        // Dedup on (tx_hash, log_index) via the existing event_id set so a re-scan is idempotent.
        if !state.seen_event_ids.insert(event_id.clone()) {
            return Ok(());
        }
        match decode_frozen_root_updated_log(&log.data) {
            Ok(d) => {
                let upd = FrozenUpdate {
                    block_number,
                    log_index,
                    tx_hash: normalize_hex_0x(&log.transaction_hash),
                    old_root_hex: format!("0x{}", hex::encode(d.old_root)),
                    new_root_hex: format!("0x{}", hex::encode(d.new_root)),
                    cmx_changed_hex: d
                        .cmx_changed
                        .iter()
                        .map(|c| format!("0x{}", hex::encode(c)))
                        .collect(),
                    is_add: d.is_add,
                };
                println!(
                    "[indexer] frozen root updated: new_root={} delta={} (block={block_number} logIndex={log_index})",
                    upd.new_root_hex,
                    upd.cmx_changed_hex.len()
                );
                state.frozen_updates.push(upd);
                ctx.persist.notify(&state);
            }
            Err(e) => eprintln!("[indexer] FrozenRootUpdated decode FAILED: {e}"),
        }
    } else if t0.as_deref() == Some(sc.as_str()) {
        // ── ShieldCompleted ──────────────────────────────────────────────────
        // NoteAdded was already processed; update shield_amount_sats on the
        // existing batch entry and re-emit.
        if !state.shield_seen_ids.insert(event_id) {
            return Ok(());
        }
        let (cmx, raw_amount) =
            decode_shield_completed_log(log.topics.as_deref().unwrap_or(&[]), &log.data)
                .map_err(|e| anyhow!("ShieldCompleted decode failed: {e}"))?;
        let amount =
            u64::try_from(raw_amount).context("ShieldCompleted amount exceeds u64")?;
        let maybe_note = state
            .batches
            .iter()
            .rev()
            .flat_map(|env| env.batch.abi_notes.iter())
            .find(|note| note.cmx == cmx && note.tx_hash == log.transaction_hash)
            .cloned()
            .map(|mut note| {
                note.shield_amount_sats = Some(amount);
                note
            });
        let envelope = maybe_note.map(|note| {
            let seq = state.latest_seq.saturating_add(1);
            state.latest_seq = seq;
            BatchEnvelope {
                seq,
                pool_address: Some(ctx.contract_address.clone()),
                batch: OrchardIndexBatch {
                    from_block: block_number,
                    to_block: block_number,
                    abi_notes: vec![note],
                    bundles: vec![],
                    latest_root: state.tree.latest_root(),
                },
            }
        });
        if let Some(envelope) = &envelope {
            state.batches.push_back(envelope.clone());
            while state.batches.len() > state.max_batches {
                state.batches.pop_front();
            }
        }
        let canonical_ready = !state.tree_out_of_order;
        let persist_snap =
            (!ctx.persist.is_paused()).then(|| CheckpointSnapshot::from_state(&state));
        drop(state);
        if let Some(envelope) = &envelope {
            ctx.archive_note_mutation(NoteArchiveMutation::Upsert(envelope.clone()))
                .await?;
        }
        ctx.archive_note_mutation(NoteArchiveMutation::ShieldAmount { cmx, amount })
            .await?;
        if canonical_ready && !ctx.broadcast_paused.load(AtomicOrdering::Acquire) {
            if let Some(envelope) = envelope {
                ctx.batch_tx.send(envelope).ok();
            }
        }
        if let Some(snap) = persist_snap {
            ctx.persist.notify_owned(snap);
        }
        return Ok(());
    } else if t0.as_deref() == Some(shielded_topic.as_str()) {
        // ── Shielded accounting ───────────────────────────────────────────────
        if state.accounting_seen_ids.contains(&event_id) {
            return Ok(());
        }
        match decode_shielded_log(log.topics.as_deref().unwrap_or(&[]), &log.data) {
            Ok(d) => {
                state.accounting_seen_ids.insert(event_id);
                state.shield_accounting.total_shielded_units = state
                    .shield_accounting
                    .total_shielded_units
                    .saturating_add(d.amount_units);
                state.shield_accounting.total_shielded_wei = state
                    .shield_accounting
                    .total_shielded_wei
                    .saturating_add(d.wei_amount);
                state.next_block = block_number.saturating_add(1).max(state.next_block);
                ctx.persist.notify(&state);
            }
            Err(e) => return Err(anyhow!("Shielded decode failed: {e}")),
        }
    } else if t0.as_deref() == Some(unshielded_topic.as_str()) {
        // ── Unshielded accounting ─────────────────────────────────────────────
        if state.accounting_seen_ids.contains(&event_id) {
            return Ok(());
        }
        match decode_unshielded_log(log.topics.as_deref().unwrap_or(&[]), &log.data) {
            Ok(d) => {
                state.accounting_seen_ids.insert(event_id);
                state.shield_accounting.total_unshielded_units = state
                    .shield_accounting
                    .total_unshielded_units
                    .saturating_add(d.amount_units);
                state.shield_accounting.total_unshielded_wei = state
                    .shield_accounting
                    .total_unshielded_wei
                    .saturating_add(d.wei_amount);
                state.next_block = block_number.saturating_add(1).max(state.next_block);
                ctx.persist.notify(&state);
            }
            Err(e) => return Err(anyhow!("Unshielded decode failed: {e}")),
        }
    }

    Ok(())
}

fn norm_topic(s: &str) -> String {
    let t = strip_0x(s).to_lowercase();
    format!("0x{t}")
}

// ─── RPC client ───────────────────────────────────────────────────────────────

/// Default (and maximum) block span for a single `eth_getLogs` request. Providers
/// enforce widely different caps (Alchemy Monad: 1000, Infura: 10k results, …);
/// the client learns the real cap at runtime by halving on range errors.
const GETLOGS_DEFAULT_SPAN: u64 = 5_000;

/// True when an RPC error indicates the `eth_getLogs` block range/result window
/// was too large for the provider (as opposed to a transport or logic error).
/// Matched loosely on provider messages: Alchemy ("up to a 1000 block range"),
/// Infura ("query returned more than 10000 results"), BSC/others ("exceed
/// maximum block range", "block range is too large").
fn is_getlogs_range_error(e: &anyhow::Error) -> bool {
    let s = format!("{e:#}").to_lowercase();
    s.contains("block range")
        || s.contains("range is too large")
        || s.contains("range too large")
        || s.contains("too many blocks")
        || s.contains("query returned more than")
        || s.contains("response size exceeded")
}

/// Inclusive upper bound of the next `eth_getLogs` window starting at `lo`,
/// never past `to`. `span == 0` is treated as 1 (guards against a stuck loop).
fn getlogs_window_end(lo: u64, to: u64, span: u64) -> u64 {
    lo.saturating_add(span.max(1) - 1).min(to)
}

#[derive(Clone)]
struct RpcClient {
    http: Client,
    urls: Vec<String>,
    /// Largest `eth_getLogs` block span the provider is known to accept.
    /// Starts at `GETLOGS_DEFAULT_SPAN` (or `PRIVACYBTC_INDEXER_GETLOGS_MAX_SPAN`)
    /// and only ever shrinks — halved each time the provider rejects a window,
    /// so a range-capped provider (e.g. Alchemy Monad testnet: 1000 blocks) can
    /// no longer wedge catchup/backfill in a permanent retry loop.
    getlogs_span: Arc<AtomicU64>,
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
        let initial_span = std::env::var("PRIVACYBTC_INDEXER_GETLOGS_MAX_SPAN")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(GETLOGS_DEFAULT_SPAN);
        Self {
            http,
            urls,
            getlogs_span: Arc::new(AtomicU64::new(initial_span)),
        }
    }

    /// Current learned `eth_getLogs` window span.
    fn getlogs_span(&self) -> u64 {
        self.getlogs_span.load(AtomicOrdering::Relaxed).max(1)
    }

    /// Record that the provider rejected `failed_span` blocks in one `eth_getLogs`:
    /// halve the learned span (floor 1) so every future window fits. Returns the
    /// new span. Shared across clones, so all ingest paths learn together.
    fn shrink_getlogs_span(&self, failed_span: u64) -> u64 {
        let new_span = (failed_span / 2).max(1);
        // Only ever shrink (another task may have already learned a smaller cap).
        self.getlogs_span
            .fetch_min(new_span, AtomicOrdering::Relaxed);
        let effective = self.getlogs_span();
        eprintln!(
            "[indexer] provider rejected eth_getLogs span of {failed_span} blocks; \
             shrinking window to {effective}"
        );
        effective
    }

    /// Monad's authoritative event boundary. `eth_blockNumber` and ordinary
    /// `latest` data can describe a Voted block that is still reversible; state
    /// derived by the indexer only advances through this finalized header.
    async fn finalized_block(&self) -> Result<(u64, String)> {
        #[derive(Deserialize)]
        struct BlockHeader {
            number: String,
            hash: String,
        }
        let header: Option<BlockHeader> = self
            .rpc_call(
                "eth_getBlockByNumber",
                serde_json::json!(["finalized", false]),
            )
            .await
            .context("eth_getBlockByNumber(finalized)")?;
        let header = header.ok_or_else(|| anyhow!("RPC returned no finalized block"))?;
        let number =
            parse_hex_u64(&header.number).context("invalid finalized block number")?;
        let hash = normalize_block_hash(&header.hash).context("invalid finalized block hash")?;
        Ok((number, hash))
    }

    async fn block_hash(&self, block: u64) -> Result<String> {
        #[derive(Deserialize)]
        struct BlockHeader {
            hash: String,
        }
        let tag = format!("0x{block:x}");
        let header: Option<BlockHeader> = self
            .rpc_call("eth_getBlockByNumber", serde_json::json!([tag, false]))
            .await
            .with_context(|| format!("eth_getBlockByNumber({tag})"))?;
        let header = header.ok_or_else(|| anyhow!("RPC returned no block {block}"))?;
        normalize_block_hash(&header.hash)
            .with_context(|| format!("invalid hash for block {block}"))
    }

    /// Verify that every fetched log belongs to the provider's canonical block
    /// at that height. Finalized scans should never encounter `removed=true` or
    /// a hash mismatch; either condition fails the whole window closed.
    async fn validate_canonical_logs(&self, logs: &[EthLog]) -> Result<()> {
        let mut canonical: HashMap<u64, String> = HashMap::new();
        for log in logs {
            let block = parse_hex_u64(&log.block_number)
                .with_context(|| format!("invalid log blockNumber {}", log.block_number))?;
            let expected = match canonical.get(&block) {
                Some(hash) => hash.clone(),
                None => {
                    let hash = self.block_hash(block).await?;
                    canonical.insert(block, hash.clone());
                    hash
                }
            };
            validate_log_against_canonical(log, block, &expected)?;
        }
        Ok(())
    }

    async fn get_transaction_count(&self, address: &str) -> Result<u64> {
        let hex_num: String = self
            .rpc_call(
                "eth_getTransactionCount",
                serde_json::json!([address, "latest"]),
            )
            .await?;
        parse_hex_u64(&hex_num).context("invalid eth_getTransactionCount")
    }

    /// Unix timestamp (seconds) of a block's header. Used to age transactions in
    /// the explorer; block timestamps are immutable so callers cache the result.
    async fn get_block_timestamp(&self, block: u64) -> Result<u64> {
        let tag = format!("0x{block:x}");
        // `false` → header only (no full tx bodies), so this stays cheap.
        let hdr: serde_json::Value = self
            .rpc_call("eth_getBlockByNumber", serde_json::json!([tag, false]))
            .await?;
        let ts = hdr
            .get("timestamp")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("block {block} has no timestamp"))?;
        parse_hex_u64(ts).context("invalid block timestamp")
    }

    async fn send_raw_transaction(&self, raw_tx: &[u8]) -> Result<String> {
        let hex_tx = format!("0x{}", hex::encode(raw_tx));
        self.rpc_call("eth_sendRawTransaction", serde_json::json!([hex_tx]))
            .await
    }

    fn transaction_call(to: &str, data: &[u8], from: Option<&str>) -> serde_json::Value {
        let mut call = serde_json::json!({
            "to": normalize_hex_0x(to),
            "data": format!("0x{}", hex::encode(data)),
            "value": "0x0",
        });
        if let Some(f) = from {
            call["from"] = serde_json::json!(normalize_hex_0x(f));
        }
        call
    }

    /// `eth_call` against `latest` — read-only contract query (and crank tx simulation).
    async fn eth_call(&self, to: &str, data: &[u8], from: Option<&str>) -> Result<Vec<u8>> {
        let call = Self::transaction_call(to, data, from);
        let out: String = self
            .rpc_call("eth_call", serde_json::json!([call, "latest"]))
            .await?;
        hex::decode(out.trim_start_matches("0x")).context("invalid eth_call result hex")
    }

    /// Exact `eth_estimateGas` for the transaction the crank signer will send.
    async fn estimate_gas(&self, to: &str, data: &[u8], from: Option<&str>) -> Result<u64> {
        let call = Self::transaction_call(to, data, from);
        let gas: String = self
            .rpc_call("eth_estimateGas", serde_json::json!([call]))
            .await?;
        parse_hex_u64(&gas).context("invalid eth_estimateGas result")
    }

    /// `eth_call` a no-arg view returning one 32-byte word (uint256 / bytes32).
    async fn eth_call_word(&self, to: &str, selector: [u8; 4]) -> Result<[u8; 32]> {
        let out = self.eth_call(to, &selector, None).await?;
        out.get(..32)
            .and_then(|s| <[u8; 32]>::try_from(s).ok())
            .ok_or_else(|| anyhow!("eth_call returned {} bytes, expected 32", out.len()))
    }

    /// Returns `None` if tx not yet mined, `Some(true)` if success, `Some(false)` if reverted.
    async fn get_transaction_receipt_status(&self, tx_hash: &str) -> Result<Option<bool>> {
        #[derive(Deserialize)]
        struct Receipt {
            status: Option<String>,
        }
        let hash = if tx_hash.starts_with("0x") || tx_hash.starts_with("0X") {
            tx_hash.to_string()
        } else {
            format!("0x{tx_hash}")
        };
        let receipt: Option<Receipt> = self
            .rpc_call("eth_getTransactionReceipt", serde_json::json!([hash]))
            .await?;
        Ok(receipt.map(|r| r.status.as_deref().unwrap_or("0x1") == "0x1"))
    }

    /// Returns the raw EthLog entries from a mined transaction receipt.
    /// Returns `None` if the transaction is not yet mined.
    async fn get_transaction_input(&self, tx_hash: &str) -> Result<Option<Vec<u8>>> {
        #[derive(Deserialize)]
        struct Tx {
            input: String,
        }
        let hash = normalize_hex_0x(tx_hash);
        let tx: Option<Tx> = self
            .rpc_call("eth_getTransactionByHash", serde_json::json!([hash]))
            .await?;
        Ok(tx.map(|t| {
            hex::decode(t.input.strip_prefix("0x").unwrap_or(&t.input)).unwrap_or_default()
        }))
    }

    /// Like `get_transaction_input`, but also returns the tx `from` (lowercase 0x) —
    /// the public depositor/issuer the explorer shows as the sender of a shield/mint.
    async fn get_transaction_input_from(&self, tx_hash: &str) -> Result<Option<(Vec<u8>, String)>> {
        #[derive(Deserialize)]
        struct Tx {
            input: String,
            // Tolerate a node that omits/nulls `from` on a mined tx: parse succeeds
            // (sender simply absent) instead of erroring into a permanent re-fetch.
            #[serde(default)]
            from: String,
        }
        let hash = normalize_hex_0x(tx_hash);
        let tx: Option<Tx> = self
            .rpc_call("eth_getTransactionByHash", serde_json::json!([hash]))
            .await?;
        Ok(tx.map(|t| {
            let input =
                hex::decode(t.input.strip_prefix("0x").unwrap_or(&t.input)).unwrap_or_default();
            (input, t.from.to_lowercase())
        }))
    }

    async fn get_transaction_receipt_logs(
        &self,
        tx_hash: &str,
    ) -> Result<Option<ReceiptWithLogs>> {
        #[derive(Deserialize)]
        struct ReceiptLog {
            #[serde(default)]
            address: String,
            #[serde(rename = "blockNumber")]
            block_number: String,
            #[serde(default, rename = "blockHash")]
            block_hash: Option<String>,
            #[serde(rename = "transactionHash")]
            transaction_hash: String,
            #[serde(rename = "logIndex")]
            log_index: String,
            #[serde(default)]
            removed: bool,
            #[serde(default)]
            topics: Option<Vec<String>>,
            data: String,
        }
        #[derive(Deserialize)]
        struct Receipt {
            /// "0x1" = success, "0x0" = revert. None if legacy pre-Byzantium.
            status: Option<String>,
            #[serde(rename = "blockNumber")]
            block_number: String,
            #[serde(rename = "blockHash")]
            block_hash: String,
            logs: Vec<ReceiptLog>,
        }
        let hash = normalize_hex_0x(tx_hash);
        let receipt: Option<Receipt> = self
            .rpc_call("eth_getTransactionReceipt", serde_json::json!([hash]))
            .await?;
        let Some(r) = receipt else {
            return Ok(None);
        };
        let success = r.status.as_deref().unwrap_or("0x1") == "0x1";
        let block_number =
            parse_hex_u64(&r.block_number).context("invalid receipt blockNumber")?;
        let block_hash =
            normalize_block_hash(&r.block_hash).context("invalid receipt blockHash")?;
        let logs = r
            .logs
            .into_iter()
            .map(|l| EthLog {
                address: l.address,
                block_number: l.block_number,
                block_hash: l.block_hash,
                transaction_hash: l.transaction_hash,
                log_index: l.log_index,
                removed: l.removed,
                topics: l.topics,
                data: l.data,
            })
            .collect();
        Ok(Some(ReceiptWithLogs {
            success,
            block_number,
            block_hash,
            logs,
        }))
    }

    async fn fetch_logs_topic0_or(
        &self,
        from_block: u64,
        to_block: u64,
        contract_address: &str,
        topic0_alternatives: &[String],
    ) -> Result<Vec<EthLog>> {
        let alt: Vec<serde_json::Value> = topic0_alternatives
            .iter()
            .cloned()
            .map(Into::into)
            .collect();
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

    /// `eth_getLogs` with topic0 alternatives AND a fixed indexed topic1 (e.g. a swap id).
    /// The topic1 pin makes even wide block ranges cheap on providers with topic indexes.
    async fn fetch_logs_topic0_or_with_topic1(
        &self,
        from_block: u64,
        to_block: u64,
        contract_address: &str,
        topic0_alternatives: &[String],
        topic1: &str,
    ) -> Result<Vec<EthLog>> {
        let alt: Vec<serde_json::Value> = topic0_alternatives
            .iter()
            .cloned()
            .map(Into::into)
            .collect();
        let filter = serde_json::json!({
            "fromBlock": format!("0x{:x}", from_block),
            "toBlock":   format!("0x{:x}", to_block),
            "address":   contract_address,
            "topics":    [ alt, topic1 ],
        });
        self.rpc_call("eth_getLogs", serde_json::json!([filter]))
            .await
            .with_context(|| format!("eth_getLogs (swap) failed for [{from_block}, {to_block}]"))
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
            "toBlock":   "finalized",
            "address":   addr,
            "topics":    [shield_pool_created_topic0_hex(), topic1],
        });
        let logs: Vec<EthLog> = self
            .rpc_call("eth_getLogs", serde_json::json!([shield_filter]))
            .await
            .context("eth_getLogs (ShieldPoolCreated metadata) failed")?;
        self.validate_canonical_logs(&logs).await?;
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
            "toBlock":   "finalized",
            "address":   addr,
            "topics":    [perc20_created_topic0(), topic1],
        });
        let logs: Vec<EthLog> = self
            .rpc_call("eth_getLogs", serde_json::json!([issuer_filter]))
            .await
            .context("eth_getLogs (Perc20Created metadata) failed")?;
        self.validate_canonical_logs(&logs).await?;
        if let Some(l) = logs.first() {
            if let Some(meta) = PoolMeta::try_from_perc20_created(&addr, &l.data) {
                return Ok(Some(meta));
            }
            // Event present but body not decodable — still a known issuer pool.
            return Ok(Some(PoolMeta::issuer_minimal(&addr)));
        }
        Ok(None)
    }

    /// Scan one trusted factory's canonical deployment event over [from, to].
    async fn fetch_factory_deployed_pools(
        &self,
        from_block: u64,
        to_block: u64,
        factory: &str,
        topic0: &str,
    ) -> Result<Vec<(String, u64)>> {
        let filter = serde_json::json!({
            "fromBlock": format!("0x{:x}", from_block),
            "toBlock":   format!("0x{:x}", to_block),
            "address":   normalize_hex_0x(factory),
            "topics":    [topic0],
        });
        let logs: Vec<EthLog> = self
            .rpc_call("eth_getLogs", serde_json::json!([filter]))
            .await
            .with_context(|| {
                format!("eth_getLogs (trusted factory {factory}) [{from_block},{to_block}]")
            })?;
        self.validate_canonical_logs(&logs).await?;
        let mut out = Vec::new();
        for l in logs {
            if normalize_hex_0x(&l.address).to_lowercase()
                != normalize_hex_0x(factory).to_lowercase()
            {
                continue;
            }
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

    async fn runtime_codehash(&self, address: &str) -> Result<String> {
        let code: String = self
            .rpc_call(
                "eth_getCode",
                serde_json::json!([normalize_hex_0x(address), "latest"]),
            )
            .await
            .with_context(|| format!("eth_getCode failed for {address}"))?;
        let bytes = hex::decode(strip_0x(&code))
            .with_context(|| format!("eth_getCode returned invalid hex for {address}"))?;
        if bytes.is_empty() {
            return Err(anyhow!("address {address} has no runtime code"));
        }
        Ok(format!("0x{}", hex::encode(Keccak256::digest(bytes))))
    }

    async fn was_pool_deployed_by(
        &self,
        factory: &str,
        pool: &str,
        event_topic: &str,
    ) -> Result<bool> {
        let filter = serde_json::json!({
            "fromBlock": "0x0",
            "toBlock":   "finalized",
            "address":   normalize_hex_0x(factory),
            "topics":    [event_topic, address_to_topic(pool)],
        });
        let logs: Vec<EthLog> = self
            .rpc_call("eth_getLogs", serde_json::json!([filter]))
            .await
            .with_context(|| format!("eth_getLogs deployment proof failed for pool {pool}"))?;
        self.validate_canonical_logs(&logs).await?;
        Ok(logs
            .iter()
            .any(|log| factory_log_matches(log, factory, event_topic, pool)))
    }

    async fn pool_uses_factory_beacon(
        &self,
        factory: &str,
        pool: &str,
        allowed_implementation_codehashes: &HashSet<String>,
    ) -> Result<bool> {
        let factory_beacon = self
            .eth_call_word(factory, eth_selector(b"beacon()"))
            .await
            .with_context(|| format!("read beacon() from trusted factory {factory}"))?;
        let slot = format!("0x{}", hex::encode(eip1967_beacon_slot()));
        let stored: String = self
            .rpc_call(
                "eth_getStorageAt",
                serde_json::json!([normalize_hex_0x(pool), slot, "latest"]),
            )
            .await
            .with_context(|| format!("read EIP-1967 beacon slot from pool {pool}"))?;
        let stored = parse_hex32(&stored)
            .ok_or_else(|| anyhow!("invalid EIP-1967 beacon slot returned for pool {pool}"))?;
        if !beacon_words_match(&factory_beacon, &stored) {
            return Ok(false);
        }
        let beacon = format!("0x{}", hex::encode(&factory_beacon[12..]));
        let implementation = self
            .eth_call_word(&beacon, eth_selector(b"implementation()"))
            .await
            .with_context(|| format!("read implementation() from trusted beacon {beacon}"))?;
        if !implementation[12..].iter().any(|byte| *byte != 0) {
            return Ok(false);
        }
        let implementation = format!("0x{}", hex::encode(&implementation[12..]));
        let hash = self.runtime_codehash(&implementation).await?;
        Ok(allowed_implementation_codehashes.contains(&hash))
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
                                last_err = anyhow!(
                                    "eth_{} failed for {url}: rpc error {}: {}",
                                    method,
                                    e.code,
                                    e.message
                                );
                                return Err(last_err);
                            }
                            _ => {
                                last_err = anyhow!(
                                    "malformed rpc response for method {method} from {url}"
                                );
                                break 'attempts;
                            }
                        },
                        Err(e) => {
                            last_err = anyhow!("eth_{} rpc decode failed: {}", method, e);
                            break 'attempts;
                        }
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
    hash[12..]
        .try_into()
        .expect("20 bytes from last 12 of keccak")
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

struct ReceiptWithLogs {
    success: bool,
    block_number: u64,
    block_hash: String,
    logs: Vec<EthLog>,
}

#[derive(Debug, Deserialize)]
struct EthLog {
    /// Contract address that emitted this log.
    #[serde(default)]
    address: String,
    #[serde(rename = "blockNumber")]
    block_number: String,
    #[serde(default, rename = "blockHash")]
    block_hash: Option<String>,
    #[serde(rename = "transactionHash")]
    transaction_hash: String,
    #[serde(rename = "logIndex")]
    log_index: String,
    #[serde(default)]
    removed: bool,
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

// ─── Utilities ────────────────────────────────────────────────────────────────

fn parse_hex_u64(hex_str: &str) -> Result<u64> {
    u64::from_str_radix(strip_0x(hex_str), 16).map_err(|e| anyhow!(e))
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(strip_0x(s)).ok()?;
    bytes.try_into().ok()
}

fn normalize_block_hash(s: &str) -> Result<String> {
    let hash = parse_hex32(s).ok_or_else(|| anyhow!("block hash must be exactly bytes32"))?;
    Ok(format!("0x{}", hex::encode(hash)))
}

fn validate_log_against_canonical(
    log: &EthLog,
    expected_block: u64,
    expected_hash: &str,
) -> Result<()> {
    if log.removed {
        return Err(anyhow!(
            "removed log {}:{} appeared in finalized scan",
            log.transaction_hash,
            log.log_index
        ));
    }
    let block = parse_hex_u64(&log.block_number)
        .with_context(|| format!("invalid log blockNumber {}", log.block_number))?;
    if block != expected_block {
        return Err(anyhow!(
            "log block mismatch: log={block} expected={expected_block}"
        ));
    }
    let log_hash = log
        .block_hash
        .as_deref()
        .ok_or_else(|| {
            anyhow!(
                "log {}:{} has no blockHash",
                log.transaction_hash,
                log.log_index
            )
        })
        .and_then(normalize_block_hash)?;
    let expected_hash = normalize_block_hash(expected_hash)?;
    if log_hash != expected_hash {
        return Err(anyhow!(
            "canonical hash mismatch at block {block}: log={log_hash} rpc={expected_hash}"
        ));
    }
    Ok(())
}

fn parse_bytes32_strict(name: &str, value: &str) -> Result<[u8; 32]> {
    parse_hex32(value)
        .ok_or_else(|| anyhow!("{name} must be exactly one 0x-prefixed bytes32 value"))
}

fn parse_address20(s: &str) -> Option<[u8; 20]> {
    let bytes = hex::decode(strip_0x(s)).ok()?;
    bytes.try_into().ok()
}

fn parse_address_set(name: &str, values: &[String]) -> Result<HashSet<String>> {
    values
        .iter()
        .filter(|v| !v.trim().is_empty())
        .map(|v| {
            if parse_address20(v).is_none() {
                return Err(anyhow!("{name} contains invalid address: {v}"));
            }
            Ok(normalize_hex_0x(v).to_lowercase())
        })
        .collect()
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
        advance_cursor, beacon_words_match, canonical_guard, classify_selector,
        compact_note_mutations, crank_gas_limit, crank_next_delay_secs,
        decode_frozen_root_updated_log, decode_json_note_archive, eip1967_beacon_slot,
        encode_crank_root_calldata, factory_log_matches, frontier_from_ordered_leaves,
        frozen_root_updated_topic0, getlogs_window_end, is_getlogs_range_error, normalize_hex_0x,
        parse_address_set, parse_bytes32_strict, parse_tx_meta, perc20_deployed_topic0,
        persist_request_is_current, pg_apply_note_mutations, pg_begin_canonical_rebuild,
        pg_commit_incremental_replay, pg_finish_canonical_rebuild, pg_load,
        push_incremental_replay_mutation, replay_frozen_set, require_admin, require_relayer,
        rlp_bytes, rlp_list, rlp_uint, validate_log_against_canonical, BatchEnvelope,
        CheckpointSnapshot, Cli, EthLog, FrozenUpdate, HourlyTxBudget, IndexerCheckpoint,
        JsonNoteArchiveUpdate, NoteArchiveMutation, RpcClient, DEFAULT_MAX_BATCHES_IN_MEMORY,
        MAX_CRANK_GAS_MARGIN_BPS,
    };

    fn frozen_update(cmx: &[&str], is_add: &[bool]) -> FrozenUpdate {
        FrozenUpdate {
            block_number: 1,
            log_index: 0,
            tx_hash: "0x".into(),
            old_root_hex: "0x00".into(),
            new_root_hex: "0x00".into(),
            cmx_changed_hex: cmx.iter().map(|s| s.to_string()).collect(),
            is_add: is_add.to_vec(),
        }
    }

    #[test]
    fn replay_frozen_set_applies_adds_and_removes() {
        // add A,B → remove A → re-add A: current set = {B, A}, idempotent, order = most-recent add.
        let feed = vec![
            frozen_update(&["0xaa", "0xbb"], &[true, true]),
            frozen_update(&["0xaa"], &[false]),
            frozen_update(&["0xaa", "0xbb"], &[true, true]), // re-add A; B already present (idempotent)
        ];
        assert_eq!(replay_frozen_set(&feed), vec!["0xbb".to_string(), "0xaa".to_string()]);

        // remove-all → empty
        let feed2 = vec![
            frozen_update(&["0xaa"], &[true]),
            frozen_update(&["0xaa"], &[false]),
        ];
        assert!(replay_frozen_set(&feed2).is_empty());
    }

    #[test]
    fn frozen_root_updated_topic0_matches_signature() {
        // `cast keccak "FrozenRootUpdated(uint256,uint256,uint256[],bool[])"`
        assert_eq!(
            frozen_root_updated_topic0(),
            "0x16a94787314fdde3719186ed905c70ca4372c384e73a2af4c9c12c511e892dc2"
        );
    }

    #[test]
    fn decode_frozen_root_updated_from_cast_fixture() {
        // Ground truth from:
        // cast abi-encode "x(uint256,uint256,uint256[],bool[])" 0x1111 0x1234 "[10,20]" "[true,false]"
        let data = "0x\
0000000000000000000000000000000000000000000000000000000000001111\
0000000000000000000000000000000000000000000000000000000000001234\
0000000000000000000000000000000000000000000000000000000000000080\
00000000000000000000000000000000000000000000000000000000000000e0\
0000000000000000000000000000000000000000000000000000000000000002\
000000000000000000000000000000000000000000000000000000000000000a\
0000000000000000000000000000000000000000000000000000000000000014\
0000000000000000000000000000000000000000000000000000000000000002\
0000000000000000000000000000000000000000000000000000000000000001\
0000000000000000000000000000000000000000000000000000000000000000";
        let d = decode_frozen_root_updated_log(data).expect("decode fixture");
        assert_eq!(d.old_root[31], 0x11);
        assert_eq!(d.old_root[30], 0x11);
        assert_eq!(d.new_root[31], 0x34);
        assert_eq!(d.new_root[30], 0x12);
        assert_eq!(d.cmx_changed.len(), 2);
        assert_eq!(d.cmx_changed[0][31], 10);
        assert_eq!(d.cmx_changed[1][31], 20);
        assert_eq!(d.is_add, vec![true, false]);
    }

    #[test]
    fn decode_frozen_root_updated_empty_delta() {
        // cast abi-encode "x(uint256,uint256,uint256[],bool[])" 0x1 0x2 "[]" "[]"
        let data = "0x\
0000000000000000000000000000000000000000000000000000000000000001\
0000000000000000000000000000000000000000000000000000000000000002\
0000000000000000000000000000000000000000000000000000000000000080\
00000000000000000000000000000000000000000000000000000000000000a0\
0000000000000000000000000000000000000000000000000000000000000000\
0000000000000000000000000000000000000000000000000000000000000000";
        let d = decode_frozen_root_updated_log(data).expect("decode empty");
        assert_eq!(d.new_root[31], 0x02);
        assert!(d.cmx_changed.is_empty());
        assert!(d.is_add.is_empty());
    }
    use axum::http::{HeaderMap, HeaderValue, StatusCode};
    use clap::CommandFactory;
    use ff::PrimeField;
    use halo2curves::bn256::Fr;
    use privacy_core::commitment_tree::frontier::{
        FrontierTree, CMX_CONFIRM_MAX_BATCH, CMX_CONFIRM_MAX_PROOFS_PER_TX,
    };
    use privacy_core::commitment_tree::frozen::fr_to_be_bytes;
    use privacy_core::ethereum::{update_root_selector, update_roots_selector};
    use privacy_core::types::{OrchardIndexBatch, OrchardIndexedAbiNote};
    use sha3::{Digest, Keccak256};
    use std::sync::Arc;

    #[test]
    fn incremental_replay_uses_a_larger_bounded_history_window() {
        assert_eq!(DEFAULT_MAX_BATCHES_IN_MEMORY, 4_096);
    }

    #[test]
    fn stale_checkpoint_requests_are_rejected_after_a_persistence_epoch_change() {
        assert!(persist_request_is_current(false, 7, 7));
        assert!(!persist_request_is_current(true, 7, 7));
        assert!(!persist_request_is_current(false, 8, 7));
    }

    #[test]
    fn incremental_replay_mutation_buffer_fails_closed_at_its_limit() {
        let mut buffered = Vec::new();
        push_incremental_replay_mutation(
            &mut buffered,
            NoteArchiveMutation::Confirm {
                cmx: [0x11; 32],
                position: 0,
            },
            1,
        )
        .unwrap();
        let error = push_incremental_replay_mutation(
            &mut buffered,
            NoteArchiveMutation::Confirm {
                cmx: [0x22; 32],
                position: 1,
            },
            1,
        )
        .unwrap_err();
        assert!(error.to_string().contains("mutation limit exceeded"));
        assert_eq!(buffered.len(), 1);
    }

    #[test]
    fn gas_price_is_configurable_from_the_runtime_environment() {
        let command = Cli::command();
        let gas_price = command
            .get_arguments()
            .find(|arg| arg.get_id() == "gas_price")
            .expect("gas_price CLI argument");
        assert_eq!(
            gas_price.get_env(),
            Some(std::ffi::OsStr::new("PRIVACYBTC_INDEXER_GAS_PRICE"))
        );
    }

    #[test]
    fn shadow_mode_is_configurable_from_the_runtime_environment() {
        let command = Cli::command();
        let shadow_mode = command
            .get_arguments()
            .find(|arg| arg.get_id() == "shadow_mode")
            .expect("shadow_mode CLI argument");
        assert_eq!(
            shadow_mode.get_env(),
            Some(std::ffi::OsStr::new("PRIVACYBTC_INDEXER_SHADOW_MODE"))
        );
        let migrate_only = command
            .get_arguments()
            .find(|arg| arg.get_id() == "migrate_only")
            .expect("migrate_only CLI argument");
        assert_eq!(
            migrate_only.get_env(),
            Some(std::ffi::OsStr::new("PRIVACYBTC_INDEXER_MIGRATE_ONLY"))
        );
    }

    fn canonical_test_leaf(value: u64) -> [u8; 32] {
        let mut be: [u8; 32] = Fr::from(value).to_repr().into();
        be.reverse();
        be
    }

    #[test]
    fn final_leaf_path_reconstructs_exact_crank_frontier() {
        let leaves: Vec<[u8; 32]> = (1..=65).map(canonical_test_leaf).collect();
        for size in [0usize, 1, 2, 3, 4, 7, 8, 31, 32, 33, 64, 65] {
            let restored = frontier_from_ordered_leaves(&leaves[..size])
                .expect("reconstruct frontier from checkpoint leaves");
            let mut replayed = FrontierTree::new();
            for leaf in &leaves[..size] {
                replayed.insert_be(*leaf);
            }
            assert_eq!(restored.next_index(), replayed.next_index(), "size={size}");
            assert_eq!(restored.filled(), replayed.filled(), "size={size}");
            assert_eq!(
                fr_to_be_bytes(restored.root()),
                fr_to_be_bytes(replayed.root()),
                "size={size}"
            );
        }
    }

    #[test]
    #[ignore = "capacity benchmark; run explicitly in release mode"]
    fn production_sized_checkpoint_frontier_rebuild() {
        const LEAVES: u64 = 61_504;
        let leaves: Vec<[u8; 32]> = (1..=LEAVES).map(canonical_test_leaf).collect();
        let started = std::time::Instant::now();
        let restored = frontier_from_ordered_leaves(&leaves)
            .expect("reconstruct production-sized checkpoint frontier");
        eprintln!(
            "reconstructed {LEAVES}-leaf frontier in {:?}",
            started.elapsed()
        );
        assert_eq!(restored.next_index(), LEAVES);
    }

    #[test]
    fn crank_gas_policy_is_configurable_from_the_runtime_environment() {
        let command = Cli::command();
        let cap = command
            .get_arguments()
            .find(|arg| arg.get_id() == "gas_limit_update_root")
            .expect("crank gas cap CLI argument");
        assert_eq!(
            cap.get_env(),
            Some(std::ffi::OsStr::new("PRIVACYBTC_INDEXER_CRANK_GAS_LIMIT"))
        );
        let margin = command
            .get_arguments()
            .find(|arg| arg.get_id() == "crank_gas_margin_bps")
            .expect("crank gas margin CLI argument");
        assert_eq!(
            margin.get_env(),
            Some(std::ffi::OsStr::new(
                "PRIVACYBTC_INDEXER_CRANK_GAS_MARGIN_BPS"
            ))
        );
        let max_proofs = command
            .get_arguments()
            .find(|arg| arg.get_id() == "crank_max_proofs_per_tx")
            .expect("crank max proofs CLI argument");
        assert_eq!(
            max_proofs.get_env(),
            Some(std::ffi::OsStr::new(
                "PRIVACYBTC_INDEXER_CRANK_MAX_PROOFS_PER_TX"
            ))
        );
        let hourly_budget = command
            .get_arguments()
            .find(|arg| arg.get_id() == "crank_max_tx_per_hour")
            .expect("crank hourly budget CLI argument");
        assert_eq!(
            hourly_budget.get_env(),
            Some(std::ffi::OsStr::new(
                "PRIVACYBTC_INDEXER_CRANK_MAX_TX_PER_HOUR"
            ))
        );
    }

    #[test]
    fn crank_calldata_keeps_single_fallback_and_uses_rlc_for_multiple_segments() {
        assert_eq!(CMX_CONFIRM_MAX_BATCH, 8);
        assert_eq!(CMX_CONFIRM_MAX_PROOFS_PER_TX, 4);
        let leaves = [[1u8; 32]; 9];
        let mut tree = FrontierTree::new();
        let inputs = tree.plan_batches(&leaves, CMX_CONFIRM_MAX_PROOFS_PER_TX);
        let proofs = vec![vec![0x11; 256], vec![0x22; 256]];

        let (single, method) =
            encode_crank_root_calldata(&inputs[..1], &proofs[..1]).expect("single calldata");
        assert_eq!(method, "updateRoot");
        assert_eq!(&single[..4], &update_root_selector());

        let (aggregate, method) =
            encode_crank_root_calldata(&inputs, &proofs).expect("aggregate calldata");
        assert_eq!(method, "updateRoots");
        assert_eq!(&aggregate[..4], &update_roots_selector());
    }

    #[test]
    fn crank_calldata_rejects_missing_or_malformed_proofs() {
        let mut tree = FrontierTree::new();
        let inputs = tree.plan_batches(&[[1u8; 32]; 9], 4);
        assert!(encode_crank_root_calldata(&inputs, &[]).is_err());
        assert!(encode_crank_root_calldata(&inputs, &[vec![0u8; 255], vec![0u8; 256]]).is_err());
    }

    #[test]
    fn crank_gas_limit_uses_ceiling_margin_and_cap() {
        assert_eq!(
            crank_gas_limit(1_665_014, 200, 2_000_000).unwrap(),
            1_698_315
        );
        assert_eq!(
            crank_gas_limit(1_588_186, 200, 2_000_000).unwrap(),
            1_619_950
        );
        assert_eq!(crank_gas_limit(2_000_000, 0, 2_000_000).unwrap(), 2_000_000);
    }

    #[test]
    fn crank_gas_limit_fails_closed_for_invalid_or_over_cap_values() {
        assert!(crank_gas_limit(0, 200, 2_000_000).is_err());
        assert!(crank_gas_limit(1_000_000, 200, 0).is_err());
        assert!(crank_gas_limit(1_900_000, 1_000, 2_000_000)
            .unwrap_err()
            .to_string()
            .contains("above cap"));
        assert!(crank_gas_limit(1_000_000, MAX_CRANK_GAS_MARGIN_BPS + 1, 2_000_000).is_err());
        assert!(crank_gas_limit(u64::MAX, 200, u64::MAX).is_err());
    }

    #[test]
    fn crank_estimate_transaction_matches_the_signed_target() {
        let to = "11".repeat(20);
        let from = format!("0x{}", "22".repeat(20));
        let call = RpcClient::transaction_call(&to, &[0xaa, 0xbb], Some(&from));
        assert_eq!(call["to"], format!("0x{to}"));
        assert_eq!(call["from"], from);
        assert_eq!(call["data"], "0xaabb");
        assert_eq!(call["value"], "0x0");
        assert!(
            call.get("gas").is_none(),
            "RPC must estimate without a fixed gas"
        );
    }

    #[test]
    fn binding_groth16_selectors_are_classified_and_legacy_remains_readable() {
        assert_eq!(
            classify_selector(&hex::decode("33b854b0").unwrap()),
            Some("shield")
        );
        assert_eq!(
            classify_selector(&hex::decode("1952ce65").unwrap()),
            Some("unshield")
        );
        assert_eq!(
            classify_selector(&hex::decode("141f641d").unwrap()),
            Some("mint")
        );
        assert_eq!(
            classify_selector(&hex::decode("b74534e9").unwrap()),
            Some("burn")
        );
        assert_eq!(
            classify_selector(&hex::decode("b2d4797b").unwrap()),
            Some("transfer")
        );
        assert_eq!(
            classify_selector(&hex::decode("5e09e2b1").unwrap()),
            Some("transfer")
        );
        assert_eq!(
            classify_selector(&hex::decode("d41e4a7a").unwrap()),
            Some("swap")
        );
        assert_eq!(
            classify_selector(&hex::decode("74da02c8").unwrap()),
            Some("swap")
        );
        assert_eq!(
            classify_selector(&hex::decode("e3b3fae4").unwrap()),
            Some("swap")
        );
        assert_eq!(
            classify_selector(&hex::decode("eda1a0ac").unwrap()),
            Some("transfer")
        );

        let mut unshield = vec![0u8; 68];
        unshield[..4].copy_from_slice(&hex::decode("1952ce65").unwrap());
        unshield[48..68].fill(0x42);
        assert_eq!(
            parse_tx_meta(&unshield).recipient,
            Some(format!("0x{}", "42".repeat(20)))
        );
    }

    #[test]
    fn verifier_set_id_parser_requires_exact_bytes32() {
        assert_eq!(
            parse_bytes32_strict("ID", &format!("0x{}", "ab".repeat(32))).unwrap(),
            [0xabu8; 32]
        );
        assert!(parse_bytes32_strict("ID", &format!("0x{}", "ab".repeat(31))).is_err());
    }

    /// The indexer's empty frozen tree must publish the same `rt_frozen` the PERC20
    /// circuit/prover expect, and a freeze must change the root while the witness for
    /// a non-frozen cmx still opens to the live root.
    #[test]
    fn frozen_imt_root_matches_perc20_and_updates_on_freeze() {
        use privacy_core::commitment_tree::frozen::{fr_from_be_bytes, fr_to_le_hex, FrozenImt};

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

    #[test]
    fn normalize_hex_keeps_or_adds_prefix() {
        assert_eq!(normalize_hex_0x("abcd"), "0xabcd");
        assert_eq!(normalize_hex_0x("0xabcd"), "0xabcd");
    }

    #[test]
    fn factory_admission_rejects_self_emitted_or_wrong_factory_logs() {
        let factory = format!("0x{}", "11".repeat(20));
        let pool = format!("0x{}", "22".repeat(20));
        let topic0 = perc20_deployed_topic0();
        let make_log = |address: String, event: String| EthLog {
            address,
            block_number: "0x1".into(),
            block_hash: Some(format!("0x{}", "aa".repeat(32))),
            transaction_hash: format!("0x{}", "33".repeat(32)),
            log_index: "0x0".into(),
            removed: false,
            topics: Some(vec![event, super::address_to_topic(&pool)]),
            data: "0x".into(),
        };
        assert!(factory_log_matches(
            &make_log(factory.clone(), topic0.clone()),
            &factory,
            &topic0,
            &pool
        ));
        assert!(!factory_log_matches(
            &make_log(pool.clone(), topic0.clone()),
            &factory,
            &topic0,
            &pool
        ));
        assert!(!factory_log_matches(
            &make_log(factory.clone(), format!("0x{}", "44".repeat(32))),
            &factory,
            &topic0,
            &pool
        ));
    }

    #[test]
    fn finalized_log_validation_requires_canonical_hash_and_rejects_removed() {
        let canonical = format!("0x{}", "aa".repeat(32));
        let mut log = EthLog {
            address: format!("0x{}", "11".repeat(20)),
            block_number: "0x2a".into(),
            block_hash: Some(canonical.clone()),
            transaction_hash: format!("0x{}", "22".repeat(32)),
            log_index: "0x0".into(),
            removed: false,
            topics: None,
            data: "0x".into(),
        };
        assert!(validate_log_against_canonical(&log, 42, &canonical).is_ok());
        log.block_hash = Some(format!("0x{}", "bb".repeat(32)));
        assert!(validate_log_against_canonical(&log, 42, &canonical).is_err());
        log.block_hash = Some(canonical.clone());
        log.removed = true;
        assert!(validate_log_against_canonical(&log, 42, &canonical).is_err());
        log.removed = false;
        log.block_hash = None;
        assert!(validate_log_against_canonical(&log, 42, &canonical).is_err());
    }

    #[test]
    fn checkpoint_schema_accepts_legacy_and_roundtrips_finalized_cursor() {
        let legacy: IndexerCheckpoint =
            serde_json::from_str(r#"{"next_block":7}"#).expect("legacy checkpoint");
        assert_eq!(legacy.last_finalized_block, None);
        assert_eq!(legacy.last_finalized_block_hash, None);
        assert_eq!(legacy.confirmed_count, None);
        assert_eq!(legacy.last_leaf_block, None);
        assert_eq!(legacy.last_leaf_log_index, None);

        let hash = format!("0x{}", "ab".repeat(32));
        let current: IndexerCheckpoint = serde_json::from_value(serde_json::json!({
            "next_block": 43,
            "last_finalized_block": 42,
            "last_finalized_block_hash": hash.clone(),
            "confirmed_count": 9,
            "last_leaf_block": 41,
            "last_leaf_log_index": 3,
        }))
        .expect("current checkpoint");
        assert_eq!(current.last_finalized_block, Some(42));
        assert_eq!(
            current.last_finalized_block_hash.as_deref(),
            Some(hash.as_str())
        );
        assert_eq!(current.confirmed_count, Some(9));
        assert_eq!(current.last_leaf_block, Some(41));
        assert_eq!(current.last_leaf_log_index, Some(3));
    }

    fn sample_note_envelope(cmx_byte: u8, seq: u64) -> BatchEnvelope {
        sample_note_envelope_for_cmx([cmx_byte; 32], seq)
    }

    fn sample_note_envelope_for_cmx(cmx: [u8; 32], seq: u64) -> BatchEnvelope {
        let note = OrchardIndexedAbiNote {
            block_number: 100 + seq,
            tx_hash: format!("0x{}", hex::encode(cmx)),
            log_index: seq,
            cmx,
            enc_ciphertext: vec![1, 2, 3],
            epk: [2u8; 32],
            out_ciphertext: vec![4, 5],
            cv_net_x: Some([3u8; 32]),
            nf_old: [4u8; 32],
            ack_hash: [5u8; 32],
            cmx_position: None,
            shield_amount_sats: None,
            is_confirmed: false,
        };
        BatchEnvelope {
            seq,
            pool_address: Some(format!("0x{}", "11".repeat(20))),
            batch: OrchardIndexBatch {
                from_block: note.block_number,
                to_block: note.block_number,
                abi_notes: vec![note],
                bundles: vec![],
                latest_root: None,
            },
        }
    }

    fn unique_cmx(index: u64) -> [u8; 32] {
        let mut cmx = [0x5a; 32];
        cmx[24..].copy_from_slice(&index.to_be_bytes());
        cmx
    }

    #[test]
    fn canonical_guard_fails_closed_during_rebuild_or_cursor_mismatch() {
        assert!(canonical_guard(false).is_ok());
        assert_eq!(
            canonical_guard(true).unwrap_err().0,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn rebuild_note_mutations_keep_full_rows_and_compact_updates() {
        let first = sample_note_envelope(0x11, 1);
        let mut latest = first.clone();
        latest.seq = 2;
        latest.batch.abi_notes[0].block_number = 102;
        let mutations = vec![
            NoteArchiveMutation::Upsert(first),
            NoteArchiveMutation::Upsert(latest),
            NoteArchiveMutation::Confirm {
                cmx: [0x11; 32],
                position: 7,
            },
            NoteArchiveMutation::ShieldAmount {
                cmx: [0x11; 32],
                amount: 99,
            },
            NoteArchiveMutation::Upsert(sample_note_envelope(0x22, 3)),
        ];
        let compacted = compact_note_mutations(&mutations);
        assert_eq!(compacted.upserts.len(), 2);
        let row = compacted
            .upserts
            .iter()
            .find(|row| row.note.cmx == [0x11; 32])
            .unwrap();
        assert_eq!(row.seq, 2, "latest row for one cmx must win");
        assert_eq!(compacted.confirmations, vec![([0x11; 32], 7)]);
        assert_eq!(compacted.shield_amounts, vec![([0x11; 32], 99)]);
    }

    #[test]
    fn json_note_archive_applies_late_confirmation_and_amount_updates() {
        let pool = format!("0x{}", "11".repeat(20));
        let env = sample_note_envelope(0x33, 9);
        let records = [
            serde_json::to_string(&env).unwrap(),
            serde_json::to_string(&JsonNoteArchiveUpdate::Confirm {
                cmx_hex: hex::encode([0x33; 32]),
                position: 12,
            })
            .unwrap(),
            serde_json::to_string(&JsonNoteArchiveUpdate::ShieldAmount {
                cmx_hex: hex::encode([0x33; 32]),
                amount: 500,
            })
            .unwrap(),
            "{torn".to_string(),
        ]
        .join("\n");
        let decoded = decode_json_note_archive(&records, &pool);
        assert_eq!(decoded.len(), 1);
        let note = &decoded[0].batch.abi_notes[0];
        assert_eq!(note.cmx_position, Some(12));
        assert!(note.is_confirmed);
        assert_eq!(note.shield_amount_sats, Some(500));
        assert_eq!(decoded[0].pool_address.as_deref(), Some(pool.as_str()));
    }

    async fn clear_pg_rebuild_test_pool(pool: &sqlx::PgPool, pool_address: &str) {
        for statement in [
            "DELETE FROM notes_rebuild WHERE pool_address=$1",
            "DELETE FROM notes WHERE pool_address=$1",
            "DELETE FROM cmx_leaves WHERE pool_address=$1",
            "DELETE FROM pending_tx WHERE pool_address=$1",
            "DELETE FROM frozen_updates WHERE pool_address=$1",
            "DELETE FROM shield_pool_stats WHERE pool_address=$1",
            "DELETE FROM indexer_meta WHERE pool_address=$1",
        ] {
            sqlx::query(statement)
                .bind(pool_address)
                .execute(pool)
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn pg_checkpoint_integrity_enables_warm_start_when_database_is_configured() {
        let Ok(database_url) = std::env::var("PRIVACY_INDEXER_TEST_DATABASE_URL") else {
            return;
        };
        let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let pool_address = format!("0x{}", "ec".repeat(20));
        clear_pg_rebuild_test_pool(&pool, &pool_address).await;

        let cmx = canonical_test_leaf(77);
        let note = sample_note_envelope_for_cmx(cmx, 1);
        let frontier = frontier_from_ordered_leaves(&[cmx]).unwrap();
        let snap = CheckpointSnapshot {
            next_block: 102,
            last_finalized_block: Some(101),
            last_finalized_block_hash: Some(format!("0x{}", "cd".repeat(32))),
            cmx_ordered: vec![cmx],
            active_root: Some(fr_to_be_bytes(frontier.root())),
            confirmed_count: 1,
            last_leaf_key: Some((101, 1)),
            latest_seq: 1,
            ..CheckpointSnapshot::default()
        };
        pg_commit_incremental_replay(
            &pool,
            &pool_address,
            &[
                NoteArchiveMutation::Upsert(note),
                NoteArchiveMutation::Confirm { cmx, position: 0 },
            ],
            &snap,
        )
        .await
        .unwrap();

        let loaded = pg_load(&pool, &pool_address, 1).await;
        assert!(loaded.warm_start_candidate);
        assert_eq!(loaded.confirmed_count, 1);
        assert_eq!(loaded.last_leaf_key, Some((101, 1)));
        assert!(loaded.confirmed_cmx.contains(&cmx));

        // Version 0 models an old writer that cannot maintain the new scalar
        // columns. The read-only snapshot derives them from the atomic note
        // archive, then the Poseidon/RPC warm-start checks still apply.
        sqlx::query(
            "UPDATE indexer_meta SET checkpoint_version=0, confirmed_count=0, \
             last_leaf_block=NULL, last_leaf_log_index=NULL WHERE pool_address=$1",
        )
        .bind(&pool_address)
        .execute(&pool)
        .await
        .unwrap();
        let legacy_writer = pg_load(&pool, &pool_address, 1).await;
        assert!(legacy_writer.warm_start_candidate);
        assert_eq!(legacy_writer.confirmed_count, 1);
        assert_eq!(legacy_writer.last_leaf_key, Some((101, 1)));

        sqlx::query(
            "UPDATE indexer_meta SET checkpoint_version=1, confirmed_count=1, \
             last_leaf_block=101, last_leaf_log_index=2 WHERE pool_address=$1",
        )
        .bind(&pool_address)
        .execute(&pool)
        .await
        .unwrap();
        let rejected = pg_load(&pool, &pool_address, 1).await;
        assert!(!rejected.warm_start_candidate);

        clear_pg_rebuild_test_pool(&pool, &pool_address).await;
    }

    #[tokio::test]
    async fn pg_canonical_note_rebuild_swaps_full_history_when_database_is_configured() {
        let Ok(database_url) = std::env::var("PRIVACY_INDEXER_TEST_DATABASE_URL") else {
            return;
        };
        let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let pool_address = format!("0x{}", "ee".repeat(20));
        clear_pg_rebuild_test_pool(&pool, &pool_address).await;

        // Seed one stale Voted/reorg note in the canonical table.
        pg_apply_note_mutations(
            &pool,
            &pool_address,
            None,
            &[NoteArchiveMutation::Upsert(sample_note_envelope(0xaa, 1))],
        )
        .await
        .unwrap();

        let generation = "integration-generation";
        pg_begin_canonical_rebuild(&pool, &pool_address, generation)
            .await
            .unwrap();
        pg_apply_note_mutations(
            &pool,
            &pool_address,
            Some(generation),
            &[
                NoteArchiveMutation::Upsert(sample_note_envelope(0xbb, 2)),
                NoteArchiveMutation::Confirm {
                    cmx: [0xbb; 32],
                    position: 0,
                },
                NoteArchiveMutation::ShieldAmount {
                    cmx: [0xbb; 32],
                    amount: 77,
                },
            ],
        )
        .await
        .unwrap();

        // Intentionally leave the finite in-memory ring empty: activation must
        // source full history from staging, not CheckpointSnapshot::batches.
        let snap = CheckpointSnapshot {
            next_block: 102,
            last_finalized_block: Some(101),
            last_finalized_block_hash: Some(format!("0x{}", "cc".repeat(32))),
            cmx_ordered: vec![[0xbb; 32]],
            latest_seq: 2,
            ..CheckpointSnapshot::default()
        };
        pg_finish_canonical_rebuild(&pool, &pool_address, generation, &snap)
            .await
            .unwrap();

        let rows: Vec<(String, Option<i64>, bool, Option<i64>)> = sqlx::query_as(
            "SELECT cmx_hex, position, is_confirmed, shield_amount_sats \
             FROM notes WHERE pool_address=$1",
        )
        .bind(&pool_address)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            rows,
            vec![(hex::encode([0xbb; 32]), Some(0), true, Some(77))]
        );
        let staged: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM notes_rebuild WHERE pool_address=$1",
        )
        .bind(&pool_address)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(staged, 0);
        let cursor: (i64, Option<i64>, Option<String>) = sqlx::query_as(
            "SELECT next_block, last_finalized_block, last_finalized_block_hash \
             FROM indexer_meta WHERE pool_address=$1",
        )
        .bind(&pool_address)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(cursor.0, 102);
        assert_eq!(cursor.1, Some(101));
        assert_eq!(cursor.2, snap.last_finalized_block_hash);

        clear_pg_rebuild_test_pool(&pool, &pool_address).await;
    }

    #[tokio::test]
    async fn pg_incremental_replay_is_atomic_and_appends_only_new_leaves_when_configured() {
        let Ok(database_url) = std::env::var("PRIVACY_INDEXER_TEST_DATABASE_URL") else {
            return;
        };
        let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let pool_address = format!("0x{}", "ed".repeat(20));
        clear_pg_rebuild_test_pool(&pool, &pool_address).await;

        const EXISTING_LEAVES: u64 = 58_000;
        const REPLAY_NOTES: u64 = 340;

        let prefix_snap = CheckpointSnapshot {
            next_block: 1_001,
            last_finalized_block: Some(1_000),
            last_finalized_block_hash: Some(format!("0x{}", "cd".repeat(32))),
            cmx_ordered: (0..EXISTING_LEAVES).map(unique_cmx).collect(),
            ..CheckpointSnapshot::default()
        };
        pg_commit_incremental_replay(&pool, &pool_address, &[], &prefix_snap)
            .await
            .expect("seed production-sized cmx prefix");
        let first_xmin: String = sqlx::query_scalar(
            "SELECT xmin::text FROM cmx_leaves WHERE pool_address=$1 AND position=0",
        )
        .bind(&pool_address)
        .fetch_one(&pool)
        .await
        .expect("read prefix xmin");

        let mut mutations = Vec::with_capacity(REPLAY_NOTES as usize * 3);
        let mut cmx_ordered = prefix_snap.cmx_ordered.clone();
        for offset in 0..REPLAY_NOTES {
            let position = EXISTING_LEAVES + offset;
            let cmx = unique_cmx(position);
            let seq = position * 2 + 1;
            let initial = sample_note_envelope_for_cmx(cmx, seq);
            let mut confirmed = initial.clone();
            confirmed.seq = seq + 1;
            confirmed.batch.abi_notes[0].is_confirmed = true;
            confirmed.batch.abi_notes[0].cmx_position = Some(position);
            mutations.push(NoteArchiveMutation::Upsert(initial));
            mutations.push(NoteArchiveMutation::Upsert(confirmed));
            mutations.push(NoteArchiveMutation::Confirm { cmx, position });
            cmx_ordered.push(cmx);
        }
        let snap = CheckpointSnapshot {
            next_block: 2_001,
            last_finalized_block: Some(2_000),
            last_finalized_block_hash: Some(format!("0x{}", "ab".repeat(32))),
            cmx_ordered,
            latest_seq: (EXISTING_LEAVES + REPLAY_NOTES) * 2,
            ..CheckpointSnapshot::default()
        };
        let started = std::time::Instant::now();
        pg_commit_incremental_replay(&pool, &pool_address, &mutations, &snap)
            .await
            .unwrap();
        eprintln!(
            "{EXISTING_LEAVES}-leaf prefix plus {REPLAY_NOTES}-note incremental replay transaction completed in {:?}",
            started.elapsed()
        );

        let counts: (i64, i64, i64) = sqlx::query_as(
            "SELECT \
               (SELECT count(*) FROM notes WHERE pool_address=$1), \
               (SELECT count(*) FROM notes WHERE pool_address=$1 AND is_confirmed), \
               (SELECT count(*) FROM cmx_leaves WHERE pool_address=$1)",
        )
        .bind(&pool_address)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            counts,
            (
                REPLAY_NOTES as i64,
                REPLAY_NOTES as i64,
                (EXISTING_LEAVES + REPLAY_NOTES) as i64,
            )
        );
        let first_xmin_after_replay: String = sqlx::query_scalar(
            "SELECT xmin::text FROM cmx_leaves WHERE pool_address=$1 AND position=0",
        )
        .bind(&pool_address)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            first_xmin_after_replay, first_xmin,
            "incremental replay must not rewrite the existing cmx prefix"
        );

        let cursor_before_failure: i64 =
            sqlx::query_scalar("SELECT next_block FROM indexer_meta WHERE pool_address=$1")
                .bind(&pool_address)
                .fetch_one(&pool)
                .await
                .unwrap();
        let bad_cmx = unique_cmx(EXISTING_LEAVES + REPLAY_NOTES);
        let bad_seq = snap.latest_seq + 1;
        let mut bad_snap = snap.clone();
        let persisted_boundary = bad_snap.cmx_ordered.len() - 1;
        bad_snap.cmx_ordered[persisted_boundary] = unique_cmx(9_999);
        bad_snap.cmx_ordered.push(bad_cmx);
        bad_snap.next_block = 9_999;
        let error = pg_commit_incremental_replay(
            &pool,
            &pool_address,
            &[
                NoteArchiveMutation::Upsert(sample_note_envelope_for_cmx(bad_cmx, bad_seq)),
                NoteArchiveMutation::Confirm {
                    cmx: bad_cmx,
                    position: EXISTING_LEAVES + REPLAY_NOTES,
                },
            ],
            &bad_snap,
        )
        .await
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("append-only cmx checkpoint prefix mismatch"));

        let state_after_failure: (i64, i64, i64) = sqlx::query_as(
            "SELECT \
               (SELECT count(*) FROM notes WHERE pool_address=$1), \
               (SELECT count(*) FROM cmx_leaves WHERE pool_address=$1), \
               (SELECT next_block FROM indexer_meta WHERE pool_address=$1)",
        )
        .bind(&pool_address)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            state_after_failure,
            (
                REPLAY_NOTES as i64,
                (EXISTING_LEAVES + REPLAY_NOTES) as i64,
                cursor_before_failure,
            )
        );
        let bad_note_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM notes WHERE pool_address=$1 AND cmx_hex=$2")
                .bind(&pool_address)
                .bind(hex::encode(bad_cmx))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            bad_note_count, 0,
            "failed replay must roll back note upsert"
        );

        clear_pg_rebuild_test_pool(&pool, &pool_address).await;
    }

    #[test]
    fn beacon_binding_and_eip1967_slot_are_exact() {
        assert_eq!(
            hex::encode(eip1967_beacon_slot()),
            "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
        );
        let mut factory = [0u8; 32];
        factory[12..].fill(0x11);
        let mut same = [0u8; 32];
        same[12..].fill(0x11);
        let mut other = [0u8; 32];
        other[12..].fill(0x22);
        assert!(beacon_words_match(&factory, &same));
        assert!(!beacon_words_match(&factory, &other));
        assert!(!beacon_words_match(&[0u8; 32], &[0u8; 32]));
    }

    #[test]
    fn crank_hourly_budget_is_rolling_and_fail_closed() {
        let mut budget = HourlyTxBudget::new(2);
        assert!(budget.try_take(10));
        assert!(budget.try_take(20));
        assert!(!budget.try_take(30));
        assert!(budget.try_take(3610));
        assert!(!budget.try_take(3611));
    }

    #[test]
    fn crank_hourly_budget_supports_four_hundred_transactions_and_precise_backoff() {
        let mut budget = HourlyTxBudget::new(400);
        for _ in 0..400 {
            assert!(budget.try_take(10));
        }
        assert!(!budget.try_take(10));
        assert_eq!(budget.retry_after_seconds(10), Some(3600));
        assert_eq!(budget.retry_after_seconds(3609), Some(1));
        assert_eq!(budget.retry_after_seconds(3610), None);
        assert!(budget.try_take(3610));
    }

    #[test]
    fn successful_crank_batches_stay_hot_until_the_budget_requires_backoff() {
        assert_eq!(crank_next_delay_secs(true, None, 15), None);
        assert_eq!(crank_next_delay_secs(false, None, 15), Some(15));
        assert_eq!(crank_next_delay_secs(false, None, 0), Some(1));
        assert_eq!(crank_next_delay_secs(true, Some(27), 15), Some(27));
        assert_eq!(crank_next_delay_secs(false, Some(0), 15), Some(1));
    }

    #[test]
    fn configured_address_sets_reject_malformed_values() {
        let valid = vec![format!("0x{}", "ab".repeat(20))];
        assert_eq!(parse_address_set("test", &valid).unwrap().len(), 1);
        assert!(parse_address_set("test", &["0x1234".into()]).is_err());
    }

    #[test]
    fn frozen_admin_auth_requires_configured_bearer_token() {
        let mut headers = HeaderMap::new();
        let token = Arc::<str>::from("secret");

        assert_eq!(
            require_admin(&headers, None).unwrap_err().0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            require_admin(&headers, Some(&token)).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );

        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer wrong"),
        );
        assert_eq!(
            require_admin(&headers, Some(&token)).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );

        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer secret"),
        );
        assert!(require_admin(&headers, Some(&token)).is_ok());
    }

    #[test]
    fn relayer_auth_requires_a_distinct_configured_bearer_token() {
        let mut headers = HeaderMap::new();
        let token = Arc::<str>::from("relayer-secret");
        assert_eq!(
            require_relayer(&headers, None).unwrap_err().0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            require_relayer(&headers, Some(&token)).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer relayer-secret"),
        );
        assert!(require_relayer(&headers, Some(&token)).is_ok());
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

    // Regression for "indexer wedged by provider getLogs range cap" (Alchemy Monad
    // testnet allows at most 1000 blocks per eth_getLogs): the window math must
    // stay within bounds and the client must learn a smaller span from provider
    // rejections instead of retrying the same oversized window forever.

    #[test]
    fn getlogs_window_end_clamps_to_range_and_survives_zero_span() {
        assert_eq!(getlogs_window_end(1, 12_000, 5_000), 5_000);
        assert_eq!(getlogs_window_end(5_001, 12_000, 5_000), 10_000);
        assert_eq!(getlogs_window_end(10_001, 12_000, 5_000), 12_000);
        // Single block and degenerate span values never exceed `to`.
        assert_eq!(getlogs_window_end(42, 42, 5_000), 42);
        assert_eq!(getlogs_window_end(7, 100, 0), 7); // span 0 treated as 1
                                                      // No overflow at the top of the u64 range.
        assert_eq!(getlogs_window_end(u64::MAX - 1, u64::MAX, 5_000), u64::MAX);
    }

    #[test]
    fn getlogs_range_error_detection_matches_provider_messages() {
        let alchemy = anyhow::anyhow!(
            "eth_eth_getLogs failed for https://example: rpc error -32600: \
             You can make eth_getLogs requests with up to a 1000 block range."
        );
        assert!(is_getlogs_range_error(&alchemy));
        let infura = anyhow::anyhow!("query returned more than 10000 results");
        assert!(is_getlogs_range_error(&infura));
        let transport = anyhow::anyhow!("eth_getLogs send failed: connection refused");
        assert!(!is_getlogs_range_error(&transport));
    }

    #[test]
    fn shrink_getlogs_span_halves_monotonically_with_floor_of_one() {
        let rpc = RpcClient::new("http://127.0.0.1:1".to_string());
        let initial = rpc.getlogs_span();
        assert!(initial >= 1);
        // Provider rejected a 5000-block window: learn 2500.
        assert_eq!(rpc.shrink_getlogs_span(5_000), initial.min(2_500));
        // A stale larger failure cannot grow the learned span back.
        rpc.shrink_getlogs_span(1_000); // -> 500
        assert_eq!(rpc.getlogs_span(), 500);
        rpc.shrink_getlogs_span(10_000); // half is 5000, but fetch_min keeps 500
        assert_eq!(rpc.getlogs_span(), 500);
        // Floor at 1 so the loop always makes progress.
        rpc.shrink_getlogs_span(1);
        assert_eq!(rpc.getlogs_span(), 1);
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
