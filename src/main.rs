mod compact_tree;

use std::{
    collections::{HashMap, HashSet, VecDeque},
    convert::Infallible,
    io::Write,
    net::SocketAddr,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use axum::{
    body::{to_bytes, Body},
    extract::{DefaultBodyLimit, Query, State},
    http::{HeaderMap, Method, Request, StatusCode},
    middleware::{self, Next},
    response::sse::{Event, KeepAlive, Sse},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use clap::{Parser, ValueEnum};
use ethabi::{decode as abi_decode, encode as abi_encode, ParamType, Token};
use futures_util::stream::{self, StreamExt};
use futures_util::SinkExt;
use k256::ecdsa::{RecoveryId, SigningKey};
use privacy_core::commitment_tree::frontier::{
    CmxConfirmWitnessInput, CMX_CONFIRM_MAX_BATCH, CMX_CONFIRM_MAX_PROOFS_PER_TX,
};
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
    SwapInitiateCalldata,
};
use privacy_core::types::{OrchardIndexBatch, OrchardIndexedAbiNote};
use rayon::prelude::*;
use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use tokio::sync::{broadcast, Mutex, RwLock, Semaphore};
use tokio_stream::wrappers::BroadcastStream;
use tokio_tungstenite::tungstenite::Message;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::timeout::TimeoutLayer;

use compact_tree::{
    export_segment_frozen_paths, frontier_from_leaves, required_witness_nodes, witness_from_nodes,
    witness_root_be, CompactFrontier, MerkleNode, MerkleNodeKey, StreamingFrontierBuilder,
};

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
        return Some(hex::encode(state.confirmed_frontier.root_le()));
    }
    // Nothing confirmed — the on-chain confirmedRoot is the empty-tree root.
    let mut le = EVM_EMPTY_IMT_ROOT;
    le.reverse();
    Some(hex::encode(le))
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

const DEFAULT_MAX_BATCHES_IN_MEMORY: usize = 4_096;
const MAX_INCREMENTAL_REPLAY_MUTATIONS: usize = 8_192;
const MAX_RECENT_EVENT_IDS: usize = 65_536;
const MAX_BUNDLE_OUT_CACHE: usize = 4_096;
const DEFAULT_FROZEN_UPDATE_PAGE: usize = 1_000;
const MAX_FROZEN_UPDATE_PAGE: usize = 4_096;
const MAX_FROZEN_LEAVES_RESPONSE: usize = 100_000;
const DEFAULT_TIP_FREEZE_PAGE_SIZE: usize = 4_096;
const MAX_TIP_FREEZE_PAGE_SIZE: usize = 16_384;
const DEFAULT_TIP_FREEZE_WORKERS: usize = 4;
const MAX_TIP_FREEZE_WORKERS: usize = 32;
const DEFAULT_MERKLE_PATH_CONCURRENCY: usize = 16;
const DEFAULT_MERKLE_PATH_MAX_RESPONSE_BYTES: usize = 128 * 1024;
const DEFAULT_MERKLE_PATH_HOURLY_BYTES: u64 = 256 * 1024 * 1024;
const DEFAULT_MERKLE_PATH_DAILY_BYTES: u64 = 1024 * 1024 * 1024;
const DEFAULT_TXS_CONCURRENCY: usize = 8;
const DEFAULT_TXS_MAX_RESPONSE_BYTES: usize = 256 * 1024;
const DEFAULT_TXS_HOURLY_BYTES: u64 = 128 * 1024 * 1024;
const DEFAULT_TXS_DAILY_BYTES: u64 = 1024 * 1024 * 1024;
const MINIMAL_TXS_MAX_LIMIT: usize = 25;
/// Re-scan a short finalized tail so a provider that transiently returns an
/// incomplete `eth_getLogs` result cannot permanently hide a newly-created
/// pool. Explicit startup pools have an independent admission retry loop.
const FACTORY_DISCOVERY_RESCAN_BLOCKS: u64 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum PublicApiMode {
    /// Backwards-compatible developer/internal behavior.
    Full,
    /// Public callers receive only health and immutable frozen Merkle paths.
    Minimal,
}

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
    /// Public HTTP surface. `minimal` keeps only bounded wallet/browser reads;
    /// an independent internal bearer token retains the other read APIs for
    /// reviewed services.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_PUBLIC_API_MODE",
        default_value = "full",
        value_enum
    )]
    public_api_mode: PublicApiMode,
    /// Global concurrency fuse for the only retained public data route.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_MERKLE_PATH_MAX_CONCURRENCY",
        default_value_t = DEFAULT_MERKLE_PATH_CONCURRENCY
    )]
    merkle_path_max_concurrency: usize,
    /// Maximum serialized body accepted from the Merkle path handler.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_MERKLE_PATH_MAX_RESPONSE_BYTES",
        default_value_t = DEFAULT_MERKLE_PATH_MAX_RESPONSE_BYTES
    )]
    merkle_path_max_response_bytes: usize,
    /// Process-wide hard egress budget. Buckets reset on UTC wall-clock boundaries.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_MERKLE_PATH_HOURLY_BYTES",
        default_value_t = DEFAULT_MERKLE_PATH_HOURLY_BYTES
    )]
    merkle_path_hourly_bytes: u64,
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_MERKLE_PATH_DAILY_BYTES",
        default_value_t = DEFAULT_MERKLE_PATH_DAILY_BYTES
    )]
    merkle_path_daily_bytes: u64,
    /// Independent public Browser fuse. It cannot consume the Merkle-path budget.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_TXS_MAX_CONCURRENCY",
        default_value_t = DEFAULT_TXS_CONCURRENCY
    )]
    txs_max_concurrency: usize,
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_TXS_MAX_RESPONSE_BYTES",
        default_value_t = DEFAULT_TXS_MAX_RESPONSE_BYTES
    )]
    txs_max_response_bytes: usize,
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_TXS_HOURLY_BYTES",
        default_value_t = DEFAULT_TXS_HOURLY_BYTES
    )]
    txs_hourly_bytes: u64,
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_TXS_DAILY_BYTES",
        default_value_t = DEFAULT_TXS_DAILY_BYTES
    )]
    txs_daily_bytes: u64,
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
    /// Materialize historical frozen Merkle paths from one validated PostgreSQL
    /// checkpoint and exit. This maintenance mode never starts HTTP, WebSocket,
    /// discovery, crank, signer, or persistence tasks, so it can run beside the
    /// existing primary while that primary keeps serving traffic. The target
    /// confirmed prefix/root are pinned once at job start; later chain appends
    /// are handled by the normal startup delta before cutover.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_FREEZE_ONLY",
        default_value_t = false,
        value_parser = parse_bool_flag
    )]
    freeze_only: bool,
    /// One-shot tip-snapshot bootstrap for `frozen_paths` (mainnet upgrade path).
    /// After warm-start / full rebuild succeeds, any confirmed cmx that still
    /// lacks a frozen record is assigned a witness pinned to the pool's current
    /// local confirmed root (must match on-chain `confirmedRoot` when counts
    /// agree). Already-frozen cmxs are left untouched. Opt-in: turn off after
    /// the archive is full (`count(frozen_paths) == confirmed_count`).
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_FREEZE_TIP_PATHS",
        default_value_t = false,
        value_parser = parse_bool_flag
    )]
    freeze_tip_paths: bool,
    /// Maximum confirmed leaves processed per frozen-path maintenance page.
    /// Memory stays bounded by this page and its de-duplicated witness nodes.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_FREEZE_PAGE_SIZE",
        default_value_t = DEFAULT_TIP_FREEZE_PAGE_SIZE
    )]
    freeze_page_size: usize,
    /// Rayon worker threads used only for frozen-path witness calculation.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_FREEZE_WORKERS",
        default_value_t = DEFAULT_TIP_FREEZE_WORKERS
    )]
    freeze_workers: usize,
    /// First block to scan when no checkpoint exists; resume never goes below this.
    #[arg(long, env = "PRIVACYBTC_START_BLOCK", default_value_t = 0)]
    start_block: u64,
    /// Number of blocks required before an event is ingested. `0` preserves the
    /// chain's `finalized` boundary; `1` accepts the current mined/latest block.
    /// Values above one scan through `latest - (confirmations - 1)`.
    #[arg(long, env = "PRIVACYBTC_INDEXER_CONFIRMATIONS", default_value_t = 0)]
    confirmations: u64,
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
    /// Transaction envelope used by the crank signer. `legacy` preserves the
    /// current Monad path; Ethereum deployments must explicitly select `eip1559`.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_CRANK_TX_TYPE",
        value_enum,
        default_value = "legacy"
    )]
    crank_tx_type: CrankTxType,
    /// Gas price in wei for legacy crank transactions. Default: 1 Gwei.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_GAS_PRICE",
        default_value_t = 1_000_000_000u64
    )]
    gas_price: u64,
    /// Priority fee for EIP-1559 crank transactions. Ignored in legacy mode.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_CRANK_MAX_PRIORITY_FEE_PER_GAS",
        default_value_t = 1_000_000_000u64
    )]
    crank_max_priority_fee_per_gas: u64,
    /// Hard maxFeePerGas ceiling for EIP-1559 crank transactions. Required and
    /// non-zero in eip1559 mode; a base-fee spike above it fails closed.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_CRANK_MAX_FEE_PER_GAS_CAP",
        default_value_t = 0u64
    )]
    crank_max_fee_per_gas_cap: u64,
    /// Durable single-signer transaction journal. Required for EIP-1559 mode:
    /// raw bytes are fsynced here before broadcast and replayed after restart.
    #[arg(long, env = "PRIVACYBTC_INDEXER_CRANK_TX_JOURNAL")]
    crank_tx_journal: Option<String>,
    /// Seconds before an unmined EIP-1559 crank transaction may be replaced.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_CRANK_REPLACEMENT_AFTER_SECS",
        default_value_t = 120u64
    )]
    crank_replacement_after_secs: u64,
    /// Maximum same-nonce EIP-1559 replacements retained in the durable journal.
    #[arg(
        long,
        env = "PRIVACYBTC_INDEXER_CRANK_MAX_REPLACEMENTS",
        default_value_t = 3u32
    )]
    crank_max_replacements: u32,
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
    /// Pools whose presence and serving readiness are required by `/healthz`.
    /// This is an availability assertion only and never grants admission.
    #[arg(long, env = "PRIVACYBTC_INDEXER_REQUIRED_POOLS", value_delimiter = ',')]
    required_pool: Vec<String>,
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

/// Compose may retain a key with an empty value when an inherited production
/// secret is deliberately cleared for a read-only process. Treat whitespace-only
/// values as absent while preserving the fail-closed handling of any real key.
fn nonempty_trimmed(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

// ─── Domain types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
struct ShieldAccounting {
    total_shielded_units: u128,
    total_shielded_wei: u128,
    total_unshielded_units: u128,
    total_unshielded_wei: u128,
    /// Protocol fees collected by this pool (shield + unshield), in note units / wei.
    /// Independent of the shielded-supply figures above — fees never enter custody accounting.
    #[serde(default)]
    total_fee_units: u128,
    #[serde(default)]
    total_fee_wei: u128,
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

/// Bounded overlap/reconnect dedup.  The finalized cursor is the durable proof
/// that older logs were processed; only a recent window is needed to absorb WS,
/// receipt-recovery, and catch-up overlap inside the current process lifetime.
#[derive(Default)]
struct RecentEventIds {
    order: VecDeque<String>,
    set: HashSet<String>,
}

impl RecentEventIds {
    fn contains(&self, event_id: &str) -> bool {
        self.set.contains(event_id)
    }

    fn insert(&mut self, event_id: String) -> bool {
        if !self.set.insert(event_id.clone()) {
            return false;
        }
        self.order.push_back(event_id);
        while self.order.len() > MAX_RECENT_EVENT_IDS {
            if let Some(expired) = self.order.pop_front() {
                self.set.remove(&expired);
            }
        }
        true
    }

    fn clear(&mut self) {
        self.order.clear();
        self.set.clear();
    }
}

/// One on-chain `RootUpdated` event waiting for the immediately-following
/// `NoteConfirmed` events from the same updateRoot/updateRoots transaction.
///
/// OrchardVerifier emits the batch seal first and the confirmed leaves second.
/// Keep the working frontier isolated until the whole segment validates so
/// `/root`, the crank, and durable checkpoints continue to expose the previous
/// complete on-chain boundary while the event stream is between those logs.
#[derive(Clone)]
struct PendingRootUpdate {
    transaction_hash: String,
    target_root: [u8; 32],
    from_count: u64,
    to_count: u64,
    batch_size: u32,
    frontier: CompactFrontier,
    /// Pre-segment frontier ommers, captured at `begin`. Together with
    /// `segment_nodes` they let the seal export every leaf's frozen witness
    /// without touching the (possibly lagging) node archive.
    begin_filled_be: Vec<[u8; 32]>,
    /// Confirmed leaves staged so far, in position order.
    segment_cmxs: Vec<[u8; 32]>,
    /// Complete nodes emitted by the staged appends.
    segment_nodes: HashMap<MerkleNodeKey, [u8; 32]>,
}

impl PendingRootUpdate {
    fn begin(
        confirmed_frontier: &CompactFrontier,
        confirmed_count: u64,
        tree_size: u64,
        transaction_hash: &str,
        target_root: [u8; 32],
        from_count: u64,
        to_count: u64,
        batch_size: u32,
    ) -> Result<Self> {
        let declared = to_count
            .checked_sub(from_count)
            .ok_or_else(|| anyhow!("RootUpdated count range is reversed"))?;
        if batch_size == 0
            || batch_size as usize > CMX_CONFIRM_MAX_BATCH
            || declared != u64::from(batch_size)
        {
            bail!(
                "RootUpdated batch/count mismatch: from={from_count}, to={to_count}, batch={batch_size}, max={CMX_CONFIRM_MAX_BATCH}"
            );
        }
        if confirmed_frontier.next_index() != confirmed_count || from_count != confirmed_count {
            bail!(
                "RootUpdated does not start at the compact confirmed frontier: from={from_count}, local_count={confirmed_count}, frontier_count={}",
                confirmed_frontier.next_index()
            );
        }
        if to_count > tree_size {
            bail!(
                "RootUpdated confirms leaves not yet ingested: to={to_count}, tree_size={tree_size}"
            );
        }
        Ok(Self {
            transaction_hash: normalize_hex_0x(transaction_hash),
            target_root,
            from_count,
            to_count,
            batch_size,
            frontier: confirmed_frontier.clone(),
            begin_filled_be: confirmed_frontier.filled_be(),
            segment_cmxs: Vec::with_capacity(batch_size as usize),
            segment_nodes: HashMap::new(),
        })
    }

    /// Append one NoteConfirmed leaf. The event repeats the segment's final
    /// root for every leaf, so only the last append may compare the computed
    /// frontier root with `target_root`.
    fn append_confirmation(
        &mut self,
        transaction_hash: &str,
        cmx: [u8; 32],
        event_root: [u8; 32],
        position: u64,
        tree_size: u64,
    ) -> Result<(Vec<MerkleNode>, bool)> {
        if !self
            .transaction_hash
            .eq_ignore_ascii_case(&normalize_hex_0x(transaction_hash))
        {
            bail!("NoteConfirmed transaction does not match the pending RootUpdated segment");
        }
        if event_root != self.target_root {
            bail!(
                "NoteConfirmed target root differs from RootUpdated: event={}, target={}",
                hex::encode(event_root),
                hex::encode(self.target_root)
            );
        }
        let expected_position = self.frontier.next_index();
        if position != expected_position || position >= self.to_count || position >= tree_size {
            bail!(
                "NoteConfirmed position is outside the pending RootUpdated segment: event={position}, expected={expected_position}, segment=[{}, {}), tree_size={tree_size}",
                self.from_count,
                self.to_count
            );
        }

        // Mutate the staged copy only after every precondition has passed. A
        // final-root mismatch leaves the committed frontier untouched.
        let mut next = self.frontier.clone();
        let nodes = next
            .append_be(cmx)
            .context("advance staged compact confirmed frontier")?;
        let complete = next.next_index() == self.to_count;
        if complete && next.root_be() != self.target_root {
            bail!(
                "RootUpdated final root mismatch after {} confirmations: local={}, event={}",
                self.batch_size,
                hex::encode(next.root_be()),
                hex::encode(self.target_root)
            );
        }
        self.frontier = next;
        self.segment_cmxs.push(cmx);
        for node in &nodes {
            self.segment_nodes.insert(node.key, node.hash_be);
        }
        Ok((nodes, complete))
    }

    /// Frozen witness per staged leaf, pinned to the sealed segment root.
    /// Only valid on a complete segment; any failure means the staged state is
    /// inconsistent and the caller must fail closed without writing paths.
    fn export_frozen_paths(&self) -> Result<Vec<FrozenPathRecord>> {
        let paths = export_segment_frozen_paths(
            &self.begin_filled_be,
            self.from_count,
            self.to_count,
            &self.segment_cmxs,
            &self.segment_nodes,
            self.target_root,
        )?;
        Ok(paths
            .into_iter()
            .map(|path| FrozenPathRecord {
                cmx: path.cmx_be,
                position: path.position,
                siblings: path.siblings,
                anchor_root: self.target_root,
            })
            .collect())
    }
}

/// One leaf's long-lived frozen authentication path, written exactly once when
/// its `RootUpdated` segment seals (docs/note-sync-indexer-frozen-merkle-path.md).
/// `anchor_root` is that segment's `newRoot` in EVM byte order. The record is
/// never rewritten by later appends and never deleted by reads; only a
/// canonical rebuild replaces the whole table.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct FrozenPathRecord {
    cmx: [u8; 32],
    position: u64,
    /// 32 little-endian 0x-hex siblings — the `/merkle_path` wire encoding.
    siblings: Vec<String>,
    anchor_root: [u8; 32],
}

fn ensure_root_update_boundary_sealed(state: &SharedState) -> Result<()> {
    if let Some(pending) = state.pending_root_update.as_ref() {
        bail!(
            "incomplete RootUpdated segment at replay boundary: confirmed=[{}, {}), staged_count={}, batch={}",
            pending.from_count,
            pending.to_count,
            pending.frontier.next_index(),
            pending.batch_size
        );
    }
    Ok(())
}

struct SharedState {
    next_block: u64,
    /// Last fully scanned Monad-finalized block and its canonical hash.
    ///
    /// Older checkpoints have neither field; startup performs a full finalized
    /// rebuild and writes them before incremental scanning resumes.
    last_finalized_block: Option<u64>,
    last_finalized_block_hash: Option<String>,
    latest_seq: u64,
    recent_event_ids: RecentEventIds,
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
    /// O(depth) frontier over all ingested leaves (pending included).
    tree_frontier: CompactFrontier,
    /// Batch-update watermark: number of leaves folded into the on-chain
    /// `confirmedRoot` (event-derived from `NoteConfirmed` positions and
    /// `RootUpdated.to_count`; rebuilt by the startup backfill replay).
    /// Leaves at positions `>= confirmed_count` are pending — excluded from
    /// `/root` anchors and `/merkle_path` witnesses.
    confirmed_count: u64,
    /// O(depth) frontier over the confirmed prefix. This is both the `/root`
    /// source and the crank's exact starting state.
    confirmed_frontier: CompactFrontier,
    /// Latest fully-sealed Orchard commitment tree root.
    /// Updated only after every NoteConfirmed in a RootUpdated segment validates.
    active_root: Option<[u8; 32]>,
    /// Transient, bounded (at most 8 leaves) RootUpdated segment. Never persisted.
    pending_root_update: Option<PendingRootUpdate>,
    /// Tx hashes submitted by the relayer but whose events haven't been received
    /// via WebSocket yet. On WS reconnect, these are recovered via receipt lookup.
    pending_tx_hashes: VecDeque<String>,
    /// Parsed `bundle()` calldata per tx (for OVK `out_ciphertext` + `cv_net_x`).
    bundle_out_cache: HashMap<String, HashMap<[u8; 32], BundleActionCiphertexts>>,
    bundle_out_order: VecDeque<String>,
    /// Bounded in-memory compliance summary. Historical deltas and the current
    /// leaf set live in PostgreSQL; no full compliance history is replayed into
    /// the process on restart.
    frozen_root_hex: String,
    frozen_count: u64,
    frozen_update_count: u64,
}

// ─── Signing (ETH transaction relay) ─────────────────────────────────────────

struct SignerConfig {
    signing_key: SigningKey,
    address: [u8; 20],
    chain_id: u64,
    gas_price: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum CrankTxType {
    Legacy,
    Eip1559,
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
    /// False while the opt-in legacy frozen-path bootstrap is still running.
    frozen_paths_ready: Arc<AtomicBool>,
    contract_address: String,
    /// Reviewed lower bound for this pool's deployment and event history.
    /// Admission and metadata lookups must never fall back to genesis-wide scans.
    start_block: u64,
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
    /// Ring-miss / recovery-source counters, shared with this pool's event loop.
    ring_recovery: Arc<RingRecoveryMetrics>,
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
    /// See [`Cli::freeze_tip_paths`].
    freeze_tip_paths: bool,
    freeze_config: TipFreezeConfig,
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
        if !self.shadow_mode {
            if let Err(error) = backend
                .upgrade_legacy_compact_checkpoint(contract_address, start_block)
                .await
            {
                eprintln!(
                    "[indexer][{}] compact checkpoint upgrade did not complete: {error:#}",
                    &contract_address[..10.min(contract_address.len())]
                );
            }
        }
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
        if ck.latest_seq == 0 && ck.tree_frontier.next_index() == 0 && ck.frozen_update_count == 0 {
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

        if ck.tree_frontier.next_index() > 0 {
            println!(
                "[indexer][{}] restored compact frontier with {} leaves through block {}",
                &contract_address[..10.min(contract_address.len())],
                ck.tree_frontier.next_index(),
                ck.next_block.saturating_sub(1)
            );
        }

        let shared = Arc::new(RwLock::new(SharedState {
            next_block: ck.next_block,
            last_finalized_block: ck.last_finalized_block,
            last_finalized_block_hash: ck.last_finalized_block_hash,
            latest_seq: ck.latest_seq,
            recent_event_ids: RecentEventIds::default(),
            shield_accounting: ck.shield_accounting,
            last_leaf_key: ck.last_leaf_key,
            warm_start_candidate: ck.warm_start_candidate,
            startup_source: "pending".to_string(),
            // Startup state is untrusted until the persisted finalized cursor
            // has been checked and the finalized replay completes.
            tree_out_of_order: true,
            batches: ck.batches,
            max_batches: self.max_batches,
            tree_frontier: ck.tree_frontier,
            confirmed_count: ck.confirmed_count,
            confirmed_frontier: ck.confirmed_frontier,
            active_root: ck.active_root,
            pending_root_update: None,
            pending_tx_hashes: ck.pending_tx_hashes,
            bundle_out_cache: HashMap::new(),
            bundle_out_order: VecDeque::new(),
            frozen_root_hex: ck.frozen_root_hex,
            frozen_count: ck.frozen_count,
            frozen_update_count: ck.frozen_update_count,
        }));

        let (batch_tx, _) = broadcast::channel::<BatchEnvelope>(256);
        let recover_trigger = Arc::new(tokio::sync::Notify::new());

        let ingest_lock = Arc::new(tokio::sync::Mutex::new(()));
        let ring_recovery = Arc::new(RingRecoveryMetrics::default());
        let frozen_paths_ready = Arc::new(AtomicBool::new(!self.freeze_tip_paths));
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
            freeze_tip_paths: self.freeze_tip_paths,
            freeze_config: self.freeze_config,
            frozen_paths_ready: Arc::clone(&frozen_paths_ready),
            ring_recovery: Arc::clone(&ring_recovery),
        };
        let addr_label = contract_address.to_string();
        tokio::spawn(async move {
            if let Err(e) = run_event_loop(poll_ctx).await {
                eprintln!("indexer event loop stopped [{addr_label}]: {e:#}");
            }
        });

        AppContext {
            state: shared,
            frozen_paths_ready,
            contract_address: contract_address.to_string(),
            start_block,
            persist,
            ingest_lock,
            batch_tx,
            recover_trigger,
            backend,
            shadow_mode: self.shadow_mode,
            ring_recovery,
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
    /// Explicit health-only membership assertion. These addresses do not grant
    /// admission and must still pass the normal static/factory trust checks.
    required_pools: HashSet<String>,
    registry_file: Option<String>,
    /// Global reviewed deployment floor used when a runtime registration omits
    /// its pool-specific start block.
    default_start_block: u64,
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
    /// Independent read token for Official Prover/Store/Relayer/LP Bot. It does
    /// not authorize admin writes or relayer notifications by itself.
    internal_read_token: Option<Arc<str>>,
    public_api_mode: PublicApiMode,
    egress_metrics: Arc<EgressMetrics>,
    merkle_path_semaphore: Arc<Semaphore>,
    merkle_path_max_response_bytes: usize,
    merkle_path_budget: Arc<Mutex<EgressBudget>>,
    txs_semaphore: Arc<Semaphore>,
    txs_max_response_bytes: usize,
    txs_budget: Arc<Mutex<EgressBudget>>,
    /// Bounds expensive runtime registration RPC work.
    write_semaphore: Arc<Semaphore>,
    /// Bounds archive reads and their JSON serialization. Historical catch-up
    /// used to be unbounded, so a handful of concurrent clients could each
    /// materialize the complete `notes` table and exhaust the process heap.
    history_read_semaphore: Arc<Semaphore>,
    /// Single-flight cache so Browser polling cannot cause repeated aggregate
    /// reads. PostgreSQL refreshes it from the compact one-row-per-tx index.
    system_stats_cache: Arc<Mutex<Option<(Instant, u64)>>>,
}

#[derive(Default)]
struct EgressMetrics {
    merkle_path_requests: AtomicU64,
    merkle_path_bytes: AtomicU64,
    merkle_path_2xx: AtomicU64,
    merkle_path_4xx: AtomicU64,
    merkle_path_5xx: AtomicU64,
    merkle_path_limited: AtomicU64,
    txs_requests: AtomicU64,
    txs_bytes: AtomicU64,
    txs_2xx: AtomicU64,
    txs_4xx: AtomicU64,
    txs_5xx: AtomicU64,
    txs_limited: AtomicU64,
    public_denied: AtomicU64,
}

#[derive(Debug)]
struct EgressBudget {
    hour_bucket: u64,
    day_bucket: u64,
    hour_bytes: u64,
    day_bytes: u64,
    max_hour_bytes: u64,
    max_day_bytes: u64,
}

impl EgressBudget {
    fn new(max_hour_bytes: u64, max_day_bytes: u64) -> Self {
        Self {
            hour_bucket: 0,
            day_bucket: 0,
            hour_bytes: 0,
            day_bytes: 0,
            max_hour_bytes,
            max_day_bytes,
        }
    }

    fn refresh(&mut self, now: u64) {
        let hour = now / 3_600;
        let day = now / 86_400;
        if self.hour_bucket != hour {
            self.hour_bucket = hour;
            self.hour_bytes = 0;
        }
        if self.day_bucket != day {
            self.day_bucket = day;
            self.day_bytes = 0;
        }
    }

    fn has_capacity(&mut self, now: u64) -> bool {
        self.refresh(now);
        self.hour_bytes < self.max_hour_bytes && self.day_bytes < self.max_day_bytes
    }

    fn try_consume(&mut self, now: u64, bytes: u64) -> bool {
        self.refresh(now);
        let Some(next_hour) = self.hour_bytes.checked_add(bytes) else {
            return false;
        };
        let Some(next_day) = self.day_bytes.checked_add(bytes) else {
            return false;
        };
        if next_hour > self.max_hour_bytes || next_day > self.max_day_bytes {
            return false;
        }
        self.hour_bytes = next_hour;
        self.day_bytes = next_day;
        true
    }
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct FactoryDiscoveredPool {
    pool: String,
    block: u64,
    factory: String,
    topic0: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingFactoryAdmission {
    discovered: FactoryDiscoveredPool,
    attempts: u64,
}

fn bind_factory_discovery_source(
    factory: &str,
    topic0: &str,
    pools: Vec<(String, u64)>,
) -> Vec<FactoryDiscoveredPool> {
    pools
        .into_iter()
        .map(|(pool, block)| FactoryDiscoveredPool {
            pool,
            block,
            factory: normalize_hex_0x(factory).to_lowercase(),
            topic0: normalize_hex_0x(topic0).to_lowercase(),
        })
        .collect()
}

fn factory_discovery_source_is_trusted(
    discovered: &FactoryDiscoveredPool,
    trusted_sources: &[(String, String)],
) -> bool {
    trusted_sources
        .iter()
        .any(|(candidate_factory, candidate_topic)| {
            candidate_factory.eq_ignore_ascii_case(&discovered.factory)
                && candidate_topic.eq_ignore_ascii_case(&discovered.topic0)
        })
}

fn queue_factory_discovery_range(
    pending: &mut Vec<PendingFactoryAdmission>,
    factory: &str,
    topic0: &str,
    pools: Vec<(String, u64)>,
    next_from: &mut u64,
    range_end: u64,
) {
    for discovered in bind_factory_discovery_source(factory, topic0, pools) {
        if pending.iter().any(|entry| {
            entry.discovered.pool.eq_ignore_ascii_case(&discovered.pool)
                && entry
                    .discovered
                    .factory
                    .eq_ignore_ascii_case(&discovered.factory)
                && entry
                    .discovered
                    .topic0
                    .eq_ignore_ascii_case(&discovered.topic0)
        }) {
            continue;
        }
        pending.push(PendingFactoryAdmission {
            discovered,
            attempts: 0,
        });
    }
    // Factory log retrieval, not admission, defines discovery progress. Every
    // canonical event above remains queued for retry after this cursor advances.
    *next_from = range_end.saturating_add(1);
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
        let start_block = effective_pool_start_block(start_block, self.default_start_block);
        let active = self.pools.read().await.contains_key(&address);
        let verified = self.verified_pools.read().await.contains(&address);
        if !persist && completed_admission_can_short_circuit(active, verified) {
            // This is only reachable after a trust-checked admission in this
            // process. Both maps are empty on startup, so restart still replays
            // provenance and runtime pins fail closed.
            return Ok(false);
        }
        if !self.verify_pool_admitted(&address, start_block).await? {
            return Err(anyhow!(
                "pool {address} is not from a trusted factory or explicit static allowlist"
            ));
        }
        self.add_pool(&address, start_block, persist).await
    }

    /// Admit a pool using the exact trusted factory event that discovery just
    /// fetched. Keeping that provenance prevents a Shield pool from first
    /// scanning an unrelated PERC20 factory all the way to the chain tip.
    async fn add_factory_discovered_pool(
        &self,
        discovered: &FactoryDiscoveredPool,
        persist: bool,
    ) -> Result<bool> {
        let address = normalize_hex_0x(&discovered.pool).to_lowercase();
        let factory = normalize_hex_0x(&discovered.factory).to_lowercase();
        let topic0 = normalize_hex_0x(&discovered.topic0).to_lowercase();
        let trusted_source =
            factory_discovery_source_is_trusted(discovered, &self.admission.discovery_sources());
        if !trusted_source {
            return Err(anyhow!(
                "pool {address} discovery source is not an explicitly trusted factory"
            ));
        }
        // Tail re-scans intentionally return already-admitted pools. Avoid
        // repeating codehash/beacon/protocol RPC checks for those entries; the
        // crank path independently revalidates trust before every signature.
        if self.pools.read().await.contains_key(&address) {
            if persist {
                self.persist_factory_discovery(discovered);
            }
            return Ok(false);
        }
        let start_block = effective_pool_start_block(discovered.block, self.default_start_block);
        let codehash = self.builder.rpc.runtime_codehash(&address).await?;
        if !self.admission.pool_codehashes.contains(&codehash) {
            return Err(anyhow!(
                "pool {address} has unapproved runtime codehash {codehash}"
            ));
        }
        if !self
            .builder
            .rpc
            .was_pool_deployed_by(&factory, &address, &topic0, start_block)
            .await?
        {
            return Err(anyhow!(
                "pool {address} no longer has its canonical trusted-factory deployment proof"
            ));
        }
        if !self
            .builder
            .rpc
            .pool_uses_factory_beacon(
                &factory,
                &address,
                &self.admission.implementation_codehashes,
            )
            .await?
        {
            return Err(anyhow!(
                "pool {address} is not bound to the trusted factory beacon/current implementation"
            ));
        }
        self.ensure_pool_protocol(&address).await?;
        self.verified_pools.write().await.insert(address.clone());
        self.verified_pool_provenance
            .write()
            .await
            .insert(address.clone(), PoolProvenance::Factory(factory));
        let added = self.add_pool(&address, start_block, false).await?;
        if persist {
            self.persist_factory_discovery(discovered);
        }
        Ok(added)
    }

    fn persist_factory_discovery(&self, discovered: &FactoryDiscoveredPool) {
        if let Some(path) = &self.registry_file {
            if let Err(e) = append_factory_pools_registry(path, discovered) {
                eprintln!("[indexer] failed to persist factory pool registry {path}: {e:#}");
            }
        }
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
    async fn verify_pool_admitted(&self, pool_lc: &str, start_block: u64) -> Result<bool> {
        if self.verified_pools.read().await.contains(pool_lc) {
            return Ok(true);
        }
        let start_block = effective_pool_start_block(start_block, self.default_start_block);
        if let Some(provenance) = self.resolve_pool_provenance(pool_lc, start_block).await? {
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
            None => {
                let start_block = self
                    .pools
                    .read()
                    .await
                    .get(pool_lc)
                    .map(|ctx| ctx.start_block)
                    .unwrap_or(self.default_start_block);
                match self.resolve_pool_provenance(pool_lc, start_block).await? {
                    Some(value) => value,
                    None => return Ok(false),
                }
            }
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

    async fn resolve_pool_provenance(
        &self,
        pool_lc: &str,
        start_block: u64,
    ) -> Result<Option<PoolProvenance>> {
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
                .was_pool_deployed_by(&factory, pool_lc, &topic0, start_block)
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
        let start_block = self
            .pools
            .read()
            .await
            .get(pool_lc)
            .map(|ctx| ctx.start_block)
            .unwrap_or(self.default_start_block);
        match self
            .builder
            .rpc
            .fetch_pool_metadata(pool_lc, start_block)
            .await
        {
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

fn completed_admission_can_short_circuit(active: bool, verified: bool) -> bool {
    active && verified
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    factory: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    topic0: Option<String>,
}

fn factory_discovery_from_registry_entry(
    entry: &PoolRegistryEntry,
    start_block: u64,
) -> Result<Option<FactoryDiscoveredPool>> {
    match (&entry.factory, &entry.topic0) {
        (None, None) => Ok(None),
        (Some(factory), Some(topic0)) => {
            if parse_address20(&entry.address).is_none() || parse_address20(factory).is_none() {
                return Err(anyhow!(
                    "factory-provenance registry entry has an invalid address"
                ));
            }
            let topic = strip_0x(topic0);
            if topic.len() != 64 || !topic.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(anyhow!(
                    "factory-provenance registry entry has an invalid topic0"
                ));
            }
            Ok(Some(FactoryDiscoveredPool {
                pool: normalize_hex_0x(&entry.address).to_lowercase(),
                block: start_block,
                factory: normalize_hex_0x(factory).to_lowercase(),
                topic0: normalize_hex_0x(topic0).to_lowercase(),
            }))
        }
        _ => Err(anyhow!(
            "factory-provenance registry entry requires both factory and topic0"
        )),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingPoolAdmission {
    address: String,
    start_block: u64,
    source: &'static str,
}

fn queue_pending_pool_admission(
    pending: &mut Vec<PendingPoolAdmission>,
    address: &str,
    start_block: u64,
    source: &'static str,
) {
    let address = normalize_hex_0x(address).to_lowercase();
    if pending.iter().any(|entry| entry.address == address) {
        return;
    }
    pending.push(PendingPoolAdmission {
        address,
        start_block,
        source,
    });
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
    append_pools_registry_entry(path, address, start_block, None)
}

fn append_factory_pools_registry(path: &str, discovered: &FactoryDiscoveredPool) -> Result<()> {
    append_pools_registry_entry(
        path,
        &discovered.pool,
        discovered.block,
        Some((&discovered.factory, &discovered.topic0)),
    )
}

fn append_pools_registry_entry(
    path: &str,
    address: &str,
    start_block: u64,
    provenance: Option<(&str, &str)>,
) -> Result<()> {
    let mut reg = PoolsRegistryFile {
        pools: load_pools_registry(path),
    };
    let norm = normalize_hex_0x(address).to_lowercase();
    let provenance = provenance.map(|(factory, topic0)| {
        (
            normalize_hex_0x(factory).to_lowercase(),
            normalize_hex_0x(topic0).to_lowercase(),
        )
    });
    let mut changed = false;
    if let Some(entry) = reg
        .pools
        .iter_mut()
        .find(|e| normalize_hex_0x(&e.address).eq_ignore_ascii_case(&norm))
    {
        if entry.address != norm {
            entry.address = norm.clone();
            changed = true;
        }
        if start_block != 0 && entry.start_block != start_block {
            entry.start_block = start_block;
            changed = true;
        }
        if let Some((factory, topic0)) = &provenance {
            if entry.factory.as_ref() != Some(factory) {
                entry.factory = Some(factory.clone());
                changed = true;
            }
            if entry.topic0.as_ref() != Some(topic0) {
                entry.topic0 = Some(topic0.clone());
                changed = true;
            }
        }
    } else {
        let (factory, topic0) = provenance
            .map(|(factory, topic0)| (Some(factory), Some(topic0)))
            .unwrap_or((None, None));
        reg.pools.push(PoolRegistryEntry {
            address: norm,
            start_block,
            factory,
            topic0,
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

const DEFAULT_BATCH_PAGE_LIMIT: usize = 1_000;
const MAX_BATCH_PAGE_LIMIT: usize = 2_000;
const HISTORY_READ_CONCURRENCY: usize = 4;
const MAX_TX_HISTORY_NOTE_ROWS: usize = 2_000;
const SYSTEM_STATS_CACHE_TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Deserialize)]
struct BatchesPageQuery {
    after_seq: Option<u64>,
    /// Stable high-watermark for this catch-up pass. Omit on the first request;
    /// reuse the returned target_seq on every subsequent page.
    to_seq: Option<u64>,
    /// Soft envelope limit. A page is extended when necessary so envelopes that
    /// share one seq are never split across pages.
    limit: Option<usize>,
    /// Contract address of the pool to query. Omit to use the primary pool.
    pool: Option<String>,
}

#[derive(Debug, Serialize)]
struct BatchesPageResponse {
    envelopes: Vec<BatchEnvelope>,
    /// Exclusive cursor for the next request. This can advance across valid
    /// archive gaps when the server has completely inspected the target window.
    next_after_seq: u64,
    scanned_to_seq: u64,
    target_seq: u64,
    latest_seq: u64,
    has_more: bool,
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
    /// True only after the optional legacy frozen-path bootstrap has completed.
    frozen_paths_ready: bool,
    /// `pending`, `checkpoint`, `full_replay`, or a fail-closed rejection state.
    startup_source: String,
    shadow_mode: bool,
    last_finalized_block: Option<u64>,
    last_finalized_block_hash: Option<String>,
    latest_seq: u64,
    cached_batches: usize,
    confirmed_notes: u64,
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
    /// Re-emission lookups the `batches` ring could not answer, and where the
    /// payload came from instead. A steadily rising `ring_misses` means
    /// `--max-batches-in-memory` no longer covers the lag between a note's
    /// `NoteAdded` and its `NoteConfirmed`; `ring_recovery_unrecovered` rising
    /// means the archive is incomplete and those notes were never republished.
    ring_misses: u64,
    ring_recovery_from_buffer: u64,
    ring_recovery_from_archive: u64,
    ring_recovery_unrecovered: u64,
}

#[derive(Debug, Serialize)]
struct ShieldStatsResponse {
    pools: Vec<ShieldPoolStats>,
}

/// `ERC20Shield.FeeCharged(address indexed payer, uint256 feeUnits, uint256 feeAmount, address collector)`
///
/// Emitted by `shield` and `unshield` when a protocol fee is deducted. Declared locally rather
/// than pulled from `privacy-core`: the event ships with the fee release and the core crate is
/// pinned to an earlier rev.
///
/// NOTE on the surrounding accounting: `Shielded` carries the NET units credited to the note and
/// `Unshielded` the GROSS units that left the shielded supply, so `current_shielded_*` continues
/// to track `shieldedSupply` exactly. The fee is a separate flow — never add it back in.
fn fee_charged_topic0_hex() -> String {
    format!(
        "0x{}",
        hex::encode(Keccak256::digest(
            b"FeeCharged(address,uint256,uint256,address)"
        ))
    )
}

struct DecodedFeeCharged {
    fee_units: u128,
    fee_wei: u128,
}

/// data = feeUnits(32) || feeAmount(32) || collector(32); `payer` is indexed (topic1).
fn decode_fee_charged_log(data: &str) -> Result<DecodedFeeCharged> {
    let raw = hex::decode(strip_0x(data)).context("FeeCharged data is not hex")?;
    if raw.len() < 96 {
        return Err(anyhow!(
            "FeeCharged data too short: {} bytes (expected >= 96)",
            raw.len()
        ));
    }
    // u128 is enough: note units are circuit-bounded to 64 bits and wei fits comfortably.
    let be_u128 = |w: &[u8]| -> u128 {
        let mut out = 0u128;
        for b in &w[16..32] {
            out = (out << 8) | u128::from(*b);
        }
        out
    };
    Ok(DecodedFeeCharged {
        fee_units: be_u128(&raw[0..32]),
        fee_wei: be_u128(&raw[32..64]),
    })
}

#[derive(Debug, Serialize)]
struct SystemStatsResponse {
    total_transactions: u64,
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
    total_fee_units: String,
    total_fee_wei: String,
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
    let signer_key = nonempty_trimmed(cli.signer_key.as_deref());
    let maintenance_modes =
        usize::from(cli.migrate_only) + usize::from(cli.freeze_only) + usize::from(cli.shadow_mode);
    if maintenance_modes > 1 {
        return Err(anyhow!(
            "migrate-only, freeze-only and shadow mode are mutually exclusive"
        ));
    }
    if (cli.migrate_only || cli.freeze_only) && cli.database_url.is_none() {
        return Err(anyhow!(
            "migrate-only and freeze-only require PRIVACYBTC_INDEXER_DATABASE_URL"
        ));
    }
    if !(1..=MAX_TIP_FREEZE_PAGE_SIZE).contains(&cli.freeze_page_size) {
        return Err(anyhow!(
            "PRIVACYBTC_INDEXER_FREEZE_PAGE_SIZE must be 1..={MAX_TIP_FREEZE_PAGE_SIZE}"
        ));
    }
    if !(1..=MAX_TIP_FREEZE_WORKERS).contains(&cli.freeze_workers) {
        return Err(anyhow!(
            "PRIVACYBTC_INDEXER_FREEZE_WORKERS must be 1..={MAX_TIP_FREEZE_WORKERS}"
        ));
    }
    if cli.freeze_only {
        if cli.crank || signer_key.is_some() {
            return Err(anyhow!(
                "freeze-only forbids crank and signer configuration"
            ));
        }
        if cli.allow_runtime_pool_registration || cli.discover_pools {
            return Err(anyhow!(
                "freeze-only forbids runtime pool registration and discovery"
            ));
        }
        if cli.freeze_tip_paths {
            return Err(anyhow!(
                "freeze-only already performs the tip freeze; do not also set freeze-tip-paths"
            ));
        }
    }
    if cli.shadow_mode {
        if cli.database_url.is_none() {
            return Err(anyhow!(
                "shadow mode requires PRIVACYBTC_INDEXER_DATABASE_URL"
            ));
        }
        if cli.crank || signer_key.is_some() {
            return Err(anyhow!(
                "shadow mode forbids crank and signer configuration"
            ));
        }
        if cli.allow_runtime_pool_registration {
            return Err(anyhow!("shadow mode forbids runtime pool registration"));
        }
    }

    let signer = if cli.migrate_only || cli.freeze_only {
        None
    } else {
        match signer_key {
            Some(key) => {
                let cfg = SignerConfig::from_hex_key(key, cli.chain_id, cli.gas_price)?;
                let addr_hex = hex::encode(cfg.address);
                println!("indexer signer account: 0x{addr_hex}");
                Some(Arc::new(cfg))
            }
            None => None,
        }
    };

    let rpc = RpcClient::new(cli.rpc_url.clone(), cli.confirmations);
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
    if cli.freeze_only {
        let pool = pg_pool
            .as_ref()
            .context("freeze-only requires PostgreSQL")?;
        let mut addresses = cli.contract_address.clone();
        if let Some(path) = &cli.pools_registry {
            addresses.extend(
                load_pools_registry(path)
                    .into_iter()
                    .map(|entry| entry.address),
            );
        }
        let mut seen = HashSet::new();
        addresses.retain(|address| seen.insert(normalize_hex_0x(address).to_lowercase()));
        if addresses.is_empty() {
            return Err(anyhow!(
                "freeze-only requires at least one --contract-address or persisted pools registry entry"
            ));
        }
        let reports = run_freeze_only(
            &rpc,
            pool,
            &addresses,
            cli.start_block,
            TipFreezeConfig {
                page_size: cli.freeze_page_size,
                workers: cli.freeze_workers,
            },
        )
        .await?;
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "mode": "freeze-only",
                "result": "pass",
                "pools": reports,
            }))?
        );
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
        freeze_tip_paths: cli.freeze_tip_paths,
        freeze_config: TipFreezeConfig {
            page_size: cli.freeze_page_size,
            workers: cli.freeze_workers,
        },
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
        if cli.crank_tx_type == CrankTxType::Eip1559 {
            if cli.crank_max_priority_fee_per_gas == 0 {
                return Err(anyhow!(
                    "EIP-1559 crank requires PRIVACYBTC_INDEXER_CRANK_MAX_PRIORITY_FEE_PER_GAS > 0"
                ));
            }
            if cli.crank_max_fee_per_gas_cap == 0 {
                return Err(anyhow!(
                    "EIP-1559 crank requires PRIVACYBTC_INDEXER_CRANK_MAX_FEE_PER_GAS_CAP > 0"
                ));
            }
            if cli.crank_max_priority_fee_per_gas > cli.crank_max_fee_per_gas_cap {
                return Err(anyhow!("EIP-1559 crank priority fee exceeds max fee cap"));
            }
            let journal = cli
                .crank_tx_journal
                .as_deref()
                .filter(|path| !path.trim().is_empty())
                .ok_or_else(|| {
                    anyhow!("EIP-1559 crank requires PRIVACYBTC_INDEXER_CRANK_TX_JOURNAL")
                })?;
            validate_crank_journal_parent(journal)?;
            if !(30..=3_600).contains(&cli.crank_replacement_after_secs) {
                return Err(anyhow!(
                    "PRIVACYBTC_INDEXER_CRANK_REPLACEMENT_AFTER_SECS must be in 30..=3600"
                ));
            }
            if cli.crank_max_replacements > 10 {
                return Err(anyhow!(
                    "PRIVACYBTC_INDEXER_CRANK_MAX_REPLACEMENTS must be <= 10"
                ));
            }
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
    let internal_read_token = std::env::var("PRIVACYBTC_INDEXER_INTERNAL_READ_TOKEN")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .map(|value| {
            if value.len() < 32 {
                Err(anyhow!(
                    "PRIVACYBTC_INDEXER_INTERNAL_READ_TOKEN must contain at least 32 characters"
                ))
            } else {
                Ok(Arc::<str>::from(value))
            }
        })
        .transpose()?;
    if cli.public_api_mode == PublicApiMode::Minimal && internal_read_token.is_none() {
        return Err(anyhow!(
            "minimal public API mode requires PRIVACYBTC_INDEXER_INTERNAL_READ_TOKEN"
        ));
    }
    if cli.merkle_path_max_concurrency == 0
        || cli.merkle_path_max_response_bytes == 0
        || cli.merkle_path_hourly_bytes == 0
        || cli.merkle_path_daily_bytes == 0
        || cli.merkle_path_daily_bytes < cli.merkle_path_hourly_bytes
    {
        return Err(anyhow!(
            "Merkle path egress limits must be positive and daily bytes must be >= hourly bytes"
        ));
    }
    if cli.txs_max_concurrency == 0
        || cli.txs_max_response_bytes == 0
        || cli.txs_hourly_bytes == 0
        || cli.txs_daily_bytes == 0
        || cli.txs_daily_bytes < cli.txs_hourly_bytes
    {
        return Err(anyhow!(
            "Transaction-list egress limits must be positive and daily bytes must be >= hourly bytes"
        ));
    }
    let registry = PoolRegistry {
        pools: Arc::new(RwLock::new(HashMap::new())),
        primary: Arc::new(RwLock::new(None)),
        builder,
        admission,
        add_lock: Arc::new(tokio::sync::Mutex::new(())),
        max_pools: cli.max_pools,
        allow_runtime_pool_registration: cli.allow_runtime_pool_registration,
        require_pool: cli.shadow_mode
            || cli.discover_pools
            || !cli.contract_address.is_empty()
            || !cli.required_pool.is_empty(),
        required_pools: parse_address_set("PRIVACYBTC_INDEXER_REQUIRED_POOLS", &cli.required_pool)?,
        registry_file: cli.pools_registry.clone(),
        default_start_block: cli.start_block,
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
        internal_read_token,
        public_api_mode: cli.public_api_mode,
        egress_metrics: Arc::new(EgressMetrics::default()),
        merkle_path_semaphore: Arc::new(Semaphore::new(cli.merkle_path_max_concurrency)),
        merkle_path_max_response_bytes: cli.merkle_path_max_response_bytes,
        merkle_path_budget: Arc::new(Mutex::new(EgressBudget::new(
            cli.merkle_path_hourly_bytes,
            cli.merkle_path_daily_bytes,
        ))),
        txs_semaphore: Arc::new(Semaphore::new(cli.txs_max_concurrency)),
        txs_max_response_bytes: cli.txs_max_response_bytes,
        txs_budget: Arc::new(Mutex::new(EgressBudget::new(
            cli.txs_hourly_bytes,
            cli.txs_daily_bytes,
        ))),
        write_semaphore: Arc::new(Semaphore::new(2)),
        history_read_semaphore: Arc::new(Semaphore::new(HISTORY_READ_CONCURRENCY)),
        system_stats_cache: Arc::new(Mutex::new(None)),
    };
    registry.validate_trust_roots().await?;

    let mut pending_pool_admissions = Vec::new();
    let mut pending_factory_admissions = Vec::new();

    // 1) CLI pools (the first one becomes the default query target).
    for raw_addr in &cli.contract_address {
        if let Err(e) = registry
            .add_admitted_pool(raw_addr, cli.start_block, false)
            .await
        {
            eprintln!("[indexer] add CLI pool {raw_addr} failed: {e:#}");
            queue_pending_pool_admission(
                &mut pending_pool_admissions,
                raw_addr,
                cli.start_block,
                "cli",
            );
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
            match factory_discovery_from_registry_entry(&entry, sb) {
                Ok(Some(discovered)) => {
                    if let Err(e) = registry
                        .add_factory_discovered_pool(&discovered, false)
                        .await
                    {
                        eprintln!(
                            "[indexer] re-add factory registry pool {} failed: {e:#}",
                            entry.address
                        );
                        pending_factory_admissions.push(PendingFactoryAdmission {
                            discovered,
                            attempts: 0,
                        });
                    }
                }
                Ok(None) => {
                    if let Err(e) = registry.add_admitted_pool(&entry.address, sb, false).await {
                        eprintln!(
                            "[indexer] re-add registry pool {} failed: {e:#}",
                            entry.address
                        );
                        queue_pending_pool_admission(
                            &mut pending_pool_admissions,
                            &entry.address,
                            sb,
                            "registry",
                        );
                    }
                }
                Err(e) => eprintln!(
                    "[indexer] reject malformed registry pool {} provenance: {e:#}",
                    entry.address
                ),
            }
        }
        println!("[indexer] pools registry: {path}");
    }
    if !pending_pool_admissions.is_empty() {
        tokio::spawn(pool_admission_retry_task(
            registry.clone(),
            pending_pool_admissions,
            cli.discover_poll_secs,
        ));
    }
    if !pending_factory_admissions.is_empty() {
        tokio::spawn(factory_admission_retry_task(
            registry.clone(),
            pending_factory_admissions,
            cli.discover_poll_secs,
        ));
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
                        tx_type: cli.crank_tx_type,
                        max_priority_fee_per_gas: cli.crank_max_priority_fee_per_gas,
                        max_fee_per_gas_cap: cli.crank_max_fee_per_gas_cap,
                        tx_journal: cli.crank_tx_journal.clone(),
                        replacement_after_secs: cli.crank_replacement_after_secs,
                        max_replacements: cli.crank_max_replacements,
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
        .route("/batches/page", get(get_batches_page))
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
        .route("/stats", get(get_system_stats))
        .route("/shield/stats", get(get_shield_stats))
        .route("/frozen_root", get(get_frozen_root))
        .route("/frozen_updates", get(get_frozen_updates))
        .route("/frozen_leaves", get(get_frozen_leaves))
        .route("/internal/egress_metrics", get(get_egress_metrics))
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

async fn pool_admission_retry_task(
    registry: PoolRegistry,
    mut pending: Vec<PendingPoolAdmission>,
    poll_secs: u64,
) {
    let mut attempt = 0_u64;
    while !pending.is_empty() {
        tokio::time::sleep(Duration::from_secs(poll_secs.max(1))).await;
        attempt = attempt.saturating_add(1);
        let mut remaining = Vec::new();
        for request in pending {
            match registry
                .add_admitted_pool(&request.address, request.start_block, false)
                .await
            {
                Ok(_) => println!(
                    "[indexer] recovered {} pool admission {} after {} retries",
                    request.source, request.address, attempt
                ),
                Err(_) => {
                    // Keep retry logs bounded and never include provider URLs or
                    // nested RPC errors. The original startup error is logged
                    // once with the RPC client's credential-safe endpoint label.
                    if attempt == 1 || attempt % 10 == 0 {
                        eprintln!(
                            "[indexer] {} pool admission {} still pending (retry {})",
                            request.source, request.address, attempt
                        );
                    }
                    remaining.push(request);
                }
            }
        }
        pending = remaining;
    }
}

fn next_factory_discovery_from(start_block: u64, head: u64, scan_cursor: u64) -> u64 {
    if scan_cursor <= head {
        return scan_cursor;
    }
    head.saturating_sub(FACTORY_DISCOVERY_RESCAN_BLOCKS.saturating_sub(1))
        .max(start_block)
}

/// Background task: poll deployment events emitted by explicitly trusted factories.
/// Re-scans from `start_block` on boot; `add_pool` is idempotent so already-known
/// pools are skipped. Each trusted factory has an independent cursor. Canonical
/// events are retained in a retry queue before that source advances, so one bad
/// pool or one failing factory cannot starve later pools or unrelated sources.
async fn pool_discovery_task(
    reg: PoolRegistry,
    rpc: RpcClient,
    mut sources: Vec<(String, String)>,
    start_block: u64,
    poll_secs: u64,
) {
    // HashSet-derived trust roots otherwise make catch-up order nondeterministic.
    // Sorting plus one range per source per round prevents a long issuer-factory
    // history from starving a later-deployed Shield factory.
    sources.sort();
    let mut cursors = vec![start_block; sources.len()];
    let mut pending_admissions = Vec::<PendingFactoryAdmission>::new();
    let retry_interval = Duration::from_secs(poll_secs.max(1));
    let mut last_pending_retry = Instant::now();
    loop {
        if !pending_admissions.is_empty() {
            pending_admissions =
                attempt_factory_admissions(&reg, std::mem::take(&mut pending_admissions)).await;
            last_pending_retry = Instant::now();
        }
        if let Ok((head, _)) = rpc.confirmation_head().await {
            for cursor in &mut cursors {
                *cursor = next_factory_discovery_from(start_block, head, *cursor);
            }
            let mut blocked_sources = vec![false; sources.len()];
            loop {
                let mut scanned_any = false;
                for (source_index, (factory, topic0)) in sources.iter().enumerate() {
                    let lo = cursors[source_index];
                    if blocked_sources[source_index] || lo > head {
                        continue;
                    }
                    scanned_any = true;
                    let hi = getlogs_window_end(lo, head, rpc.getlogs_span());
                    match rpc
                        .fetch_factory_deployed_pools(lo, hi, factory, topic0)
                        .await
                    {
                        Ok(pools) => {
                            let prior_pending = pending_admissions.len();
                            queue_factory_discovery_range(
                                &mut pending_admissions,
                                factory,
                                topic0,
                                pools,
                                &mut cursors[source_index],
                                hi,
                            );
                            // Admit only this range's new events immediately. An
                            // invalid event remains queued, but later valid events
                            // in the same range are still attempted in this pass.
                            let newly_discovered = pending_admissions.split_off(prior_pending);
                            let failed = attempt_factory_admissions(&reg, newly_discovered).await;
                            pending_admissions.extend(failed);
                        }
                        Err(e) if hi > lo && is_getlogs_range_error(&e) => {
                            // Window too large for this provider: shrink and retry
                            // the same source offset in the next round.
                            rpc.shrink_getlogs_span(hi - lo + 1);
                        }
                        Err(e) => {
                            eprintln!(
                                "[indexer] discovery getLogs factory {factory} [{lo},{hi}] failed: {e:#}"
                            );
                            blocked_sources[source_index] = true;
                        }
                    }
                }
                if last_pending_retry.elapsed() >= retry_interval && !pending_admissions.is_empty()
                {
                    pending_admissions =
                        attempt_factory_admissions(&reg, std::mem::take(&mut pending_admissions))
                            .await;
                    last_pending_retry = Instant::now();
                }
                if !scanned_any {
                    break;
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(poll_secs.max(1))).await;
    }
}

async fn attempt_factory_admissions(
    reg: &PoolRegistry,
    requests: Vec<PendingFactoryAdmission>,
) -> Vec<PendingFactoryAdmission> {
    let mut remaining = Vec::new();
    for mut request in requests {
        match reg
            .add_factory_discovered_pool(&request.discovered, true)
            .await
        {
            Ok(true) => println!(
                "[indexer] auto-discovered pool {} (block {})",
                request.discovered.pool, request.discovered.block
            ),
            Ok(false) => {}
            Err(e) => {
                request.attempts = request.attempts.saturating_add(1);
                if request.attempts == 1 {
                    eprintln!(
                        "[indexer] auto-discover admission {} failed; retained for retry: {e:#}",
                        request.discovered.pool
                    );
                } else if request.attempts % 10 == 0 {
                    eprintln!(
                        "[indexer] auto-discover admission {} still pending (retry {})",
                        request.discovered.pool, request.attempts
                    );
                }
                remaining.push(request);
            }
        }
    }
    remaining
}

async fn factory_admission_retry_task(
    reg: PoolRegistry,
    mut pending: Vec<PendingFactoryAdmission>,
    poll_secs: u64,
) {
    while !pending.is_empty() {
        tokio::time::sleep(Duration::from_secs(poll_secs.max(1))).await;
        pending = attempt_factory_admissions(&reg, pending).await;
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
    tx_type: CrankTxType,
    max_priority_fee_per_gas: u64,
    max_fee_per_gas_cap: u64,
    tx_journal: Option<String>,
    replacement_after_secs: u64,
    max_replacements: u32,
    allowed_pools: HashSet<String>,
    max_tx_per_hour: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct CrankTxAttempt {
    tx_hash: String,
    raw_tx_hex: String,
    max_priority_fee_per_gas: u128,
    max_fee_per_gas: u128,
    prepared_at: u64,
    broadcast_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct CrankTxJournal {
    schema: String,
    chain_id: u64,
    signer: String,
    pool: String,
    method: String,
    nonce: u64,
    gas_limit: u64,
    calldata_hex: String,
    attempts: Vec<CrankTxAttempt>,
}

impl CrankTxJournal {
    const SCHEMA: &'static str = "privacy-indexer-crank-tx/v1";

    fn load(path: &str, chain_id: u64, signer: &str) -> Result<Option<Self>> {
        validate_crank_journal_parent(path)?;
        let raw = match std::fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("read crank journal {path}")),
        };
        let journal: Self =
            serde_json::from_str(&raw).with_context(|| format!("decode crank journal {path}"))?;
        if journal.schema != Self::SCHEMA {
            return Err(anyhow!(
                "unsupported crank journal schema {}",
                journal.schema
            ));
        }
        if journal.chain_id != chain_id || !journal.signer.eq_ignore_ascii_case(signer) {
            return Err(anyhow!(
                "crank journal belongs to chain {} signer {}, expected chain {chain_id} signer {signer}",
                journal.chain_id,
                journal.signer
            ));
        }
        if journal.attempts.is_empty() {
            return Err(anyhow!("crank journal has no signed attempts"));
        }
        for attempt in &journal.attempts {
            let raw_tx = hex::decode(strip_0x(&attempt.raw_tx_hex))
                .context("crank journal raw transaction is not hex")?;
            let expected = raw_tx_hash(&raw_tx);
            if !expected.eq_ignore_ascii_case(&attempt.tx_hash) {
                return Err(anyhow!("crank journal raw transaction hash mismatch"));
            }
        }
        Ok(Some(journal))
    }

    fn save(&self, path: &str) -> Result<()> {
        let parent = validate_crank_journal_parent(path)?;
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let tmp = parent.join(format!(
            ".{}.{}.{}.tmp",
            Path::new(path)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("crank-tx"),
            std::process::id(),
            unique
        ));
        let bytes = serde_json::to_vec(self).context("serialize crank transaction journal")?;
        {
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&tmp)
                .with_context(|| format!("create crank journal temp {}", tmp.display()))?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp, path).with_context(|| format!("replace crank journal {path}"))?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }

    fn clear(path: &str) -> Result<()> {
        match std::fs::remove_file(path) {
            Ok(()) => {
                std::fs::File::open(validate_crank_journal_parent(path)?)?.sync_all()?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| format!("remove crank journal {path}")),
        }
    }
}

fn validate_crank_journal_parent(path: &str) -> Result<&Path> {
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err(anyhow!("crank transaction journal path must be absolute"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("crank transaction journal has no parent"))?;
    let metadata = std::fs::symlink_metadata(parent)
        .with_context(|| format!("stat crank journal parent {}", parent.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(anyhow!(
            "crank transaction journal parent must be a real directory"
        ));
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(anyhow!("crank transaction journal must not be a symlink"));
        }
        Ok(metadata) if !metadata.is_file() => {
            return Err(anyhow!("crank transaction journal must be a regular file"));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("stat crank transaction journal"),
    }
    Ok(parent)
}

fn raw_tx_hash(raw_tx: &[u8]) -> String {
    format!("0x{}", hex::encode(Keccak256::digest(raw_tx)))
}

fn bump_eip1559_fee(value: u128) -> u128 {
    value.saturating_add((value / 8).max(1))
}

fn broadcasted_crank_attempts(journal: &CrankTxJournal) -> impl Iterator<Item = &CrankTxAttempt> {
    journal
        .attempts
        .iter()
        .filter(|attempt| attempt.broadcast_at.is_some())
}

fn validate_crank_journal_signed_payloads(
    journal: &CrankTxJournal,
    signing_key: &SigningKey,
) -> Result<()> {
    let calldata = hex::decode(strip_0x(&journal.calldata_hex))
        .context("crank journal calldata is not hex")?;
    for attempt in &journal.attempts {
        let expected = build_and_sign_eip1559_tx(
            journal.nonce,
            attempt.max_priority_fee_per_gas,
            attempt.max_fee_per_gas,
            journal.gas_limit,
            &journal.pool,
            0,
            &calldata,
            journal.chain_id,
            signing_key,
        )?;
        let persisted = hex::decode(strip_0x(&attempt.raw_tx_hex))
            .context("crank journal raw transaction is not hex")?;
        if persisted != expected {
            return Err(anyhow!(
                "crank journal signed payload does not match its durable transaction fields"
            ));
        }
    }
    Ok(())
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
    let mut frontiers: HashMap<String, CompactFrontier> = HashMap::new();
    let mut tx_budget = HourlyTxBudget::new(cfg.max_tx_per_hour);
    let signer_hex = format!("0x{}", hex::encode(cfg.signer.address));

    println!(
        "[crank] root crank ON (prover={}, interval={}s, max_proofs_per_tx={}, max_leaves_per_tx={}, max_tx_per_hour={}, account=0x{})",
        cfg.prover_url,
        cfg.interval_secs,
        cfg.max_proofs_per_tx,
        CMX_CONFIRM_MAX_BATCH * cfg.max_proofs_per_tx,
        cfg.max_tx_per_hour,
        hex::encode(cfg.signer.address)
    );

    // EIP-1559 mode is a single durable signer lane. A crash may occur after
    // fsync but before broadcast, or after broadcast but before the receipt was
    // persisted. Resolve that exact signed transaction (and any same-nonce
    // replacements) before reading/proving new work or allocating another nonce.
    if cfg.tx_type == CrankTxType::Eip1559 {
        if let Some(path) = cfg.tx_journal.as_deref() {
            loop {
                match CrankTxJournal::load(path, cfg.signer.chain_id, &signer_hex) {
                    Ok(None) => break,
                    Ok(Some(journal)) => {
                        eprintln!(
                            "[crank] recovering durable transaction nonce={} pool={} attempts={}",
                            journal.nonce,
                            journal.pool,
                            journal.attempts.len()
                        );
                        match drive_crank_journal(&rpc, &cfg, &mut tx_budget, journal).await {
                            Ok(ok) => {
                                println!(
                                    "[crank] recovered transaction reached terminal status={}",
                                    if ok { "confirmed" } else { "reverted" }
                                );
                                break;
                            }
                            Err(error) => {
                                eprintln!("[crank] durable transaction recovery paused: {error:#}");
                                tokio::time::sleep(Duration::from_secs(cfg.interval_secs.max(1)))
                                    .await;
                            }
                        }
                    }
                    Err(error) => {
                        // A corrupt or foreign journal is an operator-repair
                        // condition. Never delete it or allocate a new nonce.
                        eprintln!("[crank] durable transaction journal rejected: {error:#}");
                        tokio::time::sleep(Duration::from_secs(cfg.interval_secs.max(1))).await;
                    }
                }
            }
        }
    }

    loop {
        // A journal can be created successfully and then fail before the first broadcast
        // (for example, a transient/malformed RPC response). Startup recovery alone is not
        // enough for that case because the task is already running: every later pool would
        // merely refuse to overwrite the unresolved signer lane forever. Resolve the durable
        // lane before doing any new proof work on every tick.
        if cfg.tx_type == CrankTxType::Eip1559 {
            if let Some(path) = cfg.tx_journal.as_deref() {
                match CrankTxJournal::load(path, cfg.signer.chain_id, &signer_hex) {
                    Ok(Some(journal)) => {
                        eprintln!(
                            "[crank] recovering durable transaction nonce={} pool={} attempts={}",
                            journal.nonce,
                            journal.pool,
                            journal.attempts.len()
                        );
                        match drive_crank_journal(&rpc, &cfg, &mut tx_budget, journal).await {
                            Ok(ok) => println!(
                                "[crank] recovered transaction reached terminal status={}",
                                if ok { "confirmed" } else { "reverted" }
                            ),
                            Err(error) => {
                                eprintln!("[crank] durable transaction recovery paused: {error:#}");
                                tokio::time::sleep(Duration::from_secs(cfg.interval_secs.max(1)))
                                    .await;
                                continue;
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        eprintln!("[crank] durable transaction journal rejected: {error:#}");
                        tokio::time::sleep(Duration::from_secs(cfg.interval_secs.max(1))).await;
                        continue;
                    }
                }
            }
        }

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

            // 3. Local leaves at the chain watermark. Historical commitments
            // stay in PostgreSQL; only this bounded crank window enters RAM.
            let (local_len, restored) = {
                let s = ctx.state.read().await;
                let restored = (s.confirmed_frontier.next_index() == chain_count)
                    .then(|| s.confirmed_frontier.clone());
                (s.tree_frontier.next_index(), restored)
            };
            let take = (chain_pending as usize)
                .min(CMX_CONFIRM_MAX_BATCH * cfg.max_proofs_per_tx)
                .min(local_len.saturating_sub(chain_count) as usize);
            let leaves = match ctx
                .backend
                .load_cmx_range(&ctx.contract_address, chain_count, take)
                .await
            {
                Ok(leaves) => leaves,
                Err(error) => {
                    eprintln!("[crank][{label}] bounded cmx read failed: {error:#}");
                    continue;
                }
            };
            if leaves.is_empty() {
                // Indexer has not ingested the pending NoteAdded events yet.
                println!(
                    "[crank][{label}] chain has {chain_pending} pending at count {chain_count}, \
                     local tree only {local_len} leaves — waiting for ingest"
                );
                continue;
            }

            // Restore the exact compact confirmed-state frontier. A count
            // mismatch is a canonical-state problem; never rebuild history in
            // the crank hot path.
            let frontier_matches = frontiers
                .get(&pool)
                .is_some_and(|frontier| frontier.next_index() == chain_count);
            if !frontier_matches {
                if let Some(frontier) = restored {
                    frontiers.insert(pool.clone(), frontier);
                } else {
                    eprintln!(
                        "[crank][{label}] compact frontier count does not match chain watermark {chain_count}"
                    );
                    continue;
                }
            }
            let frontier = frontiers
                .get_mut(&pool)
                .expect("frontier inserted after successful restore");
            // Byte-identity guard: local frontier must reproduce the chain root.
            let local_root = frontier.root_be();
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
            let inputs = match planned.plan_batches(&leaves, cfg.max_proofs_per_tx) {
                Ok(inputs) => inputs,
                Err(error) => {
                    eprintln!("[crank][{label}] compact frontier planning failed: {error:#}");
                    continue;
                }
            };
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
    let nonce = match cfg.tx_type {
        CrankTxType::Legacy => rpc.get_transaction_count(&from_hex).await?,
        CrankTxType::Eip1559 => rpc.get_pending_transaction_count(&from_hex).await?,
    };
    let (raw, dynamic_fees) = match cfg.tx_type {
        CrankTxType::Legacy => (
            build_and_sign_raw_tx(
                nonce,
                cfg.signer.gas_price,
                gas_limit,
                pool,
                0u64,
                calldata,
                cfg.signer.chain_id,
                &cfg.signer.signing_key,
            )?,
            None,
        ),
        CrankTxType::Eip1559 => {
            let base_fee = rpc.base_fee_per_gas().await?;
            let (priority_fee, max_fee) = eip1559_crank_fees(
                base_fee,
                cfg.max_priority_fee_per_gas,
                cfg.max_fee_per_gas_cap,
            )?;
            println!(
                "[crank] {what} EIP-1559 fees: base={base_fee} priority={priority_fee} max={max_fee} cap={}",
                cfg.max_fee_per_gas_cap
            );
            (
                build_and_sign_eip1559_tx(
                    nonce,
                    priority_fee,
                    max_fee,
                    gas_limit,
                    pool,
                    0u64,
                    calldata,
                    cfg.signer.chain_id,
                    &cfg.signer.signing_key,
                )?,
                Some((priority_fee, max_fee)),
            )
        }
    };
    if cfg.tx_type == CrankTxType::Eip1559 {
        let path = cfg
            .tx_journal
            .as_deref()
            .ok_or_else(|| anyhow!("EIP-1559 crank has no durable journal path"))?;
        if CrankTxJournal::load(path, cfg.signer.chain_id, &from_hex)?.is_some() {
            return Err(anyhow!(
                "refusing to overwrite unresolved crank transaction journal {path}"
            ));
        }
        let tx_hash = raw_tx_hash(&raw);
        let now = unix_seconds();
        let (priority_fee, max_fee) = dynamic_fees.expect("EIP-1559 fees were selected");
        let journal = CrankTxJournal {
            schema: CrankTxJournal::SCHEMA.to_string(),
            chain_id: cfg.signer.chain_id,
            signer: from_hex,
            pool: normalize_hex_0x(pool),
            method: what.to_string(),
            nonce,
            gas_limit,
            calldata_hex: format!("0x{}", hex::encode(calldata)),
            attempts: vec![CrankTxAttempt {
                tx_hash,
                raw_tx_hex: format!("0x{}", hex::encode(raw)),
                max_priority_fee_per_gas: priority_fee,
                max_fee_per_gas: max_fee,
                prepared_at: now,
                broadcast_at: None,
            }],
        };
        journal.save(path)?;
        return drive_crank_journal(rpc, cfg, budget, journal).await;
    }

    if !budget.try_take(unix_seconds()) {
        return Err(anyhow!(
            "hourly crank transaction budget exhausted (limit={})",
            cfg.max_tx_per_hour
        ));
    }
    let tx_hash = rpc.send_raw_transaction(&raw).await?;
    println!("[crank] {what} submitted: {tx_hash}");
    wait_for_crank_receipt(rpc, &tx_hash, what, 90).await
}

async fn wait_for_crank_receipt(
    rpc: &RpcClient,
    tx_hash: &str,
    what: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs.max(1));
    loop {
        match rpc.get_transaction_receipt_status(tx_hash).await {
            Ok(Some(ok)) => return Ok(ok),
            Ok(None) | Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Ok(None) | Err(_) => {
                return Err(anyhow!(
                    "{what} tx {tx_hash} did not reach a receipt before timeout"
                ));
            }
        }
    }
}

async fn drive_crank_journal(
    rpc: &RpcClient,
    cfg: &CrankConfig,
    budget: &mut HourlyTxBudget,
    mut journal: CrankTxJournal,
) -> Result<bool> {
    let path = cfg
        .tx_journal
        .as_deref()
        .ok_or_else(|| anyhow!("EIP-1559 crank has no durable journal path"))?;
    if !cfg.allowed_pools.contains(&journal.pool.to_lowercase()) {
        return Err(anyhow!(
            "durable crank journal pool {} is not in the current allowlist",
            journal.pool
        ));
    }
    validate_crank_journal_signed_payloads(&journal, &cfg.signer.signing_key)?;
    // A prepared-but-not-yet-broadcast attempt cannot have a receipt. Querying it here is
    // both wasted work and a liveness hazard: an RPC error would abort before the first
    // `eth_sendRawTransaction`, leaving a durable journal that never got on-chain.
    for attempt in broadcasted_crank_attempts(&journal) {
        if let Some(ok) = rpc.get_transaction_receipt_status(&attempt.tx_hash).await? {
            CrankTxJournal::clear(path)?;
            return Ok(ok);
        }
    }

    loop {
        let attempt = journal
            .attempts
            .last()
            .cloned()
            .ok_or_else(|| anyhow!("crank journal has no current attempt"))?;
        let raw = hex::decode(strip_0x(&attempt.raw_tx_hex))?;
        if attempt.broadcast_at.is_none() && !budget.try_take(unix_seconds()) {
            return Err(anyhow!(
                "hourly crank transaction budget exhausted before durable broadcast (limit={})",
                cfg.max_tx_per_hour
            ));
        }
        match rpc.send_raw_transaction(&raw).await {
            Ok(rpc_hash) if rpc_hash.eq_ignore_ascii_case(&attempt.tx_hash) => {}
            Ok(rpc_hash) => {
                return Err(anyhow!(
                    "RPC returned crank tx hash {rpc_hash}, expected {}",
                    attempt.tx_hash
                ));
            }
            Err(error) if rpc_error_already_known(&error) => {}
            Err(error) if rpc_error_nonce_too_low(&error) => {
                for alias in &journal.attempts {
                    if let Some(ok) = rpc.get_transaction_receipt_status(&alias.tx_hash).await? {
                        CrankTxJournal::clear(path)?;
                        return Ok(ok);
                    }
                }
                return Err(anyhow!(
                    "crank nonce {} is too low but no persisted hash has a receipt; refusing a new nonce: {error:#}",
                    journal.nonce
                ));
            }
            Err(error) => return Err(error).context("broadcast persisted crank transaction"),
        }
        let now = unix_seconds();
        if journal
            .attempts
            .last()
            .and_then(|entry| entry.broadcast_at)
            .is_none()
        {
            journal
                .attempts
                .last_mut()
                .expect("attempt exists")
                .broadcast_at = Some(now);
            journal.save(path)?;
        }

        let broadcast_at = journal
            .attempts
            .last()
            .and_then(|entry| entry.broadcast_at)
            .unwrap_or(now);
        let wait_secs = broadcast_at
            .saturating_add(cfg.replacement_after_secs.max(1))
            .saturating_sub(unix_seconds());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(wait_secs);
        loop {
            for alias in &journal.attempts {
                if let Some(ok) = rpc.get_transaction_receipt_status(&alias.tx_hash).await? {
                    CrankTxJournal::clear(path)?;
                    return Ok(ok);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }

        let replacements = journal.attempts.len().saturating_sub(1) as u32;
        if replacements >= cfg.max_replacements {
            return Err(anyhow!(
                "crank tx nonce {} is still pending after {} replacement(s); durable journal retained",
                journal.nonce,
                replacements
            ));
        }
        let base_fee = rpc.base_fee_per_gas().await?;
        let suggested = eip1559_crank_fees(
            base_fee,
            cfg.max_priority_fee_per_gas,
            cfg.max_fee_per_gas_cap,
        )?;
        let priority = bump_eip1559_fee(attempt.max_priority_fee_per_gas).max(suggested.0);
        let max_fee = bump_eip1559_fee(attempt.max_fee_per_gas)
            .max(suggested.1)
            .max(priority);
        if max_fee > u128::from(cfg.max_fee_per_gas_cap) {
            return Err(anyhow!(
                "replacement maxFeePerGas {max_fee} exceeds configured cap {}",
                cfg.max_fee_per_gas_cap
            ));
        }
        let calldata = hex::decode(strip_0x(&journal.calldata_hex))?;
        let replacement_raw = build_and_sign_eip1559_tx(
            journal.nonce,
            priority,
            max_fee,
            journal.gas_limit,
            &journal.pool,
            0,
            &calldata,
            journal.chain_id,
            &cfg.signer.signing_key,
        )?;
        let replacement_hash = raw_tx_hash(&replacement_raw);
        journal.attempts.push(CrankTxAttempt {
            tx_hash: replacement_hash,
            raw_tx_hex: format!("0x{}", hex::encode(replacement_raw)),
            max_priority_fee_per_gas: priority,
            max_fee_per_gas: max_fee,
            prepared_at: unix_seconds(),
            broadcast_at: None,
        });
        // Persist the same-nonce signed replacement before its first broadcast.
        journal.save(path)?;
    }
}

fn rpc_error_already_known(error: &anyhow::Error) -> bool {
    let message = format!("{error:#}").to_ascii_lowercase();
    message.contains("already known")
        || message.contains("known transaction")
        || message.contains("already imported")
}

fn rpc_error_nonce_too_low(error: &anyhow::Error) -> bool {
    format!("{error:#}")
        .to_ascii_lowercase()
        .contains("nonce too low")
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

fn bearer_matches(headers: &HeaderMap, token: Option<&Arc<str>>) -> bool {
    let Some(expected) = token else {
        return false;
    };
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|supplied| !supplied.is_empty() && supplied == expected.as_ref())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApiAccess {
    Allow,
    Gone,
    Hidden,
}

fn public_api_access(
    mode: PublicApiMode,
    method: &Method,
    path: &str,
    internal_read: bool,
) -> ApiAccess {
    let read_method = method == Method::GET || method == Method::HEAD || method == Method::OPTIONS;
    if path == "/internal/egress_metrics" {
        return if internal_read && read_method {
            ApiAccess::Allow
        } else {
            ApiAccess::Hidden
        };
    }
    if mode == PublicApiMode::Full {
        return ApiAccess::Allow;
    }
    // The internal token is read-only by construction. It can never open a
    // POST/PUT/PATCH/DELETE route; those continue through their distinct admin
    // or relayer authorization paths below.
    if internal_read && read_method {
        return ApiAccess::Allow;
    }
    if read_method
        && matches!(
            path,
            "/healthz" | "/merkle_path" | "/txs" | "/stats" | "/shield/stats"
        )
    {
        return ApiAccess::Allow;
    }
    // Permit only these two POSTs to reach their existing, independent token
    // validators. No internal-read credential is consulted by those handlers.
    if method == Method::POST && (path == "/notify_tx" || path == "/pools") {
        return ApiAccess::Allow;
    }
    if read_method && matches!(path, "/batches" | "/batches/page" | "/batches/stream") {
        ApiAccess::Gone
    } else {
        ApiAccess::Hidden
    }
}

fn is_public_merkle_path(path: &str, internal_read: bool) -> bool {
    path == "/merkle_path" && !internal_read
}

fn is_public_txs(path: &str, internal_read: bool) -> bool {
    path == "/txs" && !internal_read
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

async fn require_canonical_context(ctx: &AppContext) -> Result<(), (StatusCode, String)> {
    canonical_guard(ctx.state.read().await.tree_out_of_order)
}

async fn require_serving_context(ctx: &AppContext) -> Result<(), (StatusCode, String)> {
    require_canonical_context(ctx).await?;
    if !ctx.frozen_paths_ready.load(AtomicOrdering::Acquire) {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "indexer frozen-path initialization is not ready".to_owned(),
        ));
    }
    Ok(())
}

async fn acquire_history_read(
    reg: &PoolRegistry,
) -> Result<tokio::sync::SemaphorePermit<'_>, (StatusCode, String)> {
    reg.history_read_semaphore.acquire().await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "historical batch reader is shutting down".to_string(),
        )
    })
}

async fn canonical_api_gate(
    State(reg): State<PoolRegistry>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let path = request.uri().path().to_owned();
    let method = request.method().clone();
    let internal_read = bearer_matches(request.headers(), reg.internal_read_token.as_ref());
    match public_api_access(reg.public_api_mode, &method, &path, internal_read) {
        ApiAccess::Allow => {}
        ApiAccess::Gone => {
            reg.egress_metrics
                .public_denied
                .fetch_add(1, AtomicOrdering::Relaxed);
            return (StatusCode::GONE, "public historical API is disabled").into_response();
        }
        ApiAccess::Hidden => {
            reg.egress_metrics
                .public_denied
                .fetch_add(1, AtomicOrdering::Relaxed);
            return StatusCode::NOT_FOUND.into_response();
        }
    }
    // Anonymous public reads consume the traffic/cost fuse. Authenticated
    // internal services remain available even when abusive public traffic has
    // exhausted that budget; their access is protected by the separate
    // read-only bearer token and private network boundary.
    let public_merkle_path = is_public_merkle_path(&path, internal_read);
    let public_txs = is_public_txs(&path, internal_read);
    let _merkle_path_permit = if public_merkle_path {
        reg.egress_metrics
            .merkle_path_requests
            .fetch_add(1, AtomicOrdering::Relaxed);
        let permit = match reg.merkle_path_semaphore.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                reg.egress_metrics
                    .merkle_path_4xx
                    .fetch_add(1, AtomicOrdering::Relaxed);
                reg.egress_metrics
                    .merkle_path_limited
                    .fetch_add(1, AtomicOrdering::Relaxed);
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    "Merkle path concurrency limit",
                )
                    .into_response();
            }
        };
        if !reg
            .merkle_path_budget
            .lock()
            .await
            .has_capacity(unix_seconds())
        {
            reg.egress_metrics
                .merkle_path_4xx
                .fetch_add(1, AtomicOrdering::Relaxed);
            reg.egress_metrics
                .merkle_path_limited
                .fetch_add(1, AtomicOrdering::Relaxed);
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "Merkle path egress budget exhausted",
            )
                .into_response();
        }
        Some(permit)
    } else {
        None
    };
    let _txs_permit = if public_txs {
        reg.egress_metrics
            .txs_requests
            .fetch_add(1, AtomicOrdering::Relaxed);
        let permit = match reg.txs_semaphore.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                reg.egress_metrics
                    .txs_4xx
                    .fetch_add(1, AtomicOrdering::Relaxed);
                reg.egress_metrics
                    .txs_limited
                    .fetch_add(1, AtomicOrdering::Relaxed);
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    "Transaction list concurrency limit",
                )
                    .into_response();
            }
        };
        if !reg.txs_budget.lock().await.has_capacity(unix_seconds()) {
            reg.egress_metrics
                .txs_4xx
                .fetch_add(1, AtomicOrdering::Relaxed);
            reg.egress_metrics
                .txs_limited
                .fetch_add(1, AtomicOrdering::Relaxed);
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "Transaction list egress budget exhausted",
            )
                .into_response();
        }
        Some(permit)
    } else {
        None
    };
    if path == "/status" || path == "/healthz" {
        return next.run(request).await;
    }
    let contexts: Vec<AppContext> = reg.pools.read().await.values().cloned().collect();
    for ctx in contexts {
        if let Err(error) = require_serving_context(&ctx).await {
            return error.into_response();
        }
    }
    let response = next.run(request).await;
    if public_txs {
        let response_status = response.status();
        let (parts, body) = response.into_parts();
        return match to_bytes(body, reg.txs_max_response_bytes).await {
            Ok(bytes) => {
                if !reg
                    .txs_budget
                    .lock()
                    .await
                    .try_consume(unix_seconds(), bytes.len() as u64)
                {
                    reg.egress_metrics
                        .txs_4xx
                        .fetch_add(1, AtomicOrdering::Relaxed);
                    reg.egress_metrics
                        .txs_limited
                        .fetch_add(1, AtomicOrdering::Relaxed);
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        "Transaction list egress budget exhausted",
                    )
                        .into_response();
                }
                match response_status.as_u16() {
                    200..=299 => &reg.egress_metrics.txs_2xx,
                    400..=499 => &reg.egress_metrics.txs_4xx,
                    _ => &reg.egress_metrics.txs_5xx,
                }
                .fetch_add(1, AtomicOrdering::Relaxed);
                reg.egress_metrics
                    .txs_bytes
                    .fetch_add(bytes.len() as u64, AtomicOrdering::Relaxed);
                Response::from_parts(parts, Body::from(bytes))
            }
            Err(error) => {
                reg.egress_metrics
                    .txs_5xx
                    .fetch_add(1, AtomicOrdering::Relaxed);
                (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    format!("bounded /txs response exceeded limit: {error}"),
                )
                    .into_response()
            }
        };
    }
    if !public_merkle_path {
        return response;
    }
    let response_status = response.status();
    let (parts, body) = response.into_parts();
    match to_bytes(body, reg.merkle_path_max_response_bytes).await {
        Ok(bytes) => {
            if !reg
                .merkle_path_budget
                .lock()
                .await
                .try_consume(unix_seconds(), bytes.len() as u64)
            {
                reg.egress_metrics
                    .merkle_path_4xx
                    .fetch_add(1, AtomicOrdering::Relaxed);
                reg.egress_metrics
                    .merkle_path_limited
                    .fetch_add(1, AtomicOrdering::Relaxed);
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    "Merkle path egress budget exhausted",
                )
                    .into_response();
            }
            match response_status.as_u16() {
                200..=299 => &reg.egress_metrics.merkle_path_2xx,
                400..=499 => &reg.egress_metrics.merkle_path_4xx,
                _ => &reg.egress_metrics.merkle_path_5xx,
            }
            .fetch_add(1, AtomicOrdering::Relaxed);
            reg.egress_metrics
                .merkle_path_bytes
                .fetch_add(bytes.len() as u64, AtomicOrdering::Relaxed);
            Response::from_parts(parts, Body::from(bytes))
        }
        Err(error) => {
            reg.egress_metrics
                .merkle_path_5xx
                .fetch_add(1, AtomicOrdering::Relaxed);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("measure /merkle_path response: {error}"),
            )
                .into_response()
        }
    }
}

async fn get_egress_metrics(State(reg): State<PoolRegistry>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "schema": "privacy-indexer-egress/v1",
        "public_api_mode": match reg.public_api_mode {
            PublicApiMode::Full => "full",
            PublicApiMode::Minimal => "minimal",
        },
        "merkle_path": {
            "requests": reg.egress_metrics.merkle_path_requests.load(AtomicOrdering::Relaxed),
            "bytes": reg.egress_metrics.merkle_path_bytes.load(AtomicOrdering::Relaxed),
            "status_2xx": reg.egress_metrics.merkle_path_2xx.load(AtomicOrdering::Relaxed),
            "status_4xx": reg.egress_metrics.merkle_path_4xx.load(AtomicOrdering::Relaxed),
            "status_5xx": reg.egress_metrics.merkle_path_5xx.load(AtomicOrdering::Relaxed),
            "limited": reg.egress_metrics.merkle_path_limited.load(AtomicOrdering::Relaxed),
        },
        "txs": {
            "requests": reg.egress_metrics.txs_requests.load(AtomicOrdering::Relaxed),
            "bytes": reg.egress_metrics.txs_bytes.load(AtomicOrdering::Relaxed),
            "status_2xx": reg.egress_metrics.txs_2xx.load(AtomicOrdering::Relaxed),
            "status_4xx": reg.egress_metrics.txs_4xx.load(AtomicOrdering::Relaxed),
            "status_5xx": reg.egress_metrics.txs_5xx.load(AtomicOrdering::Relaxed),
            "limited": reg.egress_metrics.txs_limited.load(AtomicOrdering::Relaxed),
        },
        "public_denied": reg.egress_metrics.public_denied.load(AtomicOrdering::Relaxed),
    }))
}

async fn healthz(State(reg): State<PoolRegistry>) -> Result<&'static str, (StatusCode, String)> {
    let pools = reg.pools.read().await;
    let active: HashSet<String> = pools.keys().cloned().collect();
    let missing = missing_required_pools(&reg.required_pools, &active);
    if !missing.is_empty() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            format!("required pools missing: {}", missing.join(",")),
        ));
    }
    let mut contexts: Vec<AppContext> = pools.values().cloned().collect();
    drop(pools);
    if contexts.is_empty() && reg.require_pool {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "no required pool has been configured or discovered".to_owned(),
        ));
    }
    contexts.sort_by(|a, b| a.contract_address.cmp(&b.contract_address));
    for ctx in contexts {
        require_serving_context(&ctx).await.map_err(|error| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("pool {} is not ready: {}", ctx.contract_address, error.1),
            )
        })?;
    }
    Ok("ok")
}

fn missing_required_pools(required: &HashSet<String>, active: &HashSet<String>) -> Vec<String> {
    let mut missing: Vec<String> = required.difference(active).cloned().collect();
    missing.sort();
    missing
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

/// `GET /stats` — exact system-wide transaction aggregates for the explorer.
async fn get_system_stats(
    State(reg): State<PoolRegistry>,
) -> Result<Json<SystemStatsResponse>, (StatusCode, String)> {
    let mut cache = reg.system_stats_cache.lock().await;
    if let Some((refreshed_at, total_transactions)) = *cache {
        if refreshed_at.elapsed() < SYSTEM_STATS_CACHE_TTL {
            return Ok(Json(SystemStatsResponse { total_transactions }));
        }
    }

    let total_transactions = if let Some(pool) = reg.builder.pg_pool.as_ref() {
        let total: i64 = sqlx::query_scalar("SELECT count(*) FROM indexed_transactions")
            .fetch_one(pool)
            .await
            .map_err(|error| {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("load transaction stats: {error}"),
                )
            })?;
        u64::try_from(total).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "stored transaction count is negative".to_owned(),
            )
        })?
    } else {
        // JSON is development-only and has no aggregate tables. Preserve API
        // parity by folding its complete archives at most once per cache TTL.
        let _history_permit = acquire_history_read(&reg).await?;
        let contexts: Vec<AppContext> = reg.pools.read().await.values().cloned().collect();
        let mut hashes = HashSet::new();
        for ctx in &contexts {
            if let StateBackend::Json(Some(path)) = &ctx.backend {
                for envelope in StateBackend::read_json_archive(path, &ctx.contract_address) {
                    for note in envelope.batch.abi_notes {
                        hashes.insert(normalize_hex_0x(&note.tx_hash).to_lowercase());
                    }
                }
            }
            let state = ctx.state.read().await;
            canonical_guard(state.tree_out_of_order)?;
            for envelope in &state.batches {
                for note in &envelope.batch.abi_notes {
                    hashes.insert(normalize_hex_0x(&note.tx_hash).to_lowercase());
                }
            }
        }
        hashes.len() as u64
    };
    *cache = Some((Instant::now(), total_transactions));
    Ok(Json(SystemStatsResponse { total_transactions }))
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
            total_fee_units: stats.total_fee_units.to_string(),
            total_fee_wei: stats.total_fee_wei.to_string(),
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
    let start_block = effective_pool_start_block(req.start_block, reg.default_start_block);
    match reg.verify_pool_admitted(&addr_lc, start_block).await {
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
        .add_admitted_pool(&req.contract_address, start_block, true)
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
            "start_block": start_block,
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
    let tree_size = s.tree_frontier.next_index();
    let local_tree_root_hex = (tree_size > 0).then(|| hex::encode(s.tree_frontier.root_le()));
    Ok(Json(StatusResponse {
        next_block: s.next_block,
        canonical: !s.tree_out_of_order,
        frozen_paths_ready: ctx.frozen_paths_ready.load(AtomicOrdering::Acquire),
        startup_source: s.startup_source.clone(),
        shadow_mode: ctx.shadow_mode,
        last_finalized_block: s.last_finalized_block,
        last_finalized_block_hash: s.last_finalized_block_hash.clone(),
        latest_seq: s.latest_seq,
        cached_batches: s.batches.len(),
        confirmed_notes: s.confirmed_count,
        active_root_hex: http_root_hex(&s),
        local_tree_root_hex,
        tree_size,
        confirmed_count: s.confirmed_count,
        pending_cmx: tree_size.saturating_sub(s.confirmed_count),
        pool_address: ctx.contract_address.clone(),
        ring_misses: RingRecoveryMetrics::get(&ctx.ring_recovery.ring_misses),
        ring_recovery_from_buffer: RingRecoveryMetrics::get(
            &ctx.ring_recovery.recovered_from_buffer,
        ),
        ring_recovery_from_archive: RingRecoveryMetrics::get(
            &ctx.ring_recovery.recovered_from_archive,
        ),
        ring_recovery_unrecovered: RingRecoveryMetrics::get(&ctx.ring_recovery.unrecovered),
    }))
}

async fn get_batches(
    State(reg): State<PoolRegistry>,
    Query(q): Query<BatchesQuery>,
) -> Result<Json<Vec<BatchEnvelope>>, (StatusCode, String)> {
    let _history_permit = acquire_history_read(&reg).await?;
    let ctx = reg.resolve(q.pool.as_deref()).await?;
    let after = q.after_seq.unwrap_or(0);
    let target = ctx.state.read().await.latest_seq;
    let (out, has_more) = collect_batch_page(&ctx, after, target, MAX_BATCH_PAGE_LIMIT).await?;
    if has_more {
        return Err((
            StatusCode::CONFLICT,
            "legacy /batches history exceeds the bounded response; use /batches/page".to_string(),
        ));
    }
    Ok(Json(out))
}

/// Paginated batch history for wallet catch-up.
///
/// The first request omits `to_seq`; the indexer freezes `target_seq` at its
/// current latest sequence. Clients send that target back on later requests so
/// a busy pool cannot make one catch-up pass chase a moving head forever.
/// `limit` is soft because every envelope sharing the boundary seq stays in the
/// same page. On the final page `scanned_to_seq` advances to the target even if
/// the archive contains valid numeric seq gaps.
async fn get_batches_page(
    State(reg): State<PoolRegistry>,
    Query(q): Query<BatchesPageQuery>,
) -> Result<Json<BatchesPageResponse>, (StatusCode, String)> {
    let _history_permit = acquire_history_read(&reg).await?;
    let ctx = reg.resolve(q.pool.as_deref()).await?;
    let after_seq = q.after_seq.unwrap_or(0);
    let initial_latest_seq = {
        let s = ctx.state.read().await;
        canonical_guard(s.tree_out_of_order)?;
        s.latest_seq
    };
    let target_seq = q
        .to_seq
        .unwrap_or(initial_latest_seq)
        .min(initial_latest_seq);
    let limit = q
        .limit
        .unwrap_or(DEFAULT_BATCH_PAGE_LIMIT)
        .clamp(1, MAX_BATCH_PAGE_LIMIT);

    if after_seq > target_seq {
        return Err((
            StatusCode::BAD_REQUEST,
            "after_seq cannot exceed the fixed to_seq boundary".to_string(),
        ));
    }
    if after_seq == target_seq {
        return Ok(Json(BatchesPageResponse {
            envelopes: Vec::new(),
            next_after_seq: after_seq,
            scanned_to_seq: after_seq,
            target_seq,
            latest_seq: initial_latest_seq,
            has_more: false,
        }));
    }

    let (envelopes, has_more) = collect_batch_page(&ctx, after_seq, target_seq, limit).await?;
    let scanned_to_seq = if has_more {
        envelopes
            .last()
            .map(|envelope| envelope.seq)
            .unwrap_or(after_seq)
    } else {
        // `collect_batch_page` inspected the complete retained window. Moving
        // to target is therefore safe even when confirmation upserts created
        // numeric gaps with no row at exactly target_seq.
        target_seq
    };
    // Report the head again after the archive read, so a client can immediately
    // start another fixed-target pass when new envelopes arrived mid-request.
    let latest_seq = {
        let s = ctx.state.read().await;
        canonical_guard(s.tree_out_of_order)?;
        s.latest_seq
    };

    Ok(Json(BatchesPageResponse {
        envelopes,
        next_after_seq: scanned_to_seq,
        scanned_to_seq,
        target_seq,
        latest_seq,
        has_more,
    }))
}

/// Return the page boundary without splitting envelopes that share a sequence.
fn batch_page_end(sequences: &[u64], limit: usize) -> usize {
    if sequences.len() <= limit {
        return sequences.len();
    }
    let boundary_seq = sequences[limit - 1];
    let mut end = limit;
    while end < sequences.len() && sequences[end] == boundary_seq {
        end += 1;
    }
    end
}

/// One bounded page with `after < seq <= target`, oldest first. The archive is
/// read by keyset page and then joined to the finite in-memory ring. At most one
/// equal-sequence group may extend `limit`.
async fn collect_batch_page(
    ctx: &AppContext,
    after: u64,
    target: u64,
    limit: usize,
) -> Result<(Vec<BatchEnvelope>, bool), (StatusCode, String)> {
    let (mut ring, ring_front, latest_seq) = {
        let s = ctx.state.read().await;
        canonical_guard(s.tree_out_of_order)?;
        let ring: Vec<BatchEnvelope> = s
            .batches
            .iter()
            .filter(|b| b.seq > after && b.seq <= target)
            .cloned()
            .collect();
        (ring, s.batches.front().map(|b| b.seq), s.latest_seq)
    };
    ring.sort_by_key(|envelope| envelope.seq);
    // The ring covers (front..=latest); anything in (after..front) was evicted.
    let missing_before = match ring_front {
        Some(front) if front > after.saturating_add(1) => Some(front),
        None if latest_seq > after => Some(u64::MAX),
        _ => None,
    };
    let mut out = Vec::new();
    if let Some(before) = missing_before {
        let archived = ctx
            .backend
            .load_archived_batch_page(&ctx.contract_address, after, target, before, limit)
            .await
            .map_err(|error| {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("bounded batch archive read failed: {error:#}"),
                )
            })?;
        out = archived.envelopes;
        if archived.has_more {
            require_canonical_context(ctx).await?;
            return Ok((out, true));
        }
    }

    if out.len() >= limit {
        let has_more = !ring.is_empty();
        require_canonical_context(ctx).await?;
        return Ok((out, has_more));
    }

    let remaining = limit - out.len();
    let ring_end = batch_page_end(
        &ring.iter().map(|envelope| envelope.seq).collect::<Vec<_>>(),
        remaining,
    );
    let has_more = ring_end < ring.len();
    out.extend(ring.into_iter().take(ring_end));
    // A cursor mismatch may be detected while the archive query is in flight.
    // Recheck before returning any historical rows.
    require_canonical_context(ctx).await?;
    Ok((out, has_more))
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
    let _history_permit = acquire_history_read(&reg).await?;
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

    // The legacy SSE endpoint keeps only a bounded compatibility window. New
    // clients must catch up through `/batches/page` before opening a live feed.
    let target = ctx.state.read().await.latest_seq;
    let (historical, has_more) =
        collect_batch_page(&ctx, after_seq, target, MAX_BATCH_PAGE_LIMIT).await?;
    if has_more {
        return Err((
            StatusCode::CONFLICT,
            "SSE backlog exceeds the bounded compatibility window; catch up with /batches/page"
                .to_string(),
        ));
    }
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
        tree_size: s.tree_frontier.next_index(),
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

    {
        let s = ctx.state.read().await;
        canonical_guard(s.tree_out_of_order)?;
        for batch in s.batches.iter().rev() {
            for note in &batch.batch.abi_notes {
                if note.cmx == cmx {
                    return Ok(Json(note.clone()));
                }
            }
        }
    }
    // Ring miss: the note is older than the most recent `max_batches` envelopes.
    // The ring is a hot cache, not the source of truth — answering 404 here would
    // make an evicted note unspendable (the prover refreshes its witness fields
    // through this endpoint) and break the wallet's history decrypt.
    let note = ctx
        .backend
        .load_note_by_cmx(&ctx.contract_address, None, cmx)
        .await
        .ok_or_else(|| (StatusCode::NOT_FOUND, "cmx not found in indexer".to_owned()))?;
    // A cursor mismatch may be detected while the archive query is in flight.
    require_canonical_context(&ctx).await?;
    Ok(Json(note))
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
) -> Result<Json<Vec<TxLookupNote>>, (StatusCode, String)> {
    let want = normalize_hex_0x(&q.hash).to_lowercase();
    let contexts: Vec<AppContext> = match q.pool.as_deref() {
        Some(addr) => vec![reg.resolve(Some(addr)).await?],
        None => reg.pools.read().await.values().cloned().collect(),
    };

    // Per-note pool attribution (address + unit): a swap settle's two legs live in
    // different pools and the explorer renders each in its own symbol/decimals.
    let mut out: Vec<TxLookupNote> = Vec::new();
    let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    for ctx in contexts {
        let pool_lc = ctx.contract_address.to_lowercase();
        {
            let s = ctx.state.read().await;
            canonical_guard(s.tree_out_of_order)?;
            for batch in s.batches.iter() {
                for note in &batch.batch.abi_notes {
                    if normalize_hex_0x(&note.tx_hash).to_lowercase() == want
                        && seen.insert(note.cmx)
                    {
                        out.push(TxLookupNote {
                            note: note.clone(),
                            pool: pool_lc.clone(),
                            symbol: None,
                            decimals: None,
                        });
                    }
                }
            }
        }
        // Then the archive, for notes this pool's ring has already evicted. The ring
        // pass runs first and `seen` dedupes, so an in-ring note keeps its (fresher)
        // in-memory copy and the archive only ever *adds* rows. A tx whose notes
        // straddle the eviction boundary would otherwise return a partial list.
        for note in ctx
            .backend
            .load_notes_by_tx_hash(&ctx.contract_address, &want)
            .await
        {
            if seen.insert(note.cmx) {
                out.push(TxLookupNote {
                    note,
                    pool: pool_lc.clone(),
                    symbol: None,
                    decimals: None,
                });
            }
        }
        require_canonical_context(&ctx).await?;
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
        // Protocol-fee release. `ERC20Shield.unshield` grew `(bytes32 context,
        // address executor)` between `recipient` and `call`, which changed its
        // selector; `Perc20FeeGateway.transferWithFee` is new. Pools created
        // before the fee release keep the 3-argument form above, so BOTH must
        // stay classified — this is history for existing and new pools alike.
        [0x73, 0xa9, 0x3e, 0x1b] => Some("unshield"), // unshield(uint256,address,bytes32,address,(bytes,uint256[8]))
        // The target is the GATEWAY, not a pool, and the leading args are pool
        // addresses rather than a uint amount — classifying it as "transfer" is
        // what keeps it out of the arg0-is-an-amount decoding in `parse_tx_meta`.
        //
        // The multi-fee-asset release put `address feePool` in FRONT of the target
        // pool, which moved the selector. Both stay classified: the old one is
        // history for every sponsored transfer already mined, and dropping it would
        // silently blank the op label on those rows.
        [0x25, 0x78, 0x4a, 0x2e] => Some("transfer"), // transferWithFee(address,address,(bytes,uint256[8]),(bytes,uint256[8]))
        [0x4c, 0x4b, 0xa9, 0x3b] => Some("transfer"), // historical: transferWithFee(address,(bytes,uint256[8]),(bytes,uint256[8]))
        // Ethereum native-asset UX adapter. The indexer sees the pool's NoteAdded/
        // Shielded/Unshielded logs, but the containing transaction targets the
        // gateway, so classify its top-level calldata as the same logical pool op.
        // Both functions retain amount at arg0; native unshield's final recipient
        // is arg1 and is decoded below just like a direct pool unshield.
        [0xa6, 0xc3, 0x58, 0x9d] => Some("shield"), // shieldETH(uint256,(bytes,uint256[8]))
        [0xd6, 0xc7, 0x5f, 0xd4] => Some("unshield"), // unshieldETH(uint256,address,(bytes,uint256[8]))
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
        [0xf0, 0xae, 0xbc, 0x43] => Some("swap"), // permit-gated initiateSwap v2
        [0xd1, 0x12, 0x9e, 0x37] => Some("swap"), // per-order-fee settle v2
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
    // exact selector here rather than the `op` label.
    //
    // The protocol-fee `unshield` appended its two new arguments AFTER `recipient`,
    // so arg1 keeps calldata[36..68] and the same slice works for all three forms.
    let recipient = if input.len() >= 68
        && (input[0..4] == [0x19, 0x52, 0xce, 0x65]     // v3 unshield
            || input[0..4] == [0x73, 0xa9, 0x3e, 0x1b]  // v3 unshield, protocol-fee release
            || input[0..4] == [0xd6, 0xc7, 0x5f, 0xd4]  // NativeEthGateway.unshieldETH
            || input[0..4] == [0x53, 0x64, 0x4c, 0x61])
    // historical v2
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

/// Compact Browser wire note. The archive stores byte arrays, but JSON number arrays
/// inflate one 580-byte ciphertext several-fold. `/txs` needs only the decryptable
/// public envelope, so encode bytes as 0x hex and omit duplicate/archive-only fields.
/// A swap settle's two legs land in different pools, hence per-note attribution.
#[derive(Clone, Serialize)]
struct TxLookupNote {
    #[serde(flatten)]
    note: OrchardIndexedAbiNote,
    pool: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decimals: Option<u8>,
}

#[derive(Clone, Serialize)]
struct TxListNote {
    cmx: String,
    epk: String,
    enc_ciphertext: String,
    nf_old: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    out_ciphertext: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cv_net_x: Option<String>,
    log_index: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    shield_amount_sats: Option<u64>,
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
    notes: Vec<TxListNote>,
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
/// page prefers the in-memory ring (cheap, hot poll path); if that ring is empty
/// (Postgres warm-start does not refill it), the same request falls back to the
/// persisted archive so explorers are not blank until the next live ingest. Older
/// pages (cursor set) always read the archive. The cursor never splits a block
/// across pages, so callers can't skip or double-count boundary txs.
async fn get_txs(
    State(reg): State<PoolRegistry>,
    Query(q): Query<TxsListQuery>,
) -> Result<Json<TxsListResponse>, (StatusCode, String)> {
    let _history_permit = acquire_history_read(&reg).await?;
    let max_limit = if reg.public_api_mode == PublicApiMode::Minimal {
        MINIMAL_TXS_MAX_LIMIT
    } else {
        100
    };
    let limit = q.limit.unwrap_or(25).clamp(1, max_limit);
    let before = q.before_block.unwrap_or(u64::MAX);
    let contexts: Vec<AppContext> = match q.pool.as_deref() {
        Some(addr) => vec![reg.resolve(Some(addr)).await?],
        None => reg.pools.read().await.values().cloned().collect(),
    };

    // Aggregate notes into per-tx buckets. A tx can appear across pools (a swap
    // settle emits a note in each leg's pool), so key by hash and merge.
    // Newest page (no cursor) reads the in-memory ring when it has data. Any older
    // page (cursor set) — or a newest page whose rings are all empty — reads a
    // bounded PostgreSQL/JSONL block page so history survives warm-start and deep
    // pagination reaches beyond the ring without materializing the full archive.
    let mut full_history = q.before_block.is_some();
    if !full_history {
        let mut ring_empty = true;
        for ctx in &contexts {
            let s = ctx.state.read().await;
            if !s.batches.is_empty() {
                ring_empty = false;
                break;
            }
        }
        if ring_empty {
            full_history = true;
        }
    }
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
    let mut archive_has_older = false;
    let per_pool_note_limit = MAX_TX_HISTORY_NOTE_ROWS.div_ceil(contexts.len().max(1));
    for ctx in &contexts {
        let pool_lc = ctx.contract_address.to_lowercase();
        let batches: Vec<BatchEnvelope> = if full_history {
            let page = ctx
                .backend
                .load_archived_batches_before_block(
                    &ctx.contract_address,
                    before,
                    per_pool_note_limit,
                )
                .await
                .map_err(|error| {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        format!("bounded transaction archive read failed: {error:#}"),
                    )
                })?;
            archive_has_older |= page.has_more;
            page.envelopes
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
                entry.notes.push(TxListNote {
                    cmx: format!("0x{}", hex::encode(note.cmx)),
                    epk: format!("0x{}", hex::encode(note.epk)),
                    enc_ciphertext: format!("0x{}", hex::encode(&note.enc_ciphertext)),
                    nf_old: format!("0x{}", hex::encode(note.nf_old)),
                    out_ciphertext: (!note.out_ciphertext.is_empty())
                        .then(|| format!("0x{}", hex::encode(&note.out_ciphertext))),
                    cv_net_x: note
                        .cv_net_x
                        .map(|value| format!("0x{}", hex::encode(value))),
                    log_index: note.log_index,
                    shield_amount_sats: note.shield_amount_sats,
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
        tx.notes.sort_by_key(|n| n.log_index);
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
    let mut truncated = archive_has_older;
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

const DEX_INITIATE_V2_SELECTOR: [u8; 4] = [0xf0, 0xae, 0xbc, 0x43];

fn privacy_call_param_for_dex() -> ParamType {
    ParamType::Tuple(vec![
        ParamType::Bytes,
        ParamType::FixedArray(Box::new(ParamType::Uint(256)), 8),
    ])
}

fn order_ref_param_for_dex() -> ParamType {
    ParamType::Tuple(vec![
        ParamType::FixedBytes(32),
        ParamType::Uint(256),
        ParamType::Uint(256),
    ])
}

/// Decode the new permit-gated initiate without duplicating PrivacyCall parsing. The first three
/// arguments are unchanged; HTLC/rk/deadline/salt moved into the permit tuple. Repack those eight
/// fields into the already-audited plan-A decoder after validating the full new ABI shape.
fn decode_dex_initiate_calldata(calldata: &[u8]) -> Result<SwapInitiateCalldata, String> {
    if calldata.len() < 4 || calldata[..4] != DEX_INITIATE_V2_SELECTOR {
        return Err("bad permit-gated initiate selector".into());
    }
    let permit = ParamType::Tuple(vec![
        ParamType::FixedBytes(32),
        ParamType::Address,
        ParamType::FixedBytes(32),
        ParamType::FixedBytes(32),
        ParamType::Uint(256),
        ParamType::Uint(256),
        ParamType::Uint(64),
        ParamType::FixedBytes(32),
        order_ref_param_for_dex(),
        order_ref_param_for_dex(),
        ParamType::Address,
        ParamType::Uint(256),
    ]);
    let tokens = abi_decode(
        &[
            ParamType::Address,
            ParamType::Address,
            privacy_call_param_for_dex(),
            permit,
            ParamType::Bytes,
        ],
        &calldata[4..],
    )
    .map_err(|error| error.to_string())?;
    let Token::Tuple(fields) = &tokens[3] else {
        return Err("match permit is not a tuple".into());
    };
    if fields.len() != 12 {
        return Err("match permit has the wrong field count".into());
    }
    let legacy_body = abi_encode(&[
        tokens[0].clone(),
        tokens[1].clone(),
        tokens[2].clone(),
        fields[3].clone(),
        fields[4].clone(),
        fields[5].clone(),
        fields[6].clone(),
        fields[7].clone(),
    ]);
    let mut legacy = Vec::with_capacity(4 + legacy_body.len());
    legacy.extend_from_slice(&swap_initiate_selector());
    legacy.extend_from_slice(&legacy_body);
    decode_swap_initiate_calldata(&legacy).map_err(|error| error.to_string())
}

fn decode_any_swap_initiate(calldata: &[u8]) -> Result<SwapInitiateCalldata, String> {
    if calldata.len() >= 4 && calldata[..4] == DEX_INITIATE_V2_SELECTOR {
        decode_dex_initiate_calldata(calldata)
    } else {
        decode_swap_initiate_calldata(calldata).map_err(|error| error.to_string())
    }
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
    if input[..4] == swap_initiate_selector() || input[..4] == DEX_INITIATE_V2_SELECTOR {
        let d = decode_any_swap_initiate(&input).map_err(|e| {
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
        .confirmation_head()
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
    rpc.validate_canonical_logs(&logs).await.map_err(|e| {
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
                if let Ok(d) = decode_any_swap_initiate(&input) {
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

/// `/merkle_path` response (docs/note-sync-indexer-frozen-merkle-path.md §4.3).
///
/// `anchor_root` is the root the siblings open to. For a frozen record that is
/// the sealing segment's `newRoot` — a historical anchor the wallet validates
/// with `isValidAnchor`, NOT the current tip. `root` repeats the same value for
/// clients that expect that field name. Encoding is little-endian 0x hex, the
/// same convention as `siblings` and the prover's `parse_fr_le`.
#[derive(Serialize)]
struct MerklePathResponse {
    /// Canonical big-endian 0x hex, echoed from the query.
    cmx: String,
    position: u32,
    siblings: Vec<String>,
    anchor_root: String,
    root: String,
    /// Always true: `/merkle_path` serves only durable frozen records.
    frozen: bool,
}

/// EVM/on-chain byte order → little-endian 0x hex (prover `parse_fr_le`).
fn be32_to_le_hex_0x(mut bytes: [u8; 32]) -> String {
    bytes.reverse();
    format!("0x{}", hex::encode(bytes))
}

async fn get_merkle_path(
    State(reg): State<PoolRegistry>,
    Query(q): Query<MerklePathQuery>,
) -> Result<Json<MerklePathResponse>, (StatusCode, String)> {
    let _history_permit = acquire_history_read(&reg).await?;
    let ctx = reg.resolve(q.pool.as_deref()).await?;
    let cmx = parse_hex32(&q.cmx)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid cmx hex".to_owned()))?;

    // Serializing with canonical ingestion closes the short interval between a
    // NoteConfirmed state update and its immutable-node transaction. The lock is
    // held only across bounded point/node reads, never a historical scan.
    let _ingest = ctx.ingest_lock.lock().await;
    let confirmed_count = {
        let state = ctx.state.read().await;
        canonical_guard(state.tree_out_of_order)?;
        state.confirmed_count
    };

    // Authoritative source: the segment-end frozen record, written exactly once
    // when this cmx's RootUpdated segment sealed. Reads never mutate the store,
    // so repeated GETs return byte-identical siblings and anchor_root.
    let frozen = ctx
        .backend
        .load_frozen_path(&ctx.contract_address, cmx)
        .await
        .map_err(|error| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("frozen path archive unavailable: {error:#}"),
            )
        })?;
    if let Some(record) = frozen {
        // Final integrity guard: a corrupted row can never leave the process
        // as an unchecked path.
        let reopened =
            witness_root_be(cmx, record.position, &record.siblings).map_err(|error| {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("frozen path validation failed: {error:#}"),
                )
            })?;
        if reopened != record.anchor_root {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "frozen path does not recompute its sealed anchor root".to_owned(),
            ));
        }
        let position = u32::try_from(record.position).map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Merkle position exceeds the depth-32 tree capacity".to_owned(),
            )
        })?;
        let anchor_root = be32_to_le_hex_0x(record.anchor_root);
        return Ok(Json(MerklePathResponse {
            cmx: format!("0x{}", hex::encode(cmx)),
            position,
            siblings: record.siblings,
            root: anchor_root.clone(),
            anchor_root,
            frozen: true,
        }));
    }

    // No compatibility fallback: a confirmed cmx without a durable frozen row
    // means initialization or canonical persistence is incomplete. Never hide
    // that condition by manufacturing a tip-relative path at request time.
    let position = ctx
        .backend
        .load_cmx_position(&ctx.contract_address, cmx)
        .await
        .map_err(|error| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("cmx position archive unavailable: {error:#}"),
            )
        })?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "cmx not found in tree".to_owned()))?;

    // A pending note has no sealed path yet. It becomes available after the
    // segment seals and its frozen row is persisted.
    if position >= confirmed_count {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "note is pending batch confirmation (position {position}, confirmed {}); retry after the next updateRoot",
                confirmed_count
            ),
        ));
    }

    Err((
        StatusCode::SERVICE_UNAVAILABLE,
        "confirmed cmx has no persisted frozen Merkle path; indexer archive is incomplete"
            .to_owned(),
    ))
}

// ─── Compliance frozen Indexed-MT (rt_frozen) ────────────────────────────────
#[derive(Serialize)]
struct FrozenRootResponse {
    /// `rt_frozen` as 0x-prefixed little-endian 32-byte hex (prover `parse_fr_le`).
    /// Set this on-chain via `setFrozenRoot(rt_frozen)`.
    root_hex: String,
    /// Number of frozen `cmx` (excludes the `{0,0}` sentinel).
    frozen_count: u64,
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
#[derive(Clone, Debug, Serialize, Deserialize)]
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

/// Apply one disclosed frozen delta to a bounded membership projection. The
/// projection contains exactly the cmx values referenced by this event, while
/// `current_count` is the cardinality of the complete persisted set. This keeps
/// idempotent re-add/remove semantics without retaining the whole set in RAM.
fn frozen_count_after_delta(
    current_count: u64,
    mut projected_membership: HashSet<String>,
    update: &FrozenUpdate,
) -> Result<u64> {
    if update.cmx_changed_hex.len() != update.is_add.len() {
        bail!("frozen update cmx/op length mismatch");
    }
    let mut next_count = current_count;
    for (raw_cmx, is_add) in update.cmx_changed_hex.iter().zip(&update.is_add) {
        let cmx =
            parse_hex32(raw_cmx).ok_or_else(|| anyhow!("invalid frozen cmx in disclosed delta"))?;
        let canonical = format!("0x{}", hex::encode(cmx));
        if *is_add {
            if projected_membership.insert(canonical) {
                next_count = next_count.checked_add(1).context("frozen count overflow")?;
            }
        } else if projected_membership.remove(&canonical) {
            next_count = next_count
                .checked_sub(1)
                .context("materialized frozen count underflow")?;
        }
    }
    Ok(next_count)
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
    canonical_guard(s.tree_out_of_order)?;
    Ok(Json(FrozenRootResponse {
        root_hex: s.frozen_root_hex.clone(),
        frozen_count: s.frozen_count,
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
    let _history_permit = acquire_history_read(&reg).await?;
    let ctx = reg.resolve(q.pool.as_deref()).await?;
    let _ingest = ctx.ingest_lock.lock().await;
    let (root_hex, frozen_count) = {
        let state = ctx.state.read().await;
        canonical_guard(state.tree_out_of_order)?;
        (state.frozen_root_hex.clone(), state.frozen_count)
    };
    if frozen_count > MAX_FROZEN_LEAVES_RESPONSE as u64 {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "frozen set has {frozen_count} leaves; compatibility response limit is {MAX_FROZEN_LEAVES_RESPONSE}"
            ),
        ));
    }
    let leaves = ctx
        .backend
        .load_frozen_leaves(&ctx.contract_address, MAX_FROZEN_LEAVES_RESPONSE)
        .await
        .map_err(|error| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("frozen current set unavailable: {error:#}"),
            )
        })?;
    if leaves.len() as u64 != frozen_count {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "frozen current set does not match the sealed checkpoint".to_owned(),
        ));
    }
    Ok(Json(FrozenLeavesResponse {
        count: leaves.len(),
        root_hex,
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
    /// Maximum deltas returned. The cursor always points at the final returned
    /// delta, so existing polling clients can continue until the page is empty.
    #[serde(default)]
    limit: Option<usize>,
}

/// `GET /frozen_updates?pool=&since=cursor` — the compliance leaf-delta feed (PR2 main path).
/// Wallets replay these deltas to maintain their local Frozen IMT, then assert
/// `localRoot == cmxFrozenRoot()` on-chain before proving. The indexer stays dumb: it does not
/// rebuild the tree or serve witnesses.
async fn get_frozen_updates(
    State(reg): State<PoolRegistry>,
    Query(q): Query<FrozenUpdatesQuery>,
) -> Result<Json<FrozenUpdatesResponse>, (StatusCode, String)> {
    let _history_permit = acquire_history_read(&reg).await?;
    let ctx = reg.resolve(q.pool.as_deref()).await?;
    let after = match q.since.as_deref() {
        Some(value) => {
            let (block, log) = value
                .split_once(':')
                .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid frozen cursor".to_owned()))?;
            Some((
                block.parse::<u64>().map_err(|_| {
                    (
                        StatusCode::BAD_REQUEST,
                        "invalid frozen cursor block".to_owned(),
                    )
                })?,
                log.parse::<u64>().map_err(|_| {
                    (
                        StatusCode::BAD_REQUEST,
                        "invalid frozen cursor log index".to_owned(),
                    )
                })?,
            ))
        }
        None => None,
    };
    let limit = q
        .limit
        .unwrap_or(DEFAULT_FROZEN_UPDATE_PAGE)
        .clamp(1, MAX_FROZEN_UPDATE_PAGE);
    let _ingest = ctx.ingest_lock.lock().await;
    canonical_guard(ctx.state.read().await.tree_out_of_order)?;
    let updates = ctx
        .backend
        .load_frozen_updates_after(&ctx.contract_address, after, limit)
        .await
        .map_err(|error| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("frozen update archive unavailable: {error:#}"),
            )
        })?;
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
    #[serde(default)]
    checkpoint_version: u8,
    next_block: u64,
    #[serde(default)]
    last_finalized_block: Option<u64>,
    #[serde(default)]
    last_finalized_block_hash: Option<String>,
    #[serde(default)]
    cmx_leaves_hex: Vec<String>,
    #[serde(default)]
    tree_size: Option<u64>,
    #[serde(default)]
    tree_root_hex: Option<String>,
    #[serde(default)]
    tree_frontier_hex: Vec<String>,
    #[serde(default)]
    confirmed_frontier_hex: Vec<String>,
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
    /// in legacy JSON checkpoints only. V2 stores the feed in the backend archive.
    #[serde(default)]
    frozen_updates: Vec<FrozenUpdate>,
    #[serde(default)]
    frozen_root_hex: Option<String>,
    #[serde(default)]
    frozen_count: Option<u64>,
    #[serde(default)]
    frozen_update_count: Option<u64>,
    /// Event-derived ERC20Shield aggregate accounting.
    #[serde(default)]
    shield_accounting: ShieldAccounting,
}

/// Loaded result from a checkpoint file.
struct CheckpointData {
    next_block: u64,
    last_finalized_block: Option<u64>,
    last_finalized_block_hash: Option<String>,
    tree_frontier: CompactFrontier,
    active_root: Option<[u8; 32]>,
    confirmed_count: u64,
    confirmed_frontier: CompactFrontier,
    last_leaf_key: Option<(u64, u64)>,
    warm_start_candidate: bool,
    latest_seq: u64,
    batches: VecDeque<BatchEnvelope>,
    pending_tx_hashes: VecDeque<String>,
    frozen_root_hex: String,
    frozen_count: u64,
    frozen_update_count: u64,
    shield_accounting: ShieldAccounting,
}

fn load_checkpoint(path: &str, start_block: u64) -> CheckpointData {
    let loaded = (|| -> Result<CheckpointData> {
        let raw = std::fs::read_to_string(path).context("read JSON checkpoint")?;
        let ck: IndexerCheckpoint = serde_json::from_str(&raw).context("parse JSON checkpoint")?;
        let resumed = ck.next_block.max(start_block);
        let active_root = ck.active_root_hex.as_deref().and_then(parse_hex32);
        let confirmed_count = ck.confirmed_count.unwrap_or(0);

        let (tree_frontier, confirmed_frontier) = if ck.checkpoint_version >= 2 {
            let tree_size = ck.tree_size.context("missing compact tree_size")?;
            let tree_root = ck
                .tree_root_hex
                .as_deref()
                .and_then(parse_hex32)
                .context("missing compact tree root")?;
            let tree_filled = parse_hex32_vec(&ck.tree_frontier_hex)?;
            let confirmed_filled = parse_hex32_vec(&ck.confirmed_frontier_hex)?;
            let confirmed_root = active_root.unwrap_or(EVM_EMPTY_IMT_ROOT);
            (
                CompactFrontier::from_parts_be(&tree_filled, tree_size, tree_root)?,
                CompactFrontier::from_parts_be(&confirmed_filled, confirmed_count, confirmed_root)?,
            )
        } else {
            // Legacy JSON is a development-only compatibility path. Rebuild the
            // compact frontier once and immediately discard the historical vector.
            let leaves = parse_hex32_vec(&ck.cmx_leaves_hex)?;
            if confirmed_count > leaves.len() as u64 {
                bail!("legacy confirmed_count exceeds tree size");
            }
            (
                frontier_from_leaves(&leaves)?,
                frontier_from_leaves(&leaves[..confirmed_count as usize])?,
            )
        };
        let legacy_frozen_root = latest_frozen_root_hex(&ck.frozen_updates);
        let legacy_frozen_count = replay_frozen_set(&ck.frozen_updates).len() as u64;
        let legacy_frozen_update_count = ck.frozen_updates.len() as u64;
        let frozen_root_hex = ck.frozen_root_hex.unwrap_or(legacy_frozen_root);
        let frozen_count = ck.frozen_count.unwrap_or(legacy_frozen_count);
        let frozen_update_count = ck.frozen_update_count.unwrap_or(legacy_frozen_update_count);
        println!(
            "[indexer] resumed compact checkpoint {path}: next_block={resumed}, leaves={}",
            tree_frontier.next_index()
        );
        Ok(CheckpointData {
            next_block: resumed,
            last_finalized_block: ck.last_finalized_block,
            last_finalized_block_hash: ck
                .last_finalized_block_hash
                .and_then(|hash| normalize_block_hash(&hash).ok()),
            tree_frontier,
            active_root,
            confirmed_count,
            confirmed_frontier,
            last_leaf_key: ck.last_leaf_block.zip(ck.last_leaf_log_index),
            // JSON note history and its checkpoint are separate files, so JSON
            // mode remains ineligible for transactional warm-start.
            warm_start_candidate: false,
            latest_seq: ck.latest_seq,
            batches: VecDeque::from(ck.batches),
            pending_tx_hashes: VecDeque::from(ck.pending_tx_hashes),
            frozen_root_hex,
            frozen_count,
            frozen_update_count,
            shield_accounting: ck.shield_accounting,
        })
    })();
    match loaded {
        Ok(checkpoint) => checkpoint,
        Err(error) => {
            eprintln!(
                "[indexer] checkpoint unavailable ({error:#}), starting from block {start_block}"
            );
            empty_checkpoint(start_block)
        }
    }
}

fn parse_hex32_vec(values: &[String]) -> Result<Vec<[u8; 32]>> {
    values
        .iter()
        .map(|value| parse_hex32(value).ok_or_else(|| anyhow!("invalid 32-byte hex value")))
        .collect()
}

fn save_checkpoint(path: &str, snap: &CheckpointSnapshot) -> Result<()> {
    let ck = IndexerCheckpoint {
        checkpoint_version: 2,
        next_block: snap.next_block,
        last_finalized_block: snap.last_finalized_block,
        last_finalized_block_hash: snap.last_finalized_block_hash.clone(),
        cmx_leaves_hex: Vec::new(),
        tree_size: Some(snap.tree_frontier.next_index()),
        tree_root_hex: Some(hex::encode(snap.tree_frontier.root_be())),
        tree_frontier_hex: snap
            .tree_frontier
            .filled_be()
            .into_iter()
            .map(hex::encode)
            .collect(),
        confirmed_frontier_hex: snap
            .confirmed_frontier
            .filled_be()
            .into_iter()
            .map(hex::encode)
            .collect(),
        active_root_hex: snap.active_root.map(hex::encode),
        confirmed_count: Some(snap.confirmed_count),
        last_leaf_block: snap.last_leaf_key.map(|(block, _)| block),
        last_leaf_log_index: snap.last_leaf_key.map(|(_, log_index)| log_index),
        latest_seq: snap.latest_seq,
        batches: snap.batches.clone(),
        pending_tx_hashes: snap.pending_tx_hashes.clone(),
        frozen_updates: Vec::new(),
        frozen_root_hex: Some(snap.frozen_root_hex.clone()),
        frozen_count: Some(snap.frozen_count),
        frozen_update_count: Some(snap.frozen_update_count),
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
#[derive(Clone)]
struct CheckpointSnapshot {
    next_block: u64,
    last_finalized_block: Option<u64>,
    last_finalized_block_hash: Option<String>,
    tree_frontier: CompactFrontier,
    active_root: Option<[u8; 32]>,
    confirmed_count: u64,
    confirmed_frontier: CompactFrontier,
    last_leaf_key: Option<(u64, u64)>,
    latest_seq: u64,
    batches: Vec<BatchEnvelope>,
    pending_tx_hashes: Vec<String>,
    frozen_root_hex: String,
    frozen_count: u64,
    frozen_update_count: u64,
    shield_accounting: ShieldAccounting,
}

impl Default for CheckpointSnapshot {
    fn default() -> Self {
        Self {
            next_block: 0,
            last_finalized_block: None,
            last_finalized_block_hash: None,
            tree_frontier: CompactFrontier::new(),
            active_root: None,
            confirmed_count: 0,
            confirmed_frontier: CompactFrontier::new(),
            last_leaf_key: None,
            latest_seq: 0,
            batches: Vec::new(),
            pending_tx_hashes: Vec::new(),
            frozen_root_hex: format!("0x{}", "00".repeat(32)),
            frozen_count: 0,
            frozen_update_count: 0,
            shield_accounting: ShieldAccounting::default(),
        }
    }
}

impl CheckpointSnapshot {
    fn is_complete_finalized_boundary(&self) -> bool {
        checkpoint_is_complete_finalized_boundary(
            self.next_block,
            self.last_finalized_block,
            self.last_finalized_block_hash.as_deref(),
        )
    }

    fn from_state(s: &SharedState) -> Self {
        Self {
            next_block: s.next_block,
            last_finalized_block: s.last_finalized_block,
            last_finalized_block_hash: s.last_finalized_block_hash.clone(),
            tree_frontier: s.tree_frontier.clone(),
            active_root: s.active_root,
            confirmed_count: s.confirmed_count,
            confirmed_frontier: s.confirmed_frontier.clone(),
            last_leaf_key: s.last_leaf_key,
            latest_seq: s.latest_seq,
            batches: s.batches.iter().cloned().collect(),
            pending_tx_hashes: s.pending_tx_hashes.iter().cloned().collect(),
            frozen_root_hex: s.frozen_root_hex.clone(),
            frozen_count: s.frozen_count,
            frozen_update_count: s.frozen_update_count,
            shield_accounting: s.shield_accounting,
        }
    }
    fn from_checkpoint_data(ck: &CheckpointData) -> Self {
        Self {
            next_block: ck.next_block,
            last_finalized_block: ck.last_finalized_block,
            last_finalized_block_hash: ck.last_finalized_block_hash.clone(),
            tree_frontier: ck.tree_frontier.clone(),
            active_root: ck.active_root,
            confirmed_count: ck.confirmed_count,
            confirmed_frontier: ck.confirmed_frontier.clone(),
            last_leaf_key: ck.last_leaf_key,
            latest_seq: ck.latest_seq,
            batches: ck.batches.iter().cloned().collect(),
            pending_tx_hashes: ck.pending_tx_hashes.iter().cloned().collect(),
            frozen_root_hex: ck.frozen_root_hex.clone(),
            frozen_count: ck.frozen_count,
            frozen_update_count: ck.frozen_update_count,
            shield_accounting: ck.shield_accounting,
        }
    }
}

fn checkpoint_is_complete_finalized_boundary(
    next_block: u64,
    last_finalized_block: Option<u64>,
    last_finalized_block_hash: Option<&str>,
) -> bool {
    matches!(
        (last_finalized_block, last_finalized_block_hash),
        (Some(block), Some(hash))
            if !hash.is_empty() && next_block == block.saturating_add(1)
    )
}

/// Where persisted state lives. `Json` is per-pool (its own file); `Pgsql` is one shared
/// connection pool with every row keyed by `pool_address`.
#[derive(Clone, Debug)]
enum NoteArchiveMutation {
    Upsert(BatchEnvelope),
    Confirm {
        cmx: [u8; 32],
        position: u64,
        nodes: Vec<MerkleNode>,
    },
    ShieldAmount {
        cmx: [u8; 32],
        amount: u64,
    },
    Frozen {
        position: u64,
        update: FrozenUpdate,
    },
    /// Segment-end frozen witnesses for one sealed RootUpdated segment.
    FrozenPaths(Vec<FrozenPathRecord>),
}

/// How often the `batches` ring failed to answer a re-emission lookup, and where
/// the payload was recovered from instead.
///
/// A ring miss is not an error — the archive fallback makes it correct — but the
/// rate is the signal for sizing `--max-batches-in-memory`: a steadily non-zero
/// `ring_misses` means the ring no longer covers the lag between a note's
/// `NoteAdded` and its `NoteConfirmed`. `unrecovered` is the one that indicates a
/// real problem: the payload was in neither the ring nor the archive, so the
/// confirmation could not be republished at all.
#[derive(Debug, Default)]
struct RingRecoveryMetrics {
    /// Re-emission lookups the ring could not answer (all event kinds).
    ring_misses: AtomicU64,
    /// Recovered from the uncommitted rebuild/incremental-replay buffer.
    recovered_from_buffer: AtomicU64,
    /// Recovered from the persisted archive (PostgreSQL row or JSON line).
    recovered_from_archive: AtomicU64,
    /// Found in neither. The note is not republished with a new seq.
    unrecovered: AtomicU64,
}

impl RingRecoveryMetrics {
    fn get(counter: &AtomicU64) -> u64 {
        counter.load(AtomicOrdering::Relaxed)
    }

    fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, AtomicOrdering::Relaxed);
    }
}

/// Newest buffered `Upsert` payload for `cmx`, if any. Scans in reverse because a
/// note can be upserted more than once in a batch and the last write is current.
fn latest_upserted_note(
    mutations: &[NoteArchiveMutation],
    cmx: [u8; 32],
) -> Option<OrchardIndexedAbiNote> {
    mutations.iter().rev().find_map(|mutation| match mutation {
        NoteArchiveMutation::Upsert(env) => env
            .batch
            .abi_notes
            .iter()
            .find(|note| note.cmx == cmx)
            .cloned(),
        _ => None,
    })
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
    Confirm { cmx_hex: String, position: u64 },
    ShieldAmount { cmx_hex: String, amount: u64 },
    Frozen { position: u64, update: FrozenUpdate },
    FrozenPath(FrozenPathRecord),
}

#[derive(Clone)]
enum StateBackend {
    Json(Option<String>),
    Pgsql(sqlx::PgPool),
}

struct ArchivedBatchPage {
    envelopes: Vec<BatchEnvelope>,
    has_more: bool,
}

impl StateBackend {
    /// Sidecar JSONL file holding every batch envelope ever emitted (JSON mode).
    /// The in-memory ring only caches the most recent `max_batches`; this archive
    /// is what lets `/batches/page` traverse history after eviction.
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
                        NoteArchiveMutation::Confirm { cmx, position, .. } => {
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
                        NoteArchiveMutation::Frozen { position, update } => {
                            Self::append_json_line(
                                &archive_path,
                                &JsonNoteArchiveUpdate::Frozen {
                                    position: *position,
                                    update: update.clone(),
                                },
                            )?;
                        }
                        NoteArchiveMutation::FrozenPaths(records) => {
                            for record in records {
                                Self::append_json_line(
                                    &archive_path,
                                    &JsonNoteArchiveUpdate::FrozenPath(record.clone()),
                                )?;
                            }
                        }
                    }
                }
                Ok(())
            }
            StateBackend::Json(None) => Ok(()),
            StateBackend::Pgsql(pool) => {
                pg_apply_note_mutations(pool, pool_address, rebuild_generation, mutations).await
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

    async fn begin_canonical_rebuild(&self, pool_address: &str, generation: &str) -> Result<()> {
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
                let staged_notes = decode_json_note_archive(&staged_raw, pool_address).len();
                if staged_notes as u64 != snap.tree_frontier.next_index() {
                    return Err(anyhow!(
                        "canonical note activation mismatch: staged={staged_notes}, tree_leaves={}",
                        snap.tree_frontier.next_index()
                    ));
                }
                save_checkpoint(path, snap)?;
                std::fs::rename(rebuild_path, Self::json_archive_path(path)).with_context(
                    || format!("activate finalized note archive for {pool_address}"),
                )?;
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

    /// Load one bounded keyset page with `after_seq < seq <= target_seq` and
    /// `seq < before_seq`, oldest first. PostgreSQL applies the limit before
    /// decoding rows; only the final equal-sequence group may extend the soft
    /// limit so clients never split one logical batch across cursors.
    async fn load_archived_batch_page(
        &self,
        pool_address: &str,
        after_seq: u64,
        target_seq: u64,
        before_seq: u64,
        limit: usize,
    ) -> Result<ArchivedBatchPage> {
        match self {
            StateBackend::Json(Some(path)) => {
                // JSON is a development backend whose update records require a
                // full fold. Keep response size bounded even though decoding it
                // remains O(history); production PostgreSQL is truly keyset-paged.
                let mut candidates: Vec<_> = Self::read_json_archive(path, pool_address)
                    .into_iter()
                    .filter(|env| {
                        env.seq > after_seq && env.seq <= target_seq && env.seq < before_seq
                    })
                    .collect();
                candidates.sort_by_key(|env| env.seq);
                let end = batch_page_end(
                    &candidates.iter().map(|env| env.seq).collect::<Vec<_>>(),
                    limit,
                );
                let has_more = end < candidates.len();
                candidates.truncate(end);
                Ok(ArchivedBatchPage {
                    envelopes: candidates,
                    has_more,
                })
            }
            StateBackend::Json(None) => Ok(ArchivedBatchPage {
                envelopes: Vec::new(),
                has_more: false,
            }),
            StateBackend::Pgsql(pool) => {
                let after_seq = pg_archive_seq_bound(after_seq);
                let target_seq = pg_archive_seq_bound(target_seq);
                let before_seq = pg_archive_seq_bound(before_seq);
                let sql_limit = i64::try_from(limit).context("batch page limit exceeds i64")?;
                let mut rows: Vec<NoteRow> = sqlx::query_as(&format!(
                    "SELECT {NOTE_SELECT_COLUMNS} FROM notes \
                     WHERE pool_address=$1 AND seq > $2 AND seq <= $3 AND seq < $4 \
                     ORDER BY seq, cmx_hex LIMIT $5"
                ))
                .bind(pool_address)
                .bind(after_seq)
                .bind(target_seq)
                .bind(before_seq)
                .bind(sql_limit)
                .fetch_all(pool)
                .await
                .context("load bounded archived batch page")?;

                let mut has_more = false;
                if rows.len() == limit {
                    let boundary_seq = rows.last().map(|row| row.1).unwrap_or(after_seq);
                    let boundary_cmx = rows.last().map(|row| row.0.clone()).unwrap_or_default();
                    let mut boundary_tail: Vec<NoteRow> = sqlx::query_as(&format!(
                        "SELECT {NOTE_SELECT_COLUMNS} FROM notes \
                         WHERE pool_address=$1 AND seq=$2 AND cmx_hex > $3 \
                         ORDER BY cmx_hex"
                    ))
                    .bind(pool_address)
                    .bind(boundary_seq)
                    .bind(boundary_cmx)
                    .fetch_all(pool)
                    .await
                    .context("extend archived page through equal-sequence boundary")?;
                    rows.append(&mut boundary_tail);
                    has_more = sqlx::query_scalar::<_, bool>(
                        "SELECT EXISTS(SELECT 1 FROM notes \
                         WHERE pool_address=$1 AND seq > $2 AND seq <= $3 AND seq < $4)",
                    )
                    .bind(pool_address)
                    .bind(boundary_seq)
                    .bind(target_seq)
                    .bind(before_seq)
                    .fetch_one(pool)
                    .await
                    .context("check archived batch page continuation")?;
                }
                Ok(ArchivedBatchPage {
                    envelopes: note_rows_into_envelopes(rows, pool_address),
                    has_more,
                })
            }
        }
    }

    /// Bounded archive page for the explorer's block cursor. The final block is
    /// always complete, even when that soft-extends `limit`.
    async fn load_archived_batches_before_block(
        &self,
        pool_address: &str,
        before_block: u64,
        limit: usize,
    ) -> Result<ArchivedBatchPage> {
        match self {
            StateBackend::Json(Some(path)) => {
                let mut candidates: Vec<_> = Self::read_json_archive(path, pool_address)
                    .into_iter()
                    .filter(|env| {
                        env.batch
                            .abi_notes
                            .first()
                            .is_some_and(|note| note.block_number < before_block)
                    })
                    .collect();
                candidates.sort_by(|left, right| {
                    let left_note = left.batch.abi_notes.first();
                    let right_note = right.batch.abi_notes.first();
                    right_note
                        .map(|note| (note.block_number, note.log_index))
                        .cmp(&left_note.map(|note| (note.block_number, note.log_index)))
                });
                let mut end = limit.min(candidates.len());
                if end > 0 && end < candidates.len() {
                    let boundary = candidates[end - 1].batch.abi_notes[0].block_number;
                    while end < candidates.len()
                        && candidates[end].batch.abi_notes[0].block_number == boundary
                    {
                        end += 1;
                    }
                }
                let has_more = end < candidates.len();
                candidates.truncate(end);
                Ok(ArchivedBatchPage {
                    envelopes: candidates,
                    has_more,
                })
            }
            StateBackend::Json(None) => Ok(ArchivedBatchPage {
                envelopes: Vec::new(),
                has_more: false,
            }),
            StateBackend::Pgsql(pool) => {
                let before_block = pg_archive_seq_bound(before_block);
                let sql_limit = i64::try_from(limit).context("tx history limit exceeds i64")?;
                let mut rows: Vec<NoteRow> = sqlx::query_as(&format!(
                    "SELECT {NOTE_SELECT_COLUMNS} FROM notes \
                     WHERE pool_address=$1 AND block_number < $2 \
                     ORDER BY block_number DESC, log_index DESC, cmx_hex LIMIT $3"
                ))
                .bind(pool_address)
                .bind(before_block)
                .bind(sql_limit)
                .fetch_all(pool)
                .await
                .context("load bounded transaction history")?;
                let mut has_more = false;
                if rows.len() == limit {
                    let boundary_block = rows.last().map(|row| row.2).unwrap_or(before_block);
                    rows.retain(|row| row.2 != boundary_block);
                    let mut boundary_rows: Vec<NoteRow> = sqlx::query_as(&format!(
                        "SELECT {NOTE_SELECT_COLUMNS} FROM notes \
                         WHERE pool_address=$1 AND block_number=$2 \
                         ORDER BY log_index DESC, cmx_hex"
                    ))
                    .bind(pool_address)
                    .bind(boundary_block)
                    .fetch_all(pool)
                    .await
                    .context("extend transaction history through block boundary")?;
                    rows.append(&mut boundary_rows);
                    has_more = sqlx::query_scalar::<_, bool>(
                        "SELECT EXISTS(SELECT 1 FROM notes \
                         WHERE pool_address=$1 AND block_number < $2)",
                    )
                    .bind(pool_address)
                    .bind(boundary_block)
                    .fetch_one(pool)
                    .await
                    .context("check transaction history continuation")?;
                }
                Ok(ArchivedBatchPage {
                    envelopes: note_rows_into_envelopes(rows, pool_address),
                    has_more,
                })
            }
        }
    }

    /// Read + decode the whole JSON note archive. JSON mode is a development
    /// backend: this is O(total history) per call, which is why production must
    /// run on PostgreSQL (see `load_note_by_cmx` / `load_notes_by_tx_hash`).
    fn read_json_archive(path: &str, pool_address: &str) -> Vec<BatchEnvelope> {
        match std::fs::read_to_string(Self::json_archive_path(path)) {
            Ok(raw) => decode_json_note_archive(&raw, pool_address),
            Err(_) => Vec::new(),
        }
    }

    fn read_json_frozen_updates(path: &str) -> Vec<(u64, FrozenUpdate)> {
        Self::read_json_frozen_updates_at(&Self::json_archive_path(path))
    }

    fn read_json_frozen_updates_at(archive_path: &str) -> Vec<(u64, FrozenUpdate)> {
        let Ok(raw) = std::fs::read_to_string(archive_path) else {
            return Vec::new();
        };
        let mut updates = Vec::new();
        for line in raw.lines() {
            if let Ok(JsonNoteArchiveUpdate::Frozen { position, update }) =
                serde_json::from_str::<JsonNoteArchiveUpdate>(line)
            {
                updates.push((position, update));
            }
        }
        updates.sort_by_key(|(position, _)| *position);
        updates
    }

    /// Read the persisted membership of only the requested frozen commitments.
    /// Production executes one indexed query; JSON remains a development-only
    /// full replay and never affects the PostgreSQL memory bound.
    async fn load_frozen_membership(
        &self,
        pool_address: &str,
        rebuild_generation: Option<&str>,
        wanted: &HashSet<String>,
    ) -> Result<HashSet<String>> {
        if wanted.is_empty() {
            return Ok(HashSet::new());
        }
        match self {
            StateBackend::Json(Some(path)) => {
                let archive_path = if rebuild_generation.is_some() {
                    Self::json_rebuild_archive_path(path)
                } else {
                    Self::json_archive_path(path)
                };
                let updates: Vec<_> = Self::read_json_frozen_updates_at(&archive_path)
                    .into_iter()
                    .map(|(_, update)| update)
                    .collect();
                Ok(replay_frozen_set(&updates)
                    .into_iter()
                    .filter(|cmx| wanted.contains(cmx))
                    .collect())
            }
            StateBackend::Json(None) => Ok(HashSet::new()),
            StateBackend::Pgsql(pool) => {
                let wanted: Vec<String> = wanted.iter().cloned().collect();
                let rows: Vec<String> = if let Some(generation) = rebuild_generation {
                    sqlx::query_scalar(
                        "SELECT cmx_hex FROM frozen_current_rebuild \
                         WHERE pool_address=$1 AND rebuild_generation=$2 \
                           AND cmx_hex = ANY($3::text[])",
                    )
                    .bind(pool_address)
                    .bind(generation)
                    .bind(&wanted)
                    .fetch_all(pool)
                    .await
                    .context("load staged frozen membership")?
                } else {
                    sqlx::query_scalar(
                        "SELECT cmx_hex FROM frozen_current \
                         WHERE pool_address=$1 AND cmx_hex = ANY($2::text[])",
                    )
                    .bind(pool_address)
                    .bind(&wanted)
                    .fetch_all(pool)
                    .await
                    .context("load frozen membership")?
                };
                Ok(rows.into_iter().collect())
            }
        }
    }

    /// Point lookup of one archived note by cmx.
    ///
    /// The in-memory ring only holds the most recent `max_batches` envelopes, so a
    /// ring scan alone answers `/note` with a false 404 for any note the ring has
    /// already evicted. `notes` is keyed by `(pool_address, cmx_hex)`, so on
    /// PostgreSQL this is a primary-key hit — cheaper than the ring scan it backs up.
    /// `rebuild_generation` selects the staging table a canonical rebuild writes
    /// to. Passing `None` during a rebuild would read the *previous* generation:
    /// same cmx means the same note, so the payload would still be correct, but
    /// the read is kept inside the active generation so an isolated rebuild stays
    /// isolated.
    async fn load_note_by_cmx(
        &self,
        pool_address: &str,
        rebuild_generation: Option<&str>,
        cmx: [u8; 32],
    ) -> Option<OrchardIndexedAbiNote> {
        match self {
            StateBackend::Json(Some(path)) => {
                let path = match rebuild_generation {
                    Some(_) => Self::json_rebuild_archive_path(path),
                    None => Self::json_archive_path(path),
                };
                let raw = std::fs::read_to_string(path).ok()?;
                decode_json_note_archive(&raw, pool_address)
                    .into_iter()
                    .find_map(|env| env.batch.abi_notes.into_iter().find(|note| note.cmx == cmx))
            }
            StateBackend::Json(None) => None,
            StateBackend::Pgsql(pool) => {
                let row: Option<NoteRow> = match rebuild_generation {
                    Some(generation) => sqlx::query_as(&format!(
                        "SELECT {NOTE_SELECT_COLUMNS} FROM notes_rebuild \
                           WHERE pool_address=$1 AND rebuild_generation=$2 AND cmx_hex=$3"
                    ))
                    .bind(pool_address)
                    .bind(generation)
                    .bind(hex::encode(cmx))
                    .fetch_optional(pool)
                    .await,
                    None => sqlx::query_as(&format!(
                        "SELECT {NOTE_SELECT_COLUMNS} FROM notes WHERE pool_address=$1 AND cmx_hex=$2"
                    ))
                    .bind(pool_address)
                    .bind(hex::encode(cmx))
                    .fetch_optional(pool)
                    .await,
                }
                .ok()
                .flatten();
                row.and_then(note_row_into_note)
            }
        }
    }

    /// Every archived note added by one transaction, oldest first.
    ///
    /// `tx_hash` is stored verbatim as it came off the log, so both sides are
    /// normalised the same way the in-memory scan normalises them. The PostgreSQL
    /// predicate matches `notes_tx_hash_idx` (`lower(tx_hash)`, migration 0007) —
    /// changing it without changing the index turns this into a sequential scan.
    async fn load_notes_by_tx_hash(
        &self,
        pool_address: &str,
        tx_hash: &str,
    ) -> Vec<OrchardIndexedAbiNote> {
        let want = normalize_hex_0x(tx_hash).to_lowercase();
        match self {
            StateBackend::Json(Some(path)) => Self::read_json_archive(path, pool_address)
                .into_iter()
                .flat_map(|env| env.batch.abi_notes)
                .filter(|note| normalize_hex_0x(&note.tx_hash).to_lowercase() == want)
                .collect(),
            StateBackend::Json(None) => Vec::new(),
            StateBackend::Pgsql(pool) => {
                // Accept either storage convention (`0x`-prefixed or bare) so the
                // lookup cannot miss rows written before any normalisation existed.
                let candidates = vec![want.clone(), strip_0x(&want).to_owned()];
                let rows: Vec<NoteRow> = sqlx::query_as(&format!(
                    "SELECT {NOTE_SELECT_COLUMNS} FROM notes WHERE pool_address=$1 \
                       AND lower(tx_hash) = ANY($2::text[]) ORDER BY seq"
                ))
                .bind(pool_address)
                .bind(&candidates)
                .fetch_all(pool)
                .await
                .unwrap_or_default();
                rows.into_iter().filter_map(note_row_into_note).collect()
            }
        }
    }

    /// Load a contiguous, bounded leaf window for crank planning. Production
    /// PostgreSQL applies the range and limit before decoding, so pending-CMX
    /// planning never materializes historical leaves in the process.
    async fn load_cmx_range(
        &self,
        pool_address: &str,
        start: u64,
        limit: usize,
    ) -> Result<Vec<[u8; 32]>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let start_i64 = i64::try_from(start).context("cmx range start exceeds i64")?;
        match self {
            StateBackend::Json(Some(path)) => {
                let mut positioned: Vec<_> = Self::read_json_archive(path, pool_address)
                    .into_iter()
                    .flat_map(|envelope| envelope.batch.abi_notes)
                    .filter_map(|note| note.cmx_position.map(|position| (position, note.cmx)))
                    .filter(|(position, _)| *position >= start)
                    .collect();
                positioned.sort_unstable_by_key(|(position, _)| *position);
                positioned.truncate(limit);
                let mut leaves = Vec::with_capacity(positioned.len());
                for (offset, (position, cmx)) in positioned.into_iter().enumerate() {
                    let expected = start.saturating_add(offset as u64);
                    if position != expected {
                        bail!(
                            "JSON cmx archive is not contiguous at position {expected}: found {position}"
                        );
                    }
                    leaves.push(cmx);
                }
                Ok(leaves)
            }
            StateBackend::Json(None) => Ok(Vec::new()),
            StateBackend::Pgsql(pool) => {
                let sql_limit = i64::try_from(limit).context("cmx range limit exceeds i64")?;
                let rows: Vec<(i64, String)> = sqlx::query_as(
                    "SELECT position, cmx_hex FROM cmx_leaves \
                     WHERE pool_address=$1 AND position >= $2 \
                     ORDER BY position LIMIT $3",
                )
                .bind(pool_address)
                .bind(start_i64)
                .bind(sql_limit)
                .fetch_all(pool)
                .await
                .context("load bounded cmx range")?;
                let mut leaves = Vec::with_capacity(rows.len());
                for (offset, (position, encoded)) in rows.into_iter().enumerate() {
                    let expected = start_i64
                        .checked_add(offset as i64)
                        .context("cmx range position overflow")?;
                    if position != expected {
                        bail!(
                            "cmx archive is not contiguous at position {expected}: found {position}"
                        );
                    }
                    leaves.push(
                        parse_hex32(&encoded)
                            .ok_or_else(|| anyhow!("invalid cmx at position {position}"))?,
                    );
                }
                Ok(leaves)
            }
        }
    }

    /// Load one contiguous confirmed-leaf page and whether each cmx already has
    /// a durable frozen path. PostgreSQL answers both pieces in one indexed
    /// round-trip, avoiding the historical N+1 point-query pattern.
    async fn load_cmx_freeze_page(
        &self,
        pool_address: &str,
        start: u64,
        limit: usize,
    ) -> Result<Vec<(u64, [u8; 32], bool)>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        match self {
            StateBackend::Pgsql(pool) => {
                let start_i64 = i64::try_from(start).context("freeze page start exceeds i64")?;
                let limit_i64 = i64::try_from(limit).context("freeze page limit exceeds i64")?;
                let rows: Vec<(i64, String, bool)> = sqlx::query_as(
                    "SELECT leaf.position, leaf.cmx_hex, path.cmx_hex IS NOT NULL \
                     FROM cmx_leaves AS leaf \
                     LEFT JOIN frozen_paths AS path \
                       ON path.pool_address=leaf.pool_address AND path.cmx_hex=leaf.cmx_hex \
                     WHERE leaf.pool_address=$1 AND leaf.position >= $2 \
                     ORDER BY leaf.position LIMIT $3",
                )
                .bind(pool_address)
                .bind(start_i64)
                .bind(limit_i64)
                .fetch_all(pool)
                .await
                .context("load frozen-path maintenance page")?;
                let mut page = Vec::with_capacity(rows.len());
                for (offset, (position, cmx_hex, frozen)) in rows.into_iter().enumerate() {
                    let expected = start_i64
                        .checked_add(offset as i64)
                        .context("freeze page position overflow")?;
                    if position != expected {
                        bail!(
                            "cmx archive is not contiguous at freeze position {expected}: found {position}"
                        );
                    }
                    page.push((
                        u64::try_from(position).context("negative freeze page position")?,
                        parse_hex32(&cmx_hex)
                            .ok_or_else(|| anyhow!("invalid cmx at position {position}"))?,
                        frozen,
                    ));
                }
                Ok(page)
            }
            StateBackend::Json(_) => {
                let leaves = self.load_cmx_range(pool_address, start, limit).await?;
                let mut page = Vec::with_capacity(leaves.len());
                for (offset, cmx) in leaves.into_iter().enumerate() {
                    let frozen = self.load_frozen_path(pool_address, cmx).await?.is_some();
                    page.push((start + offset as u64, cmx, frozen));
                }
                Ok(page)
            }
        }
    }

    /// Count missing frozen paths only inside the pinned confirmed prefix. A
    /// total table count is insufficient because concurrently frozen newer cmxs
    /// could otherwise hide a historical gap.
    async fn count_missing_frozen_paths(
        &self,
        pool_address: &str,
        confirmed_count: u64,
    ) -> Result<u64> {
        match self {
            StateBackend::Pgsql(pool) => {
                let bound =
                    i64::try_from(confirmed_count).context("confirmed freeze bound exceeds i64")?;
                let count: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM cmx_leaves AS leaf \
                     LEFT JOIN frozen_paths AS path \
                       ON path.pool_address=leaf.pool_address AND path.cmx_hex=leaf.cmx_hex \
                     WHERE leaf.pool_address=$1 AND leaf.position < $2 AND path.cmx_hex IS NULL",
                )
                .bind(pool_address)
                .bind(bound)
                .fetch_one(pool)
                .await
                .context("count missing frozen paths in confirmed prefix")?;
                u64::try_from(count).context("negative missing frozen-path count")
            }
            StateBackend::Json(_) => {
                let mut missing = 0u64;
                let mut start = 0u64;
                while start < confirmed_count {
                    let page = self
                        .load_cmx_freeze_page(
                            pool_address,
                            start,
                            (confirmed_count - start).min(1_024) as usize,
                        )
                        .await?;
                    if page.is_empty() {
                        bail!("confirmed cmx archive ends before position {start}");
                    }
                    missing += page.iter().filter(|(_, _, frozen)| !*frozen).count() as u64;
                    start += page.len() as u64;
                }
                Ok(missing)
            }
        }
    }

    /// Point lookup used to distinguish unknown, pending and confirmed cmxs
    /// when a durable frozen-path lookup misses.
    async fn load_cmx_position(&self, pool_address: &str, cmx: [u8; 32]) -> Result<Option<u64>> {
        match self {
            StateBackend::Json(Some(path)) => Ok(Self::read_json_archive(path, pool_address)
                .into_iter()
                .flat_map(|envelope| envelope.batch.abi_notes)
                .find(|note| note.cmx == cmx)
                .and_then(|note| note.cmx_position)),
            StateBackend::Json(None) => Ok(None),
            StateBackend::Pgsql(pool) => {
                let position: Option<i64> = sqlx::query_scalar(
                    "SELECT position FROM notes WHERE pool_address=$1 AND cmx_hex=$2",
                )
                .bind(pool_address)
                .bind(hex::encode(cmx))
                .fetch_optional(pool)
                .await
                .context("load cmx position")?;
                position
                    .map(|value| u64::try_from(value).context("negative cmx position"))
                    .transpose()
            }
        }
    }

    /// Fetch only the immutable complete nodes needed for one authentication
    /// path. The PostgreSQL query is one bounded round trip (normally tens of
    /// rows), independent of total tree size.
    async fn load_merkle_nodes(
        &self,
        pool_address: &str,
        keys: &[MerkleNodeKey],
    ) -> Result<HashMap<MerkleNodeKey, [u8; 32]>> {
        if keys.is_empty() {
            return Ok(HashMap::new());
        }
        match self {
            StateBackend::Json(Some(path)) => {
                // JSON is a development-only backend. Preserve endpoint behavior
                // without retaining a tree between requests; production uses the
                // indexed PostgreSQL node archive below.
                let wanted: HashSet<_> = keys.iter().copied().collect();
                let mut positioned: Vec<_> = Self::read_json_archive(path, pool_address)
                    .into_iter()
                    .flat_map(|envelope| envelope.batch.abi_notes)
                    .filter(|note| note.is_confirmed)
                    .filter_map(|note| note.cmx_position.map(|position| (position, note.cmx)))
                    .collect();
                positioned.sort_unstable_by_key(|(position, _)| *position);
                let mut builder = StreamingFrontierBuilder::new();
                let mut found = HashMap::with_capacity(keys.len());
                for (expected, (position, cmx)) in positioned.into_iter().enumerate() {
                    if position != expected as u64 {
                        bail!(
                            "JSON confirmed archive is not contiguous at position {expected}: found {position}"
                        );
                    }
                    for node in builder.push_nonfinal_be(cmx)? {
                        if wanted.contains(&node.key) {
                            found.insert(node.key, node.hash_be);
                        }
                    }
                }
                Ok(found)
            }
            StateBackend::Json(None) => Ok(HashMap::new()),
            StateBackend::Pgsql(pool) => {
                let levels: Vec<i16> = keys.iter().map(|key| i16::from(key.level)).collect();
                let indices: Vec<i64> = keys
                    .iter()
                    .map(|key| i64::try_from(key.index).context("Merkle node index exceeds i64"))
                    .collect::<Result<_>>()?;
                let rows: Vec<(i16, i64, String)> = sqlx::query_as(
                    // Keep the requested key set on the outer side and force one
                    // composite-PK probe per key. A plain JOIN lets PostgreSQL
                    // choose merkle_nodes as the outer relation; at production
                    // scale that degenerates into a multi-million-row scan for
                    // every freeze page despite the exact primary key.
                    "SELECT node.level, node.node_index, node.hash_hex \
                     FROM UNNEST($2::smallint[], $3::bigint[]) AS wanted(level, node_index) \
                     CROSS JOIN LATERAL ( \
                       SELECT stored.level, stored.node_index, stored.hash_hex \
                       FROM merkle_nodes AS stored \
                       WHERE stored.pool_address=$1 \
                         AND stored.level=wanted.level \
                         AND stored.node_index=wanted.node_index \
                       LIMIT 1 \
                     ) AS node",
                )
                .bind(pool_address)
                .bind(&levels)
                .bind(&indices)
                .fetch_all(pool)
                .await
                .context("load bounded Merkle witness nodes")?;
                let mut found = HashMap::with_capacity(rows.len());
                for (level, index, encoded) in rows {
                    let key = MerkleNodeKey {
                        level: u8::try_from(level).context("invalid archived Merkle level")?,
                        index: u64::try_from(index).context("negative archived Merkle index")?,
                    };
                    let hash = parse_hex32(&encoded)
                        .ok_or_else(|| anyhow!("invalid archived Merkle node {level}/{index}"))?;
                    if found.insert(key, hash).is_some() {
                        bail!("duplicate archived Merkle node {level}/{index}");
                    }
                }
                Ok(found)
            }
        }
    }

    /// Number of durable frozen-path rows for a pool (live table / JSON archive).
    #[cfg(test)]
    async fn count_frozen_paths(&self, pool_address: &str) -> Result<u64> {
        match self {
            StateBackend::Json(Some(path)) => {
                let archive_path = Self::json_archive_path(path);
                let Ok(raw) = std::fs::read_to_string(archive_path) else {
                    return Ok(0);
                };
                let mut by_cmx = HashSet::new();
                for line in raw.lines() {
                    if let Ok(JsonNoteArchiveUpdate::FrozenPath(record)) =
                        serde_json::from_str::<JsonNoteArchiveUpdate>(line)
                    {
                        by_cmx.insert(record.cmx);
                    }
                }
                Ok(by_cmx.len() as u64)
            }
            StateBackend::Json(None) => Ok(0),
            StateBackend::Pgsql(pool) => {
                let count: i64 =
                    sqlx::query_scalar("SELECT count(*) FROM frozen_paths WHERE pool_address=$1")
                        .bind(pool_address)
                        .fetch_one(pool)
                        .await
                        .context("count frozen Merkle paths")?;
                Ok(u64::try_from(count).unwrap_or(0))
            }
        }
    }

    /// Point lookup of one segment-end frozen path record. Serving reads never
    /// mutate the store, so repeated GETs stay byte-identical (idempotency
    /// contract of `/merkle_path` in docs/note-sync-indexer-frozen-merkle-path.md).
    async fn load_frozen_path(
        &self,
        pool_address: &str,
        cmx: [u8; 32],
    ) -> Result<Option<FrozenPathRecord>> {
        match self {
            StateBackend::Json(Some(path)) => {
                let archive_path = Self::json_archive_path(path);
                let Ok(raw) = std::fs::read_to_string(archive_path) else {
                    return Ok(None);
                };
                let mut found = None;
                for line in raw.lines() {
                    if let Ok(JsonNoteArchiveUpdate::FrozenPath(record)) =
                        serde_json::from_str::<JsonNoteArchiveUpdate>(line)
                    {
                        if record.cmx == cmx {
                            found = Some(record);
                        }
                    }
                }
                Ok(found)
            }
            StateBackend::Json(None) => Ok(None),
            StateBackend::Pgsql(pool) => {
                let row: Option<(i64, String, String)> = sqlx::query_as(
                    "SELECT position, siblings_json, anchor_root_hex FROM frozen_paths \
                     WHERE pool_address=$1 AND cmx_hex=$2",
                )
                .bind(pool_address)
                .bind(hex::encode(cmx))
                .fetch_optional(pool)
                .await
                .context("load frozen Merkle path")?;
                let Some((position, siblings_json, anchor_root_hex)) = row else {
                    return Ok(None);
                };
                let siblings: Vec<String> = serde_json::from_str(&siblings_json)
                    .context("decode archived frozen path siblings")?;
                let anchor_root = parse_hex32(&anchor_root_hex)
                    .ok_or_else(|| anyhow!("invalid archived frozen path anchor root"))?;
                Ok(Some(FrozenPathRecord {
                    cmx,
                    position: u64::try_from(position).context("negative frozen path position")?,
                    siblings,
                    anchor_root,
                }))
            }
        }
    }

    async fn load_frozen_updates_after(
        &self,
        pool_address: &str,
        after: Option<(u64, u64)>,
        limit: usize,
    ) -> Result<Vec<FrozenUpdate>> {
        let limit = limit.clamp(1, MAX_FROZEN_UPDATE_PAGE);
        match self {
            StateBackend::Json(Some(path)) => Ok(Self::read_json_frozen_updates(path)
                .into_iter()
                .map(|(_, update)| update)
                .filter(|update| {
                    after.is_none_or(|cursor| (update.block_number, update.log_index) > cursor)
                })
                .take(limit)
                .collect()),
            StateBackend::Json(None) => Ok(Vec::new()),
            StateBackend::Pgsql(pool) => {
                let (after_block, after_log) = after.unwrap_or((0, 0));
                let rows: Vec<(String,)> = sqlx::query_as(
                    "SELECT update_json FROM frozen_updates \
                     WHERE pool_address=$1 \
                       AND ($2::boolean OR (block_number, log_index) > ($3,$4)) \
                     ORDER BY block_number, log_index LIMIT $5",
                )
                .bind(pool_address)
                .bind(after.is_none())
                .bind(after_block as i64)
                .bind(after_log as i64)
                .bind(limit as i64)
                .fetch_all(pool)
                .await
                .context("load bounded frozen update page")?;
                rows.into_iter()
                    .map(|(encoded,)| {
                        serde_json::from_str(&encoded).context("decode archived frozen update")
                    })
                    .collect()
            }
        }
    }

    async fn load_frozen_leaves(&self, pool_address: &str, limit: usize) -> Result<Vec<String>> {
        match self {
            StateBackend::Json(Some(path)) => {
                let updates: Vec<_> = Self::read_json_frozen_updates(path)
                    .into_iter()
                    .map(|(_, update)| update)
                    .collect();
                let leaves = replay_frozen_set(&updates);
                if leaves.len() > limit {
                    bail!("frozen leaf response exceeds configured limit {limit}");
                }
                Ok(leaves)
            }
            StateBackend::Json(None) => Ok(Vec::new()),
            StateBackend::Pgsql(pool) => {
                let sql_limit = i64::try_from(limit.saturating_add(1))
                    .context("frozen leaf limit exceeds i64")?;
                let mut leaves: Vec<String> = sqlx::query_scalar(
                    "SELECT cmx_hex FROM frozen_current WHERE pool_address=$1 \
                     ORDER BY cmx_hex LIMIT $2",
                )
                .bind(pool_address)
                .bind(sql_limit)
                .fetch_all(pool)
                .await
                .context("load bounded frozen current set")?;
                if leaves.len() > limit {
                    bail!("frozen leaf response exceeds configured limit {limit}");
                }
                for leaf in &mut leaves {
                    let cmx = parse_hex32(leaf)
                        .ok_or_else(|| anyhow!("invalid materialized frozen cmx"))?;
                    *leaf = format!("0x{}", hex::encode(cmx));
                }
                Ok(leaves)
            }
        }
    }

    /// Upgrade a sealed v1 PostgreSQL checkpoint to the compact v2 format
    /// without replaying chain history. JSON checkpoints are development-only
    /// and retain their existing compatibility conversion.
    async fn upgrade_legacy_compact_checkpoint(
        &self,
        pool_address: &str,
        start_block: u64,
    ) -> Result<bool> {
        match self {
            StateBackend::Pgsql(pool) => {
                pg_upgrade_legacy_compact_checkpoint(pool, pool_address, start_block).await
            }
            StateBackend::Json(_) => Ok(false),
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
        if !snap.is_complete_finalized_boundary() {
            return Err(anyhow!(
                "refusing to save an incomplete finalized checkpoint for {pool_address}"
            ));
        }
        match self {
            StateBackend::Json(Some(path)) => save_checkpoint(path, snap),
            StateBackend::Json(None) => Ok(()),
            StateBackend::Pgsql(pool) => pg_save(pool, pool_address, snap).await,
        }
    }
}

fn pg_archive_seq_bound(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
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
            JsonNoteArchiveUpdate::Frozen { .. } => {}
            JsonNoteArchiveUpdate::FrozenPath(_) => {}
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
        tree_frontier: CompactFrontier::new(),
        active_root: None,
        confirmed_count: 0,
        confirmed_frontier: CompactFrontier::new(),
        last_leaf_key: None,
        warm_start_candidate: false,
        latest_seq: 0,
        batches: VecDeque::new(),
        pending_tx_hashes: VecDeque::new(),
        frozen_root_hex: format!("0x{}", "00".repeat(32)),
        frozen_count: 0,
        frozen_update_count: 0,
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
        if self.read_only
            || self.is_paused()
            || s.pending_root_update.is_some()
            || !checkpoint_is_complete_finalized_boundary(
                s.next_block,
                s.last_finalized_block,
                s.last_finalized_block_hash.as_deref(),
            )
        {
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
        if self.read_only || self.is_paused() || !snap.is_complete_finalized_boundary() {
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
    merkle_nodes: Vec<MerkleNode>,
    shield_amounts: Vec<([u8; 32], u64)>,
    frozen_updates: Vec<(u64, FrozenUpdate)>,
    frozen_paths: Vec<FrozenPathRecord>,
}

fn compact_note_mutations(mutations: &[NoteArchiveMutation]) -> CompactedNoteMutations {
    let mut upserts: HashMap<[u8; 32], ArchivedNoteRow> = HashMap::new();
    let mut confirmations: HashMap<[u8; 32], u64> = HashMap::new();
    let mut merkle_nodes: HashMap<MerkleNodeKey, MerkleNode> = HashMap::new();
    let mut shield_amounts: HashMap<[u8; 32], u64> = HashMap::new();
    let mut frozen_updates: HashMap<u64, FrozenUpdate> = HashMap::new();
    let mut frozen_paths: HashMap<[u8; 32], FrozenPathRecord> = HashMap::new();
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
            NoteArchiveMutation::Confirm {
                cmx,
                position,
                nodes,
            } => {
                confirmations.insert(*cmx, *position);
                for node in nodes {
                    merkle_nodes.insert(node.key, *node);
                }
            }
            NoteArchiveMutation::ShieldAmount { cmx, amount } => {
                shield_amounts.insert(*cmx, *amount);
            }
            NoteArchiveMutation::Frozen { position, update } => {
                frozen_updates.insert(*position, update.clone());
            }
            NoteArchiveMutation::FrozenPaths(records) => {
                for record in records {
                    frozen_paths.insert(record.cmx, record.clone());
                }
            }
        }
    }
    let mut upserts: Vec<ArchivedNoteRow> = upserts.into_values().collect();
    upserts.sort_by_key(|row| row.seq);
    let mut confirmations: Vec<([u8; 32], u64)> = confirmations.into_iter().collect();
    confirmations.sort_by_key(|(cmx, _)| *cmx);
    let mut merkle_nodes: Vec<MerkleNode> = merkle_nodes.into_values().collect();
    merkle_nodes.sort_by_key(|node| node.key);
    let mut shield_amounts: Vec<([u8; 32], u64)> = shield_amounts.into_iter().collect();
    shield_amounts.sort_by_key(|(cmx, _)| *cmx);
    let mut frozen_updates: Vec<(u64, FrozenUpdate)> = frozen_updates.into_iter().collect();
    frozen_updates.sort_by_key(|(position, _)| *position);
    let mut frozen_paths: Vec<FrozenPathRecord> = frozen_paths.into_values().collect();
    frozen_paths.sort_by_key(|record| record.position);
    CompactedNoteMutations {
        upserts,
        confirmations,
        merkle_nodes,
        shield_amounts,
        frozen_updates,
        frozen_paths,
    }
}

const NOTE_COLUMNS: &str = "\
pool_address, cmx_hex, seq, block_number, tx_hash, log_index, position, \
enc_ciphertext_hex, epk_hex, out_ciphertext_hex, cv_net_x_hex, nf_old_hex, ack_hash_hex, \
shield_amount_sats, is_confirmed";

/// Column list for every note read, in the order `NoteRow` decodes them — the two
/// must be changed together. `notes` and `notes_rebuild` share these columns.
const NOTE_SELECT_COLUMNS: &str = "\
cmx_hex, seq, block_number, tx_hash, log_index, position, \
enc_ciphertext_hex, epk_hex, out_ciphertext_hex, cv_net_x_hex, \
nf_old_hex, ack_hash_hex, shield_amount_sats, is_confirmed";

/// One note row in `NOTE_SELECT_COLUMNS` order.
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

/// Decode a `notes` row. Returns `None` for a row whose hex columns are malformed,
/// so one corrupt row cannot fail an entire query.
fn note_row_into_note(row: NoteRow) -> Option<OrchardIndexedAbiNote> {
    let (
        cmx_hex,
        _seq,
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
    ) = row;
    Some(OrchardIndexedAbiNote {
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
    })
}

/// Wrap `notes` rows back into the one-note-per-envelope shape `/batches` serves.
fn note_rows_into_envelopes(rows: Vec<NoteRow>, pool_address: &str) -> Vec<BatchEnvelope> {
    rows.into_iter()
        .filter_map(|row| {
            let seq = row.1 as u64;
            let note = note_row_into_note(row)?;
            Some(BatchEnvelope {
                seq,
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
            query.push(" ON CONFLICT (pool_address, rebuild_generation, cmx_hex) DO UPDATE SET ");
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

async fn pg_append_cmx_leaves(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pool_address: &str,
    rows: &[ArchivedNoteRow],
) -> Result<()> {
    let positioned: Vec<_> = rows
        .iter()
        .filter_map(|row| {
            row.note
                .cmx_position
                .map(|position| (position, row.note.cmx))
        })
        .collect();
    for chunk in positioned.chunks(500) {
        let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "INSERT INTO cmx_leaves (pool_address, position, cmx_hex) ",
        );
        query.push_values(chunk, |mut row, (position, cmx)| {
            row.push_bind(pool_address)
                .push_bind(*position as i64)
                .push_bind(hex::encode(cmx));
        });
        query.push(
            " ON CONFLICT (pool_address, position) DO UPDATE SET cmx_hex=EXCLUDED.cmx_hex \
             WHERE cmx_leaves.cmx_hex=EXCLUDED.cmx_hex",
        );
        let affected = query
            .build()
            .execute(&mut **tx)
            .await
            .context("append compact cmx leaves")?
            .rows_affected();
        if affected != chunk.len() as u64 {
            bail!("cmx leaf append conflicted with an existing position or commitment");
        }
    }
    Ok(())
}

async fn pg_append_merkle_nodes(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pool_address: &str,
    rebuild_generation: Option<&str>,
    nodes: &[MerkleNode],
) -> Result<()> {
    for chunk in nodes.chunks(500) {
        let prefix = if rebuild_generation.is_some() {
            "INSERT INTO merkle_nodes_rebuild \
             (pool_address, rebuild_generation, level, node_index, hash_hex) "
        } else {
            "INSERT INTO merkle_nodes (pool_address, level, node_index, hash_hex) "
        };
        let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(prefix);
        query.push_values(chunk, |mut row, node| {
            row.push_bind(pool_address);
            if let Some(generation) = rebuild_generation {
                row.push_bind(generation);
            }
            row.push_bind(node.key.level as i16)
                .push_bind(node.key.index as i64)
                .push_bind(hex::encode(node.hash_be));
        });
        if rebuild_generation.is_some() {
            query.push(
                " ON CONFLICT (pool_address, rebuild_generation, level, node_index) \
                 DO UPDATE SET hash_hex=EXCLUDED.hash_hex \
                 WHERE merkle_nodes_rebuild.hash_hex=EXCLUDED.hash_hex",
            );
        } else {
            query.push(
                " ON CONFLICT (pool_address, level, node_index) \
                 DO UPDATE SET hash_hex=EXCLUDED.hash_hex \
                 WHERE merkle_nodes.hash_hex=EXCLUDED.hash_hex",
            );
        }
        let affected = query
            .build()
            .execute(&mut **tx)
            .await
            .context("append complete Merkle nodes")?
            .rows_affected();
        if affected != chunk.len() as u64 {
            bail!("Merkle node archive conflicted with an existing hash");
        }
    }
    Ok(())
}

async fn pg_apply_frozen_updates(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pool_address: &str,
    rebuild_generation: Option<&str>,
    updates: &[(u64, FrozenUpdate)],
) -> Result<()> {
    for (position, update) in updates {
        if update.cmx_changed_hex.len() != update.is_add.len() {
            bail!("frozen update cmx/op length mismatch");
        }
        let encoded = serde_json::to_string(update).context("serialize frozen update")?;
        let affected = if let Some(generation) = rebuild_generation {
            sqlx::query(
                "INSERT INTO frozen_updates_rebuild \
                   (pool_address, rebuild_generation, position, block_number, log_index, update_json) \
                 VALUES ($1,$2,$3,$4,$5,$6) \
                 ON CONFLICT (pool_address, rebuild_generation, position) DO UPDATE SET \
                   block_number=EXCLUDED.block_number, log_index=EXCLUDED.log_index, \
                   update_json=EXCLUDED.update_json \
                 WHERE frozen_updates_rebuild.block_number=EXCLUDED.block_number \
                   AND frozen_updates_rebuild.log_index=EXCLUDED.log_index \
                   AND frozen_updates_rebuild.update_json=EXCLUDED.update_json",
            )
            .bind(pool_address)
            .bind(generation)
            .bind(*position as i64)
            .bind(update.block_number as i64)
            .bind(update.log_index as i64)
            .bind(&encoded)
            .execute(&mut **tx)
            .await
            .context("append staged frozen update")?
            .rows_affected()
        } else {
            sqlx::query(
                "INSERT INTO frozen_updates \
                   (pool_address, position, block_number, log_index, update_json) \
                 VALUES ($1,$2,$3,$4,$5) \
                 ON CONFLICT (pool_address, position) DO UPDATE SET \
                   block_number=EXCLUDED.block_number, log_index=EXCLUDED.log_index, \
                   update_json=EXCLUDED.update_json \
                 WHERE frozen_updates.block_number=EXCLUDED.block_number \
                   AND frozen_updates.log_index=EXCLUDED.log_index \
                   AND frozen_updates.update_json=EXCLUDED.update_json",
            )
            .bind(pool_address)
            .bind(*position as i64)
            .bind(update.block_number as i64)
            .bind(update.log_index as i64)
            .bind(&encoded)
            .execute(&mut **tx)
            .await
            .context("append frozen update")?
            .rows_affected()
        };
        if affected != 1 {
            bail!("frozen update conflicts with an existing archive position");
        }

        for (raw_cmx, is_add) in update.cmx_changed_hex.iter().zip(&update.is_add) {
            let cmx =
                parse_hex32(raw_cmx).ok_or_else(|| anyhow!("invalid frozen cmx in update"))?;
            let canonical = format!("0x{}", hex::encode(cmx));
            if let Some(generation) = rebuild_generation {
                if *is_add {
                    sqlx::query(
                        "INSERT INTO frozen_current_rebuild \
                           (pool_address, rebuild_generation, cmx_hex) VALUES ($1,$2,$3) \
                         ON CONFLICT DO NOTHING",
                    )
                    .bind(pool_address)
                    .bind(generation)
                    .bind(&canonical)
                    .execute(&mut **tx)
                    .await?
                    .rows_affected();
                } else {
                    sqlx::query(
                        "DELETE FROM frozen_current_rebuild \
                         WHERE pool_address=$1 AND rebuild_generation=$2 AND cmx_hex=$3",
                    )
                    .bind(pool_address)
                    .bind(generation)
                    .bind(&canonical)
                    .execute(&mut **tx)
                    .await?
                    .rows_affected();
                }
            } else if *is_add {
                sqlx::query(
                    "INSERT INTO frozen_current (pool_address, cmx_hex) VALUES ($1,$2) \
                     ON CONFLICT DO NOTHING",
                )
                .bind(pool_address)
                .bind(&canonical)
                .execute(&mut **tx)
                .await?
                .rows_affected();
            } else {
                sqlx::query("DELETE FROM frozen_current WHERE pool_address=$1 AND cmx_hex=$2")
                    .bind(pool_address)
                    .bind(&canonical)
                    .execute(&mut **tx)
                    .await?
                    .rows_affected();
            }
        }
    }
    Ok(())
}

/// Persist segment-end frozen path records. Writes are once-per-cmx: an exact
/// replay of the same sealed segment is a no-op, while a *different* record for
/// an already-frozen cmx (same commitment sealed under another anchor) is a
/// serious ingestion bug and fails the whole transaction — the conflicting
/// upsert matches zero rows because the `WHERE` guard requires byte equality.
async fn pg_apply_frozen_paths(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pool_address: &str,
    rebuild_generation: Option<&str>,
    records: &[FrozenPathRecord],
) -> Result<()> {
    if records.is_empty() {
        return Ok(());
    }
    let mut cmxs = Vec::with_capacity(records.len());
    let mut positions = Vec::with_capacity(records.len());
    let mut siblings = Vec::with_capacity(records.len());
    let mut roots = Vec::with_capacity(records.len());
    for record in records {
        cmxs.push(hex::encode(record.cmx));
        positions.push(i64::try_from(record.position).context("frozen path position exceeds i64")?);
        siblings.push(
            serde_json::to_string(&record.siblings).context("serialize frozen path siblings")?,
        );
        roots.push(hex::encode(record.anchor_root));
    }
    let affected = if let Some(generation) = rebuild_generation {
        sqlx::query(
            "WITH incoming(cmx_hex, position, siblings_json, anchor_root_hex) AS ( \
               SELECT * FROM UNNEST($3::text[], $4::bigint[], $5::text[], $6::text[]) \
             ) \
             INSERT INTO frozen_paths_rebuild \
               (pool_address, rebuild_generation, cmx_hex, position, siblings_json, anchor_root_hex) \
             SELECT $1, $2, cmx_hex, position, siblings_json, anchor_root_hex FROM incoming \
             ON CONFLICT (pool_address, rebuild_generation, cmx_hex) DO UPDATE SET \
               position=EXCLUDED.position, siblings_json=EXCLUDED.siblings_json, \
               anchor_root_hex=EXCLUDED.anchor_root_hex \
             WHERE frozen_paths_rebuild.position=EXCLUDED.position \
               AND frozen_paths_rebuild.siblings_json=EXCLUDED.siblings_json \
               AND frozen_paths_rebuild.anchor_root_hex=EXCLUDED.anchor_root_hex",
        )
        .bind(pool_address)
        .bind(generation)
        .bind(&cmxs)
        .bind(&positions)
        .bind(&siblings)
        .bind(&roots)
        .execute(&mut **tx)
        .await
        .context("bulk append staged frozen Merkle paths")?
        .rows_affected()
    } else {
        sqlx::query(
            "WITH incoming(cmx_hex, position, siblings_json, anchor_root_hex) AS ( \
               SELECT * FROM UNNEST($2::text[], $3::bigint[], $4::text[], $5::text[]) \
             ) \
             INSERT INTO frozen_paths \
               (pool_address, cmx_hex, position, siblings_json, anchor_root_hex) \
             SELECT $1, cmx_hex, position, siblings_json, anchor_root_hex FROM incoming \
             ON CONFLICT (pool_address, cmx_hex) DO UPDATE SET \
               position=EXCLUDED.position, siblings_json=EXCLUDED.siblings_json, \
               anchor_root_hex=EXCLUDED.anchor_root_hex \
             WHERE frozen_paths.position=EXCLUDED.position \
               AND frozen_paths.siblings_json=EXCLUDED.siblings_json \
               AND frozen_paths.anchor_root_hex=EXCLUDED.anchor_root_hex",
        )
        .bind(pool_address)
        .bind(&cmxs)
        .bind(&positions)
        .bind(&siblings)
        .bind(&roots)
        .execute(&mut **tx)
        .await
        .context("bulk append frozen Merkle paths")?
        .rows_affected()
    };
    if affected != records.len() as u64 {
        bail!(
            "frozen-path bulk write accepted {affected}/{} rows; an existing cmx conflicts under a different anchor",
            records.len()
        );
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
    if rebuild_generation.is_none() {
        pg_append_cmx_leaves(tx, pool_address, &compacted.upserts).await?;
    }
    pg_append_merkle_nodes(
        tx,
        pool_address,
        rebuild_generation,
        &compacted.merkle_nodes,
    )
    .await?;
    pg_apply_frozen_updates(
        tx,
        pool_address,
        rebuild_generation,
        &compacted.frozen_updates,
    )
    .await?;
    pg_apply_frozen_paths(
        tx,
        pool_address,
        rebuild_generation,
        &compacted.frozen_paths,
    )
    .await?;

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
                 WHERE n.pool_address=$1 AND n.rebuild_generation=$2 AND n.cmx_hex=u.cmx_hex \
                   AND n.position=u.position",
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
                 WHERE n.pool_address=$1 AND n.cmx_hex=u.cmx_hex AND n.position=u.position",
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
    sqlx::query("DELETE FROM merkle_nodes_rebuild WHERE pool_address=$1")
        .bind(pool_address)
        .execute(pool)
        .await
        .context("clear stale Merkle-node rebuild generations")?;
    sqlx::query("DELETE FROM frozen_updates_rebuild WHERE pool_address=$1")
        .bind(pool_address)
        .execute(pool)
        .await
        .context("clear stale frozen-update rebuild generations")?;
    sqlx::query("DELETE FROM frozen_current_rebuild WHERE pool_address=$1")
        .bind(pool_address)
        .execute(pool)
        .await
        .context("clear stale frozen-current rebuild generations")?;
    sqlx::query("DELETE FROM frozen_paths_rebuild WHERE pool_address=$1")
        .bind(pool_address)
        .execute(pool)
        .await
        .context("clear stale frozen-path rebuild generations")?;
    Ok(())
}

#[derive(Clone, Copy)]
enum SnapshotSaveMode {
    ReplaceDerivedState,
    AppendOnly,
}

async fn pg_save_snapshot_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pool_address: &str,
    snap: &CheckpointSnapshot,
    _mode: SnapshotSaveMode,
) -> Result<()> {
    let tree_frontier_hex: Vec<String> = snap
        .tree_frontier
        .filled_be()
        .into_iter()
        .map(hex::encode)
        .collect();
    let confirmed_frontier_hex: Vec<String> = snap
        .confirmed_frontier
        .filled_be()
        .into_iter()
        .map(hex::encode)
        .collect();
    sqlx::query(
        "INSERT INTO indexer_meta \
           (pool_address, next_block, active_root_hex, latest_seq, last_finalized_block, last_finalized_block_hash, \
            confirmed_count, last_leaf_block, last_leaf_log_index, tree_size, tree_root_hex, \
            tree_frontier_hex, confirmed_frontier_hex, frozen_root_hex, frozen_count, \
            frozen_update_count, checkpoint_version, updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,2, now()) \
         ON CONFLICT (pool_address) DO UPDATE SET \
           next_block=$2, active_root_hex=$3, latest_seq=$4, \
           last_finalized_block=$5, last_finalized_block_hash=$6, confirmed_count=$7, \
           last_leaf_block=$8, last_leaf_log_index=$9, tree_size=$10, tree_root_hex=$11, \
           tree_frontier_hex=$12, confirmed_frontier_hex=$13, frozen_root_hex=$14, \
           frozen_count=$15, frozen_update_count=$16, checkpoint_version=2, updated_at=now()",
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
    .bind(snap.tree_frontier.next_index() as i64)
    .bind(hex::encode(snap.tree_frontier.root_be()))
    .bind(&tree_frontier_hex)
    .bind(&confirmed_frontier_hex)
    .bind(&snap.frozen_root_hex)
    .bind(snap.frozen_count as i64)
    .bind(snap.frozen_update_count as i64)
    .execute(&mut **tx)
    .await
    .context("upsert indexer_meta")?;

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
          (pool_address, total_shielded_units, total_shielded_wei, total_unshielded_units, total_unshielded_wei, \
           total_fee_units, total_fee_wei, updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7, now()) \
         ON CONFLICT (pool_address) DO UPDATE SET \
          total_shielded_units=$2, total_shielded_wei=$3, total_unshielded_units=$4, total_unshielded_wei=$5, \
          total_fee_units=$6, total_fee_wei=$7, updated_at=now()",
    )
    .bind(pool_address)
    .bind(snap.shield_accounting.total_shielded_units.to_string())
    .bind(snap.shield_accounting.total_shielded_wei.to_string())
    .bind(snap.shield_accounting.total_unshielded_units.to_string())
    .bind(snap.shield_accounting.total_unshielded_wei.to_string())
    .bind(snap.shield_accounting.total_fee_units.to_string())
    .bind(snap.shield_accounting.total_fee_wei.to_string())
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
    let mut tx = pool
        .begin()
        .await
        .context("begin canonical rebuild activation")?;
    let staged: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM notes_rebuild \
         WHERE pool_address=$1 AND rebuild_generation=$2",
    )
    .bind(pool_address)
    .bind(generation)
    .fetch_one(&mut *tx)
    .await
    .context("count staged canonical notes")?;
    if staged as u64 != snap.tree_frontier.next_index() {
        return Err(anyhow!(
            "canonical note activation mismatch: staged={staged}, tree_leaves={}",
            snap.tree_frontier.next_index()
        ));
    }
    let staged_leaf_nodes: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM merkle_nodes_rebuild \
         WHERE pool_address=$1 AND rebuild_generation=$2 AND level=0",
    )
    .bind(pool_address)
    .bind(generation)
    .fetch_one(&mut *tx)
    .await
    .context("count staged confirmed Merkle leaves")?;
    if staged_leaf_nodes as u64 != snap.confirmed_count {
        bail!(
            "canonical Merkle activation mismatch: staged_leaves={staged_leaf_nodes}, confirmed={}",
            snap.confirmed_count
        );
    }
    let staged_frozen_updates: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM frozen_updates_rebuild \
         WHERE pool_address=$1 AND rebuild_generation=$2",
    )
    .bind(pool_address)
    .bind(generation)
    .fetch_one(&mut *tx)
    .await
    .context("count staged frozen updates")?;
    let staged_frozen_current: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM frozen_current_rebuild \
         WHERE pool_address=$1 AND rebuild_generation=$2",
    )
    .bind(pool_address)
    .bind(generation)
    .fetch_one(&mut *tx)
    .await
    .context("count staged frozen current set")?;
    if staged_frozen_updates as u64 != snap.frozen_update_count
        || staged_frozen_current as u64 != snap.frozen_count
    {
        bail!(
            "canonical frozen activation mismatch: updates={staged_frozen_updates}/{}, current={staged_frozen_current}/{}",
            snap.frozen_update_count,
            snap.frozen_count
        );
    }
    // Every confirmed leaf belongs to exactly one sealed RootUpdated segment,
    // and every seal freezes exactly its own leaves — so a full finalized
    // replay must have staged one frozen path per confirmed leaf.
    let staged_frozen_paths: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM frozen_paths_rebuild \
         WHERE pool_address=$1 AND rebuild_generation=$2",
    )
    .bind(pool_address)
    .bind(generation)
    .fetch_one(&mut *tx)
    .await
    .context("count staged frozen Merkle paths")?;
    if staged_frozen_paths as u64 != snap.confirmed_count {
        bail!(
            "canonical frozen-path activation mismatch: staged={staged_frozen_paths}, confirmed={}",
            snap.confirmed_count
        );
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

    sqlx::query("DELETE FROM cmx_leaves WHERE pool_address=$1")
        .bind(pool_address)
        .execute(&mut *tx)
        .await
        .context("clear previous canonical cmx leaves")?;
    let inserted_leaves = sqlx::query(
        "INSERT INTO cmx_leaves (pool_address, position, cmx_hex) \
         SELECT pool_address, position, cmx_hex FROM notes_rebuild \
         WHERE pool_address=$1 AND rebuild_generation=$2 AND position IS NOT NULL \
         ORDER BY position",
    )
    .bind(pool_address)
    .bind(generation)
    .execute(&mut *tx)
    .await
    .context("activate staged canonical cmx leaves")?
    .rows_affected();
    if inserted_leaves != snap.tree_frontier.next_index() {
        bail!(
            "canonical cmx activation mismatch: inserted={inserted_leaves}, tree_leaves={}",
            snap.tree_frontier.next_index()
        );
    }

    sqlx::query("DELETE FROM merkle_nodes WHERE pool_address=$1")
        .bind(pool_address)
        .execute(&mut *tx)
        .await
        .context("clear previous canonical Merkle nodes")?;
    sqlx::query(
        "INSERT INTO merkle_nodes (pool_address, level, node_index, hash_hex) \
         SELECT pool_address, level, node_index, hash_hex FROM merkle_nodes_rebuild \
         WHERE pool_address=$1 AND rebuild_generation=$2",
    )
    .bind(pool_address)
    .bind(generation)
    .execute(&mut *tx)
    .await
    .context("activate staged canonical Merkle nodes")?;

    sqlx::query("DELETE FROM frozen_updates WHERE pool_address=$1")
        .bind(pool_address)
        .execute(&mut *tx)
        .await
        .context("clear previous frozen update archive")?;
    sqlx::query(
        "INSERT INTO frozen_updates \
           (pool_address, position, block_number, log_index, update_json) \
         SELECT pool_address, position, block_number, log_index, update_json \
         FROM frozen_updates_rebuild \
         WHERE pool_address=$1 AND rebuild_generation=$2 ORDER BY position",
    )
    .bind(pool_address)
    .bind(generation)
    .execute(&mut *tx)
    .await
    .context("activate staged frozen update archive")?;
    sqlx::query("DELETE FROM frozen_current WHERE pool_address=$1")
        .bind(pool_address)
        .execute(&mut *tx)
        .await
        .context("clear previous frozen current set")?;
    sqlx::query(
        "INSERT INTO frozen_current (pool_address, cmx_hex) \
         SELECT pool_address, cmx_hex FROM frozen_current_rebuild \
         WHERE pool_address=$1 AND rebuild_generation=$2",
    )
    .bind(pool_address)
    .bind(generation)
    .execute(&mut *tx)
    .await
    .context("activate staged frozen current set")?;

    sqlx::query("DELETE FROM frozen_paths WHERE pool_address=$1")
        .bind(pool_address)
        .execute(&mut *tx)
        .await
        .context("clear previous frozen Merkle paths")?;
    sqlx::query(
        "INSERT INTO frozen_paths \
           (pool_address, cmx_hex, position, siblings_json, anchor_root_hex) \
         SELECT pool_address, cmx_hex, position, siblings_json, anchor_root_hex \
         FROM frozen_paths_rebuild \
         WHERE pool_address=$1 AND rebuild_generation=$2",
    )
    .bind(pool_address)
    .bind(generation)
    .execute(&mut *tx)
    .await
    .context("activate staged frozen Merkle paths")?;

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
    sqlx::query("DELETE FROM merkle_nodes_rebuild WHERE pool_address=$1")
        .bind(pool_address)
        .execute(&mut *tx)
        .await
        .context("clear activated Merkle-node staging rows")?;
    sqlx::query("DELETE FROM frozen_updates_rebuild WHERE pool_address=$1")
        .bind(pool_address)
        .execute(&mut *tx)
        .await
        .context("clear activated frozen-update staging rows")?;
    sqlx::query("DELETE FROM frozen_current_rebuild WHERE pool_address=$1")
        .bind(pool_address)
        .execute(&mut *tx)
        .await
        .context("clear activated frozen-current staging rows")?;
    sqlx::query("DELETE FROM frozen_paths_rebuild WHERE pool_address=$1")
        .bind(pool_address)
        .execute(&mut *tx)
        .await
        .context("clear activated frozen-path staging rows")?;
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

/// Convert one sealed v1 checkpoint to the v2 compact-frontier/node-archive
/// representation. The source is the transactional PostgreSQL leaf archive, not
/// RPC, so a routine binary restart does not trigger a historical chain replay.
///
/// Memory is bounded by one 4K leaf page, two depth-32 builders, and one page of
/// complete nodes. All writes live in the same transaction as the v2 metadata
/// seal; any validation or insertion failure rolls back to the untouched v1 row.
async fn pg_upgrade_legacy_compact_checkpoint(
    pool: &sqlx::PgPool,
    pool_address: &str,
    start_block: u64,
) -> Result<bool> {
    type LegacyMeta = (
        i16,
        i64,
        Option<String>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<String>,
    );

    let mut tx = pool
        .begin()
        .await
        .context("begin compact checkpoint upgrade")?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *tx)
        .await
        .context("pin compact checkpoint upgrade transaction")?;
    let Some((
        version,
        next_block,
        active_root_hex,
        raw_confirmed_count,
        last_leaf_block,
        last_leaf_log_index,
        last_finalized_block,
        last_finalized_block_hash,
    )) = sqlx::query_as::<_, LegacyMeta>(
        "SELECT checkpoint_version, next_block, active_root_hex, confirmed_count, \
                last_leaf_block, last_leaf_log_index, last_finalized_block, \
                last_finalized_block_hash \
         FROM indexer_meta WHERE pool_address=$1 FOR UPDATE",
    )
    .bind(pool_address)
    .fetch_optional(&mut *tx)
    .await
    .context("lock legacy checkpoint metadata")?
    else {
        tx.rollback().await.ok();
        return Ok(false);
    };
    if version == 2 {
        tx.rollback().await.ok();
        return Ok(false);
    }
    if version != 1 {
        tx.rollback().await.ok();
        return Ok(false);
    }
    if next_block < i64::try_from(start_block).unwrap_or(i64::MAX) {
        bail!("legacy checkpoint cursor precedes configured start block");
    }
    let finalized = last_finalized_block
        .and_then(|value| u64::try_from(value).ok())
        .context("legacy checkpoint has no valid finalized block")?;
    let finalized_hash = last_finalized_block_hash
        .as_deref()
        .map(normalize_block_hash)
        .transpose()?
        .context("legacy checkpoint has no finalized block hash")?;
    if next_block as u64 != finalized.saturating_add(1) || finalized_hash.is_empty() {
        bail!("legacy checkpoint is not sealed at a complete finalized boundary");
    }
    let confirmed_count = raw_confirmed_count
        .and_then(|value| u64::try_from(value).ok())
        .context("legacy checkpoint has no valid confirmed_count")?;
    let tree_size_i64: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cmx_leaves WHERE pool_address=$1")
            .bind(pool_address)
            .fetch_one(&mut *tx)
            .await
            .context("count legacy cmx leaves")?;
    let tree_size = u64::try_from(tree_size_i64).context("negative legacy tree size")?;
    if confirmed_count > tree_size {
        bail!("legacy confirmed_count exceeds tree size");
    }

    let leaf_shape: (i64, Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT count(*), min(position), max(position) \
         FROM cmx_leaves WHERE pool_address=$1",
    )
    .bind(pool_address)
    .fetch_one(&mut *tx)
    .await
    .context("validate legacy cmx leaf shape")?;
    let expected_min = (tree_size > 0).then_some(0i64);
    let expected_max = tree_size.checked_sub(1).map(|value| value as i64);
    if leaf_shape != (tree_size_i64, expected_min, expected_max) {
        bail!("legacy cmx leaves are not a contiguous prefix");
    }
    let note_shape: (i64, i64, i64) = sqlx::query_as(
        "SELECT count(*), count(*) FILTER (WHERE is_confirmed), \
                count(*) FILTER (WHERE position IS NULL) \
         FROM notes WHERE pool_address=$1",
    )
    .bind(pool_address)
    .fetch_one(&mut *tx)
    .await
    .context("validate legacy note shape")?;
    if note_shape != (tree_size_i64, confirmed_count as i64, 0) {
        bail!("legacy note/leaf/confirmation cardinality mismatch");
    }
    let note_leaf_mismatch: bool = sqlx::query_scalar(
        "SELECT EXISTS( \
           SELECT 1 FROM cmx_leaves AS leaf \
           FULL OUTER JOIN notes AS note \
             ON note.pool_address=leaf.pool_address \
            AND note.position=leaf.position AND lower(note.cmx_hex)=lower(leaf.cmx_hex) \
           WHERE COALESCE(leaf.pool_address, note.pool_address)=$1 \
             AND (leaf.position IS NULL OR note.position IS NULL \
                  OR note.is_confirmed IS DISTINCT FROM (note.position < $2)) \
         )",
    )
    .bind(pool_address)
    .bind(confirmed_count as i64)
    .fetch_one(&mut *tx)
    .await
    .context("validate legacy note/leaf mapping")?;
    if note_leaf_mismatch {
        bail!("legacy note and cmx leaf archives diverge");
    }
    let archived_last_leaf: Option<(i64, i64)> = if tree_size == 0 {
        None
    } else {
        sqlx::query_as(
            "SELECT block_number, log_index FROM notes \
             WHERE pool_address=$1 AND position=$2",
        )
        .bind(pool_address)
        .bind((tree_size - 1) as i64)
        .fetch_optional(&mut *tx)
        .await
        .context("load legacy last-leaf cursor")?
    };
    if archived_last_leaf != last_leaf_block.zip(last_leaf_log_index) {
        bail!("legacy last-leaf cursor does not match the note archive");
    }

    // Rebuild the immutable confirmed node archive transactionally. A rollback
    // restores the old rows if any later validation fails.
    sqlx::query("DELETE FROM merkle_nodes WHERE pool_address=$1")
        .bind(pool_address)
        .execute(&mut *tx)
        .await
        .context("clear incomplete compact node archive")?;

    const UPGRADE_PAGE: i64 = 4_096;
    let mut all_builder = StreamingFrontierBuilder::new();
    let mut confirmed_builder = StreamingFrontierBuilder::new();
    let mut tree_frontier = (tree_size == 0).then(CompactFrontier::new);
    let mut confirmed_frontier = (confirmed_count == 0).then(CompactFrontier::new);
    let mut next_position = 0u64;
    while next_position < tree_size {
        let rows: Vec<(i64, String)> = sqlx::query_as(
            "SELECT position, cmx_hex FROM cmx_leaves \
             WHERE pool_address=$1 AND position >= $2 \
             ORDER BY position LIMIT $3",
        )
        .bind(pool_address)
        .bind(next_position as i64)
        .bind(UPGRADE_PAGE)
        .fetch_all(&mut *tx)
        .await
        .context("page legacy cmx leaves")?;
        if rows.is_empty() {
            bail!("legacy cmx archive ended before tree_size");
        }
        let mut page_nodes = Vec::with_capacity(rows.len().saturating_mul(2));
        for (position, encoded) in rows {
            if position != next_position as i64 {
                bail!("legacy cmx archive gap at position {next_position}: found {position}");
            }
            let cmx = parse_hex32(&encoded)
                .ok_or_else(|| anyhow!("invalid legacy cmx at position {position}"))?;
            if next_position + 1 == tree_size {
                let (frontier, _) = all_builder.finish_with_last_be(cmx)?;
                tree_frontier = Some(frontier);
            } else {
                all_builder.push_nonfinal_be(cmx)?;
            }
            if next_position < confirmed_count {
                let generated = if next_position + 1 == confirmed_count {
                    let (frontier, nodes) = confirmed_builder.finish_with_last_be(cmx)?;
                    confirmed_frontier = Some(frontier);
                    nodes
                } else {
                    confirmed_builder.push_nonfinal_be(cmx)?
                };
                page_nodes.extend(generated);
            }
            next_position += 1;
        }
        pg_append_merkle_nodes(&mut tx, pool_address, None, &page_nodes).await?;
    }
    let tree_frontier = tree_frontier.context("compact all-leaf frontier was not completed")?;
    let confirmed_frontier =
        confirmed_frontier.context("compact confirmed frontier was not completed")?;
    let expected_confirmed_root = match (confirmed_count, active_root_hex.as_deref()) {
        (0, None) => EVM_EMPTY_IMT_ROOT,
        (0, Some(value)) => {
            let root = parse_hex32(value).context("invalid legacy active root")?;
            if root != EVM_EMPTY_IMT_ROOT {
                bail!("legacy active root is non-empty at confirmed_count zero");
            }
            root
        }
        (_, Some(value)) => parse_hex32(value).context("invalid legacy active root")?,
        (_, None) => bail!("legacy checkpoint is missing its confirmed root"),
    };
    if confirmed_frontier.root_be() != expected_confirmed_root {
        bail!(
            "legacy confirmed frontier root mismatch: rebuilt={}, checkpoint={}",
            hex::encode(confirmed_frontier.root_be()),
            hex::encode(expected_confirmed_root)
        );
    }
    let archived_confirmed_leaves: i64 =
        sqlx::query_scalar("SELECT count(*) FROM merkle_nodes WHERE pool_address=$1 AND level=0")
            .bind(pool_address)
            .fetch_one(&mut *tx)
            .await
            .context("verify upgraded Merkle leaf archive")?;
    if archived_confirmed_leaves != confirmed_count as i64 {
        bail!("upgraded Merkle leaf archive is incomplete");
    }

    // Materialize the compliance current set while upgrading. The historical
    // feed stays in PostgreSQL and is paged; only one bounded page is decoded.
    sqlx::query("DELETE FROM frozen_current WHERE pool_address=$1")
        .bind(pool_address)
        .execute(&mut *tx)
        .await
        .context("reset legacy frozen current set")?;
    let mut frozen_update_count = 0u64;
    let mut frozen_root_hex = format!("0x{}", "00".repeat(32));
    loop {
        let rows: Vec<(i64, String)> = sqlx::query_as(
            "SELECT position, update_json FROM frozen_updates \
             WHERE pool_address=$1 AND position >= $2 \
             ORDER BY position LIMIT $3",
        )
        .bind(pool_address)
        .bind(frozen_update_count as i64)
        .bind(UPGRADE_PAGE)
        .fetch_all(&mut *tx)
        .await
        .context("page legacy frozen updates")?;
        if rows.is_empty() {
            break;
        }
        let mut page = Vec::with_capacity(rows.len());
        for (position, encoded) in rows {
            if position != frozen_update_count as i64 {
                bail!(
                    "legacy frozen update gap at position {frozen_update_count}: found {position}"
                );
            }
            let update: FrozenUpdate =
                serde_json::from_str(&encoded).context("decode legacy frozen update")?;
            let expected_old =
                parse_hex32(&frozen_root_hex).context("invalid reconstructed frozen root")?;
            let actual_old =
                parse_hex32(&update.old_root_hex).context("invalid legacy frozen old root")?;
            if frozen_update_count > 0 && actual_old != expected_old {
                bail!("legacy frozen update root chain is discontinuous");
            }
            let new_root =
                parse_hex32(&update.new_root_hex).context("invalid legacy frozen new root")?;
            frozen_root_hex = format!("0x{}", hex::encode(new_root));
            page.push((frozen_update_count, update));
            frozen_update_count += 1;
        }
        pg_apply_frozen_updates(&mut tx, pool_address, None, &page).await?;
    }
    let materialized_frozen_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM frozen_current WHERE pool_address=$1")
            .bind(pool_address)
            .fetch_one(&mut *tx)
            .await
            .context("verify materialized frozen set")?;
    let frozen_count = u64::try_from(materialized_frozen_count)
        .context("negative materialized frozen-set cardinality")?;

    let tree_frontier_hex: Vec<String> = tree_frontier
        .filled_be()
        .into_iter()
        .map(hex::encode)
        .collect();
    let confirmed_frontier_hex: Vec<String> = confirmed_frontier
        .filled_be()
        .into_iter()
        .map(hex::encode)
        .collect();
    let updated = sqlx::query(
        "UPDATE indexer_meta SET checkpoint_version=2, tree_size=$2, \
                tree_root_hex=$3, tree_frontier_hex=$4, confirmed_frontier_hex=$5, \
                frozen_root_hex=$6, frozen_count=$7, frozen_update_count=$8 \
         WHERE pool_address=$1 AND checkpoint_version=1",
    )
    .bind(pool_address)
    .bind(tree_size as i64)
    .bind(hex::encode(tree_frontier.root_be()))
    .bind(&tree_frontier_hex)
    .bind(&confirmed_frontier_hex)
    .bind(&frozen_root_hex)
    .bind(frozen_count as i64)
    .bind(frozen_update_count as i64)
    .execute(&mut *tx)
    .await
    .context("seal compact checkpoint metadata")?
    .rows_affected();
    if updated != 1 {
        bail!("legacy checkpoint version changed during compact upgrade");
    }
    tx.commit()
        .await
        .context("commit compact checkpoint upgrade")?;
    println!(
        "[indexer][{}] upgraded sealed checkpoint v1 -> v2: leaves={tree_size}, confirmed={confirmed_count}",
        &pool_address[..10.min(pool_address.len())]
    );
    Ok(true)
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
        Option<i64>,
        Option<String>,
        Option<Vec<String>>,
        Option<Vec<String>>,
        Option<String>,
        Option<i64>,
        Option<i64>,
    );
    let label = &pool_address[..10.min(pool_address.len())];
    let mut warm_rejection: Option<String> = None;
    let mut reject = |reason: String| {
        warm_rejection.get_or_insert(reason);
    };
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
                checkpoint_version, tree_size, tree_root_hex, tree_frontier_hex, \
                confirmed_frontier_hex, frozen_root_hex, frozen_count, frozen_update_count \
         FROM indexer_meta WHERE pool_address=$1",
    )
    .bind(pool_address)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(row) => row,
        Err(error) => {
            reject(format!("load indexer_meta: {error}"));
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
        raw_tree_size,
        tree_root_hex,
        tree_frontier_hex,
        confirmed_frontier_hex,
        raw_frozen_root_hex,
        raw_frozen_count,
        raw_frozen_update_count,
    ) = meta.unwrap_or((
        start_block as i64,
        None,
        0,
        None,
        None,
        None,
        None,
        None,
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    ));
    if !matches!(checkpoint_version, 0..=2) {
        reject("unsupported checkpoint version".to_string());
    }
    if checkpoint_version != 2 {
        reject("legacy checkpoint requires compact-frontier upgrade".to_string());
    }
    if raw_next_block < 0 || raw_latest_seq < 0 {
        reject("negative checkpoint scalar".to_string());
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
        reject("invalid finalized cursor pair".to_string());
    }
    let confirmed_count = raw_confirmed_count
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or_else(|| {
            reject("missing or negative confirmed_count".to_string());
            0
        });
    let tree_size = raw_tree_size
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or_else(|| {
            reject("missing or negative tree_size".to_string());
            0
        });
    if confirmed_count > tree_size {
        reject("confirmed_count exceeds tree_size".to_string());
    }
    let persisted_last_leaf_key = match (raw_last_leaf_block, raw_last_leaf_log_index) {
        (Some(block), Some(log_index)) => match (u64::try_from(block), u64::try_from(log_index)) {
            (Ok(block), Ok(log_index)) => Some((block, log_index)),
            _ => {
                reject("negative last-leaf cursor".to_string());
                None
            }
        },
        (None, None) => None,
        _ => {
            reject("incomplete last-leaf cursor".to_string());
            None
        }
    };
    let active_root = match active_root_hex.as_deref() {
        Some(value) => match parse_hex32(value) {
            Some(root) => Some(root),
            None => {
                reject("invalid active_root_hex".to_string());
                None
            }
        },
        None => None,
    };

    let mut tree_frontier = CompactFrontier::new();
    let mut confirmed_frontier = CompactFrontier::new();
    let compact = (|| -> Result<(CompactFrontier, CompactFrontier)> {
        let tree_root = tree_root_hex
            .as_deref()
            .and_then(parse_hex32)
            .context("invalid compact tree root")?;
        let tree_filled = parse_hex32_vec(
            tree_frontier_hex
                .as_deref()
                .context("missing tree frontier")?,
        )?;
        let confirmed_filled = parse_hex32_vec(
            confirmed_frontier_hex
                .as_deref()
                .context("missing confirmed frontier")?,
        )?;
        let confirmed_root = match (confirmed_count, active_root) {
            (0, None) => EVM_EMPTY_IMT_ROOT,
            (0, Some(root)) if root == EVM_EMPTY_IMT_ROOT => root,
            (0, Some(_)) => bail!("non-empty root at confirmed_count zero"),
            (_, Some(root)) => root,
            (_, None) => bail!("missing confirmed root"),
        };
        Ok((
            CompactFrontier::from_parts_be(&tree_filled, tree_size, tree_root)?,
            CompactFrontier::from_parts_be(&confirmed_filled, confirmed_count, confirmed_root)?,
        ))
    })();
    match compact {
        Ok((tree, confirmed)) => {
            tree_frontier = tree;
            confirmed_frontier = confirmed;
        }
        Err(error) => reject(format!("restore compact frontiers: {error:#}")),
    }

    let frozen_root_hex = match raw_frozen_root_hex.as_deref() {
        Some(value) => match parse_hex32(value) {
            Some(root) => format!("0x{}", hex::encode(root)),
            None => {
                reject("invalid frozen_root_hex".to_string());
                format!("0x{}", "00".repeat(32))
            }
        },
        None => {
            reject("missing frozen_root_hex".to_string());
            format!("0x{}", "00".repeat(32))
        }
    };
    let frozen_count = raw_frozen_count
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or_else(|| {
            reject("missing or negative frozen_count".to_string());
            0
        });
    let frozen_update_count = raw_frozen_update_count
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or_else(|| {
            reject("missing or negative frozen_update_count".to_string());
            0
        });

    type CountSummary = (i64, Option<i64>, Option<i64>);
    let leaf_summary: CountSummary = match sqlx::query_as(
        "SELECT count(*), min(position), max(position) FROM cmx_leaves WHERE pool_address=$1",
    )
    .bind(pool_address)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(summary) => summary,
        Err(error) => {
            reject(format!("inspect cmx leaves: {error}"));
            (0, None, None)
        }
    };
    let expected_min = (tree_size > 0).then_some(0);
    let expected_max = tree_size.checked_sub(1).map(|value| value as i64);
    if leaf_summary != (tree_size as i64, expected_min, expected_max) {
        reject("cmx leaves are not a contiguous tree-sized prefix".to_string());
    }

    let note_summary: (i64, i64, i64) = match sqlx::query_as(
        "SELECT count(*), count(*) FILTER (WHERE is_confirmed), \
                count(*) FILTER (WHERE position IS NULL) \
         FROM notes WHERE pool_address=$1",
    )
    .bind(pool_address)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(summary) => summary,
        Err(error) => {
            reject(format!("inspect note archive: {error}"));
            (0, 0, 0)
        }
    };
    if note_summary != (tree_size as i64, confirmed_count as i64, 0) {
        reject("note/leaf/confirmation cardinality mismatch".to_string());
    }
    let note_leaf_mismatch: bool = sqlx::query_scalar(
        "SELECT EXISTS( \
           SELECT 1 FROM cmx_leaves AS leaf \
           FULL OUTER JOIN notes AS note \
             ON note.pool_address=leaf.pool_address \
            AND note.position=leaf.position AND lower(note.cmx_hex)=lower(leaf.cmx_hex) \
           WHERE COALESCE(leaf.pool_address, note.pool_address)=$1 \
             AND (leaf.position IS NULL OR note.position IS NULL \
                  OR note.is_confirmed IS DISTINCT FROM (note.position < $2)) \
         )",
    )
    .bind(pool_address)
    .bind(confirmed_count as i64)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(true);
    if note_leaf_mismatch {
        reject("note and cmx leaf archives diverge".to_string());
    }

    let archived_leaf_nodes: i64 =
        sqlx::query_scalar("SELECT count(*) FROM merkle_nodes WHERE pool_address=$1 AND level=0")
            .bind(pool_address)
            .fetch_one(&mut *tx)
            .await
            .unwrap_or(-1);
    if archived_leaf_nodes != confirmed_count as i64 {
        reject("confirmed Merkle leaf archive cardinality mismatch".to_string());
    }
    let merkle_leaf_mismatch: bool = sqlx::query_scalar(
        "SELECT EXISTS( \
           SELECT 1 FROM cmx_leaves AS leaf \
           LEFT JOIN merkle_nodes AS node \
             ON node.pool_address=leaf.pool_address AND node.level=0 \
            AND node.node_index=leaf.position AND lower(node.hash_hex)=lower(leaf.cmx_hex) \
           WHERE leaf.pool_address=$1 AND leaf.position < $2 AND node.node_index IS NULL \
         )",
    )
    .bind(pool_address)
    .bind(confirmed_count as i64)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(true);
    if merkle_leaf_mismatch {
        reject("confirmed Merkle leaves diverge from cmx archive".to_string());
    }

    let archive_last_leaf: Option<(i64, i64)> = sqlx::query_as(
        "SELECT block_number, log_index FROM notes \
         WHERE pool_address=$1 AND position=$2",
    )
    .bind(pool_address)
    .bind(tree_size.saturating_sub(1) as i64)
    .fetch_optional(&mut *tx)
    .await
    .unwrap_or(None);
    let archive_last_leaf = archive_last_leaf.map(|(block, log)| (block as u64, log as u64));
    if archive_last_leaf != persisted_last_leaf_key
        || tree_size == 0 && persisted_last_leaf_key.is_some()
    {
        reject("last-leaf cursor mismatch".to_string());
    }
    let last_leaf_key = persisted_last_leaf_key;
    match (last_finalized_block, last_finalized_block_hash.as_ref()) {
        (Some(block), Some(_)) if next_block == block.saturating_add(1) => {}
        _ => reject("checkpoint is not at a complete finalized boundary".to_string()),
    }
    if last_leaf_key
        .zip(last_finalized_block)
        .is_some_and(|((leaf_block, _), finalized_block)| leaf_block > finalized_block)
    {
        reject("last leaf is beyond finalized checkpoint".to_string());
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
            reject(format!("load pending txs: {error}"));
            VecDeque::new()
        }
    };

    let frozen_shape: (i64, Option<i64>, Option<i64>) = match sqlx::query_as(
        "SELECT count(*), min(position), max(position) \
         FROM frozen_updates WHERE pool_address=$1",
    )
    .bind(pool_address)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(shape) => shape,
        Err(error) => {
            reject(format!("inspect frozen updates: {error}"));
            (0, None, None)
        }
    };
    let expected_frozen_min = (frozen_update_count > 0).then_some(0i64);
    let expected_frozen_max = frozen_update_count
        .checked_sub(1)
        .map(|position| position as i64);
    if frozen_shape
        != (
            frozen_update_count as i64,
            expected_frozen_min,
            expected_frozen_max,
        )
    {
        reject("frozen update archive is not a contiguous prefix".to_string());
    }
    let materialized_frozen_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM frozen_current WHERE pool_address=$1")
            .bind(pool_address)
            .fetch_one(&mut *tx)
            .await
            .unwrap_or(-1);
    if materialized_frozen_count != frozen_count as i64 {
        reject("frozen current-set cardinality mismatch".to_string());
    }
    if frozen_update_count == 0 {
        if parse_hex32(&frozen_root_hex) != Some([0u8; 32]) || frozen_count != 0 {
            reject("empty frozen archive has a non-empty summary".to_string());
        }
    } else {
        let last_json: Option<String> = sqlx::query_scalar(
            "SELECT update_json FROM frozen_updates \
             WHERE pool_address=$1 AND position=$2",
        )
        .bind(pool_address)
        .bind((frozen_update_count - 1) as i64)
        .fetch_optional(&mut *tx)
        .await
        .unwrap_or(None);
        match last_json
            .as_deref()
            .map(serde_json::from_str::<FrozenUpdate>)
            .transpose()
        {
            Ok(Some(last)) if parse_hex32(&last.new_root_hex) == parse_hex32(&frozen_root_hex) => {}
            Ok(_) => reject("frozen summary root does not match the final delta".to_string()),
            Err(error) => reject(format!("decode final frozen update: {error}")),
        }
    }

    let stats_row: Option<(String, String, String, String, String, String)> = match sqlx::query_as(
        "SELECT total_shielded_units, total_shielded_wei, total_unshielded_units, total_unshielded_wei, \
                total_fee_units, total_fee_wei \
         FROM shield_pool_stats WHERE pool_address=$1",
    )
    .bind(pool_address)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(row) => row,
        Err(error) => {
            reject(format!("load shield stats: {error}"));
            None
        }
    };
    let shield_accounting = match stats_row {
        Some((tsu, tsw, tuu, tuw, tfu, tfw)) => match (
            tsu.parse::<u128>(),
            tsw.parse::<u128>(),
            tuu.parse::<u128>(),
            tuw.parse::<u128>(),
            tfu.parse::<u128>(),
            tfw.parse::<u128>(),
        ) {
            (Ok(tsu), Ok(tsw), Ok(tuu), Ok(tuw), Ok(tfu), Ok(tfw)) => ShieldAccounting {
                total_shielded_units: tsu,
                total_shielded_wei: tsw,
                total_unshielded_units: tuu,
                total_unshielded_wei: tuw,
                total_fee_units: tfu,
                total_fee_wei: tfw,
            },
            _ => {
                reject("invalid persisted shield stats".to_string());
                ShieldAccounting::default()
            }
        },
        None => ShieldAccounting::default(),
    };

    if let Err(error) = tx.commit().await {
        reject(format!("close checkpoint snapshot: {error}"));
    }

    let warm_start_candidate = meta_present && checkpoint_version == 2 && warm_rejection.is_none();
    if let Some(reason) = &warm_rejection {
        eprintln!("[indexer][{label}] checkpoint is not warm-start eligible: {reason}");
    }
    println!(
        "[indexer] pg load: pool={label} next_block={next_block} leaves={tree_size} confirmed={confirmed_count} pending={} frozen_updates={frozen_update_count} warm_candidate={warm_start_candidate}",
        pending_tx_hashes.len()
    );
    CheckpointData {
        next_block,
        last_finalized_block,
        last_finalized_block_hash,
        tree_frontier,
        active_root,
        confirmed_count,
        confirmed_frontier,
        last_leaf_key,
        warm_start_candidate,
        latest_seq,
        batches: VecDeque::new(),
        pending_tx_hashes,
        frozen_root_hex,
        frozen_count,
        frozen_update_count,
        shield_accounting,
    }
}

/// Load `out_ciphertext` + `cv_net_x` for one action from the tx `bundle()` calldata.
async fn lookup_bundle_out_fields(
    rpc: &RpcClient,
    state: &mut SharedState,
    tx_hash: &str,
    cmx: [u8; 32],
) -> (Vec<u8>, Option<[u8; 32]>) {
    let key = normalize_hex_0x(tx_hash);
    if !state.bundle_out_cache.contains_key(&key) {
        let decoded = match rpc.get_transaction_input(&key).await {
            Ok(Some(input)) => match bundle_actions_by_cmx(&input) {
                Ok(map) => map,
                Err(e) => {
                    eprintln!("[indexer] bundle calldata decode failed for {key}: {e}");
                    HashMap::new()
                }
            },
            Ok(None) => HashMap::new(),
            Err(e) => {
                eprintln!("[indexer] eth_getTransactionByHash failed for {key}: {e}");
                HashMap::new()
            }
        };
        state.bundle_out_cache.insert(key.clone(), decoded);
        state.bundle_out_order.push_back(key.clone());
        while state.bundle_out_order.len() > MAX_BUNDLE_OUT_CACHE {
            if let Some(expired) = state.bundle_out_order.pop_front() {
                state.bundle_out_cache.remove(&expired);
            }
        }
    }
    if let Some(entry) = state
        .bundle_out_cache
        .get(&key)
        .and_then(|actions| actions.get(&cmx))
    {
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
    /// Opt-in tip-snapshot bootstrap for missing `frozen_paths` rows.
    freeze_tip_paths: bool,
    /// Bounded page/worker settings shared by startup and maintenance freezes.
    freeze_config: TipFreezeConfig,
    /// Shared serving-readiness gate for the one-shot bootstrap.
    frozen_paths_ready: Arc<AtomicBool>,
    /// Ring-miss / recovery-source counters, shared with this pool's HTTP context.
    ring_recovery: Arc<RingRecoveryMetrics>,
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

    /// Membership projection for the commitments referenced by the next frozen
    /// delta. The durable table supplies the baseline; mutations buffered by the
    /// current finalized replay are folded over it in order. Work is therefore
    /// bounded by one event plus the already-bounded replay buffer, not history.
    async fn frozen_membership_before_next_update(
        &self,
        cmx_values: &[String],
    ) -> Result<HashSet<String>> {
        let mut wanted = HashSet::with_capacity(cmx_values.len());
        for raw_cmx in cmx_values {
            let cmx = parse_hex32(raw_cmx)
                .ok_or_else(|| anyhow!("invalid frozen cmx in disclosed delta"))?;
            wanted.insert(format!("0x{}", hex::encode(cmx)));
        }
        let generation = self.rebuild_generation.read().await.clone();
        let mut membership = self
            .backend
            .load_frozen_membership(&self.contract_address, generation.as_deref(), &wanted)
            .await?;

        let apply_buffered =
            |mutations: &[NoteArchiveMutation], membership: &mut HashSet<String>| -> Result<()> {
                for mutation in mutations {
                    let NoteArchiveMutation::Frozen { update, .. } = mutation else {
                        continue;
                    };
                    for (raw_cmx, is_add) in update.cmx_changed_hex.iter().zip(&update.is_add) {
                        let cmx = parse_hex32(raw_cmx)
                            .ok_or_else(|| anyhow!("invalid buffered frozen cmx"))?;
                        let canonical = format!("0x{}", hex::encode(cmx));
                        if !wanted.contains(&canonical) {
                            continue;
                        }
                        if *is_add {
                            membership.insert(canonical);
                        } else {
                            membership.remove(&canonical);
                        }
                    }
                }
                Ok(())
            };

        if generation.is_some() {
            let buffered = self.rebuild_mutations.lock().await;
            apply_buffered(&buffered, &mut membership)?;
        } else {
            let buffered = self.incremental_replay_mutations.lock().await;
            if let Some(buffered) = buffered.as_deref() {
                apply_buffered(buffered, &mut membership)?;
            }
        }
        Ok(membership)
    }

    /// Recover a note's full payload after the ring has evicted it, so its
    /// `NoteConfirmed` can still be republished with a fresh seq.
    ///
    /// Search order mirrors `archive_note_mutation`'s write order: mutations are
    /// buffered in memory during a canonical rebuild or an incremental replay and
    /// only reach the tables when that batch commits, so whichever sink is
    /// currently being written to holds the newest rows and is searched first.
    /// Skipping the buffer would miss a note whose `NoteAdded` is in the same
    /// uncommitted batch as its `NoteConfirmed` — exactly the case a long
    /// catch-up produces.
    async fn recover_evicted_note(&self, cmx: [u8; 32]) -> Option<OrchardIndexedAbiNote> {
        RingRecoveryMetrics::bump(&self.ring_recovery.ring_misses);
        let generation = self.rebuild_generation.read().await.clone();
        if generation.is_some() {
            if let Some(note) = latest_upserted_note(&self.rebuild_mutations.lock().await, cmx) {
                RingRecoveryMetrics::bump(&self.ring_recovery.recovered_from_buffer);
                return Some(note);
            }
        } else if let Some(buffered) = self.incremental_replay_mutations.lock().await.as_ref() {
            if let Some(note) = latest_upserted_note(buffered, cmx) {
                RingRecoveryMetrics::bump(&self.ring_recovery.recovered_from_buffer);
                return Some(note);
            }
        }
        let recovered = self
            .backend
            .load_note_by_cmx(&self.contract_address, generation.as_deref(), cmx)
            .await;
        RingRecoveryMetrics::bump(if recovered.is_some() {
            &self.ring_recovery.recovered_from_archive
        } else {
            &self.ring_recovery.unrecovered
        });
        recovered
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
        if !snap.is_complete_finalized_boundary() {
            self.incremental_replay_mutations.lock().await.take();
            self.persist.resume();
            return Err(anyhow!(
                "refusing to persist an incomplete finalized checkpoint: next_block={}, last_finalized={:?}",
                snap.next_block,
                snap.last_finalized_block
            ));
        }
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
            .apply_note_mutations(&self.contract_address, Some(&generation), &mutations)
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
    let (finalized_head, _) = ctx
        .rpc
        .confirmation_head()
        .await
        .context("resolve finalized head for warm-start")?;
    if !persisted_finalized_cursor_matches(ctx, finalized_head).await? {
        ctx.shared.write().await.startup_source = "checkpoint_rejected".to_string();
        return Err(anyhow!(
            "persisted finalized cursor is not canonical; reviewed recovery is required"
        ));
    }

    let local_root = frontier.root_be();
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
    state.confirmed_frontier = frontier;
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
        .confirmation_head()
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
        state.tree_frontier = CompactFrontier::new();
        state.recent_event_ids.clear();
        state.shield_accounting = ShieldAccounting::default();
        state.last_leaf_key = None;
        state.batches.clear();
        state.latest_seq = 0;
        state.confirmed_count = 0;
        state.confirmed_frontier = CompactFrontier::new();
        state.active_root = None;
        state.pending_root_update = None;
        state.bundle_out_cache.clear();
        state.bundle_out_order.clear();
        state.frozen_root_hex = format!("0x{}", "00".repeat(32));
        state.frozen_count = 0;
        state.frozen_update_count = 0;
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
    topic0s.push(normalize_hex_0x(&fee_charged_topic0_hex()));

    // Reset tree state for a clean rebuild so positions match on-chain order even
    // if the restored checkpoint was partial/corrupt. (pending_tx_hashes kept.)
    {
        let mut s = ctx.shared.write().await;
        // Public root endpoints fail closed until the complete finalized replay
        // and its terminal block-hash check have both succeeded.
        s.tree_out_of_order = true;
        s.tree_frontier = CompactFrontier::new();
        s.recent_event_ids.clear();
        s.shield_accounting = ShieldAccounting::default();
        s.last_leaf_key = None;
        s.batches.clear();
        s.latest_seq = 0;
        s.confirmed_count = 0;
        s.confirmed_frontier = CompactFrontier::new();
        s.active_root = None;
        s.pending_root_update = None;
        s.bundle_out_cache.clear();
        s.bundle_out_order.clear();
        s.frozen_root_hex = format!("0x{}", "00".repeat(32));
        s.frozen_count = 0;
        s.frozen_update_count = 0;
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
                {
                    let state = ctx.shared.read().await;
                    ensure_root_update_boundary_sealed(&state)
                        .with_context(|| format!("backfill RootUpdated boundary [{from},{to}]"))?;
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
    let tree_size = s.tree_frontier.next_index();
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
    let (head, finalized_hash) = match ctx.rpc.confirmation_head().await {
        Ok(value) => value,
        Err(_) => return, // transient RPC error — retry next tick from the same cursor
    };
    match persisted_finalized_cursor_matches(ctx, head).await {
        Ok(true) => {}
        Ok(false) => {
            let mut state = ctx.shared.write().await;
            state.tree_out_of_order = true;
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

fn watched_topic0s(ctx: &PollContext) -> Vec<String> {
    let mut topic0s: Vec<String> = note_added_topic0_alternatives()
        .iter()
        .map(|topic| normalize_hex_0x(topic))
        .collect();
    topic0s.push(normalize_hex_0x(&shield_completed_topic0_hex()));
    topic0s.push(normalize_hex_0x(&ctx.note_confirmed_topic0));
    topic0s.push(normalize_hex_0x(&root_updated_topic0_hex()));
    topic0s.push(normalize_hex_0x(&frozen_root_updated_topic0()));
    topic0s.push(normalize_hex_0x(&shielded_topic0_hex()));
    topic0s.push(normalize_hex_0x(&unshielded_topic0_hex()));
    topic0s.push(normalize_hex_0x(&fee_charged_topic0_hex()));
    topic0s
}

/// Fetch every watched log in the inclusive block range `[from, to]` and replay
/// them through `process_single_log` in strict (block, log_index) order.
///
/// The caller MUST hold `ctx.ingest_lock`. Returns the number of logs processed,
/// or `Err(())` if a getLogs window failed (the cursor must not advance then).
async fn replay_range(ctx: &PollContext, from: u64, to: u64) -> Result<usize, ()> {
    let label = ctx.contract_address[..10.min(ctx.contract_address.len())].to_string();
    let topic0s = watched_topic0s(ctx);

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
                {
                    let state = ctx.shared.read().await;
                    if let Err(e) = ensure_root_update_boundary_sealed(&state) {
                        eprintln!(
                            "[indexer][{label}] replay RootUpdated boundary [{lo},{hi}] failed: {e:#}"
                        );
                        return Err(());
                    }
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
            norm_topic(&frozen_root_updated_topic0()),
            norm_topic(&shielded_topic0_hex()),
            norm_topic(&unshielded_topic0_hex()),
            norm_topic(&fee_charged_topic0_hex()),
        ]
        .contains(&topic0)
}

fn state_has_event_id(state: &SharedState, event_id: &str) -> bool {
    state.recent_event_ids.contains(event_id)
}

fn finalized_cursor_covers_block(
    next_block: u64,
    last_finalized_block: Option<u64>,
    last_finalized_block_hash: Option<&str>,
    tree_out_of_order: bool,
    block_number: u64,
) -> bool {
    !tree_out_of_order
        && checkpoint_is_complete_finalized_boundary(
            next_block,
            last_finalized_block,
            last_finalized_block_hash,
        )
        && last_finalized_block.is_some_and(|finalized| finalized >= block_number)
}

fn state_covers_finalized_block(state: &SharedState, block_number: u64) -> bool {
    finalized_cursor_covers_block(
        state.next_block,
        state.last_finalized_block,
        state.last_finalized_block_hash.as_deref(),
        state.tree_out_of_order,
        block_number,
    )
}

async fn canonical_ws_log_is_visible(
    ctx: &PollContext,
    block_number: u64,
    transaction_hash: &str,
    log_index: &str,
) -> Result<bool> {
    let logs = ctx
        .rpc
        .fetch_logs_topic0_or(
            block_number,
            block_number,
            &ctx.contract_address,
            &watched_topic0s(ctx),
        )
        .await?;
    ctx.rpc.validate_canonical_logs(&logs).await?;
    Ok(logs.iter().any(|candidate| {
        candidate
            .transaction_hash
            .eq_ignore_ascii_case(transaction_hash)
            && candidate.log_index.eq_ignore_ascii_case(log_index)
    }))
}

/// Treat a live WS log only as a wake-up hint. Once the same finalized log is
/// visible through canonical `eth_getLogs`, run the ordinary catch-up all the
/// way to one finalized head and atomically publish that complete boundary.
/// This prevents the old WS fast path from persisting `next_block=B` beside an
/// older `last_finalized_block`, which made every restart in that window reject
/// warm-start and fall back to a full replay.
async fn ingest_ws_log(ctx: &PollContext, log: EthLog) -> Result<()> {
    if log.removed {
        return Err(anyhow!(
            "removed WS log {}:{} rejected",
            log.transaction_hash,
            log.log_index
        ));
    }
    let block_number = parse_hex_u64(&log.block_number)
        .with_context(|| format!("invalid blockNumber: {}", log.block_number))?;
    let event_id = format!("{}:{}", log.transaction_hash, log.log_index);
    let already_seen = {
        let state = ctx.shared.read().await;
        state_has_event_id(&state, &event_id)
    };
    if already_seen {
        return Ok(());
    }

    let mut visible = false;
    for attempt in 0u64..6 {
        let (finalized_head, _) = ctx.rpc.confirmation_head().await?;
        if block_number > finalized_head {
            // Monad publishes Voted logs before finalization. The periodic
            // catch-up will ingest this block after it becomes finalized.
            return Ok(());
        }
        if canonical_ws_log_is_visible(ctx, block_number, &log.transaction_hash, &log.log_index)
            .await?
        {
            visible = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50 * (attempt + 1))).await;
    }
    if !visible {
        return Err(anyhow!(
            "WS hint {event_id} is finalized but not visible through canonical eth_getLogs"
        ));
    }

    // Dedup sets are intentionally not persisted. After a restart, a delayed WS
    // delivery or pending-receipt recovery can therefore refer to a block that a
    // valid finalized checkpoint already covers. The sealed cursor is the durable
    // proof of coverage; do not turn that benign replay into a full rebuild.
    let already_covered = {
        let state = ctx.shared.read().await;
        state_has_event_id(&state, &event_id) || state_covers_finalized_block(&state, block_number)
    };
    if already_covered {
        return Ok(());
    }

    catchup_from_chain(ctx).await;
    let covered_after_catchup = {
        let state = ctx.shared.read().await;
        state_has_event_id(&state, &event_id) || state_covers_finalized_block(&state, block_number)
    };
    if covered_after_catchup {
        return Ok(());
    }

    // A transient canonical RPC failure leaves the cursor at/before this block.
    // Preserve the last valid checkpoint and let periodic catch-up retry. If the
    // catch-up detected an actual cursor/hash mismatch it already marked the
    // state unready itself.
    Err(anyhow!(
        "canonical catch-up did not yet cover finalized WS hint {event_id}; retry deferred"
    ))
}

/// WebSocket event-driven loop.
///
/// 1. Subscribe: `eth_subscribe logs` on the contract address.
/// 2. Treat each incoming log as a hint; ingest only via finalized canonical replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TipFreezeConfig {
    page_size: usize,
    workers: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
struct TipFreezeReport {
    confirmed_count: u64,
    already_frozen: u64,
    written: u64,
    skipped_existing: u64,
}

#[derive(Debug, Serialize)]
struct FreezeOnlyPoolReport {
    pool_address: String,
    target_confirmed_count: u64,
    target_root: String,
    elapsed_ms: u128,
    already_frozen: u64,
    written: u64,
    skipped_existing: u64,
    missing_after: u64,
}

/// Build tip-anchored frozen records for a contiguous confirmed-leaf page.
/// `leaves[i]` is the cmx at global position `start_position + i`. Every witness
/// must reopen to `tip_root` (the pool's current confirmed frontier root).
#[cfg(test)]
fn build_tip_frozen_paths(
    leaves: &[[u8; 32]],
    start_position: u64,
    confirmed_count: u64,
    tip_root: [u8; 32],
    nodes: &HashMap<MerkleNodeKey, [u8; 32]>,
) -> Result<Vec<FrozenPathRecord>> {
    let mut records = Vec::with_capacity(leaves.len());
    for (offset, cmx) in leaves.iter().enumerate() {
        let position = start_position
            .checked_add(offset as u64)
            .ok_or_else(|| anyhow!("tip-freeze position overflow"))?;
        if position >= confirmed_count {
            bail!(
                "tip-freeze leaf position {position} is outside confirmed prefix {confirmed_count}"
            );
        }
        let siblings = witness_from_nodes(position, confirmed_count, nodes)
            .with_context(|| format!("tip-freeze witness for position {position}"))?;
        let recomputed = witness_root_be(*cmx, position, &siblings)
            .with_context(|| format!("tip-freeze root check for position {position}"))?;
        if recomputed != tip_root {
            bail!(
                "tip-freeze witness for position {position} opens to {} != tip {}",
                hex::encode(recomputed),
                hex::encode(tip_root)
            );
        }
        records.push(FrozenPathRecord {
            cmx: *cmx,
            position,
            siblings,
            anchor_root: tip_root,
        });
    }
    Ok(records)
}

fn build_tip_frozen_paths_parallel(
    leaves: &[(u64, [u8; 32])],
    confirmed_count: u64,
    tip_root: [u8; 32],
    nodes: &HashMap<MerkleNodeKey, [u8; 32]>,
    worker_pool: &rayon::ThreadPool,
) -> Result<Vec<FrozenPathRecord>> {
    worker_pool.install(|| {
        leaves
            .par_iter()
            .map(|(position, cmx)| {
                if *position >= confirmed_count {
                    bail!(
                        "tip-freeze leaf position {position} is outside confirmed prefix {confirmed_count}"
                    );
                }
                let siblings = witness_from_nodes(*position, confirmed_count, nodes)
                    .with_context(|| format!("tip-freeze witness for position {position}"))?;
                let recomputed = witness_root_be(*cmx, *position, &siblings)
                    .with_context(|| format!("tip-freeze root check for position {position}"))?;
                if recomputed != tip_root {
                    bail!(
                        "tip-freeze witness for position {position} opens to {} != tip {}",
                        hex::encode(recomputed),
                        hex::encode(tip_root)
                    );
                }
                Ok(FrozenPathRecord {
                    cmx: *cmx,
                    position: *position,
                    siblings,
                    anchor_root: tip_root,
                })
            })
            .collect::<Result<Vec<_>>>()
    })
}

async fn acquire_frozen_path_backfill_lock(
    backend: &StateBackend,
    pool_address: &str,
) -> Result<Option<sqlx::pool::PoolConnection<sqlx::Postgres>>> {
    let StateBackend::Pgsql(pool) = backend else {
        return Ok(None);
    };
    let mut connection = pool
        .acquire()
        .await
        .context("acquire frozen-path advisory-lock connection")?;
    let lock_name = format!(
        "privacy-indexer:frozen-path-backfill:{}",
        normalize_hex_0x(pool_address).to_lowercase()
    );
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtextextended($1, 0))")
        .bind(lock_name)
        .fetch_one(&mut *connection)
        .await
        .context("acquire frozen-path advisory lock")?;
    if !acquired {
        bail!("another frozen-path backfill already holds the pool lock");
    }
    Ok(Some(connection))
}

async fn validate_frozen_path_target(
    rpc: &RpcClient,
    pool_address: &str,
    confirmed_count: u64,
    tip_root: [u8; 32],
) -> Result<()> {
    if confirmed_count == 0 {
        return Ok(());
    }
    let chain_count = word_to_u64(
        &rpc.eth_call_word(pool_address, eth_selector(b"confirmedCount()"))
            .await
            .context("read confirmedCount for frozen-path target")?,
    );
    if chain_count < confirmed_count {
        bail!(
            "local confirmed_count {confirmed_count} is ahead of on-chain {chain_count}; refusing frozen-path target"
        );
    }
    if chain_count == confirmed_count {
        let chain_root = rpc
            .eth_call_word(pool_address, eth_selector(b"confirmedRoot()"))
            .await
            .context("read confirmedRoot for frozen-path target")?;
        if chain_root != tip_root {
            bail!(
                "local tip {} disagrees with on-chain confirmedRoot {}",
                hex::encode(tip_root),
                hex::encode(chain_root)
            );
        }
    }
    let mut calldata = Vec::with_capacity(36);
    calldata.extend_from_slice(&eth_selector(b"isValidAnchor(bytes32)"));
    calldata.extend_from_slice(&tip_root);
    let result = rpc
        .eth_call(pool_address, &calldata, None)
        .await
        .context("validate frozen-path target with isValidAnchor")?;
    if result.len() < 32 || result[..31].iter().any(|byte| *byte != 0) || result[31] != 1 {
        bail!(
            "frozen-path target {} is not a valid on-chain historical anchor",
            hex::encode(tip_root)
        );
    }
    Ok(())
}

async fn freeze_confirmed_prefix(
    backend: &StateBackend,
    backend_write_lock: Option<&tokio::sync::Mutex<()>>,
    pool_address: &str,
    confirmed_count: u64,
    tip_root: [u8; 32],
    config: TipFreezeConfig,
) -> Result<TipFreezeReport> {
    let label = &pool_address[..10.min(pool_address.len())];
    let missing_before = backend
        .count_missing_frozen_paths(pool_address, confirmed_count)
        .await
        .context("count missing frozen paths before backfill")?;
    let already_frozen = confirmed_count.saturating_sub(missing_before);
    if missing_before == 0 {
        println!(
            "[indexer][{label}] tip-path freeze skipped: confirmed prefix {confirmed_count} is complete"
        );
        return Ok(TipFreezeReport {
            confirmed_count,
            already_frozen,
            written: 0,
            skipped_existing: already_frozen,
        });
    }

    let worker_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(config.workers)
        .thread_name(|index| format!("frozen-path-{index}"))
        .build()
        .context("build bounded frozen-path worker pool")?;
    println!(
        "[indexer][{label}] tip-path freeze starting: confirmed={confirmed_count} \
         missing={missing_before} page_size={} workers={} tip={}",
        config.page_size,
        config.workers,
        hex::encode(tip_root)
    );

    let mut written = 0u64;
    let mut skipped_existing = 0u64;
    let mut position = 0u64;
    let mut next_progress = config.page_size as u64 * 16;
    while position < confirmed_count {
        let remaining = (confirmed_count - position) as usize;
        let limit = remaining.min(config.page_size);
        let page = backend
            .load_cmx_freeze_page(pool_address, position, limit)
            .await
            .with_context(|| format!("load confirmed cmx freeze page at position {position}"))?;
        if page.is_empty() {
            bail!(
                "confirmed cmx archive has a gap at position {position} (confirmed_count={confirmed_count})"
            );
        }
        if page.len() as u64 + position > confirmed_count {
            bail!("confirmed cmx freeze page overruns confirmed_count");
        }

        let missing: Vec<(u64, [u8; 32])> = page
            .iter()
            .filter_map(|(leaf_position, cmx, frozen)| {
                if *frozen {
                    skipped_existing += 1;
                    None
                } else {
                    Some((*leaf_position, *cmx))
                }
            })
            .collect();
        if !missing.is_empty() {
            let mut keys = HashSet::new();
            for (leaf_position, _) in &missing {
                for key in required_witness_nodes(*leaf_position, confirmed_count)? {
                    keys.insert(key);
                }
            }
            let mut key_list: Vec<_> = keys.into_iter().collect();
            key_list.sort_unstable();
            let nodes = backend
                .load_merkle_nodes(pool_address, &key_list)
                .await
                .with_context(|| format!("load Merkle nodes for tip-freeze page at {position}"))?;
            let page_records = build_tip_frozen_paths_parallel(
                &missing,
                confirmed_count,
                tip_root,
                &nodes,
                &worker_pool,
            )?;
            let n = page_records.len() as u64;
            let mutation = [NoteArchiveMutation::FrozenPaths(page_records)];
            if let Some(lock) = backend_write_lock {
                let _write = lock.lock().await;
                backend
                    .apply_note_mutations(pool_address, None, &mutation)
                    .await
                    .with_context(|| format!("persist tip-frozen page at {position}"))?;
            } else {
                backend
                    .apply_note_mutations(pool_address, None, &mutation)
                    .await
                    .with_context(|| format!("persist tip-frozen page at {position}"))?;
            }
            written += n;
        }

        position += page.len() as u64;
        if position >= next_progress || position == confirmed_count {
            println!(
                "[indexer][{label}] tip-path freeze progress: {position}/{confirmed_count} \
                 written={written} skipped_existing={skipped_existing}"
            );
            next_progress = position.saturating_add(config.page_size as u64 * 16);
        }
    }

    let missing_after = backend
        .count_missing_frozen_paths(pool_address, confirmed_count)
        .await?;
    if missing_after != 0 {
        bail!(
            "tip-path freeze incomplete: {missing_after} historical cmx rows still lack frozen paths"
        );
    }
    println!(
        "[indexer][{label}] tip-path freeze complete: written={written} \
         skipped_existing={skipped_existing} target={confirmed_count} tip={}",
        hex::encode(tip_root)
    );
    Ok(TipFreezeReport {
        confirmed_count,
        already_frozen,
        written,
        skipped_existing,
    })
}

async fn run_freeze_only(
    rpc: &RpcClient,
    pg_pool: &sqlx::PgPool,
    pool_addresses: &[String],
    start_block: u64,
    config: TipFreezeConfig,
) -> Result<Vec<FreezeOnlyPoolReport>> {
    let backend = StateBackend::Pgsql(pg_pool.clone());
    let mut reports = Vec::with_capacity(pool_addresses.len());
    for raw_address in pool_addresses {
        if parse_address20(raw_address).is_none() {
            bail!("freeze-only pool address is malformed: {raw_address}");
        }
        let pool_address = normalize_hex_0x(raw_address).to_lowercase();
        let _backfill_lock = acquire_frozen_path_backfill_lock(&backend, &pool_address).await?;
        let checkpoint = backend.load(&pool_address, start_block).await;
        if !checkpoint.warm_start_candidate {
            bail!("freeze-only requires a complete v2 warm-start checkpoint for {pool_address}");
        }
        let target_count = checkpoint.confirmed_count;
        let target_root = checkpoint.confirmed_frontier.root_be();
        validate_frozen_path_target(rpc, &pool_address, target_count, target_root).await?;
        let started = Instant::now();
        let report = freeze_confirmed_prefix(
            &backend,
            None,
            &pool_address,
            target_count,
            target_root,
            config,
        )
        .await?;
        let missing_after = backend
            .count_missing_frozen_paths(&pool_address, target_count)
            .await?;
        reports.push(FreezeOnlyPoolReport {
            pool_address,
            target_confirmed_count: target_count,
            target_root: format!("0x{}", hex::encode(target_root)),
            elapsed_ms: started.elapsed().as_millis(),
            already_frozen: report.already_frozen,
            written: report.written,
            skipped_existing: report.skipped_existing,
            missing_after,
        });
    }
    Ok(reports)
}

/// Controllable init: assign every confirmed cmx that still lacks a frozen path
/// a witness pinned to the pool's **current** confirmed root (a valid historical
/// anchor). Already-frozen cmxs (segment-seal or prior tip snapshot) are skipped
/// — divergent reseal is rejected by persistence. Opt-in via `--freeze-tip-paths`.
async fn freeze_confirmed_paths_at_tip(ctx: &PollContext) -> Result<TipFreezeReport> {
    if ctx.shadow_mode {
        bail!("tip-path freeze is disabled in shadow mode");
    }
    let _ingest = ctx.ingest_lock.lock().await;
    let (confirmed_count, tip_root, tree_out_of_order) = {
        let state = ctx.shared.read().await;
        (
            state.confirmed_count,
            state.confirmed_frontier.root_be(),
            state.tree_out_of_order,
        )
    };
    if tree_out_of_order {
        bail!("refusing tip-path freeze while the commitment tree is unready");
    }
    let _backfill_lock =
        acquire_frozen_path_backfill_lock(&ctx.backend, &ctx.contract_address).await?;
    validate_frozen_path_target(&ctx.rpc, &ctx.contract_address, confirmed_count, tip_root).await?;
    freeze_confirmed_prefix(
        &ctx.backend,
        Some(&ctx.backend_write_lock),
        &ctx.contract_address,
        confirmed_count,
        tip_root,
        ctx.freeze_config,
    )
    .await
}

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
    // Controllable tip-snapshot init (mainnet upgrade): pin every still-missing
    // confirmed cmx to the current confirmed root. Segment-seal freezes that
    // already cover the archive make this a no-op.
    if ctx.freeze_tip_paths {
        loop {
            match freeze_confirmed_paths_at_tip(&ctx).await {
                Ok(report) => {
                    ctx.frozen_paths_ready.store(true, AtomicOrdering::Release);
                    println!(
                        "[indexer][{label}] tip-path freeze report: confirmed={} already={} written={} skipped={}",
                        report.confirmed_count,
                        report.already_frozen,
                        report.written,
                        report.skipped_existing
                    );
                    break;
                }
                Err(e) => {
                    eprintln!(
                        "[indexer][{label}] tip-path freeze failed closed: {e:#}; retrying in 5s"
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
                let finalized = match ctx.rpc.confirmation_head().await {
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
                        eprintln!("[indexer] cannot verify receipt block for {tx_hash}: {e:#}");
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

    let endpoint = rpc_endpoint_label(&ctx.wss_url);
    let (mut ws, _) = connect_async(&ctx.wss_url)
        .await
        .with_context(|| format!("WebSocket connect failed: {endpoint}"))?;
    println!(
        "[indexer][{}] WebSocket connected: {}",
        &ctx.contract_address[..10],
        endpoint
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
    topics.push(norm_topic(&fee_charged_topic0_hex()));

    let sub_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_subscribe",
        "params": ["logs", {
            "address": ctx.contract_address,
            "topics": [topics]
        }]
    });
    ws.send(Message::Text(sub_req.to_string()))
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
    let fee_charged_topic = norm_topic(&fee_charged_topic0_hex());

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
        if state.recent_event_ids.contains(&event_id) {
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
        if let Some(last) = state.last_leaf_key {
            if key <= last {
                eprintln!(
                    "[indexer] OUT-OF-ORDER leaf rejected: event {event_id} key={key:?} <= last appended {last:?}; scheduling tree rebuild"
                );
                state.tree_out_of_order = true;
                return Ok(());
            }
        }
        let cmx_position = state.tree_frontier.next_index();
        // Pending leaves update only the compact all-leaf frontier. Immutable
        // witness nodes are archived when the corresponding NoteConfirmed event
        // advances the confirmed prefix.
        state
            .tree_frontier
            .append_be(d.cmx)
            .context("append compact commitment frontier")?;
        state.last_leaf_key = Some(key);
        state.recent_event_ids.insert(event_id);
        const OUT_LEN: usize = 80;
        let (out_ciphertext, cv_net_x) =
            if d.out_ciphertext.len() == OUT_LEN && d.cv_net_x.is_some() {
                (d.out_ciphertext, d.cv_net_x)
            } else {
                lookup_bundle_out_fields(&ctx.rpc, &mut state, &log.transaction_hash, d.cmx).await
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
            cmx_position: Some(cmx_position),
            shield_amount_sats: None,
            is_confirmed: false,
        };
        let seq = state.latest_seq.saturating_add(1);
        state.latest_seq = seq;
        let batch = OrchardIndexBatch {
            from_block: block_number,
            to_block: block_number,
            abi_notes: vec![note],
            bundles: vec![],
            latest_root: Some(state.tree_frontier.root_le()),
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
        if state.recent_event_ids.contains(&event_id) {
            return Ok(());
        }
        let (cmx, new_root, position) =
            decode_note_confirmed_log(log.topics.as_deref().unwrap_or(&[]), &log.data)
                .map_err(|e| anyhow!("NoteConfirmed decode failed: {e}"))?;
        let tree_size = state.tree_frontier.next_index();
        let Some(pending) = state.pending_root_update.as_mut() else {
            state.tree_out_of_order = true;
            bail!("NoteConfirmed at position {position} has no preceding RootUpdated segment");
        };
        let (nodes, complete) = match pending.append_confirmation(
            &log.transaction_hash,
            cmx,
            new_root,
            position,
            tree_size,
        ) {
            Ok(result) => result,
            Err(error) => {
                state.tree_out_of_order = true;
                return Err(error.context("validate NoteConfirmed against RootUpdated segment"));
            }
        };
        let mut frozen_path_records: Option<Vec<FrozenPathRecord>> = None;
        if complete {
            let sealed = state
                .pending_root_update
                .take()
                .expect("completed RootUpdated segment remains staged");
            // Segment-end freeze (docs/note-sync-indexer-frozen-merkle-path.md §4.2):
            // export every staged leaf's witness against the sealed root before
            // the confirmed frontier advances past it. A failure means the staged
            // segment is inconsistent — fail closed and write no paths.
            match sealed.export_frozen_paths() {
                Ok(records) => frozen_path_records = Some(records),
                Err(error) => {
                    state.tree_out_of_order = true;
                    return Err(error.context("export frozen segment Merkle paths"));
                }
            }
            state.confirmed_frontier = sealed.frontier;
            state.active_root = Some(sealed.target_root);
            state.confirmed_count = sealed.to_count;
        }
        state.recent_event_ids.insert(event_id);

        // The confirmation event carries only (cmx, root, position) — republishing
        // it to subscribers needs the note's full payload, which only the original
        // NoteAdded had. The ring is a bounded cache, so under load the NoteAdded
        // can be evicted before its NoteConfirmed arrives.
        //
        // Without a fallback the confirmation is applied to state and to the
        // archive but never republished with a fresh seq. Consumers track this
        // feed by a monotonic `/batches/page` cursor, so a note whose
        // confirmation never reaches the head of the feed is skipped forever:
        // wallets never see it become spendable, and the official prover's
        // successor scan walks its cursor past it.
        //
        // Lazy fallback: the ring stays the fast path (steady-state cost is zero,
        // hit rate is ~100%), and only a miss pays for an archive read. The read
        // must happen with the state lock released — every log-ingestion path
        // holds `ingest_lock` for its whole duration, so no other ingestion can
        // interleave here, but `/root` and `/merkle_path` readers must not be
        // blocked on a database round-trip.
        let ring_hit = state
            .batches
            .iter()
            .rev()
            .flat_map(|env| env.batch.abi_notes.iter())
            .find(|note| note.cmx == cmx)
            .cloned();
        let (mut state, base_note) = match ring_hit {
            Some(note) => (state, Some(note)),
            None => {
                drop(state);
                let recovered = ctx.recover_evicted_note(cmx).await;
                if recovered.is_none() && !ctx.shadow_mode {
                    // Every NoteAdded is archived before its NoteConfirmed can be
                    // processed, so this means the archive is incomplete.
                    eprintln!(
                        "[indexer][{}] NoteConfirmed for cmx {} is absent from the ring AND the \
                         archive; it will not be republished with a new seq",
                        &ctx.contract_address[..10.min(ctx.contract_address.len())],
                        hex::encode(cmx)
                    );
                }
                (ctx.shared.write().await, recovered)
            }
        };
        let maybe_note = base_note.map(|mut note| {
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
                    latest_root: (state.tree_frontier.next_index() > 0)
                        .then(|| state.tree_frontier.root_le()),
                },
            }
        });
        if let Some(envelope) = &envelope {
            state.batches.push_back(envelope.clone());
            while state.batches.len() > state.max_batches {
                state.batches.pop_front();
            }
        }
        let canonical_ready = !state.tree_out_of_order && state.pending_root_update.is_none();
        let persist_snap = (!ctx.persist.is_paused() && state.pending_root_update.is_none())
            .then(|| CheckpointSnapshot::from_state(&state));
        drop(state);

        if let Some(envelope) = &envelope {
            ctx.archive_note_mutation(NoteArchiveMutation::Upsert(envelope.clone()))
                .await?;
        }
        ctx.archive_note_mutation(NoteArchiveMutation::Confirm {
            cmx,
            position,
            nodes,
        })
        .await?;
        if let Some(records) = frozen_path_records {
            ctx.archive_note_mutation(NoteArchiveMutation::FrozenPaths(records))
                .await?;
        }
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
        // OrchardVerifier emits RootUpdated BEFORE this segment's NoteConfirmed
        // events. Stage its target and commit only after every leaf validates.
        if state.recent_event_ids.contains(&event_id) {
            return Ok(());
        }
        match decode_root_updated_log(log.topics.as_deref().unwrap_or(&[]), &log.data) {
            Ok(d) => {
                if state.pending_root_update.is_some() {
                    state.tree_out_of_order = true;
                    bail!("RootUpdated arrived before the previous segment was sealed");
                }
                let pending = match PendingRootUpdate::begin(
                    &state.confirmed_frontier,
                    state.confirmed_count,
                    state.tree_frontier.next_index(),
                    &log.transaction_hash,
                    d.new_root,
                    d.from_count,
                    d.to_count,
                    d.batch_size,
                ) {
                    Ok(pending) => pending,
                    Err(error) => {
                        state.tree_out_of_order = true;
                        return Err(error.context("validate RootUpdated segment"));
                    }
                };
                state.pending_root_update = Some(pending);
                state.recent_event_ids.insert(event_id);
                println!(
                    "[indexer] root update staged: confirmed [{}, {}) root={} batch={}",
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
        if state.recent_event_ids.contains(&event_id) {
            return Ok(());
        }
        match decode_frozen_root_updated_log(&log.data) {
            Ok(d) => {
                let current_root =
                    parse_hex32(&state.frozen_root_hex).context("invalid in-memory frozen root")?;
                if state.frozen_update_count > 0 && d.old_root != current_root {
                    state.tree_out_of_order = true;
                    bail!(
                        "FrozenRootUpdated old root mismatch: local={}, event={}",
                        hex::encode(current_root),
                        hex::encode(d.old_root)
                    );
                }
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
                let position = state.frozen_update_count;
                let current_count = state.frozen_count;
                drop(state);
                let membership = ctx
                    .frozen_membership_before_next_update(&upd.cmx_changed_hex)
                    .await?;
                let next_count = frozen_count_after_delta(current_count, membership, &upd)?;
                // Archive/buffer first. A storage failure leaves in-memory state
                // untouched, so canonical replay can retry this event.
                ctx.archive_note_mutation(NoteArchiveMutation::Frozen {
                    position,
                    update: upd.clone(),
                })
                .await?;

                let mut state = ctx.shared.write().await;
                let still_current_root = parse_hex32(&state.frozen_root_hex)
                    .context("invalid in-memory frozen root after archive")?;
                if state.frozen_update_count != position || still_current_root != current_root {
                    state.tree_out_of_order = true;
                    bail!("frozen state changed while archiving a serialized event");
                }
                state.frozen_root_hex = upd.new_root_hex.clone();
                state.frozen_count = next_count;
                state.frozen_update_count = position.saturating_add(1);
                state.recent_event_ids.insert(event_id.clone());
                let persist_snap =
                    (!ctx.persist.is_paused()).then(|| CheckpointSnapshot::from_state(&state));
                drop(state);
                if let Some(snap) = persist_snap {
                    ctx.persist.notify_owned(snap);
                }
                return Ok(());
            }
            Err(e) => eprintln!("[indexer] FrozenRootUpdated decode FAILED: {e}"),
        }
    } else if t0.as_deref() == Some(sc.as_str()) {
        // ── ShieldCompleted ──────────────────────────────────────────────────
        // NoteAdded was already processed; update shield_amount_sats on the
        // existing batch entry and re-emit.
        if state.recent_event_ids.contains(&event_id) {
            return Ok(());
        }
        let (cmx, raw_amount) =
            decode_shield_completed_log(log.topics.as_deref().unwrap_or(&[]), &log.data)
                .map_err(|e| anyhow!("ShieldCompleted decode failed: {e}"))?;
        let amount = u64::try_from(raw_amount).context("ShieldCompleted amount exceeds u64")?;
        state.recent_event_ids.insert(event_id);
        // Same eviction hazard as NoteConfirmed: `ShieldCompleted` carries only
        // (cmx, amount), so re-emitting needs the NoteAdded payload, and the ring
        // may already have dropped it. Recovering keeps `shield_amount_sats`
        // reaching subscribers, which is what the pool's public shield accounting
        // is rendered from.
        let ring_hit = state
            .batches
            .iter()
            .rev()
            .flat_map(|env| env.batch.abi_notes.iter())
            .find(|note| note.cmx == cmx && note.tx_hash == log.transaction_hash)
            .cloned();
        let (mut state, base_note) = match ring_hit {
            Some(note) => (state, Some(note)),
            None => {
                drop(state);
                // The archive is keyed by cmx alone, so the tx_hash match the ring
                // scan applies is re-checked here: a recovered note from a
                // different transaction is not this event's note.
                let recovered = ctx.recover_evicted_note(cmx).await.filter(|note| {
                    normalize_hex_0x(&note.tx_hash).to_lowercase()
                        == normalize_hex_0x(&log.transaction_hash).to_lowercase()
                });
                (ctx.shared.write().await, recovered)
            }
        };
        let maybe_note = base_note.map(|mut note| {
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
                    latest_root: (state.tree_frontier.next_index() > 0)
                        .then(|| state.tree_frontier.root_le()),
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
        if state.recent_event_ids.contains(&event_id) {
            return Ok(());
        }
        match decode_shielded_log(log.topics.as_deref().unwrap_or(&[]), &log.data) {
            Ok(d) => {
                state.recent_event_ids.insert(event_id);
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
        if state.recent_event_ids.contains(&event_id) {
            return Ok(());
        }
        match decode_unshielded_log(log.topics.as_deref().unwrap_or(&[]), &log.data) {
            Ok(d) => {
                state.recent_event_ids.insert(event_id);
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
    } else if t0.as_deref() == Some(fee_charged_topic.as_str()) {
        // ── Protocol fee accounting (shield + unshield) ────────────────────────
        if state.recent_event_ids.contains(&event_id) {
            return Ok(());
        }
        match decode_fee_charged_log(&log.data) {
            Ok(d) => {
                state.recent_event_ids.insert(event_id);
                state.shield_accounting.total_fee_units = state
                    .shield_accounting
                    .total_fee_units
                    .saturating_add(d.fee_units);
                state.shield_accounting.total_fee_wei = state
                    .shield_accounting
                    .total_fee_wei
                    .saturating_add(d.fee_wei);
                state.next_block = block_number.saturating_add(1).max(state.next_block);
                ctx.persist.notify(&state);
            }
            Err(e) => return Err(anyhow!("FeeCharged decode failed: {e}")),
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

/// `confirmations=1` includes the mined tip itself; each additional confirmation
/// moves the scan boundary back by one block. `0` is handled by the caller as the
/// special finalized policy and therefore leaves its resolved tip unchanged.
fn confirmation_head_number(tip: u64, confirmations: u64) -> u64 {
    tip.saturating_sub(confirmations.saturating_sub(1))
}

/// Resolve an omitted per-pool floor to the environment's reviewed deployment
/// floor. Keeping this decision in one place prevents runtime registration from
/// silently reintroducing a genesis-wide admission or metadata query.
fn effective_pool_start_block(requested: u64, default_start_block: u64) -> u64 {
    if requested == 0 {
        default_start_block
    } else {
        requested
    }
}

#[derive(Clone)]
struct RpcClient {
    http: Client,
    urls: Vec<String>,
    /// `0` uses the RPC's finalized tag. Positive values count mined blocks,
    /// where `1` means the current latest block.
    confirmations: u64,
    /// Largest `eth_getLogs` block span the provider is known to accept.
    /// Starts at `GETLOGS_DEFAULT_SPAN` (or `PRIVACYBTC_INDEXER_GETLOGS_MAX_SPAN`)
    /// and only ever shrinks — halved each time the provider rejects a window,
    /// so a range-capped provider (e.g. Alchemy Monad testnet: 1000 blocks) can
    /// no longer wedge catchup/backfill in a permanent retry loop.
    getlogs_span: Arc<AtomicU64>,
}

impl RpcClient {
    fn new(url: String, confirmations: u64) -> Self {
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
            confirmations,
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

    /// Resolve the configured canonical ingest boundary. Monad deployments keep
    /// `confirmations=0` and therefore use `finalized`; Ethereum deployments may
    /// explicitly select mined-block confirmations (one means `latest`).
    async fn confirmation_head(&self) -> Result<(u64, String)> {
        #[derive(Deserialize)]
        struct BlockHeader {
            number: String,
            hash: String,
        }
        let tag = if self.confirmations == 0 {
            "finalized"
        } else {
            "latest"
        };
        let header: Option<BlockHeader> = self
            .rpc_call("eth_getBlockByNumber", serde_json::json!([tag, false]))
            .await
            .with_context(|| format!("eth_getBlockByNumber({tag})"))?;
        let header = header.ok_or_else(|| anyhow!("RPC returned no {tag} block"))?;
        let tip =
            parse_hex_u64(&header.number).with_context(|| format!("invalid {tag} block number"))?;
        let tip_hash = normalize_block_hash(&header.hash)
            .with_context(|| format!("invalid {tag} block hash"))?;
        let head = confirmation_head_number(tip, self.confirmations);
        if head == tip {
            return Ok((head, tip_hash));
        }
        Ok((head, self.block_hash(head).await?))
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

    async fn get_pending_transaction_count(&self, address: &str) -> Result<u64> {
        let hex_num: String = self
            .rpc_call(
                "eth_getTransactionCount",
                serde_json::json!([address, "pending"]),
            )
            .await?;
        parse_hex_u64(&hex_num).context("invalid pending eth_getTransactionCount")
    }

    async fn base_fee_per_gas(&self) -> Result<u64> {
        let block: serde_json::Value = self
            .rpc_call("eth_getBlockByNumber", serde_json::json!(["latest", false]))
            .await?;
        let value = block
            .get("baseFeePerGas")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("latest block has no baseFeePerGas; refusing EIP-1559 crank"))?;
        parse_hex_u64(value).context("invalid latest baseFeePerGas")
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

    async fn get_transaction_receipt_logs(&self, tx_hash: &str) -> Result<Option<ReceiptWithLogs>> {
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
        let block_number = parse_hex_u64(&r.block_number).context("invalid receipt blockNumber")?;
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
    async fn fetch_pool_metadata(&self, pool: &str, start_block: u64) -> Result<Option<PoolMeta>> {
        let addr = normalize_hex_0x(pool);
        let topic1 = format!("0x{:0>64}", addr.trim_start_matches("0x"));
        let shield_topic = shield_pool_created_topic0_hex();
        let issuer_topic = perc20_created_topic0();
        let (head, _) = self.confirmation_head().await?;
        let mut lo = start_block;
        while lo <= head {
            let hi = getlogs_window_end(lo, head, self.getlogs_span());
            // Both supported genesis events are queried together so an issuer
            // pool does not require scanning the entire chain once for the absent
            // shield event before falling back to Perc20Created.
            let filter = serde_json::json!({
                "fromBlock": format!("0x{lo:x}"),
                "toBlock":   format!("0x{hi:x}"),
                "address":   addr.clone(),
                "topics":    [[shield_topic.clone(), issuer_topic.clone()], topic1.clone()],
            });
            let logs: Vec<EthLog> = match self
                .rpc_call("eth_getLogs", serde_json::json!([filter]))
                .await
            {
                Ok(logs) => logs,
                Err(error) if hi > lo && is_getlogs_range_error(&error) => {
                    self.shrink_getlogs_span(hi - lo + 1);
                    continue;
                }
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("eth_getLogs (pool metadata) [{lo},{hi}] failed"))
                }
            };
            self.validate_canonical_logs(&logs).await?;

            // Prefer the shield-pool event because it carries scale + underlying.
            for log in &logs {
                if log
                    .topics
                    .as_ref()
                    .and_then(|topics| topics.first())
                    .map(|topic| topic.eq_ignore_ascii_case(&shield_topic))
                    .unwrap_or(false)
                {
                    if let Some(topics) = log.topics.as_ref() {
                        if let Ok(decoded) = decode_shield_pool_created_log(topics, &log.data) {
                            return Ok(Some(PoolMeta::from_shield_pool(&addr, &decoded)));
                        }
                    }
                }
            }
            for log in &logs {
                if log
                    .topics
                    .as_ref()
                    .and_then(|topics| topics.first())
                    .map(|topic| topic.eq_ignore_ascii_case(&issuer_topic))
                    .unwrap_or(false)
                {
                    if let Some(meta) = PoolMeta::try_from_perc20_created(&addr, &log.data) {
                        return Ok(Some(meta));
                    }
                    // Event present but body not decodable — still a known issuer pool.
                    return Ok(Some(PoolMeta::issuer_minimal(&addr)));
                }
            }

            if hi == u64::MAX {
                break;
            }
            lo = hi + 1;
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
        start_block: u64,
    ) -> Result<bool> {
        let (head, _) = self.confirmation_head().await?;
        let mut lo = start_block;
        while lo <= head {
            let hi = getlogs_window_end(lo, head, self.getlogs_span());
            let filter = serde_json::json!({
                "fromBlock": format!("0x{lo:x}"),
                "toBlock":   format!("0x{hi:x}"),
                "address":   normalize_hex_0x(factory),
                "topics":    [event_topic, address_to_topic(pool)],
            });
            let logs: Vec<EthLog> = match self
                .rpc_call("eth_getLogs", serde_json::json!([filter]))
                .await
            {
                Ok(logs) => logs,
                Err(error) if hi > lo && is_getlogs_range_error(&error) => {
                    self.shrink_getlogs_span(hi - lo + 1);
                    continue;
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("eth_getLogs deployment proof failed for pool {pool} [{lo},{hi}]")
                    })
                }
            };
            self.validate_canonical_logs(&logs).await?;
            if logs
                .iter()
                .any(|log| factory_log_matches(log, factory, event_topic, pool))
            {
                return Ok(true);
            }
            if hi == u64::MAX {
                break;
            }
            lo = hi + 1;
        }
        Ok(false)
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
            let endpoint = rpc_endpoint_label(url);
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
                                    "eth_{} failed for {endpoint}: rpc error {}: {}",
                                    method,
                                    e.code,
                                    e.message
                                );
                                return Err(last_err);
                            }
                            _ => {
                                last_err = anyhow!(
                                    "malformed rpc response for method {method} from {endpoint}"
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
                        last_err = anyhow!("eth_{} send failed from {endpoint}: {}", method, e);
                        if attempt == 0 {
                            // First failure — may be a stale connection; retry once silently.
                            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                            continue 'attempts;
                        }
                        eprintln!("[indexer] rpc {endpoint} failed ({e}), trying fallback…");
                    }
                }
            }
        }
        Err(last_err)
    }
}

// ─── Ethereum raw transaction ─────────────────────────────────────────────────

fn eip1559_crank_fees(base_fee: u64, priority_fee: u64, max_fee_cap: u64) -> Result<(u128, u128)> {
    if priority_fee == 0 || max_fee_cap == 0 {
        return Err(anyhow!(
            "EIP-1559 priority fee and max fee cap must be non-zero"
        ));
    }
    if priority_fee > max_fee_cap {
        return Err(anyhow!("EIP-1559 priority fee exceeds max fee cap"));
    }
    let priority = u128::from(priority_fee);
    let required = u128::from(base_fee)
        .checked_mul(2)
        .and_then(|value| value.checked_add(priority))
        .ok_or_else(|| anyhow!("EIP-1559 fee calculation overflow"))?;
    if required > u128::from(max_fee_cap) {
        return Err(anyhow!(
            "EIP-1559 base fee {base_fee} requires maxFeePerGas {required}, above configured cap {max_fee_cap}"
        ));
    }
    Ok((priority, required))
}

/// Builds and signs an EIP-155 legacy raw transaction.
#[allow(clippy::too_many_arguments)]
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

/// Builds and signs an EIP-1559 type-2 raw transaction with an empty access list.
#[allow(clippy::too_many_arguments)]
fn build_and_sign_eip1559_tx(
    nonce: u64,
    max_priority_fee_per_gas: u128,
    max_fee_per_gas: u128,
    gas_limit: u64,
    to: &str,
    value: u64,
    data: &[u8],
    chain_id: u64,
    signing_key: &SigningKey,
) -> Result<Vec<u8>> {
    if max_priority_fee_per_gas == 0 || max_priority_fee_per_gas > max_fee_per_gas {
        return Err(anyhow!("invalid EIP-1559 fee relationship"));
    }
    let to_bytes = hex::decode(strip_0x(to)).context("invalid contract address hex")?;
    if to_bytes.len() != 20 {
        return Err(anyhow!("contract address must be 20 bytes"));
    }
    let access_list = rlp_list(vec![]);
    let unsigned_payload = rlp_list(vec![
        rlp_uint(chain_id as u128),
        rlp_uint(nonce as u128),
        rlp_uint(max_priority_fee_per_gas),
        rlp_uint(max_fee_per_gas),
        rlp_uint(gas_limit as u128),
        rlp_bytes(&to_bytes),
        rlp_uint(value as u128),
        rlp_bytes(data),
        access_list.clone(),
    ]);
    let mut signing_payload = Vec::with_capacity(1 + unsigned_payload.len());
    signing_payload.push(0x02);
    signing_payload.extend_from_slice(&unsigned_payload);
    let tx_hash: [u8; 32] = Keccak256::digest(&signing_payload).into();
    let (sig, recid): (k256::ecdsa::Signature, RecoveryId) = signing_key
        .sign_prehash_recoverable(&tx_hash)
        .map_err(|e| anyhow!("signing failed: {e}"))?;
    let r: [u8; 32] = sig.r().to_bytes().into();
    let s: [u8; 32] = sig.s().to_bytes().into();
    let signed_payload = rlp_list(vec![
        rlp_uint(chain_id as u128),
        rlp_uint(nonce as u128),
        rlp_uint(max_priority_fee_per_gas),
        rlp_uint(max_fee_per_gas),
        rlp_uint(gas_limit as u128),
        rlp_bytes(&to_bytes),
        rlp_uint(value as u128),
        rlp_bytes(data),
        access_list,
        rlp_uint(recid.to_byte() as u128),
        rlp_uint256(&r),
        rlp_uint256(&s),
    ]);
    let mut raw = Vec::with_capacity(1 + signed_payload.len());
    raw.push(0x02);
    raw.extend_from_slice(&signed_payload);
    Ok(raw)
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

fn rlp_uint256(bytes: &[u8; 32]) -> Vec<u8> {
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    rlp_bytes(&bytes[start..])
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

fn rpc_endpoint_label(value: &str) -> String {
    let Some((scheme, remainder)) = value.split_once("://") else {
        return "<redacted-rpc-endpoint>".to_string();
    };
    if !matches!(scheme, "http" | "https" | "ws" | "wss") {
        return "<redacted-rpc-endpoint>".to_string();
    }
    let authority = remainder.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or_default();
    if host.is_empty() {
        return "<redacted-rpc-endpoint>".to_string();
    }
    format!("{scheme}://{host}")
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
    use std::collections::HashMap;

    use k256::ecdsa::SigningKey;

    use super::{
        advance_cursor, append_factory_pools_registry, batch_page_end, beacon_words_match,
        bind_factory_discovery_source, broadcasted_crank_attempts, build_and_sign_eip1559_tx,
        build_tip_frozen_paths, canonical_guard, checkpoint_is_complete_finalized_boundary,
        classify_selector, compact_note_mutations, completed_admission_can_short_circuit,
        confirmation_head_number, crank_gas_limit, crank_next_delay_secs,
        decode_frozen_root_updated_log, decode_json_note_archive, effective_pool_start_block,
        eip1559_crank_fees, eip1967_beacon_slot, encode_crank_root_calldata,
        export_segment_frozen_paths, factory_discovery_from_registry_entry,
        factory_discovery_source_is_trusted, factory_log_matches, finalized_cursor_covers_block,
        freeze_confirmed_prefix, frontier_from_leaves, frozen_count_after_delta,
        frozen_root_updated_topic0, getlogs_window_end, is_getlogs_range_error,
        is_public_merkle_path, is_public_txs, latest_upserted_note, missing_required_pools,
        next_factory_discovery_from, nonempty_trimmed, normalize_hex_0x, parse_address_set,
        parse_bool_flag, parse_bytes32_strict, parse_tx_meta, perc20_deployed_topic0,
        persist_request_is_current, pg_append_cmx_leaves, pg_append_merkle_nodes,
        pg_apply_note_mutations, pg_archive_seq_bound, pg_begin_canonical_rebuild,
        pg_bulk_upsert_notes, pg_commit_incremental_replay, pg_finish_canonical_rebuild, pg_load,
        pg_upgrade_legacy_compact_checkpoint, public_api_access, push_incremental_replay_mutation,
        queue_factory_discovery_range, queue_pending_pool_admission, raw_tx_hash,
        replay_frozen_set, require_admin, require_relayer, required_witness_nodes, rlp_bytes,
        rlp_list, rlp_uint, rpc_endpoint_label, strip_0x, unix_seconds,
        validate_crank_journal_parent, validate_crank_journal_signed_payloads,
        validate_log_against_canonical, witness_from_nodes, witness_root_be, ApiAccess,
        ArchivedNoteRow, BatchEnvelope, CheckpointSnapshot, Cli, CompactFrontier, CrankTxAttempt,
        CrankTxJournal, EgressBudget, EthLog, FrozenPathRecord, FrozenUpdate, HourlyTxBudget,
        IndexerCheckpoint, JsonNoteArchiveUpdate, NoteArchiveMutation, PendingFactoryAdmission,
        PendingPoolAdmission, PendingRootUpdate, PoolRegistryEntry, PoolsRegistryFile,
        PublicApiMode, RecentEventIds, RpcClient, StateBackend, StreamingFrontierBuilder,
        TipFreezeConfig, TxListNote, DEFAULT_MAX_BATCHES_IN_MEMORY,
        FACTORY_DISCOVERY_RESCAN_BLOCKS, MAX_CRANK_GAS_MARGIN_BPS, MAX_RECENT_EVENT_IDS,
        MAX_TIP_FREEZE_PAGE_SIZE, MAX_TIP_FREEZE_WORKERS,
    };
    use std::time::Instant;

    #[test]
    fn batch_page_boundary_never_splits_one_sequence() {
        assert_eq!(batch_page_end(&[11, 12, 12, 12, 15], 2), 4);
        assert_eq!(batch_page_end(&[11, 12, 15], 2), 2);
        assert_eq!(batch_page_end(&[11, 12], 500), 2);
    }

    #[test]
    fn batch_page_limit_is_a_soft_envelope_limit() {
        assert_eq!(batch_page_end(&[7, 7, 7], 1), 3);
    }

    #[test]
    fn postgres_archive_unbounded_sequence_sentinel_does_not_wrap_negative() {
        assert_eq!(pg_archive_seq_bound(0), 0);
        assert_eq!(pg_archive_seq_bound(i64::MAX as u64), i64::MAX);
        assert_eq!(pg_archive_seq_bound(u64::MAX), i64::MAX);
    }

    #[test]
    fn only_complete_finalized_boundaries_are_checkpoint_eligible() {
        assert!(checkpoint_is_complete_finalized_boundary(
            102,
            Some(101),
            Some("0xabc")
        ));
        assert!(!checkpoint_is_complete_finalized_boundary(
            101,
            Some(101),
            Some("0xabc")
        ));
        assert!(!checkpoint_is_complete_finalized_boundary(
            102,
            Some(100),
            Some("0xabc")
        ));
        assert!(!checkpoint_is_complete_finalized_boundary(
            102,
            Some(101),
            None
        ));
    }

    #[test]
    fn sealed_finalized_cursor_deduplicates_delayed_ws_logs_after_restart() {
        let hash = format!("0x{}", "ab".repeat(32));
        assert!(finalized_cursor_covers_block(
            102,
            Some(101),
            Some(&hash),
            false,
            100,
        ));
        assert!(!finalized_cursor_covers_block(
            102,
            Some(101),
            Some(&hash),
            false,
            102,
        ));
        assert!(!finalized_cursor_covers_block(
            102,
            Some(101),
            Some(&hash),
            true,
            100,
        ));
        assert!(!finalized_cursor_covers_block(
            101,
            Some(101),
            Some(&hash),
            false,
            100,
        ));
    }

    #[tokio::test]
    async fn batch_archive_database_errors_fail_closed() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://postgres@127.0.0.1:1/unreachable")
            .unwrap();
        pool.close().await;
        let result = StateBackend::Pgsql(pool)
            .load_archived_batch_page(&format!("0x{}", "11".repeat(20)), 0, 100, u64::MAX, 10)
            .await;
        assert!(
            result.is_err(),
            "archive errors must never look like an empty page"
        );
    }

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
        assert_eq!(
            replay_frozen_set(&feed),
            vec!["0xbb".to_string(), "0xaa".to_string()]
        );

        // remove-all → empty
        let feed2 = vec![
            frozen_update(&["0xaa"], &[true]),
            frozen_update(&["0xaa"], &[false]),
        ];
        assert!(replay_frozen_set(&feed2).is_empty());
    }

    #[test]
    fn frozen_count_projection_preserves_idempotent_delta_semantics() {
        let a = format!("0x{}", hex::encode(canonical_test_leaf(1)));
        let b = format!("0x{}", hex::encode(canonical_test_leaf(2)));
        let absent = format!("0x{}", hex::encode(canonical_test_leaf(3)));
        let membership = HashSet::from([a.clone(), b.clone()]);
        let update = frozen_update(&[&a, &absent], &[true, false]);
        assert_eq!(
            frozen_count_after_delta(2, membership.clone(), &update).unwrap(),
            2,
            "re-adding an existing cmx and removing an absent cmx are no-ops"
        );
        let remove = frozen_update(&[&b], &[false]);
        assert_eq!(frozen_count_after_delta(2, membership, &remove).unwrap(), 1);
    }

    #[test]
    fn recent_event_dedup_is_strictly_bounded() {
        let mut recent = RecentEventIds::default();
        for value in 0..=MAX_RECENT_EVENT_IDS {
            assert!(recent.insert(format!("event-{value}")));
        }
        assert_eq!(recent.order.len(), MAX_RECENT_EVENT_IDS);
        assert_eq!(recent.set.len(), MAX_RECENT_EVENT_IDS);
        assert!(!recent.contains("event-0"));
        assert!(recent.contains(&format!("event-{MAX_RECENT_EVENT_IDS}")));
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
    use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
    use clap::CommandFactory;
    use ff::PrimeField;
    use halo2curves::bn256::Fr;
    use privacy_core::commitment_tree::frozen::fr_to_be_bytes;
    use privacy_core::commitment_tree::{
        frontier::{FrontierTree, CMX_CONFIRM_MAX_BATCH, CMX_CONFIRM_MAX_PROOFS_PER_TX},
        OrchardCommitmentTree,
    };
    use privacy_core::ethereum::{update_root_selector, update_roots_selector};
    use privacy_core::types::{OrchardIndexBatch, OrchardIndexedAbiNote};
    use sha3::{Digest, Keccak256};
    use std::{collections::HashSet, sync::Arc};

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
                nodes: Vec::new(),
            },
            1,
        )
        .unwrap();
        let error = push_incremental_replay_mutation(
            &mut buffered,
            NoteArchiveMutation::Confirm {
                cmx: [0x22; 32],
                position: 1,
                nodes: Vec::new(),
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

    #[test]
    fn empty_inherited_signer_is_not_configured() {
        assert_eq!(nonempty_trimmed(None), None);
        assert_eq!(nonempty_trimmed(Some("")), None);
        assert_eq!(nonempty_trimmed(Some("   \t")), None);
        assert_eq!(nonempty_trimmed(Some(" 0x1234 ")), Some("0x1234"));
    }

    fn canonical_test_leaf(value: u64) -> [u8; 32] {
        let mut be: [u8; 32] = Fr::from(value).to_repr().into();
        be.reverse();
        be
    }

    fn append_test_leaves(mut frontier: CompactFrontier, leaves: &[[u8; 32]]) -> CompactFrontier {
        for leaf in leaves {
            frontier.append_be(*leaf).unwrap();
        }
        frontier
    }

    #[test]
    fn root_updated_before_note_confirmed_seals_one_eight_leaf_segment() {
        let committed = CompactFrontier::new();
        let leaves: Vec<_> = (1..=8).map(canonical_test_leaf).collect();
        let expected = append_test_leaves(committed.clone(), &leaves);
        let target_root = expected.root_be();
        let tx_hash = format!("0x{}", "11".repeat(32));
        let mut pending = PendingRootUpdate::begin(
            &committed,
            0,
            leaves.len() as u64,
            &tx_hash,
            target_root,
            0,
            8,
            8,
        )
        .unwrap();

        // The committed frontier is unchanged while the first seven events
        // repeat the final batch root.
        assert_eq!(committed.next_index(), 0);
        for (position, cmx) in leaves.into_iter().enumerate() {
            let (_, complete) = pending
                .append_confirmation(&tx_hash, cmx, target_root, position as u64, 8)
                .unwrap();
            assert_eq!(complete, position == 7);
        }
        assert_eq!(pending.frontier.next_index(), 8);
        assert_eq!(pending.frontier.root_be(), target_root);
    }

    /// Sealing a segment must yield one frozen path per leaf, every path
    /// pinned to the event's `newRoot` — and later segments must not change a
    /// single byte of the earlier exports (spec: freeze-at-seal, no tip chase).
    #[test]
    fn sealed_segments_export_frozen_paths_pinned_to_their_own_new_root() {
        let leaves: Vec<_> = (1..=19).map(canonical_test_leaf).collect();
        let tx_hash = format!("0x{}", "55".repeat(32));
        let mut committed = CompactFrontier::new();
        let mut exported: Vec<(Vec<FrozenPathRecord>, [u8; 32])> = Vec::new();

        // Two full segments plus one tail segment (j = 8, 8, 3).
        for (from, to) in [(0u64, 8u64), (8, 16), (16, 19)] {
            let segment_leaves = &leaves[from as usize..to as usize];
            let expected = append_test_leaves(committed.clone(), segment_leaves);
            let target_root = expected.root_be();
            let batch = (to - from) as u32;
            let mut pending = PendingRootUpdate::begin(
                &committed,
                from,
                19,
                &tx_hash,
                target_root,
                from,
                to,
                batch,
            )
            .unwrap();
            for (offset, cmx) in segment_leaves.iter().copied().enumerate() {
                pending
                    .append_confirmation(&tx_hash, cmx, target_root, from + offset as u64, 19)
                    .unwrap();
            }
            let records = pending.export_frozen_paths().unwrap();
            assert_eq!(records.len(), (to - from) as usize);
            for (offset, record) in records.iter().enumerate() {
                assert_eq!(record.position, from + offset as u64);
                assert_eq!(record.cmx, segment_leaves[offset]);
                assert_eq!(record.anchor_root, target_root);
                assert_eq!(
                    witness_root_be(record.cmx, record.position, &record.siblings).unwrap(),
                    target_root
                );
            }
            committed = pending.frontier;
            exported.push((records, target_root));
        }

        // All three anchors differ, and every earlier export still opens to
        // its own sealed root even though the tree has grown since.
        assert_ne!(exported[0].1, exported[1].1);
        assert_ne!(exported[1].1, exported[2].1);
        for (records, sealed_root) in &exported {
            for record in records {
                assert_eq!(
                    witness_root_be(record.cmx, record.position, &record.siblings).unwrap(),
                    *sealed_root
                );
            }
        }
    }

    /// Replaying the same sealed segment (WS + catch-up overlap) must compact
    /// to one frozen record per cmx, exactly like Confirm mutations.
    #[test]
    fn frozen_path_mutations_compact_to_one_record_per_cmx() {
        let record = |value: u64, position: u64| FrozenPathRecord {
            cmx: canonical_test_leaf(value),
            position,
            siblings: vec!["0x00".to_owned(); 32],
            anchor_root: canonical_test_leaf(1000 + position),
        };
        let first = vec![record(1, 0), record(2, 1)];
        let compacted = compact_note_mutations(&[
            NoteArchiveMutation::FrozenPaths(first.clone()),
            NoteArchiveMutation::FrozenPaths(first),
            NoteArchiveMutation::FrozenPaths(vec![record(3, 2)]),
        ]);
        assert_eq!(compacted.frozen_paths.len(), 3);
        assert_eq!(
            compacted
                .frozen_paths
                .iter()
                .map(|r| r.position)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn update_roots_event_order_seals_four_segments_and_thirty_two_leaves() {
        let leaves: Vec<_> = (1..=32).map(canonical_test_leaf).collect();
        let tx_hash = format!("0x{}", "22".repeat(32));
        let mut committed = CompactFrontier::new();

        for segment in 0..4usize {
            let from = (segment * 8) as u64;
            let to = from + 8;
            let segment_leaves = &leaves[segment * 8..segment * 8 + 8];
            let expected = append_test_leaves(committed.clone(), segment_leaves);
            let target_root = expected.root_be();
            let mut pending =
                PendingRootUpdate::begin(&committed, from, 32, &tx_hash, target_root, from, to, 8)
                    .unwrap();
            for (offset, cmx) in segment_leaves.iter().copied().enumerate() {
                let (_, complete) = pending
                    .append_confirmation(&tx_hash, cmx, target_root, from + offset as u64, 32)
                    .unwrap();
                assert_eq!(complete, offset == 7);
            }
            committed = pending.frontier;
            assert_eq!(committed.root_be(), expected.root_be());
        }
        assert_eq!(committed.next_index(), 32);
    }

    #[test]
    fn malformed_root_update_segments_fail_closed_without_partial_commit() {
        let committed = CompactFrontier::new();
        let leaves: Vec<_> = (1..=8).map(canonical_test_leaf).collect();
        let expected = append_test_leaves(committed.clone(), &leaves);
        let target_root = expected.root_be();
        let tx_hash = format!("0x{}", "33".repeat(32));

        assert!(
            PendingRootUpdate::begin(&committed, 0, 8, &tx_hash, target_root, 1, 9, 8,).is_err()
        );
        assert!(
            PendingRootUpdate::begin(&committed, 0, 8, &tx_hash, target_root, 0, 8, 7,).is_err()
        );

        let mut pending =
            PendingRootUpdate::begin(&committed, 0, 8, &tx_hash, target_root, 0, 8, 8).unwrap();
        assert!(pending
            .append_confirmation(&tx_hash, leaves[0], target_root, 1, 8)
            .is_err());
        assert_eq!(pending.frontier.next_index(), 0);
        assert!(pending
            .append_confirmation(
                &format!("0x{}", "44".repeat(32)),
                leaves[0],
                target_root,
                0,
                8,
            )
            .is_err());
        assert_eq!(pending.frontier.next_index(), 0);

        for (position, cmx) in leaves.iter().copied().take(7).enumerate() {
            pending
                .append_confirmation(&tx_hash, cmx, target_root, position as u64, 8)
                .unwrap();
        }
        assert!(pending
            .append_confirmation(&tx_hash, canonical_test_leaf(999), target_root, 7, 8,)
            .is_err());
        assert_eq!(pending.frontier.next_index(), 7);
        assert_eq!(committed.next_index(), 0);
    }

    #[test]
    fn compact_frontier_reconstructs_exact_crank_frontier() {
        let leaves: Vec<[u8; 32]> = (1..=65).map(canonical_test_leaf).collect();
        for size in [0usize, 1, 2, 3, 4, 7, 8, 31, 32, 33, 64, 65] {
            let restored = frontier_from_leaves(&leaves[..size])
                .expect("reconstruct frontier from checkpoint leaves");
            let mut replayed = FrontierTree::new();
            for leaf in &leaves[..size] {
                replayed.insert_be(*leaf);
            }
            assert_eq!(restored.next_index(), replayed.next_index(), "size={size}");
            assert_eq!(
                restored.root_be(),
                fr_to_be_bytes(replayed.root()),
                "size={size}"
            );
            assert_eq!(restored.frontier_commit(), replayed.frontier_commit());
        }
    }

    #[test]
    #[ignore = "capacity benchmark; run explicitly in release mode"]
    fn production_sized_checkpoint_frontier_rebuild() {
        const LEAVES: u64 = 350_000;
        let started = std::time::Instant::now();
        let mut builder = StreamingFrontierBuilder::new();
        for value in 1..LEAVES {
            let complete = builder
                .push_nonfinal_be(canonical_test_leaf(value))
                .expect("stream production-sized checkpoint leaf");
            assert!(complete.len() <= 32);
        }
        let (restored, complete) = builder
            .finish_with_last_be(canonical_test_leaf(LEAVES))
            .expect("finish production-sized checkpoint frontier");
        assert!(complete.len() <= 32);
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

    /// The protocol-fee release changed `ERC20Shield.unshield`'s signature (it gained
    /// `(bytes32 context, address executor)`) and added `Perc20FeeGateway.transferWithFee`.
    /// Both selectors are new; leaving them unclassified would silently drop the op,
    /// amount and recipient from the history view of every fee-release pool while the
    /// stack otherwise looked healthy.
    #[test]
    fn protocol_fee_release_selectors_are_classified() {
        // unshield(uint256,address,bytes32,address,(bytes,uint256[8]))
        assert_eq!(
            classify_selector(&hex::decode("73a93e1b").unwrap()),
            Some("unshield")
        );
        // transferWithFee(address,(bytes,uint256[8]),(bytes,uint256[8]))
        assert_eq!(
            classify_selector(&hex::decode("4c4ba93b").unwrap()),
            Some("transfer")
        );
        // ...and its multi-fee-asset successor, which inserted `address feePool` first.
        assert_eq!(
            classify_selector(&hex::decode("25784a2e").unwrap()),
            Some("transfer")
        );
        // ...and the pre-fee form must keep working: existing pools are unchanged.
        assert_eq!(
            classify_selector(&hex::decode("1952ce65").unwrap()),
            Some("unshield")
        );
    }

    /// The two new arguments were appended AFTER `recipient`, so arg0/arg1 keep their
    /// calldata offsets and the existing decoding stays correct.
    #[test]
    fn protocol_fee_unshield_still_exposes_amount_and_recipient() {
        let mut unshield = vec![0u8; 68];
        unshield[..4].copy_from_slice(&hex::decode("73a93e1b").unwrap());
        unshield[35] = 0x07; // arg0: amount = 7
        unshield[48..68].fill(0x42); // arg1: recipient
        let meta = parse_tx_meta(&unshield);
        assert_eq!(meta.op, Some("unshield"));
        assert_eq!(meta.recipient, Some(format!("0x{}", "42".repeat(20))));
        assert_eq!(meta.amount_hex, Some(format!("0x{}07", "00".repeat(31))));
    }

    /// Gateway-wrapped ETH operations still emit the authoritative note events from
    /// the sETH pool. Their transaction selector, public amount, depositor and final
    /// recipient must therefore remain visible in the same explorer model as direct
    /// ERC20Shield operations.
    #[test]
    fn native_eth_gateway_selectors_preserve_public_history_fields() {
        let mut shield = vec![0u8; 36];
        shield[..4].copy_from_slice(&hex::decode("a6c3589d").unwrap());
        shield[35] = 0x09;
        let shield_meta = parse_tx_meta(&shield);
        assert_eq!(shield_meta.op, Some("shield"));
        assert_eq!(
            shield_meta.amount_hex,
            Some(format!("0x{}09", "00".repeat(31)))
        );
        assert_eq!(shield_meta.recipient, None);

        let mut unshield = vec![0u8; 68];
        unshield[..4].copy_from_slice(&hex::decode("d6c75fd4").unwrap());
        unshield[35] = 0x07;
        unshield[48..68].fill(0x42);
        let unshield_meta = parse_tx_meta(&unshield);
        assert_eq!(unshield_meta.op, Some("unshield"));
        assert_eq!(
            unshield_meta.amount_hex,
            Some(format!("0x{}07", "00".repeat(31)))
        );
        assert_eq!(
            unshield_meta.recipient,
            Some(format!("0x{}", "42".repeat(20)))
        );
    }

    /// `transferWithFee`'s leading args are POOL ADDRESSES, not a uint amount. Decoding arg0 as
    /// one would publish a nonsensical "amount" on every sponsored transfer.
    ///
    /// This is why the multi-fee-asset release needed nothing but a selector entry: the pool
    /// moved from calldata[4..36] to [36..68], and no decoding here reads either word.
    #[test]
    fn gateway_transfer_publishes_no_amount_or_recipient() {
        for selector in ["4c4ba93b", "25784a2e"] {
            let mut gateway = vec![0u8; 100];
            gateway[..4].copy_from_slice(&hex::decode(selector).unwrap());
            gateway[16..36].fill(0x11); // arg0
            gateway[48..68].fill(0x22); // arg1
            let meta = parse_tx_meta(&gateway);
            assert_eq!(meta.op, Some("transfer"), "selector {selector}");
            assert_eq!(meta.amount_hex, None, "selector {selector}");
            assert_eq!(meta.recipient, None, "selector {selector}");
        }
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
    fn rpc_endpoint_logs_never_include_credentials_or_paths() {
        assert_eq!(
            rpc_endpoint_label("https://monad.example/v2/private-key?debug=1"),
            "https://monad.example"
        );
        assert_eq!(
            rpc_endpoint_label("wss://user:secret@rpc.example/ws/private"),
            "wss://rpc.example"
        );
        assert_eq!(
            rpc_endpoint_label("not-a-url/private-key"),
            "<redacted-rpc-endpoint>"
        );
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
    fn factory_discovery_retains_the_exact_source_for_admission() {
        let shield_factory = format!("0x{}", "11".repeat(20));
        let shield_topic = format!("0x{}", "22".repeat(32));
        let pools = vec![
            (format!("0x{}", "33".repeat(20)), 101),
            (format!("0x{}", "44".repeat(20)), 202),
        ];
        let discovered = bind_factory_discovery_source(&shield_factory, &shield_topic, pools);
        assert_eq!(discovered.len(), 2);
        assert!(discovered
            .iter()
            .all(|item| item.factory == shield_factory && item.topic0 == shield_topic));
        assert_eq!(discovered[0].block, 101);
        assert_eq!(discovered[1].block, 202);
    }

    #[test]
    fn pool_registry_legacy_schema_remains_address_only() {
        let raw = format!(
            r#"{{"pools":[{{"address":"0x{}","start_block":77}}]}}"#,
            "11".repeat(20)
        );
        let registry: PoolsRegistryFile = serde_json::from_str(&raw).unwrap();
        let entry = &registry.pools[0];
        assert_eq!(entry.start_block, 77);
        assert_eq!(entry.factory, None);
        assert_eq!(entry.topic0, None);
        assert!(factory_discovery_from_registry_entry(entry, 77)
            .unwrap()
            .is_none());
    }

    #[test]
    fn factory_registry_provenance_requires_an_exact_trusted_source() {
        let factory = format!("0x{}", "11".repeat(20));
        let topic0 = format!("0x{}", "22".repeat(32));
        let entry = PoolRegistryEntry {
            address: format!("0x{}", "33".repeat(20)),
            start_block: 88,
            factory: Some(factory.clone()),
            topic0: Some(topic0.clone()),
        };
        let discovered = factory_discovery_from_registry_entry(&entry, 88)
            .unwrap()
            .unwrap();
        assert!(factory_discovery_source_is_trusted(
            &discovered,
            &[(factory.clone(), topic0.clone())]
        ));
        assert!(!factory_discovery_source_is_trusted(
            &discovered,
            &[(format!("0x{}", "44".repeat(20)), topic0)]
        ));

        let partial = PoolRegistryEntry {
            topic0: None,
            ..entry
        };
        assert!(factory_discovery_from_registry_entry(&partial, 88).is_err());
    }

    #[test]
    fn factory_registry_persistence_is_idempotent_and_upgrades_legacy_entry() {
        let path = std::env::temp_dir().join(format!(
            "privacy-indexer-factory-registry-{}-{}.json",
            std::process::id(),
            unix_seconds()
        ));
        let path_string = path.to_string_lossy().to_string();
        let pool = format!("0x{}", "Aa".repeat(20));
        std::fs::write(
            &path,
            format!(r#"{{"pools":[{{"address":"{pool}","start_block":1}}]}}"#),
        )
        .unwrap();
        let discovered = super::FactoryDiscoveredPool {
            pool: pool.to_lowercase(),
            block: 88,
            factory: format!("0x{}", "11".repeat(20)),
            topic0: format!("0x{}", "22".repeat(32)),
        };

        append_factory_pools_registry(&path_string, &discovered).unwrap();
        let once = std::fs::read_to_string(&path).unwrap();
        append_factory_pools_registry(&path_string, &discovered).unwrap();
        let twice = std::fs::read_to_string(&path).unwrap();
        assert_eq!(once, twice);

        let registry: PoolsRegistryFile = serde_json::from_str(&once).unwrap();
        assert_eq!(registry.pools.len(), 1);
        assert_eq!(registry.pools[0].start_block, 88);
        assert_eq!(
            registry.pools[0].factory.as_deref(),
            Some(discovered.factory.as_str())
        );
        assert_eq!(
            registry.pools[0].topic0.as_deref(),
            Some(discovered.topic0.as_str())
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn failed_startup_pool_admissions_are_queued_once_for_retry() {
        let mut pending = Vec::new();
        queue_pending_pool_admission(&mut pending, "abcd", 101, "cli");
        queue_pending_pool_admission(&mut pending, "0xabcd", 202, "registry");
        assert_eq!(
            pending,
            vec![PendingPoolAdmission {
                address: "0xabcd".to_owned(),
                start_block: 101,
                source: "cli",
            }]
        );
    }

    #[test]
    fn generic_admission_short_circuits_only_after_active_verified_admission() {
        assert!(completed_admission_can_short_circuit(true, true));
        assert!(!completed_admission_can_short_circuit(true, false));
        assert!(!completed_admission_can_short_circuit(false, true));
        assert!(!completed_admission_can_short_circuit(false, false));
    }

    #[test]
    fn factory_discovery_retries_failed_ranges_and_rescans_a_bounded_tail() {
        let start = 500;
        let head = 1_000;
        assert_eq!(next_factory_discovery_from(start, head, 900), 900);
        assert_eq!(
            next_factory_discovery_from(start, head, head + 1),
            head - (FACTORY_DISCOVERY_RESCAN_BLOCKS - 1)
        );
        assert_eq!(next_factory_discovery_from(900, head, head + 1), 900);
    }

    #[test]
    fn factory_discovery_queues_every_event_before_advancing_the_source() {
        let factory = format!("0x{}", "11".repeat(20));
        let topic = format!("0x{}", "22".repeat(32));
        let invalid = format!("0x{}", "33".repeat(20));
        let later_valid = format!("0x{}", "44".repeat(20));
        let mut pending = Vec::<PendingFactoryAdmission>::new();
        let mut next_from = 100;

        queue_factory_discovery_range(
            &mut pending,
            &factory,
            &topic,
            vec![(invalid.clone(), 101), (later_valid.clone(), 109)],
            &mut next_from,
            120,
        );

        assert_eq!(next_from, 121);
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].discovered.pool, invalid);
        assert_eq!(pending[1].discovered.pool, later_valid);

        // A bounded-tail rescan must not duplicate retry work or discard the
        // exact factory provenance captured by the first canonical event.
        let duplicate = pending[0].discovered.pool.clone();
        queue_factory_discovery_range(
            &mut pending,
            &factory,
            &topic,
            vec![(duplicate, 101)],
            &mut next_from,
            125,
        );
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].attempts, 0);
        assert_eq!(pending[0].discovered.factory, factory);
        assert_eq!(next_from, 126);
    }

    #[test]
    fn required_pool_health_reports_normalized_missing_addresses_deterministically() {
        let required = parse_address_set(
            "test",
            &[
                format!("0x{}", "bb".repeat(20)),
                format!("0x{}", "aa".repeat(20)),
                format!("0x{}", "cc".repeat(20)),
            ],
        )
        .unwrap();
        let active = parse_address_set("test", &[format!("0x{}", "cc".repeat(20))]).unwrap();
        assert_eq!(
            missing_required_pools(&required, &active),
            vec![
                format!("0x{}", "aa".repeat(20)),
                format!("0x{}", "bb".repeat(20)),
            ]
        );
        assert!(missing_required_pools(&Default::default(), &active).is_empty());
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
                nodes: Vec::new(),
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

    /// `NoteConfirmed`'s ring-miss fallback searches the uncommitted mutation
    /// buffer before the tables, so it must pick the newest `Upsert` for the cmx
    /// and ignore the other mutation kinds.
    #[test]
    fn latest_upserted_note_prefers_the_newest_write_for_that_cmx() {
        let mut stale = sample_note_envelope(0x33, 4);
        stale.batch.abi_notes[0].block_number = 111;
        let mut fresh = sample_note_envelope(0x33, 9);
        fresh.batch.abi_notes[0].block_number = 222;
        let mutations = vec![
            NoteArchiveMutation::Upsert(sample_note_envelope(0x44, 3)),
            NoteArchiveMutation::Upsert(stale),
            NoteArchiveMutation::Confirm {
                cmx: [0x33; 32],
                position: 7,
                nodes: Vec::new(),
            },
            NoteArchiveMutation::Upsert(fresh),
            NoteArchiveMutation::ShieldAmount {
                cmx: [0x33; 32],
                amount: 5,
            },
        ];
        let found = latest_upserted_note(&mutations, [0x33; 32]).expect("buffered upsert");
        assert_eq!(found.block_number, 222, "expected the newest Upsert");
        assert_eq!(
            latest_upserted_note(&mutations, [0x44; 32]).map(|n| n.cmx),
            Some([0x44; 32])
        );
        // A cmx that only ever appears in non-Upsert mutations has no payload to
        // recover — the caller must fall through to the tables, not synthesise one.
        assert!(latest_upserted_note(
            &[NoteArchiveMutation::Confirm {
                cmx: [0x55; 32],
                position: 1,
                nodes: Vec::new(),
            }],
            [0x55; 32]
        )
        .is_none());
    }

    /// A canonical rebuild stages its notes in an isolated generation. The
    /// ring-miss fallback must read inside that generation while it is active,
    /// and must not see it once it has been abandoned.
    #[tokio::test]
    async fn pg_evicted_note_recovery_reads_inside_the_active_rebuild_generation() {
        let Ok(database_url) = std::env::var("PRIVACY_INDEXER_TEST_DATABASE_URL") else {
            return;
        };
        let pg = sqlx::PgPool::connect(&database_url).await.unwrap();
        sqlx::migrate!("./migrations").run(&pg).await.unwrap();
        let pool_address = format!("0x{}", "c4".repeat(20));
        clear_pg_rebuild_test_pool(&pg, &pool_address).await;
        let backend = StateBackend::Pgsql(pg.clone());
        let generation = "gen-under-test";

        // Live table carries an older copy; the rebuild stages a newer one.
        let mut live = sample_note_envelope(0x33, 1);
        live.batch.abi_notes[0].block_number = 111;
        backend
            .apply_note_mutations(&pool_address, None, &[NoteArchiveMutation::Upsert(live)])
            .await
            .unwrap();
        pg_begin_canonical_rebuild(&pg, &pool_address, generation)
            .await
            .unwrap();
        let mut staged = sample_note_envelope(0x33, 2);
        staged.batch.abi_notes[0].block_number = 222;
        backend
            .apply_note_mutations(
                &pool_address,
                Some(generation),
                &[NoteArchiveMutation::Upsert(staged)],
            )
            .await
            .unwrap();

        let in_generation = backend
            .load_note_by_cmx(&pool_address, Some(generation), [0x33; 32])
            .await
            .expect("staged note");
        assert_eq!(in_generation.block_number, 222);
        let live_row = backend
            .load_note_by_cmx(&pool_address, None, [0x33; 32])
            .await
            .expect("live note");
        assert_eq!(
            live_row.block_number, 111,
            "an active rebuild must not leak into the live table"
        );
        assert!(
            backend
                .load_note_by_cmx(&pool_address, Some("other-generation"), [0x33; 32])
                .await
                .is_none(),
            "generations must be isolated from each other"
        );

        clear_pg_rebuild_test_pool(&pg, &pool_address).await;
    }

    /// `/note` and `/tx` fall back to the archive once the ring evicts a note, so
    /// both point lookups must resolve notes the in-memory ring no longer holds.
    #[tokio::test]
    async fn json_archive_point_lookups_find_notes_evicted_from_the_ring() {
        let dir = std::env::temp_dir().join(format!("indexer-pointlookup-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state_path = dir.join("state.json");
        let state_path = state_path.to_str().unwrap().to_owned();
        let archive_path = StateBackend::json_archive_path(&state_path);
        let _ = std::fs::remove_file(&archive_path);

        let pool = format!("0x{}", "11".repeat(20));
        // Two notes in one tx (recipient + change), plus an unrelated third.
        let mut first = sample_note_envelope(0x33, 9);
        let mut second = sample_note_envelope(0x44, 10);
        let shared_tx = format!("0x{}", "ab".repeat(32));
        first.batch.abi_notes[0].tx_hash = shared_tx.clone();
        second.batch.abi_notes[0].tx_hash = shared_tx.to_uppercase();
        let other = sample_note_envelope(0x55, 11);
        for env in [&first, &second, &other] {
            StateBackend::append_json_line(&archive_path, env).unwrap();
        }
        let backend = StateBackend::Json(Some(state_path));

        let found = backend.load_note_by_cmx(&pool, None, [0x33; 32]).await;
        assert_eq!(found.map(|n| n.cmx), Some([0x33; 32]));
        assert!(backend
            .load_note_by_cmx(&pool, None, [0x99; 32])
            .await
            .is_none());

        // Casing and `0x` prefix are normalised on both sides, and the unrelated
        // note must not leak into the result.
        for needle in [
            shared_tx.as_str(),
            &shared_tx.to_uppercase(),
            strip_0x(&shared_tx),
        ] {
            let mut notes = backend.load_notes_by_tx_hash(&pool, needle).await;
            notes.sort_by_key(|n| n.cmx);
            assert_eq!(
                notes.iter().map(|n| n.cmx).collect::<Vec<_>>(),
                vec![[0x33; 32], [0x44; 32]],
                "tx lookup failed for needle {needle}"
            );
        }
        assert!(backend
            .load_notes_by_tx_hash(&pool, &format!("0x{}", "cd".repeat(32)))
            .await
            .is_empty());

        let _ = std::fs::remove_file(&archive_path);
    }

    /// Frozen paths in the JSON development backend: persisted once, served
    /// byte-identically on repeated reads, never mutated by serving.
    #[tokio::test]
    async fn json_frozen_paths_persist_and_serve_idempotently() {
        let dir = std::env::temp_dir().join(format!("indexer-frozenpath-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state_path = dir.join("state.json").to_str().unwrap().to_owned();
        let archive_path = StateBackend::json_archive_path(&state_path);
        let _ = std::fs::remove_file(&archive_path);
        let backend = StateBackend::Json(Some(state_path));
        let pool = format!("0x{}", "12".repeat(20));

        let record = FrozenPathRecord {
            cmx: canonical_test_leaf(7),
            position: 6,
            siblings: (0..32)
                .map(|level| format!("0x{}", hex::encode([level as u8; 32])))
                .collect(),
            anchor_root: canonical_test_leaf(99),
        };
        backend
            .apply_note_mutations(
                &pool,
                None,
                &[NoteArchiveMutation::FrozenPaths(vec![record.clone()])],
            )
            .await
            .unwrap();

        let first = backend
            .load_frozen_path(&pool, record.cmx)
            .await
            .unwrap()
            .expect("frozen path persisted");
        let second = backend
            .load_frozen_path(&pool, record.cmx)
            .await
            .unwrap()
            .expect("frozen path still persisted after a read");
        assert_eq!(first.position, record.position);
        assert_eq!(first.siblings, record.siblings);
        assert_eq!(first.anchor_root, record.anchor_root);
        assert_eq!(first.siblings, second.siblings);
        assert_eq!(first.anchor_root, second.anchor_root);
        assert!(backend
            .load_frozen_path(&pool, canonical_test_leaf(8))
            .await
            .unwrap()
            .is_none());

        let _ = std::fs::remove_file(&archive_path);
    }

    #[test]
    fn freeze_tip_paths_cli_flag_defaults_off_and_parses_env_style() {
        use clap::Parser;
        // Required release-bound fields so clap can construct a Cli; we only
        // assert the tip-freeze switch's default / opt-in behaviour.
        let base = [
            "privacy-indexer",
            "--rpc-url",
            "http://127.0.0.1:8545",
            "--expected-verifier-set-id",
            &format!("0x{}", "11".repeat(32)),
        ];
        let defaulted = Cli::try_parse_from(base).expect("default cli");
        assert!(!defaulted.freeze_tip_paths);
        assert!(!defaulted.freeze_only);
        assert_eq!(defaulted.freeze_page_size, 4_096);
        assert_eq!(defaulted.freeze_workers, 4);
        let enabled = Cli::try_parse_from([base.as_slice(), &["--freeze-tip-paths"]].concat())
            .expect("enabled cli");
        assert!(enabled.freeze_tip_paths);
        let maintenance = Cli::try_parse_from(
            [
                base.as_slice(),
                &[
                    "--freeze-only",
                    "--freeze-page-size",
                    "1024",
                    "--freeze-workers",
                    "8",
                ],
            ]
            .concat(),
        )
        .expect("freeze-only cli");
        assert!(maintenance.freeze_only);
        assert_eq!(maintenance.freeze_page_size, 1_024);
        assert_eq!(maintenance.freeze_workers, 8);
    }

    /// Tip-snapshot builder: every confirmed leaf's witness must open to the
    /// current tip root (the bootstrap anchor for mainnet upgrades).
    #[test]
    fn tip_frozen_paths_all_open_to_current_confirmed_root() {
        const N: u64 = 17;
        let mut builder = StreamingFrontierBuilder::new();
        let mut leaves = Vec::with_capacity(N as usize);
        let mut nodes = HashMap::new();
        let mut frontier = None;
        for position in 0..N {
            let cmx = canonical_test_leaf(position + 1);
            leaves.push(cmx);
            let generated = if position + 1 == N {
                let (done, generated) = builder.finish_with_last_be(cmx).unwrap();
                frontier = Some(done);
                generated
            } else {
                builder.push_nonfinal_be(cmx).unwrap()
            };
            for node in generated {
                nodes.insert(node.key, node.hash_be);
            }
        }
        let tip = frontier.unwrap().root_be();
        let records = build_tip_frozen_paths(&leaves, 0, N, tip, &nodes).unwrap();
        assert_eq!(records.len(), N as usize);
        for (position, record) in records.iter().enumerate() {
            assert_eq!(record.position, position as u64);
            assert_eq!(record.cmx, leaves[position]);
            assert_eq!(record.anchor_root, tip);
            assert_eq!(
                witness_root_be(record.cmx, record.position, &record.siblings).unwrap(),
                tip
            );
        }
        // A wrong tip must fail closed.
        let mut wrong = tip;
        wrong[0] ^= 1;
        assert!(build_tip_frozen_paths(&leaves, 0, N, wrong, &nodes).is_err());
    }

    /// PostgreSQL tip-snapshot init: materialize missing frozen_paths against the
    /// seeded tip, leave already-frozen cmxs untouched, and serve frozen:true.
    #[tokio::test]
    async fn pg_tip_freeze_fills_missing_paths_against_current_root() {
        let Ok(database_url) = std::env::var("PRIVACY_INDEXER_TEST_DATABASE_URL") else {
            return;
        };
        let pg = sqlx::PgPool::connect(&database_url).await.unwrap();
        sqlx::migrate!("./migrations").run(&pg).await.unwrap();
        let pool_address = format!("0x{}", "d4".repeat(20));
        clear_pg_rebuild_test_pool(&pg, &pool_address).await;

        const LEAVES: u64 = 33;
        let frontier = seed_pg_confirmed_prefix(&pg, &pool_address, LEAVES).await;
        let tip = frontier.root_be();
        let backend = StateBackend::Pgsql(pg.clone());
        assert_eq!(backend.count_frozen_paths(&pool_address).await.unwrap(), 0);

        // Pre-freeze one leaf under the tip (simulates a prior partial run).
        let pre_cmx = canonical_test_leaf(1);
        let pre_keys = required_witness_nodes(0, LEAVES).unwrap();
        let pre_nodes = backend
            .load_merkle_nodes(&pool_address, &pre_keys)
            .await
            .unwrap();
        let pre = build_tip_frozen_paths(&[pre_cmx], 0, LEAVES, tip, &pre_nodes).unwrap();
        backend
            .apply_note_mutations(
                &pool_address,
                None,
                &[NoteArchiveMutation::FrozenPaths(pre.clone())],
            )
            .await
            .unwrap();
        assert_eq!(backend.count_frozen_paths(&pool_address).await.unwrap(), 1);

        // Run the production bounded/parallel/bulk path. The odd page size
        // exercises a non-aligned final page and the pre-existing-row skip.
        let report = freeze_confirmed_prefix(
            &backend,
            None,
            &pool_address,
            LEAVES,
            tip,
            TipFreezeConfig {
                page_size: 7,
                workers: 2,
            },
        )
        .await
        .unwrap();
        assert_eq!(report.written, LEAVES - 1);
        assert_eq!(report.already_frozen, 1);
        assert_eq!(
            backend
                .count_missing_frozen_paths(&pool_address, LEAVES)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            backend.count_frozen_paths(&pool_address).await.unwrap(),
            LEAVES
        );

        // A completed rerun is a bounded no-op rather than an N+1 scan/write.
        let rerun = freeze_confirmed_prefix(
            &backend,
            None,
            &pool_address,
            LEAVES,
            tip,
            TipFreezeConfig {
                page_size: 7,
                workers: 2,
            },
        )
        .await
        .unwrap();
        assert_eq!(rerun.written, 0);
        assert_eq!(rerun.already_frozen, LEAVES);

        // Spot-check: every path is tip-anchored and reopens to tip; the
        // pre-frozen leaf is unchanged (idempotent exact record).
        for position in [0u64, 1, 16, 32] {
            let cmx = canonical_test_leaf(position + 1);
            let record = backend
                .load_frozen_path(&pool_address, cmx)
                .await
                .unwrap()
                .expect("frozen");
            assert_eq!(record.anchor_root, tip);
            assert_eq!(
                witness_root_be(record.cmx, record.position, &record.siblings).unwrap(),
                tip
            );
        }
        let pre_stored = backend
            .load_frozen_path(&pool_address, pre_cmx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pre_stored.siblings, pre[0].siblings);

        clear_pg_rebuild_test_pool(&pg, &pool_address).await;
    }

    /// Release benchmark for the mainnet migration shape. It is deliberately
    /// ignored and refuses to run unless the target database name contains
    /// `frozen_bench`, so it cannot be pointed at a live Indexer database by
    /// accident. Run in `--release` with an isolated PostgreSQL container.
    #[tokio::test]
    #[ignore = "1.41M-row isolated PostgreSQL release benchmark"]
    async fn pg_production_sized_frozen_path_backfill_benchmark() {
        let database_url = std::env::var("PRIVACY_INDEXER_BENCHMARK_DATABASE_URL")
            .expect("set isolated PRIVACY_INDEXER_BENCHMARK_DATABASE_URL");
        let pg = sqlx::PgPool::connect(&database_url).await.unwrap();
        let database_name: String = sqlx::query_scalar("SELECT current_database()")
            .fetch_one(&pg)
            .await
            .unwrap();
        assert!(
            database_name.contains("frozen_bench"),
            "benchmark database name must contain frozen_bench"
        );
        sqlx::migrate!("./migrations").run(&pg).await.unwrap();
        let leaf_count = std::env::var("PRIVACY_INDEXER_BENCHMARK_LEAVES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(1_412_730);
        let page_size = std::env::var("PRIVACY_INDEXER_BENCHMARK_PAGE_SIZE")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(4_096);
        let workers = std::env::var("PRIVACY_INDEXER_BENCHMARK_WORKERS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(4);
        let reuse_seed = std::env::var("PRIVACY_INDEXER_BENCHMARK_REUSE_SEED")
            .ok()
            .map(|value| parse_bool_flag(&value).expect("valid benchmark reuse flag"))
            .unwrap_or(false);
        assert!(leaf_count > 0 && leaf_count <= 2_000_000);
        assert!((1..=MAX_TIP_FREEZE_PAGE_SIZE).contains(&page_size));
        assert!((1..=MAX_TIP_FREEZE_WORKERS).contains(&workers));

        let pool_address = format!("0x{}", "b7".repeat(20));
        let seed_started = Instant::now();
        let tip_root = if reuse_seed {
            let counts: (i64, i64, i64) = sqlx::query_as(
                "SELECT \
                   (SELECT count(*) FROM cmx_leaves WHERE pool_address=$1), \
                   (SELECT count(*) FROM merkle_nodes WHERE pool_address=$1), \
                   (SELECT count(*) FROM frozen_paths WHERE pool_address=$1)",
            )
            .bind(&pool_address)
            .fetch_one(&pg)
            .await
            .unwrap();
            assert_eq!(counts.0, leaf_count as i64, "reused leaf count mismatch");
            assert!(
                counts.1 >= leaf_count as i64,
                "reused node archive is incomplete"
            );
            assert_eq!(
                counts.2, 0,
                "reused benchmark already contains frozen paths"
            );
            let backend = StateBackend::Pgsql(pg.clone());
            let keys = required_witness_nodes(0, leaf_count).unwrap();
            let nodes = backend
                .load_merkle_nodes(&pool_address, &keys)
                .await
                .expect("load reused benchmark witness nodes");
            let siblings = witness_from_nodes(0, leaf_count, &nodes)
                .expect("rebuild reused benchmark witness");
            witness_root_be(canonical_test_leaf(1), 0, &siblings)
                .expect("rebuild reused benchmark tip root")
        } else {
            clear_pg_rebuild_test_pool(&pg, &pool_address).await;
            seed_pg_confirmed_prefix(&pg, &pool_address, leaf_count)
                .await
                .root_be()
        };
        let seed_elapsed = seed_started.elapsed();
        let bytes_before: i64 = sqlx::query_scalar("SELECT pg_database_size(current_database())")
            .fetch_one(&pg)
            .await
            .unwrap();

        let backend = StateBackend::Pgsql(pg.clone());
        let freeze_started = Instant::now();
        let report = freeze_confirmed_prefix(
            &backend,
            None,
            &pool_address,
            leaf_count,
            tip_root,
            TipFreezeConfig { page_size, workers },
        )
        .await
        .unwrap();
        let freeze_elapsed = freeze_started.elapsed();
        assert_eq!(report.written, leaf_count);
        assert_eq!(
            backend
                .count_missing_frozen_paths(&pool_address, leaf_count)
                .await
                .unwrap(),
            0
        );
        for position in [0, leaf_count / 2, leaf_count - 1] {
            let cmx = canonical_test_leaf(position + 1);
            let frozen = backend
                .load_frozen_path(&pool_address, cmx)
                .await
                .unwrap()
                .expect("benchmark frozen path");
            assert_eq!(frozen.position, position);
            assert_eq!(frozen.anchor_root, tip_root);
            assert_eq!(
                witness_root_be(frozen.cmx, frozen.position, &frozen.siblings).unwrap(),
                tip_root
            );
        }
        let rerun_started = Instant::now();
        let rerun = freeze_confirmed_prefix(
            &backend,
            None,
            &pool_address,
            leaf_count,
            tip_root,
            TipFreezeConfig { page_size, workers },
        )
        .await
        .unwrap();
        let rerun_elapsed = rerun_started.elapsed();
        assert_eq!(rerun.written, 0);
        let bytes_after: i64 = sqlx::query_scalar("SELECT pg_database_size(current_database())")
            .fetch_one(&pg)
            .await
            .unwrap();
        eprintln!(
            "FROZEN_PATH_BENCHMARK_JSON={}",
            serde_json::json!({
                "database": database_name,
                "leaves": leaf_count,
                "page_size": page_size,
                "workers": workers,
                "reused_seed": reuse_seed,
                "seed_elapsed_ms": seed_elapsed.as_millis(),
                "freeze_elapsed_ms": freeze_elapsed.as_millis(),
                "idempotent_rerun_elapsed_ms": rerun_elapsed.as_millis(),
                "database_bytes_before": bytes_before,
                "database_bytes_after": bytes_after,
                "frozen_bytes_delta": bytes_after.saturating_sub(bytes_before),
                "missing_after": 0,
            })
        );
    }

    /// PostgreSQL frozen paths: write-once per cmx. An exact replay is a no-op;
    /// a divergent record for the same cmx (different anchor) fails closed.
    #[tokio::test]
    async fn pg_frozen_paths_freeze_once_and_reject_divergent_reseals() {
        let Ok(database_url) = std::env::var("PRIVACY_INDEXER_TEST_DATABASE_URL") else {
            return;
        };
        let pg = sqlx::PgPool::connect(&database_url).await.unwrap();
        sqlx::migrate!("./migrations").run(&pg).await.unwrap();
        let pool_address = format!("0x{}", "c9".repeat(20));
        clear_pg_rebuild_test_pool(&pg, &pool_address).await;
        let backend = StateBackend::Pgsql(pg.clone());

        let record = FrozenPathRecord {
            cmx: canonical_test_leaf(21),
            position: 20,
            siblings: (0..32)
                .map(|level| format!("0x{}", hex::encode([level as u8; 32])))
                .collect(),
            anchor_root: canonical_test_leaf(500),
        };
        let mutation = NoteArchiveMutation::FrozenPaths(vec![record.clone()]);
        backend
            .apply_note_mutations(&pool_address, None, std::slice::from_ref(&mutation))
            .await
            .unwrap();
        // Exact replay (WS + catch-up overlap) is idempotent.
        backend
            .apply_note_mutations(&pool_address, None, std::slice::from_ref(&mutation))
            .await
            .unwrap();

        let stored = backend
            .load_frozen_path(&pool_address, record.cmx)
            .await
            .unwrap()
            .expect("frozen path persisted");
        assert_eq!(stored.position, record.position);
        assert_eq!(stored.siblings, record.siblings);
        assert_eq!(stored.anchor_root, record.anchor_root);

        // Same cmx sealed under a different anchor = ingestion bug: fail closed
        // and keep the original record byte-identical.
        let mut divergent = record.clone();
        divergent.anchor_root = canonical_test_leaf(501);
        let error = backend
            .apply_note_mutations(
                &pool_address,
                None,
                &[NoteArchiveMutation::FrozenPaths(vec![divergent])],
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("conflicts with an existing"));
        let unchanged = backend
            .load_frozen_path(&pool_address, record.cmx)
            .await
            .unwrap()
            .expect("original record survives the rejected reseal");
        assert_eq!(unchanged.anchor_root, record.anchor_root);
        assert_eq!(unchanged.siblings, record.siblings);

        clear_pg_rebuild_test_pool(&pg, &pool_address).await;
    }

    /// The PostgreSQL `/tx` predicate must match `notes_tx_hash_idx` (migration
    /// 0007). `enable_seqscan=off` asserts the index is *usable* by the query —
    /// asserting the planner *chose* it would fail spuriously on a small table,
    /// where a sequential scan is genuinely cheaper.
    #[tokio::test]
    async fn pg_note_and_tx_point_lookups_use_the_archive_when_database_is_configured() {
        let Ok(database_url) = std::env::var("PRIVACY_INDEXER_TEST_DATABASE_URL") else {
            return;
        };
        let pg = sqlx::PgPool::connect(&database_url).await.unwrap();
        sqlx::migrate!("./migrations").run(&pg).await.unwrap();
        let pool_address = format!("0x{}", "b7".repeat(20));
        clear_pg_rebuild_test_pool(&pg, &pool_address).await;

        let shared_tx = format!("0x{}", "ab".repeat(32));
        let mut first = sample_note_envelope(0x33, 9);
        let mut second = sample_note_envelope(0x44, 10);
        first.batch.abi_notes[0].tx_hash = shared_tx.clone();
        // Stored verbatim from the log, so the archive must tolerate mixed casing.
        second.batch.abi_notes[0].tx_hash = shared_tx.to_uppercase();
        let backend = StateBackend::Pgsql(pg.clone());
        backend
            .apply_note_mutations(
                &pool_address,
                None,
                &[
                    NoteArchiveMutation::Upsert(first),
                    NoteArchiveMutation::Upsert(second),
                    NoteArchiveMutation::Upsert(sample_note_envelope(0x55, 11)),
                ],
            )
            .await
            .unwrap();

        let found = backend
            .load_note_by_cmx(&pool_address, None, [0x44; 32])
            .await;
        assert_eq!(found.map(|n| n.cmx), Some([0x44; 32]));
        assert!(backend
            .load_note_by_cmx(&pool_address, None, [0x99; 32])
            .await
            .is_none());

        let mut notes = backend
            .load_notes_by_tx_hash(&pool_address, &shared_tx)
            .await;
        notes.sort_by_key(|n| n.cmx);
        assert_eq!(
            notes.iter().map(|n| n.cmx).collect::<Vec<_>>(),
            vec![[0x33; 32], [0x44; 32]]
        );

        // Only the forced plan is asserted. On a table this small Postgres will
        // reasonably prefer a sequential scan (or another index), so asserting the
        // *chosen* plan would be flaky in both directions — it would fail on a
        // legitimate small-table plan, and it would pass on a bare `Seq Scan`,
        // which is precisely the outcome the index exists to prevent.
        //
        // `SET LOCAL` inside a transaction, not a bare `SET`: `enable_seqscan` is
        // session state, and sqlx hands out pooled connections, so a bare `SET`
        // may not apply to the connection the EXPLAIN lands on — and would leak to
        // whichever test borrows that connection next.
        let mut tx = pg.begin().await.unwrap();
        sqlx::query("SET LOCAL enable_seqscan = off")
            .execute(&mut *tx)
            .await
            .unwrap();
        // Other indexes also lead with `pool_address`, so on a tiny fixture the
        // planner may legitimately scan one of them and filter `tx_hash`. Disable
        // an explicit sort and request the expression-index order to turn this
        // EXPLAIN into a deterministic *index usability* probe. The production
        // query above is still exercised separately for result correctness.
        sqlx::query("SET LOCAL enable_sort = off")
            .execute(&mut *tx)
            .await
            .unwrap();
        let forced: Vec<(String,)> = sqlx::query_as(
            "EXPLAIN SELECT cmx_hex FROM notes \
             WHERE pool_address=$1 AND lower(tx_hash) = ANY($2::text[]) \
             ORDER BY pool_address, lower(tx_hash)",
        )
        .bind(&pool_address)
        .bind(vec![shared_tx.to_lowercase()])
        .fetch_all(&mut *tx)
        .await
        .unwrap();
        tx.rollback().await.unwrap();
        let forced = forced
            .into_iter()
            .map(|(line,)| line)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            forced.contains("notes_tx_hash_idx"),
            "the /tx predicate cannot use notes_tx_hash_idx; it would seq-scan `notes` \
             at production size. Plan:\n{forced}"
        );

        clear_pg_rebuild_test_pool(&pg, &pool_address).await;
    }

    async fn clear_pg_rebuild_test_pool(pool: &sqlx::PgPool, pool_address: &str) {
        for statement in [
            "DELETE FROM frozen_current_rebuild WHERE pool_address=$1",
            "DELETE FROM frozen_updates_rebuild WHERE pool_address=$1",
            "DELETE FROM frozen_paths_rebuild WHERE pool_address=$1",
            "DELETE FROM merkle_nodes_rebuild WHERE pool_address=$1",
            "DELETE FROM notes_rebuild WHERE pool_address=$1",
            "DELETE FROM frozen_current WHERE pool_address=$1",
            "DELETE FROM frozen_paths WHERE pool_address=$1",
            "DELETE FROM merkle_nodes WHERE pool_address=$1",
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
    async fn pg_transaction_stats_deduplicate_notes_and_pools_and_follow_deletes() {
        let Ok(database_url) = std::env::var("PRIVACY_INDEXER_TEST_DATABASE_URL") else {
            return;
        };
        let pg = sqlx::PgPool::connect(&database_url).await.unwrap();
        sqlx::migrate!("./migrations").run(&pg).await.unwrap();
        let pool_a = format!("0x{}", "d1".repeat(20));
        let pool_b = format!("0x{}", "d2".repeat(20));
        clear_pg_rebuild_test_pool(&pg, &pool_a).await;
        clear_pg_rebuild_test_pool(&pg, &pool_b).await;

        let shared_hash = format!("0x{}", "ef".repeat(32));
        let mut first = sample_note_envelope(0xa1, 1);
        let mut second = sample_note_envelope(0xa2, 2);
        first.batch.abi_notes[0].tx_hash = shared_hash.clone();
        // Legacy rows may differ in case and omit 0x; they are one transaction.
        second.batch.abi_notes[0].tx_hash = strip_0x(&shared_hash).to_uppercase();
        let backend = StateBackend::Pgsql(pg.clone());
        backend
            .apply_note_mutations(&pool_a, None, &[NoteArchiveMutation::Upsert(first)])
            .await
            .unwrap();
        backend
            .apply_note_mutations(&pool_b, None, &[NoteArchiveMutation::Upsert(second)])
            .await
            .unwrap();

        let note_count: i64 =
            sqlx::query_scalar("SELECT note_count FROM indexed_transactions WHERE tx_hash=$1")
                .bind(&shared_hash)
                .fetch_one(&pg)
                .await
                .unwrap();
        assert_eq!(note_count, 2);

        clear_pg_rebuild_test_pool(&pg, &pool_a).await;
        let note_count: i64 =
            sqlx::query_scalar("SELECT note_count FROM indexed_transactions WHERE tx_hash=$1")
                .bind(&shared_hash)
                .fetch_one(&pg)
                .await
                .unwrap();
        assert_eq!(note_count, 1, "the other swap pool still references the tx");

        clear_pg_rebuild_test_pool(&pg, &pool_b).await;
        let remains: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM indexed_transactions WHERE tx_hash=$1)",
        )
        .bind(&shared_hash)
        .fetch_one(&pg)
        .await
        .unwrap();
        assert!(!remains);
    }

    #[tokio::test]
    async fn pg_batch_history_is_keyset_paged_and_keeps_boundary_sequence_whole() {
        let Ok(database_url) = std::env::var("PRIVACY_INDEXER_TEST_DATABASE_URL") else {
            return;
        };
        let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let pool_address = format!("0x{}", "e9".repeat(20));
        clear_pg_rebuild_test_pool(&pool, &pool_address).await;

        let mut mutations: Vec<NoteArchiveMutation> = (1..=2_505u64)
            .map(|seq| {
                NoteArchiveMutation::Upsert(sample_note_envelope_for_cmx(unique_cmx(seq), seq))
            })
            .collect();
        for suffix in 1..=3u64 {
            mutations.push(NoteArchiveMutation::Upsert(sample_note_envelope_for_cmx(
                unique_cmx(10_000 + suffix),
                1_000,
            )));
        }
        pg_apply_note_mutations(&pool, &pool_address, None, &mutations)
            .await
            .unwrap();

        let backend = StateBackend::Pgsql(pool.clone());
        let first = backend
            .load_archived_batch_page(&pool_address, 0, 2_505, u64::MAX, 1_000)
            .await
            .unwrap();
        assert!(first.has_more);
        assert_eq!(first.envelopes.len(), 1_003);
        assert!(first.envelopes.iter().all(|envelope| envelope.seq <= 1_000));
        assert_eq!(
            first
                .envelopes
                .iter()
                .filter(|envelope| envelope.seq == 1_000)
                .count(),
            4
        );

        let second = backend
            .load_archived_batch_page(&pool_address, 1_000, 2_505, u64::MAX, 1_000)
            .await
            .unwrap();
        assert!(second.has_more);
        assert_eq!(second.envelopes.len(), 1_000);
        assert_eq!(second.envelopes.first().unwrap().seq, 1_001);
        assert_eq!(second.envelopes.last().unwrap().seq, 2_000);

        let final_page = backend
            .load_archived_batch_page(&pool_address, 2_000, 2_505, u64::MAX, 1_000)
            .await
            .unwrap();
        assert!(!final_page.has_more);
        assert_eq!(final_page.envelopes.len(), 505);
        assert_eq!(final_page.envelopes.last().unwrap().seq, 2_505);

        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL enable_seqscan = off")
            .execute(&mut *tx)
            .await
            .unwrap();
        let plan: Vec<(String,)> = sqlx::query_as(
            "EXPLAIN SELECT cmx_hex FROM notes \
             WHERE pool_address=$1 AND seq > $2 AND seq <= $3 AND seq < $4 \
             ORDER BY seq, cmx_hex LIMIT $5",
        )
        .bind(&pool_address)
        .bind(0i64)
        .bind(2_505i64)
        .bind(i64::MAX)
        .bind(1_000i64)
        .fetch_all(&mut *tx)
        .await
        .unwrap();
        tx.rollback().await.unwrap();
        assert!(
            plan.into_iter()
                .map(|(line,)| line)
                .any(|line| line.contains("notes_history_seq_idx")),
            "bounded history query must use the composite keyset index"
        );

        clear_pg_rebuild_test_pool(&pool, &pool_address).await;
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
        let mut note = sample_note_envelope_for_cmx(cmx, 1);
        note.batch.abi_notes[0].cmx_position = Some(0);
        note.batch.abi_notes[0].is_confirmed = true;
        let mut frontier = CompactFrontier::new();
        let nodes = frontier.append_be(cmx).unwrap();
        let snap = CheckpointSnapshot {
            next_block: 102,
            last_finalized_block: Some(101),
            last_finalized_block_hash: Some(format!("0x{}", "cd".repeat(32))),
            tree_frontier: frontier.clone(),
            active_root: Some(frontier.root_be()),
            confirmed_count: 1,
            confirmed_frontier: frontier.clone(),
            last_leaf_key: Some((101, 1)),
            latest_seq: 1,
            ..CheckpointSnapshot::default()
        };
        pg_commit_incremental_replay(
            &pool,
            &pool_address,
            &[
                NoteArchiveMutation::Upsert(note),
                NoteArchiveMutation::Confirm {
                    cmx,
                    position: 0,
                    nodes,
                },
            ],
            &snap,
        )
        .await
        .unwrap();

        let loaded = pg_load(&pool, &pool_address, 1).await;
        assert!(loaded.warm_start_candidate);
        assert_eq!(loaded.confirmed_count, 1);
        assert_eq!(loaded.last_leaf_key, Some((101, 1)));
        assert_eq!(loaded.tree_frontier.next_index(), 1);
        assert_eq!(loaded.confirmed_frontier.root_be(), frontier.root_be());
        let backend = StateBackend::Pgsql(pool.clone());
        let mut incomplete = snap.clone();
        incomplete.next_block = 101;
        assert!(backend.save(&pool_address, &incomplete).await.is_err());
        assert!(pg_load(&pool, &pool_address, 1).await.warm_start_candidate);

        let archived = backend
            .load_archived_batch_page(&pool_address, 0, u64::MAX, u64::MAX, 10)
            .await
            .unwrap();
        assert!(!archived.has_more);
        assert_eq!(archived.envelopes.len(), 1);
        assert_eq!(archived.envelopes[0].seq, 1);

        // A sealed v1 row is not directly warm-startable. The bounded legacy
        // upgrade rebuilds only the depth-32 frontiers/node archive from PG and
        // atomically seals v2 metadata, without consulting RPC history.
        sqlx::query(
            "UPDATE indexer_meta SET checkpoint_version=1, tree_size=NULL, \
             tree_root_hex=NULL, tree_frontier_hex=NULL, confirmed_frontier_hex=NULL, \
             frozen_root_hex=NULL, frozen_count=NULL, frozen_update_count=NULL \
             WHERE pool_address=$1",
        )
        .bind(&pool_address)
        .execute(&pool)
        .await
        .unwrap();
        assert!(!pg_load(&pool, &pool_address, 1).await.warm_start_candidate);
        assert!(
            pg_upgrade_legacy_compact_checkpoint(&pool, &pool_address, 1)
                .await
                .unwrap()
        );
        let upgraded = pg_load(&pool, &pool_address, 1).await;
        assert!(upgraded.warm_start_candidate);
        assert_eq!(upgraded.confirmed_frontier.root_be(), frontier.root_be());

        // Version 0 was never transactionally sealed, so it is deliberately
        // ineligible for automatic promotion and must fail closed.
        sqlx::query("UPDATE indexer_meta SET checkpoint_version=0 WHERE pool_address=$1")
            .bind(&pool_address)
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            !pg_upgrade_legacy_compact_checkpoint(&pool, &pool_address, 1)
                .await
                .unwrap()
        );
        assert!(!pg_load(&pool, &pool_address, 1).await.warm_start_candidate);

        sqlx::query(
            "UPDATE indexer_meta SET checkpoint_version=1, confirmed_count=1, \
             last_leaf_block=101, last_leaf_log_index=2, tree_size=NULL, \
             tree_root_hex=NULL, tree_frontier_hex=NULL, confirmed_frontier_hex=NULL, \
             frozen_root_hex=NULL, frozen_count=NULL, frozen_update_count=NULL \
             WHERE pool_address=$1",
        )
        .bind(&pool_address)
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            pg_upgrade_legacy_compact_checkpoint(&pool, &pool_address, 1)
                .await
                .unwrap_err()
                .to_string()
                .contains("last-leaf cursor")
        );
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
        let cmx = canonical_test_leaf(0xbb);
        let mut rebuilt = sample_note_envelope_for_cmx(cmx, 1);
        rebuilt.batch.abi_notes[0].cmx_position = Some(0);
        rebuilt.batch.abi_notes[0].is_confirmed = true;
        let begin_filled = CompactFrontier::new().filled_be();
        let mut frontier = CompactFrontier::new();
        let nodes = frontier.append_be(cmx).unwrap();
        let segment_nodes: std::collections::HashMap<_, _> =
            nodes.iter().map(|node| (node.key, node.hash_be)).collect();
        let frozen_records: Vec<FrozenPathRecord> = export_segment_frozen_paths(
            &begin_filled,
            0,
            1,
            &[cmx],
            &segment_nodes,
            frontier.root_be(),
        )
        .unwrap()
        .into_iter()
        .map(|path| FrozenPathRecord {
            cmx: path.cmx_be,
            position: path.position,
            siblings: path.siblings,
            anchor_root: frontier.root_be(),
        })
        .collect();
        pg_apply_note_mutations(
            &pool,
            &pool_address,
            Some(generation),
            &[
                NoteArchiveMutation::Upsert(rebuilt),
                NoteArchiveMutation::Confirm {
                    cmx,
                    position: 0,
                    nodes,
                },
                NoteArchiveMutation::ShieldAmount { cmx, amount: 77 },
                NoteArchiveMutation::FrozenPaths(frozen_records),
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
            tree_frontier: frontier.clone(),
            active_root: Some(frontier.root_be()),
            confirmed_count: 1,
            confirmed_frontier: frontier,
            last_leaf_key: Some((101, 1)),
            latest_seq: 1,
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
        assert_eq!(rows, vec![(hex::encode(cmx), Some(0), true, Some(77))]);
        let activated_frozen_paths: Vec<(String, i64, String)> = sqlx::query_as(
            "SELECT cmx_hex, position, anchor_root_hex FROM frozen_paths WHERE pool_address=$1",
        )
        .bind(&pool_address)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            activated_frozen_paths,
            vec![(
                hex::encode(cmx),
                0,
                hex::encode(snap.confirmed_frontier.root_be())
            )]
        );
        let staged: i64 =
            sqlx::query_scalar("SELECT count(*) FROM notes_rebuild WHERE pool_address=$1")
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

    async fn seed_pg_confirmed_prefix(
        pool: &sqlx::PgPool,
        pool_address: &str,
        leaf_count: u64,
    ) -> CompactFrontier {
        assert!(leaf_count > 0);
        let mut tx = pool.begin().await.unwrap();
        let mut builder = StreamingFrontierBuilder::new();
        let mut completed = None;
        let mut rows = Vec::with_capacity(500);
        let mut nodes = Vec::with_capacity(1_000);
        for position in 0..leaf_count {
            let cmx = canonical_test_leaf(position + 1);
            let generated = if position + 1 == leaf_count {
                let (frontier, generated) = builder.finish_with_last_be(cmx).unwrap();
                completed = Some(frontier);
                generated
            } else {
                builder.push_nonfinal_be(cmx).unwrap()
            };
            nodes.extend(generated);
            let seq = position + 1;
            let mut envelope = sample_note_envelope_for_cmx(cmx, seq);
            let note = &mut envelope.batch.abi_notes[0];
            note.cmx_position = Some(position);
            note.is_confirmed = true;
            rows.push(ArchivedNoteRow {
                seq,
                note: note.clone(),
            });
            if rows.len() == 500 || position + 1 == leaf_count {
                pg_bulk_upsert_notes(&mut tx, pool_address, None, &rows)
                    .await
                    .unwrap();
                pg_append_cmx_leaves(&mut tx, pool_address, &rows)
                    .await
                    .unwrap();
                pg_append_merkle_nodes(&mut tx, pool_address, None, &nodes)
                    .await
                    .unwrap();
                rows.clear();
                nodes.clear();
            }
        }
        tx.commit().await.unwrap();
        completed.unwrap()
    }

    #[tokio::test]
    async fn pg_merkle_witness_reads_only_required_archived_nodes() {
        let Ok(database_url) = std::env::var("PRIVACY_INDEXER_TEST_DATABASE_URL") else {
            return;
        };
        let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let pool_address = format!("0x{}", "e7".repeat(20));
        clear_pg_rebuild_test_pool(&pool, &pool_address).await;

        const LEAVES: u64 = 129;
        let frontier = seed_pg_confirmed_prefix(&pool, &pool_address, LEAVES).await;
        let backend = StateBackend::Pgsql(pool.clone());
        let mut reference = OrchardCommitmentTree::new();
        for position in 0..LEAVES {
            reference.append(canonical_test_leaf(position + 1));
        }

        for position in [0, 1, 63, 64, 127, 128] {
            let cmx = canonical_test_leaf(position + 1);
            assert_eq!(
                backend.load_cmx_position(&pool_address, cmx).await.unwrap(),
                Some(position)
            );
            let keys = required_witness_nodes(position, LEAVES).unwrap();
            let nodes = backend
                .load_merkle_nodes(&pool_address, &keys)
                .await
                .unwrap();
            let siblings = witness_from_nodes(position, LEAVES, &nodes).unwrap();
            assert_eq!(
                siblings,
                reference.merkle_path_at(position, LEAVES).unwrap().siblings
            );
            assert_eq!(
                witness_root_be(cmx, position, &siblings).unwrap(),
                frontier.root_be()
            );
        }

        // A missing archived node must fail closed instead of returning an
        // unchecked witness.
        let keys = required_witness_nodes(64, LEAVES).unwrap();
        let missing = keys[0];
        sqlx::query(
            "DELETE FROM merkle_nodes \
             WHERE pool_address=$1 AND level=$2 AND node_index=$3",
        )
        .bind(&pool_address)
        .bind(i16::from(missing.level))
        .bind(missing.index as i64)
        .execute(&pool)
        .await
        .unwrap();
        let incomplete = backend
            .load_merkle_nodes(&pool_address, &keys)
            .await
            .unwrap();
        assert!(witness_from_nodes(64, LEAVES, &incomplete).is_err());

        clear_pg_rebuild_test_pool(&pool, &pool_address).await;
    }

    #[tokio::test]
    async fn pg_frozen_history_is_paged_and_current_set_is_idempotent() {
        let Ok(database_url) = std::env::var("PRIVACY_INDEXER_TEST_DATABASE_URL") else {
            return;
        };
        let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let pool_address = format!("0x{}", "e6".repeat(20));
        clear_pg_rebuild_test_pool(&pool, &pool_address).await;

        let root = |value| format!("0x{}", hex::encode(canonical_test_leaf(value)));
        let a = root(101);
        let b = root(102);
        let absent = root(103);
        let updates = [
            FrozenUpdate {
                block_number: 10,
                log_index: 0,
                tx_hash: format!("0x{}", "10".repeat(32)),
                old_root_hex: root(1),
                new_root_hex: root(2),
                cmx_changed_hex: vec![a.clone(), b.clone()],
                is_add: vec![true, true],
            },
            FrozenUpdate {
                block_number: 11,
                log_index: 0,
                tx_hash: format!("0x{}", "11".repeat(32)),
                old_root_hex: root(2),
                new_root_hex: root(3),
                cmx_changed_hex: vec![a.clone(), absent],
                is_add: vec![true, false],
            },
            FrozenUpdate {
                block_number: 12,
                log_index: 0,
                tx_hash: format!("0x{}", "12".repeat(32)),
                old_root_hex: root(3),
                new_root_hex: root(4),
                cmx_changed_hex: vec![b],
                is_add: vec![false],
            },
        ];
        for (position, update) in updates.iter().cloned().enumerate() {
            pg_apply_note_mutations(
                &pool,
                &pool_address,
                None,
                &[NoteArchiveMutation::Frozen {
                    position: position as u64,
                    update,
                }],
            )
            .await
            .unwrap();
        }

        let backend = StateBackend::Pgsql(pool.clone());
        assert_eq!(
            backend.load_frozen_leaves(&pool_address, 10).await.unwrap(),
            vec![a]
        );
        let first_page = backend
            .load_frozen_updates_after(&pool_address, None, 2)
            .await
            .unwrap();
        assert_eq!(first_page.len(), 2);
        assert_eq!(first_page[0].block_number, 10);
        let second_page = backend
            .load_frozen_updates_after(&pool_address, Some((11, 0)), 2)
            .await
            .unwrap();
        assert_eq!(second_page.len(), 1);
        assert_eq!(second_page[0].block_number, 12);

        let snap = CheckpointSnapshot {
            next_block: 21,
            last_finalized_block: Some(20),
            last_finalized_block_hash: Some(format!("0x{}", "20".repeat(32))),
            frozen_root_hex: root(4),
            frozen_count: 1,
            frozen_update_count: 3,
            ..CheckpointSnapshot::default()
        };
        backend.save(&pool_address, &snap).await.unwrap();
        let loaded = pg_load(&pool, &pool_address, 1).await;
        assert!(loaded.warm_start_candidate);
        assert_eq!(loaded.frozen_count, 1);
        assert_eq!(loaded.frozen_update_count, 3);

        sqlx::query(
            "UPDATE indexer_meta SET checkpoint_version=1, tree_size=NULL, \
             tree_root_hex=NULL, tree_frontier_hex=NULL, confirmed_frontier_hex=NULL, \
             frozen_root_hex=NULL, frozen_count=NULL, frozen_update_count=NULL \
             WHERE pool_address=$1",
        )
        .bind(&pool_address)
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            pg_upgrade_legacy_compact_checkpoint(&pool, &pool_address, 1)
                .await
                .unwrap()
        );
        let upgraded = pg_load(&pool, &pool_address, 1).await;
        assert!(upgraded.warm_start_candidate);
        assert_eq!(upgraded.frozen_count, 1);
        assert_eq!(upgraded.frozen_update_count, 3);

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

        let prefix_frontier = seed_pg_confirmed_prefix(&pool, &pool_address, EXISTING_LEAVES).await;
        let prefix_finalized = 100 + EXISTING_LEAVES;
        let prefix_snap = CheckpointSnapshot {
            next_block: prefix_finalized + 1,
            last_finalized_block: Some(prefix_finalized),
            last_finalized_block_hash: Some(format!("0x{}", "cd".repeat(32))),
            tree_frontier: prefix_frontier.clone(),
            active_root: Some(prefix_frontier.root_be()),
            confirmed_count: EXISTING_LEAVES,
            confirmed_frontier: prefix_frontier.clone(),
            last_leaf_key: Some((prefix_finalized, EXISTING_LEAVES)),
            latest_seq: EXISTING_LEAVES,
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

        let mut mutations = Vec::with_capacity(REPLAY_NOTES as usize * 2);
        let mut frontier = prefix_frontier;
        for offset in 0..REPLAY_NOTES {
            let position = EXISTING_LEAVES + offset;
            let cmx = canonical_test_leaf(position + 1);
            let seq = position + 1;
            let mut confirmed = sample_note_envelope_for_cmx(cmx, seq);
            confirmed.batch.abi_notes[0].is_confirmed = true;
            confirmed.batch.abi_notes[0].cmx_position = Some(position);
            let nodes = frontier.append_be(cmx).unwrap();
            mutations.push(NoteArchiveMutation::Upsert(confirmed));
            mutations.push(NoteArchiveMutation::Confirm {
                cmx,
                position,
                nodes,
            });
        }
        let replay_finalized = 100 + EXISTING_LEAVES + REPLAY_NOTES;
        let snap = CheckpointSnapshot {
            next_block: replay_finalized + 1,
            last_finalized_block: Some(replay_finalized),
            last_finalized_block_hash: Some(format!("0x{}", "ab".repeat(32))),
            tree_frontier: frontier.clone(),
            active_root: Some(frontier.root_be()),
            confirmed_count: EXISTING_LEAVES + REPLAY_NOTES,
            confirmed_frontier: frontier,
            last_leaf_key: Some((replay_finalized, EXISTING_LEAVES + REPLAY_NOTES)),
            latest_seq: EXISTING_LEAVES + REPLAY_NOTES,
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
                (EXISTING_LEAVES + REPLAY_NOTES) as i64,
                (EXISTING_LEAVES + REPLAY_NOTES) as i64,
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
        let bad_cmx = canonical_test_leaf(999_999);
        let bad_seq = snap.latest_seq + 1;
        let mut bad_snap = snap.clone();
        bad_snap.next_block = 9_999;
        let conflicting_position = EXISTING_LEAVES + REPLAY_NOTES - 1;
        let mut conflicting = sample_note_envelope_for_cmx(bad_cmx, bad_seq);
        conflicting.batch.abi_notes[0].cmx_position = Some(conflicting_position);
        conflicting.batch.abi_notes[0].is_confirmed = true;
        let error = pg_commit_incremental_replay(
            &pool,
            &pool_address,
            &[
                NoteArchiveMutation::Upsert(conflicting),
                NoteArchiveMutation::Confirm {
                    cmx: bad_cmx,
                    position: conflicting_position,
                    nodes: Vec::new(),
                },
            ],
            &bad_snap,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("cmx leaf append conflicted"));

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
                (EXISTING_LEAVES + REPLAY_NOTES) as i64,
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
    fn minimal_public_api_exposes_health_and_bounded_browser_reads() {
        assert_eq!(
            public_api_access(PublicApiMode::Minimal, &Method::GET, "/healthz", false),
            ApiAccess::Allow
        );
        assert_eq!(
            public_api_access(PublicApiMode::Minimal, &Method::GET, "/merkle_path", false),
            ApiAccess::Allow
        );
        assert_eq!(
            public_api_access(PublicApiMode::Minimal, &Method::GET, "/txs", false),
            ApiAccess::Allow
        );
        assert_eq!(
            public_api_access(PublicApiMode::Minimal, &Method::GET, "/stats", false),
            ApiAccess::Allow
        );
        assert_eq!(
            public_api_access(PublicApiMode::Minimal, &Method::GET, "/shield/stats", false),
            ApiAccess::Allow
        );
        assert_eq!(
            public_api_access(PublicApiMode::Minimal, &Method::GET, "/batches/page", false),
            ApiAccess::Gone
        );
        assert_eq!(
            public_api_access(PublicApiMode::Minimal, &Method::GET, "/status", false),
            ApiAccess::Hidden
        );
    }

    #[test]
    fn merkle_path_egress_budget_is_hard_bounded_and_resets_by_utc_bucket() {
        let mut budget = EgressBudget::new(100, 250);
        assert!(budget.has_capacity(3_600));
        assert!(budget.try_consume(3_600, 60));
        assert!(!budget.try_consume(3_600, 41));
        // New hour resets only the hourly bucket; the daily total remains 60.
        assert!(budget.try_consume(7_200, 100));
        assert!(!budget.try_consume(10_800, 91));
        // New UTC day resets both buckets.
        assert!(budget.try_consume(86_400, 100));
    }

    #[test]
    fn txs_wire_note_uses_compact_hex_and_omits_archive_only_fields() {
        let note = TxListNote {
            cmx: format!("0x{}", "11".repeat(32)),
            epk: format!("0x{}", "22".repeat(32)),
            enc_ciphertext: format!("0x{}", "ab".repeat(580)),
            nf_old: format!("0x{}", "33".repeat(32)),
            out_ciphertext: Some(format!("0x{}", "cd".repeat(80))),
            cv_net_x: Some(format!("0x{}", "44".repeat(32))),
            log_index: 7,
            shield_amount_sats: None,
            pool: format!("0x{}", "55".repeat(20)),
            symbol: Some("sUSDC".to_string()),
            decimals: Some(6),
        };
        let wire = serde_json::to_string(&note).unwrap();
        assert!(wire.contains(&format!("0x{}", "ab".repeat(580))));
        assert!(!wire.contains("ack_hash"));
        assert!(!wire.contains("cmx_position"));
        assert!(wire.len() < 2_000);
    }

    #[test]
    fn internal_merkle_path_does_not_consume_the_public_egress_fuse() {
        assert!(is_public_merkle_path("/merkle_path", false));
        assert!(!is_public_merkle_path("/merkle_path", true));
        assert!(!is_public_merkle_path("/status", false));
        assert!(is_public_txs("/txs", false));
        assert!(!is_public_txs("/txs", true));
        assert!(!is_public_txs("/merkle_path", false));
    }

    #[test]
    fn internal_read_token_never_authorizes_mutation_routes() {
        assert_eq!(
            public_api_access(PublicApiMode::Minimal, &Method::GET, "/status", true),
            ApiAccess::Allow
        );
        assert_eq!(
            public_api_access(PublicApiMode::Minimal, &Method::DELETE, "/pools", true),
            ApiAccess::Hidden
        );
        // POST reaches the pre-existing admin validator, not an internal-token
        // bypass. The pure gate does not itself authorize the operation.
        assert_eq!(
            public_api_access(PublicApiMode::Minimal, &Method::POST, "/pools", true),
            ApiAccess::Allow
        );
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
    fn eip1559_crank_fee_policy_is_dynamic_and_cap_bounded() {
        assert_eq!(
            eip1559_crank_fees(20_000_000_000, 1_000_000_000, 60_000_000_000).unwrap(),
            (1_000_000_000, 41_000_000_000)
        );
        assert!(eip1559_crank_fees(40_000_000_000, 1_000_000_000, 60_000_000_000).is_err());
        assert!(eip1559_crank_fees(1, 2, 1).is_err());
    }

    #[test]
    fn eip1559_crank_signer_emits_type_two_envelope() {
        let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let raw = build_and_sign_eip1559_tx(
            3,
            1_000_000_000,
            31_000_000_000,
            4_000_000,
            "0x1111111111111111111111111111111111111111",
            0,
            &[0xaa, 0xbb],
            1,
            &key,
        )
        .unwrap();
        assert_eq!(raw[0], 0x02);
        assert!(raw.len() > 80);
    }

    #[test]
    fn crank_transaction_journal_roundtrips_and_rejects_tampering() {
        let dir = std::env::temp_dir().join(format!(
            "privacy-indexer-crank-journal-{}-{}",
            std::process::id(),
            unix_seconds()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pending.json");
        let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let raw = build_and_sign_eip1559_tx(
            3,
            1_000_000_000,
            31_000_000_000,
            4_000_000,
            "0x1111111111111111111111111111111111111111",
            0,
            &[0xaa, 0xbb],
            1,
            &key,
        )
        .unwrap();
        let signer = "0x2222222222222222222222222222222222222222";
        let mut journal = CrankTxJournal {
            schema: CrankTxJournal::SCHEMA.to_string(),
            chain_id: 1,
            signer: signer.to_string(),
            pool: "0x1111111111111111111111111111111111111111".to_string(),
            method: "updateRoot".to_string(),
            nonce: 3,
            gas_limit: 4_000_000,
            calldata_hex: "0xaabb".to_string(),
            attempts: vec![CrankTxAttempt {
                tx_hash: raw_tx_hash(&raw),
                raw_tx_hex: format!("0x{}", hex::encode(&raw)),
                max_priority_fee_per_gas: 1_000_000_000,
                max_fee_per_gas: 31_000_000_000,
                prepared_at: 1,
                broadcast_at: None,
            }],
        };
        let path_string = path.to_string_lossy().to_string();
        journal.save(&path_string).unwrap();
        let loaded = CrankTxJournal::load(&path_string, 1, signer)
            .unwrap()
            .unwrap();
        assert_eq!(loaded, journal);
        validate_crank_journal_signed_payloads(&loaded, &key).unwrap();

        journal.calldata_hex = "0xdead".to_string();
        journal.save(&path_string).unwrap();
        let tampered_fields = CrankTxJournal::load(&path_string, 1, signer)
            .unwrap()
            .unwrap();
        assert!(validate_crank_journal_signed_payloads(&tampered_fields, &key).is_err());

        journal.calldata_hex = "0xaabb".to_string();
        journal.attempts[0].raw_tx_hex = "0x02c0".to_string();
        journal.save(&path_string).unwrap();
        assert!(CrankTxJournal::load(&path_string, 1, signer).is_err());
        CrankTxJournal::clear(&path_string).unwrap();
        assert!(!path.exists());
        std::fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn prepared_crank_attempt_is_not_a_receipt_candidate_until_broadcast() {
        let attempt = |tx_hash: &str, broadcast_at| CrankTxAttempt {
            tx_hash: tx_hash.to_string(),
            raw_tx_hex: "0x02c0".to_string(),
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 2,
            prepared_at: 3,
            broadcast_at,
        };
        let journal = CrankTxJournal {
            schema: CrankTxJournal::SCHEMA.to_string(),
            chain_id: 1,
            signer: "0x2222222222222222222222222222222222222222".to_string(),
            pool: "0x1111111111111111111111111111111111111111".to_string(),
            method: "updateRoot".to_string(),
            nonce: 0,
            gas_limit: 4_000_000,
            calldata_hex: "0xaabb".to_string(),
            attempts: vec![attempt("0xprepared", None), attempt("0xbroadcast", Some(4))],
        };

        let candidates = broadcasted_crank_attempts(&journal)
            .map(|attempt| attempt.tx_hash.as_str())
            .collect::<Vec<_>>();
        assert_eq!(candidates, vec!["0xbroadcast"]);
    }

    #[test]
    fn crank_journal_requires_an_absolute_real_parent() {
        assert!(validate_crank_journal_parent("relative.json").is_err());
        let missing = std::env::temp_dir()
            .join("privacy-indexer-no-such-journal-parent")
            .join("pending.json");
        assert!(validate_crank_journal_parent(&missing.to_string_lossy()).is_err());
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
    fn confirmation_boundary_counts_the_mined_tip_as_one_block() {
        assert_eq!(confirmation_head_number(1_000, 0), 1_000);
        assert_eq!(confirmation_head_number(1_000, 1), 1_000);
        assert_eq!(confirmation_head_number(1_000, 2), 999);
        assert_eq!(confirmation_head_number(2, 10), 0);

        let command = Cli::command();
        let confirmations = command
            .get_arguments()
            .find(|arg| arg.get_id() == "confirmations")
            .expect("confirmations CLI argument");
        assert_eq!(
            confirmations.get_env(),
            Some(std::ffi::OsStr::new("PRIVACYBTC_INDEXER_CONFIRMATIONS"))
        );
    }

    #[test]
    fn omitted_pool_start_uses_reviewed_global_floor() {
        assert_eq!(effective_pool_start_block(0, 11_506_049), 11_506_049);
        assert_eq!(
            effective_pool_start_block(11_506_075, 11_506_049),
            11_506_075
        );
        assert_eq!(effective_pool_start_block(0, 0), 0);
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
        let rpc = RpcClient::new("http://127.0.0.1:1".to_string(), 0);
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
