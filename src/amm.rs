//! Privacy-AMM (Launch) settlement reads: `AmmSettlement.Settled` / `PoolCreated` decoding,
//! the public blind words a recipient subtracts its PRF pad from, and the global slot that
//! each pool-local output occupies (docs/privacy-launch-frontend-prd.md §B6).
//!
//! Slot layout (fixed by asset, `side` is private):
//!   meme pool call  → slots 0 (reserve X out) and 1 (user X out)
//!   quote pool call → slots 2 (reserve Y out), 3 (user Y out), 4 (fee → creator), 5 (fee → treasury)
//! `blind_payout` opens whichever of slots 1 / 3 carries value; 4 / 5 open with the fee blinds.
use super::*;

type ApiError = (StatusCode, String);
fn unavailable(message: &str) -> ApiError { (StatusCode::SERVICE_UNAVAILABLE, message.into()) }

pub(crate) const MEME_ACTIONS: usize = 2;
pub(crate) const QUOTE_ACTIONS: usize = 4;

#[derive(Deserialize)]
pub(crate) struct AmmBlindsQuery { tx: String, gateway: Option<String> }
#[derive(Deserialize)]
pub(crate) struct AmmPoolsQuery { gateway: Option<String>, from_block: Option<u64>, limit: Option<usize> }

#[derive(Clone, Debug, Serialize)]
pub(crate) struct AmmSettled {
    pub(crate) gateway: String,
    pub(crate) pool_id: String,
    /// `poolId == uint160(memePool)`; surfaced as an address for clients.
    pub(crate) meme_pool: String,
    pub(crate) tip_cm_x: String,
    pub(crate) tip_cm_y: String,
    pub(crate) blind_payout: String,
    pub(crate) blind_fee_c: String,
    pub(crate) blind_fee_t: String,
    pub(crate) block_number: u64,
    pub(crate) tx_hash: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct AmmPoolCreated {
    pub(crate) gateway: String,
    pub(crate) pool_id: String,
    pub(crate) meme_pool: String,
    pub(crate) quote_pool: String,
    pub(crate) creator_evm: String,
    pub(crate) creator_addr_commit: String,
    pub(crate) tip_cm_x: String,
    pub(crate) tip_cm_y: String,
    pub(crate) block_number: u64,
    pub(crate) tx_hash: String,
}

pub(crate) fn settled_topic0() -> String {
    event_topic0(b"Settled(uint256,bytes32,bytes32,uint256,uint256,uint256)")
}
pub(crate) fn pool_created_topic0() -> String {
    event_topic0(b"PoolCreated(uint256,address,address,address,uint256,bytes32,bytes32)")
}

fn word_hex(w: &[u8]) -> String { format!("0x{}", hex::encode(w)) }
fn uint_dec(w: &[u8]) -> String { ethabi::Uint::from_big_endian(w).to_string() }

/// `poolId` must be a zero-extended address; anything else is not a Launch pool.
fn pool_id_to_address(topic: &str) -> Option<String> {
    let raw = parse_hex32(topic)?;
    if raw[..12] != [0; 12] || raw[12..] == [0; 20] { return None; }
    Some(format!("0x{}", hex::encode(&raw[12..])))
}

pub(crate) fn decode_settled_log(log: &EthLog, gateway: Option<&str>) -> Result<Option<AmmSettled>> {
    let topics = log.topics.as_deref().unwrap_or(&[]);
    if topics.first().map(|s| s.to_lowercase()) != Some(settled_topic0()) { return Ok(None); }
    if gateway.is_some_and(|g| !g.eq_ignore_ascii_case(&log.address)) { return Ok(None); }
    if log.removed { bail!("removed Settled log"); }
    if topics.len() != 2 { bail!("Settled must carry exactly one indexed topic"); }
    let pool_id = parse_hex32(&topics[1]).ok_or_else(|| anyhow!("invalid poolId topic"))?;
    let meme_pool = pool_id_to_address(&topics[1]).ok_or_else(|| anyhow!("poolId is not an address"))?;
    let data = hex::decode(log.data.trim_start_matches("0x"))?;
    if data.len() != 5 * 32 { bail!("Settled data must be five words"); }
    Ok(Some(AmmSettled {
        gateway: log.address.to_lowercase(),
        pool_id: uint_dec(&pool_id),
        meme_pool,
        tip_cm_x: word_hex(&data[0..32]),
        tip_cm_y: word_hex(&data[32..64]),
        blind_payout: uint_dec(&data[64..96]),
        blind_fee_c: uint_dec(&data[96..128]),
        blind_fee_t: uint_dec(&data[128..160]),
        block_number: parse_hex_u64(&log.block_number)?,
        tx_hash: normalize_hex_0x(&log.transaction_hash).to_lowercase(),
    }))
}

pub(crate) fn decode_pool_created_log(log: &EthLog, gateway: Option<&str>) -> Result<Option<AmmPoolCreated>> {
    let topics = log.topics.as_deref().unwrap_or(&[]);
    if topics.first().map(|s| s.to_lowercase()) != Some(pool_created_topic0()) { return Ok(None); }
    if gateway.is_some_and(|g| !g.eq_ignore_ascii_case(&log.address)) { return Ok(None); }
    if log.removed { bail!("removed PoolCreated log"); }
    if topics.len() != 4 { bail!("PoolCreated must carry three indexed topics"); }
    let pool_id = parse_hex32(&topics[1]).ok_or_else(|| anyhow!("invalid poolId topic"))?;
    let meme_pool = topic_to_address(&topics[2]).ok_or_else(|| anyhow!("invalid memePool topic"))?;
    let quote_pool = topic_to_address(&topics[3]).ok_or_else(|| anyhow!("invalid quotePool topic"))?;
    if pool_id_to_address(&topics[1]).as_deref() != Some(meme_pool.as_str()) { bail!("poolId does not name the meme pool"); }
    let data = hex::decode(log.data.trim_start_matches("0x"))?;
    if data.len() != 4 * 32 { bail!("PoolCreated data must be four words"); }
    if data[..12] != [0; 12] { bail!("invalid creatorEvm word"); }
    Ok(Some(AmmPoolCreated {
        gateway: log.address.to_lowercase(),
        pool_id: uint_dec(&pool_id),
        meme_pool,
        quote_pool,
        creator_evm: word_hex(&data[12..32]),
        creator_addr_commit: uint_dec(&data[32..64]),
        tip_cm_x: word_hex(&data[64..96]),
        tip_cm_y: word_hex(&data[96..128]),
        block_number: parse_hex_u64(&log.block_number)?,
        tx_hash: normalize_hex_0x(&log.transaction_hash).to_lowercase(),
    }))
}

/// Exactly one `Settled` in a receipt, or none. Two is ambiguous and refused.
pub(crate) fn decode_settled(receipt: &ReceiptWithLogs, gateway: Option<&str>) -> Result<Option<AmmSettled>> {
    let mut found = None;
    for log in &receipt.logs {
        if let Some(s) = decode_settled_log(log, gateway)? {
            if found.is_some() { bail!("ambiguous AMM settlement receipt"); }
            found = Some(s);
        }
    }
    Ok(found)
}

/// Global slot of the `index`-th note this pool emitted in an AMM settlement, and the blind
/// (as a decimal string) that opens it, if any. Reserve slots (0 / 2) have no public blind:
/// the matcher holds the reserve opening.
pub(crate) fn slot_for_pool(pool: &str, index: usize, record: &AmmSettled) -> Option<(usize, Option<String>)> {
    if pool.eq_ignore_ascii_case(&record.meme_pool) {
        return match index {
            0 => Some((0, None)),
            1 => Some((1, Some(record.blind_payout.clone()))),
            _ => None,
        };
    }
    match index {
        0 => Some((2, None)),
        1 => Some((3, Some(record.blind_payout.clone()))),
        2 => Some((4, Some(record.blind_fee_c.clone()))),
        3 => Some((5, Some(record.blind_fee_t.clone()))),
        _ => None,
    }
}

pub(crate) fn expected_outputs(pool: &str, record: &AmmSettled) -> usize {
    if pool.eq_ignore_ascii_case(&record.meme_pool) { MEME_ACTIONS } else { QUOTE_ACTIONS }
}

fn default_gateway(reg: &PoolRegistry, q: Option<&str>) -> Result<Option<String>, ApiError> {
    match q.map(str::trim).filter(|s| !s.is_empty()) {
        Some(g) => {
            parse_address20(g).ok_or((StatusCode::BAD_REQUEST, "invalid gateway address".into()))?;
            Ok(Some(normalize_hex_0x(g).to_lowercase()))
        }
        None => Ok(reg.amm_settlement.clone()),
    }
}

/// `GET /amm/settlement/blinds?tx=&gateway=` — the three public blinds of one settlement.
pub(crate) async fn get_amm_settlement_blinds(State(reg): State<PoolRegistry>, Query(q): Query<AmmBlindsQuery>)
    -> Result<Json<AmmSettled>, ApiError>
{
    let _permit = acquire_history_read(&reg).await?;
    let gateway = default_gateway(&reg, q.gateway.as_deref())?;
    let tx = hex32_0x(&parse_hex32(&q.tx).ok_or((StatusCode::BAD_REQUEST, "invalid transaction hash".into()))?);
    let receipt = vnote::confirmed_receipt(&reg.builder.rpc, &tx).await?;
    let record = decode_settled(&receipt, gateway.as_deref())
        .map_err(|_| unavailable("Settled event is malformed or ambiguous"))?
        .ok_or((StatusCode::NOT_FOUND, "no AmmSettlement.Settled event".into()))?;
    Ok(Json(record))
}

/// `GET /amm/pools?gateway=&from_block=&limit=` — `PoolCreated` registry of one gateway, in
/// canonical log order. Bounded scan from `from_block` (default: indexer start block).
pub(crate) async fn get_amm_pools(State(reg): State<PoolRegistry>, Query(q): Query<AmmPoolsQuery>)
    -> Result<Json<serde_json::Value>, ApiError>
{
    let _permit = acquire_history_read(&reg).await?;
    let gateway = default_gateway(&reg, q.gateway.as_deref())?
        .ok_or((StatusCode::BAD_REQUEST, "gateway required (no PRIVACYBTC_INDEXER_AMM_SETTLEMENT configured)".into()))?;
    let limit = q.limit.unwrap_or(200).clamp(1, 1000);
    let from = q.from_block.unwrap_or(reg.default_start_block);
    let pools = reg.builder.rpc.fetch_amm_pool_created(&gateway, from, limit).await
        .map_err(|_| unavailable("PoolCreated scan unavailable"))?;
    Ok(Json(serde_json::json!({ "gateway": gateway, "from_block": from, "pools": pools })))
}

impl RpcClient {
    pub(crate) async fn fetch_amm_pool_created(&self, gateway: &str, start_block: u64, limit: usize) -> Result<Vec<AmmPoolCreated>> {
        let topic0 = pool_created_topic0();
        let (head, _) = self.confirmation_head().await?;
        let mut out = Vec::new();
        let mut lo = start_block;
        while lo <= head && out.len() < limit {
            let hi = getlogs_window_end(lo, head, self.getlogs_span());
            let filter = serde_json::json!({
                "fromBlock": format!("0x{lo:x}"), "toBlock": format!("0x{hi:x}"),
                "address": normalize_hex_0x(gateway), "topics": [topic0.clone()],
            });
            let logs: Vec<EthLog> = match self.rpc_call("eth_getLogs", serde_json::json!([filter])).await {
                Ok(logs) => logs,
                Err(error) if hi > lo && is_getlogs_range_error(&error) => { self.shrink_getlogs_span(hi - lo + 1); continue; }
                Err(error) => return Err(error).with_context(|| format!("eth_getLogs (PoolCreated) [{lo},{hi}] failed")),
            };
            self.validate_canonical_logs(&logs).await?;
            for log in &logs {
                if !log.address.eq_ignore_ascii_case(gateway) { continue; }
                if let Some(p) = decode_pool_created_log(log, Some(gateway))? { out.push(p); }
                if out.len() >= limit { break; }
            }
            if hi == u64::MAX { break; }
            lo = hi + 1;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn log(topics: Vec<String>, data: Vec<u8>) -> EthLog {
        EthLog {
            address: format!("0x{}", hex::encode([9; 20])), block_number: "0x64".into(), block_hash: Some(hex32_0x(&[7; 32])),
            transaction_hash: hex32_0x(&[8; 32]), log_index: "0x1".into(), removed: false,
            topics: Some(topics), data: format!("0x{}", hex::encode(data)),
        }
    }
    fn addr_topic(id: u8) -> String { format!("0x{}{}", "00".repeat(12), hex::encode([id; 20])) }

    #[test]
    fn settled_decodes_and_maps_slots() {
        let mut data = vec![0u8; 160];
        data[31] = 0xaa; data[63] = 0xbb; data[95] = 7; data[127] = 8; data[159] = 9;
        let l = log(vec![settled_topic0(), addr_topic(1)], data);
        let s = decode_settled_log(&l, None).unwrap().unwrap();
        assert_eq!(s.meme_pool, format!("0x{}", hex::encode([1; 20])));
        assert_eq!((s.blind_payout.as_str(), s.blind_fee_c.as_str(), s.blind_fee_t.as_str()), ("7", "8", "9"));
        assert!(s.tip_cm_x.ends_with("aa") && s.tip_cm_y.ends_with("bb"));
        assert_eq!(slot_for_pool(&s.meme_pool, 0, &s), Some((0, None)));
        assert_eq!(slot_for_pool(&s.meme_pool, 1, &s), Some((1, Some("7".into()))));
        assert_eq!(slot_for_pool(&s.meme_pool, 2, &s), None);
        assert_eq!(slot_for_pool("0xquote", 1, &s), Some((3, Some("7".into()))));
        assert_eq!(slot_for_pool("0xquote", 2, &s), Some((4, Some("8".into()))));
        assert_eq!(slot_for_pool("0xquote", 3, &s), Some((5, Some("9".into()))));
        assert_eq!(slot_for_pool("0xquote", 4, &s), None);
        assert_eq!(expected_outputs(&s.meme_pool, &s), 2);
        assert_eq!(expected_outputs("0xquote", &s), 4);
        // gateway filter, malformed data, non-address poolId all refuse.
        assert!(decode_settled_log(&l, Some("0x0000000000000000000000000000000000000001")).unwrap().is_none());
        let mut short = l.clone(); short.data.truncate(10);
        assert!(decode_settled_log(&short, None).is_err());
        let bad = log(vec![settled_topic0(), hex32_0x(&[1; 32])], vec![0u8; 160]);
        assert!(decode_settled_log(&bad, None).is_err());
    }

    #[test]
    fn two_settled_logs_are_ambiguous() {
        let l = log(vec![settled_topic0(), addr_topic(1)], vec![0u8; 160]);
        let r = ReceiptWithLogs { success: true, block_number: 100, block_hash: hex32_0x(&[7; 32]), logs: vec![l.clone(), l] };
        assert!(decode_settled(&r, None).is_err());
    }

    #[test]
    fn pool_created_decodes() {
        let mut data = vec![0u8; 128];
        data[12..32].copy_from_slice(&[5; 20]); data[63] = 42; data[95] = 1; data[127] = 2;
        let l = log(vec![pool_created_topic0(), addr_topic(1), addr_topic(1), addr_topic(2)], data);
        let p = decode_pool_created_log(&l, None).unwrap().unwrap();
        assert_eq!(p.quote_pool, format!("0x{}", hex::encode([2; 20])));
        assert_eq!(p.creator_evm, format!("0x{}", hex::encode([5; 20])));
        assert_eq!(p.creator_addr_commit, "42");
        let mismatch = log(vec![pool_created_topic0(), addr_topic(3), addr_topic(1), addr_topic(2)], vec![0u8; 128]);
        assert!(decode_pool_created_log(&mismatch, None).is_err());
    }
}
