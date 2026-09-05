//! Bounded vnote recovery reads over the durable note index and canonical receipts.
//! Missing/failed storage or incomplete settlement output data is never a zero balance.
use super::*;

type ApiError = (StatusCode,String);
fn unavailable(message: &str) -> ApiError { (StatusCode::SERVICE_UNAVAILABLE,message.into()) }

#[derive(Deserialize)]
pub(crate) struct NoteByNfQuery { nf: String, pool: Option<String> }
#[derive(Deserialize)]
pub(crate) struct BlindsQuery { tx: String, gateway: Option<String> }

#[derive(Clone,Debug,Serialize)]
pub(crate) struct SettlementBlinds {
    pool_x: String,
    pool_y: String,
    fee_pool: String,
    gateway: String,
    fee_unshield_total: String,
    blinds: Vec<String>,
}

fn decode_blinds(receipt: &ReceiptWithLogs, gateway: Option<&str>) -> Result<Option<SettlementBlinds>> {
    let topic = event_topic0(b"SettlementExecuted(address,address,address,uint256,uint256[6])");
    let mut result = None;
    for log in &receipt.logs {
        let topics = log.topics.as_deref().unwrap_or(&[]);
        if topics.first().map(|s|s.to_lowercase()) != Some(topic.clone()) { continue; }
        if gateway.is_some_and(|g|!g.eq_ignore_ascii_case(&log.address)) { continue; }
        if log.removed || topics.len()!=3 || result.is_some() { bail!("ambiguous settlement receipt"); }
        let x = parse_hex32(&topics[1]).ok_or_else(||anyhow!("invalid pool X topic"))?;
        let y = parse_hex32(&topics[2]).ok_or_else(||anyhow!("invalid pool Y topic"))?;
        if x[..12]!=[0;12] || y[..12]!=[0;12] || x==y { bail!("invalid settlement pools"); }
        let data = hex::decode(log.data.trim_start_matches("0x"))?;
        if data.len()!=8*32 { bail!("settlement event must contain fee pool, amount and six blinds"); }
        if data[..12]!=[0;12] { bail!("invalid settlement fee pool"); }
        result = Some(SettlementBlinds {
            pool_x:format!("0x{}",hex::encode(&x[12..])), pool_y:format!("0x{}",hex::encode(&y[12..])),
            fee_pool:format!("0x{}",hex::encode(&data[12..32])), gateway:log.address.to_lowercase(),
            fee_unshield_total:ethabi::Uint::from_big_endian(&data[32..64]).to_string(),
            blinds:data[64..].chunks_exact(32).map(|word|format!("0x{}",hex::encode(word))).collect(),
        });
    }
    Ok(result)
}

/// Fee calls follow both trade calls. When feePool aliases a trade pool, its
/// pool-local actions 2/3 are global slots 4/5, not another trade pair.
fn settle_slot_for_pool(pool: &str, index: usize, record: &SettlementBlinds) -> Option<usize> {
    let trade = if pool.eq_ignore_ascii_case(&record.pool_x) {Some(0)}
        else if pool.eq_ignore_ascii_case(&record.pool_y) {Some(2)} else {None};
    if let Some(base) = trade {
        if index<2 { return Some(base+index); }
        if pool.eq_ignore_ascii_case(&record.fee_pool) && index<4 { return Some(4+index-2); }
    } else if pool.eq_ignore_ascii_case(&record.fee_pool) && index<2 { return Some(4+index); }
    None
}

async fn confirmed_receipt(rpc: &RpcClient, hash: &str) -> Result<ReceiptWithLogs,ApiError> {
    let receipt = rpc.get_transaction_receipt_logs(hash).await.map_err(|_|unavailable("receipt RPC unavailable"))?
        .ok_or_else(||unavailable("transaction receipt not available yet"))?;
    if !receipt.success { return Err(unavailable("spend transaction reverted")); }
    let (head,_) = rpc.confirmation_head().await.map_err(|_|unavailable("canonical confirmation head unavailable"))?;
    if receipt.block_number>head { return Err(unavailable("spend transaction is not yet confirmed")); }
    let canonical = rpc.block_hash(receipt.block_number).await.map_err(|_|unavailable("canonical block unavailable"))?;
    if canonical!=receipt.block_hash { return Err(unavailable("spend receipt is not canonical")); }
    verify_log_provenance(&receipt, hash, &canonical).map_err(|_|unavailable("receipt log provenance mismatch"))?;
    Ok(receipt)
}

fn verify_log_provenance(receipt: &ReceiptWithLogs, hash: &str, canonical: &str) -> Result<()> {
    let mut positions = HashSet::new();
    for log in &receipt.logs {
        if log.removed || normalize_hex_0x(&log.transaction_hash).to_lowercase()!=hash.to_lowercase()
            || log.block_hash.as_deref().map(|h|h.to_lowercase()).as_deref()!=Some(canonical)
            || parse_hex_u64(&log.block_number)? != receipt.block_number
            || !positions.insert(parse_hex_u64(&log.log_index)?)
        { bail!("receipt log provenance mismatch"); }
    }
    Ok(())
}

pub(crate) async fn get_settlement_blinds(State(reg):State<PoolRegistry>,Query(q):Query<BlindsQuery>)
    -> Result<Json<SettlementBlinds>,ApiError>
{
    let _permit = acquire_history_read(&reg).await?;
    let tx = hex32_0x(&parse_hex32(&q.tx).ok_or((StatusCode::BAD_REQUEST,"invalid transaction hash".into()))?);
    let receipt = confirmed_receipt(&reg.builder.rpc,&tx).await?;
    let record = decode_blinds(&receipt,q.gateway.as_deref()).map_err(|_|unavailable("settlement event is malformed or ambiguous"))?
        .ok_or((StatusCode::NOT_FOUND,"no SettlementExecuted event".into()))?;
    Ok(Json(record))
}

async fn find_spend_tx(ctx: &AppContext, nf: [u8;32]) -> Result<Option<String>> {
    let mut hashes: HashSet<String> = HashSet::new();
    { let state = ctx.state.read().await;
        for envelope in &state.batches { for note in &envelope.batch.abi_notes {
            if note.nf_old==nf { hashes.insert(normalize_hex_0x(&note.tx_hash).to_lowercase()); }
        }}
    }
    match &ctx.backend {
        StateBackend::Pgsql(pool) => {
            // Uses the original notes_nf_old_idx(pool_address,nf_old_hex). Keep
            // errors explicit: a failed SELECT must never look like an unspent note.
            let candidates = vec![hex::encode(nf),hex32_0x(&nf)];
            let rows: Vec<String> = sqlx::query_scalar(
                "SELECT DISTINCT tx_hash FROM notes WHERE pool_address=$1 AND nf_old_hex=ANY($2::text[]) LIMIT 2",
            ).bind(&ctx.contract_address).bind(candidates).fetch_all(pool).await?;
            hashes.extend(rows.iter().map(|hash|normalize_hex_0x(hash).to_lowercase()));
        }
        StateBackend::Json(Some(path)) => {
            for envelope in StateBackend::read_json_archive(path,&ctx.contract_address) {
                for note in envelope.batch.abi_notes { if note.nf_old==nf { hashes.insert(normalize_hex_0x(&note.tx_hash).to_lowercase()); } }
            }
        }
        StateBackend::Json(None) => {}
    }
    if hashes.len()>1 { bail!("ambiguous nullifier spend in canonical archive"); }
    Ok(hashes.into_iter().next())
}

pub(crate) async fn get_note_by_nf(State(reg):State<PoolRegistry>,Query(q):Query<NoteByNfQuery>)
    -> Result<Json<serde_json::Value>,ApiError>
{
    let _permit = acquire_history_read(&reg).await?;
    let nf = parse_hex32(&q.nf).ok_or((StatusCode::BAD_REQUEST,"invalid nullifier".into()))?;
    if nf==[0;32] { return Err((StatusCode::BAD_REQUEST,"zero nullifier is not a spend identity".into())); }
    let ctx = reg.resolve(q.pool.as_deref()).await?;
    require_canonical_context(&ctx).await?;
    let tx = find_spend_tx(&ctx,nf).await.map_err(|_|unavailable("durable nullifier lookup unavailable"))?;
    let Some(tx) = tx else {
        let mut calldata = Keccak256::digest(b"isSpent(bytes32)")[..4].to_vec(); calldata.extend_from_slice(&nf);
        let spent = reg.builder.rpc.eth_call(&ctx.contract_address,&calldata,None).await.map_err(|_|unavailable("nullifier state unavailable"))?;
        if spent.len()!=32 { return Err(unavailable("invalid nullifier state response")); }
        if spent.iter().any(|b|*b!=0) { return Err(unavailable("spent nullifier has no durable spend record yet")); }
        return Err((StatusCode::NOT_FOUND,"nullifier is unspent".into()));
    };
    let receipt = confirmed_receipt(&reg.builder.rpc,&tx).await?;
    let record = decode_blinds(&receipt,None).map_err(|_|unavailable("settlement event is malformed or ambiguous"))?;
    let note_topics = note_added_topic0_alternatives();
    let pool = ctx.contract_address.to_lowercase();
    let mut notes = Vec::new();
    for log in &receipt.logs {
        if !log.address.eq_ignore_ascii_case(&pool) { continue; }
        let topics = log.topics.as_deref().unwrap_or(&[]);
        if !topics.first().is_some_and(|t|note_topics.iter().any(|n|n.eq_ignore_ascii_case(t))) {continue;}
        let note = decode_note_added_log(topics,&log.data).map_err(|_|unavailable("receipt note data is malformed"))?;
        notes.push((parse_hex_u64(&log.log_index).map_err(|_|unavailable("receipt note position invalid"))?,note));
    }
    notes.sort_by_key(|(index,_)|*index);
    if !notes.iter().any(|(_,note)|note.nf_old==nf) { return Err(unavailable("durable spend identity disagrees with canonical receipt")); }
    if let Some(record) = &record {
        let expected = if pool==record.fee_pool && (pool==record.pool_x || pool==record.pool_y) {4} else {2};
        if notes.len()!=expected { return Err(unavailable("settlement receipt has an incomplete output set")); }
    }
    let outputs = notes.into_iter().enumerate().map(|(i,(_,note))| -> Result<_,ApiError> {
        let slot = match &record {Some(record)=>Some(settle_slot_for_pool(&pool,i,record).ok_or_else(||unavailable("settlement pool slot mapping failed"))?),None=>None};
        Ok(serde_json::json!({"pool":pool,"cmx_hex":hex32_0x(&note.cmx),"nf_old_hex":hex32_0x(&note.nf_old),
            "enc_ciphertext_hex":hex::encode(&note.enc_ciphertext),"action_index":i,"settle_slot":slot,
            "blind":slot.and_then(|j|record.as_ref().map(|r|r.blinds[j].clone()))}))
    }).collect::<Result<Vec<_>,_>>()?;
    require_canonical_context(&ctx).await?;
    Ok(Json(serde_json::json!({"tx_hash":tx,"outputs":outputs,"settlement":record.is_some(),"canonical":true})))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn receipt() -> ReceiptWithLogs {
        let word = |id:u8| format!("0x{}{}", "00".repeat(12),hex::encode([id;20]));
        let mut data = vec![0u8;256]; data[12..32].copy_from_slice(&[3;20]); data[63]=100;
        for i in 0..6 {data[95+i*32]=i as u8+10;}
        ReceiptWithLogs { success:true,block_number:100,block_hash:hex32_0x(&[7;32]),logs:vec![EthLog {
            address:format!("0x{}",hex::encode([4;20])),block_number:"0x64".into(),block_hash:Some(hex32_0x(&[7;32])),
            transaction_hash:hex32_0x(&[8;32]),log_index:"0x2".into(),removed:false,
            topics:Some(vec![event_topic0(b"SettlementExecuted(address,address,address,uint256,uint256[6])"),word(1),word(2)]),data:format!("0x{}",hex::encode(data)),
        }] }
    }

    #[test]
    fn canonical_receipt_event_decoding_is_exact_and_rejects_ambiguity() {
        let mut r=receipt();
        verify_log_provenance(&r,&hex32_0x(&[8;32]),&r.block_hash).unwrap();
        let decoded=decode_blinds(&r,None).unwrap().unwrap();
        assert_eq!(decoded.fee_unshield_total,"100");
        assert_eq!(decoded.blinds.len(),6);
        assert!(decoded.blinds[5].ends_with("0f"));
        assert!(decode_blinds(&r,Some("0x0000000000000000000000000000000000000001")).unwrap().is_none());
        r.logs.push(receipt().logs.remove(0));
        assert!(decode_blinds(&r,None).is_err());
        assert!(verify_log_provenance(&r,&hex32_0x(&[8;32]),&r.block_hash).is_err());
        r.logs.pop(); r.logs[0].data.truncate(20);
        assert!(decode_blinds(&r,None).is_err());
    }

    #[test]
    fn receipt_provenance_never_accepts_removed_or_reorged_logs() {
        for case in 0..4 {
            let mut r=receipt();
            match case {
                0=>r.logs[0].removed=true,
                1=>r.logs[0].block_hash=Some(hex32_0x(&[9;32])),
                2=>r.logs[0].transaction_hash=hex32_0x(&[9;32]),
                _=>r.logs[0].block_number="0x65".into(),
            }
            assert!(verify_log_provenance(&r,&hex32_0x(&[8;32]),&r.block_hash).is_err());
        }
    }
    #[test]
    fn fee_pool_alias_keeps_global_slots() {
        let mut r = SettlementBlinds {pool_x:"x".into(),pool_y:"y".into(),fee_pool:"f".into(),gateway:"g".into(),fee_unshield_total:"2".into(),blinds:vec![]};
        assert_eq!(settle_slot_for_pool("x",1,&r),Some(1));
        assert_eq!(settle_slot_for_pool("y",1,&r),Some(3));
        assert_eq!(settle_slot_for_pool("f",1,&r),Some(5));
        r.fee_pool="x".into();
        assert_eq!(settle_slot_for_pool("x",2,&r),Some(4));
        assert_eq!(settle_slot_for_pool("x",3,&r),Some(5));
        assert_eq!(settle_slot_for_pool("x",4,&r),None);
        r.fee_pool="y".into();
        assert_eq!(settle_slot_for_pool("y",2,&r),Some(4));
    }
}
