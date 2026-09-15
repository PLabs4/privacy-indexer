use super::*;
#[derive(Deserialize)]
pub(crate) struct AssetReadinessQuery { pool: String }
pub(crate) async fn get_asset_readiness(State(reg): State<PoolRegistry>, headers: HeaderMap, Query(q): Query<AssetReadinessQuery>) -> Result<Json<serde_json::Value>,(StatusCode,String)> {
    if !catalog_admission::readiness_authorized(headers.get("authorization").and_then(|v|v.to_str().ok())) {return Err((StatusCode::UNAUTHORIZED,"readiness credential required".into()))}
    let ctx=reg.resolve(Some(&q.pool)).await?;
    let ack=catalog_admission::require(&ctx.contract_address,"sync").map_err(|e|(StatusCode::SERVICE_UNAVAILABLE,e))?
        .ok_or((StatusCode::SERVICE_UNAVAILABLE,"signed admission not configured".into()))?;
    if !reg.verify_pool_current(&ctx.contract_address).await.map_err(|_|(StatusCode::SERVICE_UNAVAILABLE,"pool verification unavailable".into()))? {return Err((StatusCode::SERVICE_UNAVAILABLE,"pool verification failed".into()))}
    let s=ctx.state.read().await;
    let ready=!s.tree_out_of_order && ctx.frozen_paths_ready.load(AtomicOrdering::Acquire) && !ctx.shadow_mode;
    Ok(Json(serde_json::json!({"admission":ack,"pool":ctx.contract_address,"from_block":ctx.start_block,"canonical":ready,
        "indexed_through":s.next_block.saturating_sub(1),"confirmed_count":s.confirmed_count,"root":http_root_hex(&s),"pending_cmx":s.tree_frontier.next_index().saturating_sub(s.confirmed_count)})))
}
