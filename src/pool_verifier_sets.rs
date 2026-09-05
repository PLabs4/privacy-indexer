//! Exact, release-bound exceptions for pools whose Action verifier is rotated.
//! Entries select one expected set for one pool; they never grant pool admission.
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Clone, Debug, Default)]
pub(crate) struct PoolVerifierSets(HashMap<String, [u8; 32]>);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    pool: String,
    verifier_set_id: String,
}

impl PoolVerifierSets {
    pub(crate) fn from_json(raw: &str) -> Result<Self> {
        if raw.len() > 32_768 { bail!("verifier overrides exceed size limit"); }
        let entries: Vec<Entry> = serde_json::from_str(raw)
            .context("verifier overrides must be an array of pool/verifier_set_id entries")?;
        if entries.len() > 128 { bail!("too many verifier overrides"); }
        let mut sets = HashMap::new();
        for entry in entries {
            let address = strict_hex::<20>(&entry.pool)?;
            let set = strict_hex::<32>(&entry.verifier_set_id)?;
            let pool = format!("0x{}", hex::encode(address));
            if sets.insert(pool, set).is_some() { bail!("duplicate pool verifier override"); }
        }
        Ok(Self(sets))
    }

    pub(crate) fn expected<'a>(&'a self, pool: &str, default: &'a [u8; 32]) -> &'a [u8; 32] {
        self.0.get(&pool.to_ascii_lowercase()).unwrap_or(default)
    }

}

fn strict_hex<const N: usize>(value: &str) -> Result<[u8; N]> {
    let raw = value.strip_prefix("0x").filter(|s| s.len() == N * 2)
        .ok_or_else(|| anyhow::anyhow!("verifier override requires exact 0x-prefixed hex"))?;
    let mut bytes = [0; N];
    hex::decode_to_slice(raw, &mut bytes).context("invalid verifier override hex")?;
    if bytes.iter().all(|b| *b == 0) { bail!("zero verifier override is forbidden"); }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_named_pool_changes_its_single_expected_set() {
        let pool = format!("0x{}", "ab".repeat(20));
        let set = format!("0x{}", "cd".repeat(32));
        let overrides = PoolVerifierSets::from_json(&serde_json::json!([
            {"pool": pool, "verifier_set_id": set}
        ]).to_string()).unwrap();
        assert_eq!(overrides.expected(&pool, &[1;32]), &[0xcd;32]);
        assert_eq!(overrides.expected(&format!("0x{}", "AB".repeat(20)), &[1;32]), &[0xcd;32]);
        assert_eq!(overrides.expected(&format!("0x{}", "ef".repeat(20)), &[1;32]), &[1;32]);
        assert_eq!(PoolVerifierSets::from_json("[]").unwrap().expected(&pool, &[1;32]), &[1;32]);
    }
    #[test]
    fn malformed_zero_and_duplicate_entries_fail_closed() {
        let entry = serde_json::json!({"pool":format!("0x{}", "ab".repeat(20)), "verifier_set_id":format!("0x{}", "cd".repeat(32))});
        let mut duplicate = entry.clone();
        duplicate["pool"] = format!("0x{}", "AB".repeat(20)).into();
        assert!(PoolVerifierSets::from_json(&serde_json::json!([entry.clone(), duplicate]).to_string()).is_err());
        for (field, value) in [("pool", "0x11".to_string()), ("pool", format!("0x{}", "00".repeat(20))),
            ("verifier_set_id", format!("0x{}", "00".repeat(32))), ("verifier_set_id", format!("0x{}", "zz".repeat(32)))] {
            let mut bad = entry.clone(); bad[field] = value.into();
            assert!(PoolVerifierSets::from_json(&serde_json::json!([bad]).to_string()).is_err());
        }
        let mut bad = entry; bad["allow_any"] = true.into();
        assert!(PoolVerifierSets::from_json(&serde_json::json!([bad]).to_string()).is_err());
        assert!(PoolVerifierSets::from_json("{}").is_err());
    }
}
