//! Bounded-memory BN254 Poseidon commitment-tree state.
//!
//! The indexer used to retain every leaf plus every memoized Merkle node in one
//! `OrchardCommitmentTree`.  Warm-start then populated that cache eagerly.  At
//! mainnet scale the allocation churn alone was enough to drive the process into
//! the cgroup OOM limit.  This module keeps only the 32-element append frontier
//! in RAM.  Complete nodes are emitted for archival in PostgreSQL and witnesses
//! are reconstructed from that archive with a bounded (depth-sized) working set.

use std::{
    collections::{HashMap, HashSet},
    sync::OnceLock,
};

use anyhow::{anyhow, bail, Context, Result};
use ethabi::Uint;
use ff::{Field, PrimeField};
use halo2_poseidon::{generate_constants, Mds, Spec};
use halo2curves::bn256::Fr;
use privacy_core::commitment_tree::frontier::{
    CmxConfirmWitnessInput, CMX_CONFIRM_MAX_BATCH, CMX_CONFIRM_MAX_PROOFS_PER_TX,
};

pub const TREE_DEPTH: usize = 32;
const DOMAIN_FRONTIER: u64 = 3006;

/// One immutable, complete Merkle node. `level=0` is a leaf; level 32 is the
/// root of a full 2^32-leaf tree.  Partial right-edge nodes are deliberately not
/// archived: they are reconstructed from complete cover nodes plus empty roots.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MerkleNodeKey {
    pub level: u8,
    pub index: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MerkleNode {
    pub key: MerkleNodeKey,
    /// EVM/on-chain byte order.
    pub hash_be: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
struct Bn254PoseidonMerkleSpec;

impl Spec<Fr, 3, 2> for Bn254PoseidonMerkleSpec {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    fn sbox(val: Fr) -> Fr {
        val.pow_vartime([5])
    }

    fn secure_mds() -> usize {
        0
    }

    fn constants() -> (Vec<[Fr; 3]>, Mds<Fr, 3>, Mds<Fr, 3>) {
        generate_constants::<Fr, Self, 3, 2>()
    }
}

struct PoseidonConstants {
    round_constants: Vec<[Fr; 3]>,
    mds: Mds<Fr, 3>,
}

fn poseidon_constants() -> &'static PoseidonConstants {
    static CONSTANTS: OnceLock<PoseidonConstants> = OnceLock::new();
    CONSTANTS.get_or_init(|| {
        let (round_constants, mds, _) = generate_constants::<Fr, Bn254PoseidonMerkleSpec, 3, 2>();
        PoseidonConstants {
            round_constants,
            mds,
        }
    })
}

fn poseidon_permute(state: &mut [Fr; 3], mds: &Mds<Fr, 3>, round_constants: &[[Fr; 3]]) {
    let half_full = Bn254PoseidonMerkleSpec::full_rounds() / 2;
    let partial = Bn254PoseidonMerkleSpec::partial_rounds();
    for (round, constants) in round_constants.iter().enumerate() {
        if round < half_full || round >= half_full + partial {
            for (word, constant) in state.iter_mut().zip(constants) {
                *word = (*word + constant).pow_vartime([5]);
            }
        } else {
            for (word, constant) in state.iter_mut().zip(constants) {
                *word += constant;
            }
            state[0] = state[0].pow_vartime([5]);
        }
        let mut mixed = [Fr::ZERO; 3];
        for (row, output) in mixed.iter_mut().enumerate() {
            for (column, word) in state.iter().enumerate() {
                *output += mds[row][column] * word;
            }
        }
        *state = mixed;
    }
}

/// Allocation-free `Hash<ConstantLength<3>>([domain, left, right])`.
///
/// `halo2_poseidon::Hash::init()` owns a freshly cloned round-constant vector.
/// A full historical tree performs hundreds of thousands of hashes, so that
/// otherwise-correct API creates pathological allocator pressure.  Constant
/// length 3 at rate 2 is exactly two permutations: absorb `(domain,left)`, then
/// absorb `(right,0)`.  The constants below are generated once and borrowed.
#[inline]
pub fn poseidon_pair(domain: u64, left: Fr, right: Fr) -> Fr {
    let constants = poseidon_constants();
    let mut state = [Fr::from(domain), left, Fr::from_u128(3u128 << 64)];
    poseidon_permute(&mut state, &constants.mds, &constants.round_constants);
    state[0] += right;
    poseidon_permute(&mut state, &constants.mds, &constants.round_constants);
    state[0]
}

#[inline]
pub fn merkle_compress(level: u8, left: Fr, right: Fr) -> Fr {
    poseidon_pair(level as u64, left, right)
}

fn empty_roots() -> &'static [Fr; TREE_DEPTH + 1] {
    static EMPTY: OnceLock<[Fr; TREE_DEPTH + 1]> = OnceLock::new();
    EMPTY.get_or_init(|| {
        let mut roots = [Fr::ZERO; TREE_DEPTH + 1];
        for level in 0..TREE_DEPTH {
            roots[level + 1] = merkle_compress(level as u8, roots[level], roots[level]);
        }
        roots
    })
}

#[derive(Clone, Debug)]
pub struct CompactFrontier {
    filled: [Fr; TREE_DEPTH],
    next_index: u64,
    root: Fr,
}

impl CompactFrontier {
    pub fn new() -> Self {
        Self {
            filled: [Fr::ZERO; TREE_DEPTH],
            next_index: 0,
            root: empty_roots()[TREE_DEPTH],
        }
    }

    pub fn from_parts_be(
        filled_be: &[[u8; 32]],
        next_index: u64,
        expected_root_be: [u8; 32],
    ) -> Result<Self> {
        if filled_be.len() != TREE_DEPTH {
            bail!(
                "compact frontier has {} slots, expected {TREE_DEPTH}",
                filled_be.len()
            );
        }
        if next_index >= (1u64 << TREE_DEPTH) {
            bail!("compact frontier count exceeds tree capacity");
        }
        let mut filled = [Fr::ZERO; TREE_DEPTH];
        for (slot, encoded) in filled.iter_mut().zip(filled_be) {
            *slot = fr_from_be(*encoded)?;
        }
        let root = root_from_filled(&filled, next_index);
        if fr_to_be(root) != expected_root_be {
            bail!("compact frontier root does not match checkpoint root");
        }
        Ok(Self {
            filled,
            next_index,
            root,
        })
    }

    pub fn next_index(&self) -> u64 {
        self.next_index
    }

    pub fn root_be(&self) -> [u8; 32] {
        fr_to_be(self.root)
    }

    pub fn root_le(&self) -> [u8; 32] {
        self.root.to_repr().into()
    }

    pub fn filled_be(&self) -> Vec<[u8; 32]> {
        self.filled.iter().copied().map(fr_to_be).collect()
    }

    pub fn frontier_commit(&self) -> Fr {
        self.filled.iter().fold(Fr::ZERO, |acc, value| {
            poseidon_pair(DOMAIN_FRONTIER, acc, *value)
        })
    }

    /// Append one leaf and return every node that became immutable/complete.
    /// This is one leaf plus one parent for each trailing one bit in the old
    /// index (two nodes on average), never all 32 transient right-edge nodes.
    pub fn append_be(&mut self, leaf_be: [u8; 32]) -> Result<Vec<MerkleNode>> {
        let leaf = fr_from_be(leaf_be)?;
        let index = self.next_index;
        if index >= (1u64 << TREE_DEPTH) {
            bail!("commitment tree is full");
        }

        let mut complete = true;
        let mut node = leaf;
        let mut archived = vec![MerkleNode {
            key: MerkleNodeKey { level: 0, index },
            hash_be: leaf_be,
        }];
        for level in 0..TREE_DEPTH {
            if ((index >> level) & 1) == 0 {
                self.filled[level] = node;
                node = merkle_compress(level as u8, node, empty_roots()[level]);
                complete = false;
            } else {
                node = merkle_compress(level as u8, self.filled[level], node);
                if complete {
                    archived.push(MerkleNode {
                        key: MerkleNodeKey {
                            level: (level + 1) as u8,
                            index: index >> (level + 1),
                        },
                        hash_be: fr_to_be(node),
                    });
                }
            }
        }
        self.next_index = index + 1;
        self.root = node;
        Ok(archived)
    }

    pub fn plan_batch(&mut self, leaves: &[[u8; 32]]) -> Result<CmxConfirmWitnessInput> {
        if leaves.is_empty() || leaves.len() > CMX_CONFIRM_MAX_BATCH {
            bail!("batch size must be 1..={CMX_CONFIRM_MAX_BATCH}");
        }
        let old_root = self.root;
        let old_frontier_commit = self.frontier_commit();
        let start_index = self.next_index;
        let filled_start = self.filled;
        let mut cmxs = [Fr::ZERO; CMX_CONFIRM_MAX_BATCH];
        for (slot, leaf) in cmxs.iter_mut().zip(leaves.iter()) {
            *slot = fr_from_be(*leaf)?;
            self.append_be(*leaf)?;
        }
        Ok(CmxConfirmWitnessInput {
            old_root: fr_decimal(old_root),
            new_root: fr_decimal(self.root),
            j: leaves.len().to_string(),
            start_idx: start_index.to_string(),
            old_frontier_commit: fr_decimal(old_frontier_commit),
            new_frontier_commit: fr_decimal(self.frontier_commit()),
            cmxs: cmxs.iter().copied().map(fr_decimal).collect(),
            filled_start: filled_start.iter().copied().map(fr_decimal).collect(),
        })
    }

    pub fn plan_batches(
        &mut self,
        leaves: &[[u8; 32]],
        max_proofs: usize,
    ) -> Result<Vec<CmxConfirmWitnessInput>> {
        if !(1..=CMX_CONFIRM_MAX_PROOFS_PER_TX).contains(&max_proofs) {
            bail!("max proofs must be 1..={CMX_CONFIRM_MAX_PROOFS_PER_TX}");
        }
        if leaves.is_empty() || leaves.len() > CMX_CONFIRM_MAX_BATCH * max_proofs {
            bail!(
                "aggregate batch size must be 1..={}",
                CMX_CONFIRM_MAX_BATCH * max_proofs
            );
        }
        leaves
            .chunks(CMX_CONFIRM_MAX_BATCH)
            .map(|chunk| self.plan_batch(chunk))
            .collect()
    }
}

impl Default for CompactFrontier {
    fn default() -> Self {
        Self::new()
    }
}

/// Streaming O(depth)-memory builder used only to upgrade legacy checkpoints.
/// Every non-final append performs one hash on average.  The final leaf is fed
/// through the exact frontier insertion so all stale `filled` slots (which are
/// part of the on-chain frontier commitment) are reconstructed byte-for-byte.
#[derive(Clone, Debug)]
pub struct StreamingFrontierBuilder {
    stack: [Option<Fr>; TREE_DEPTH],
    count: u64,
}

impl StreamingFrontierBuilder {
    pub fn new() -> Self {
        Self {
            stack: [None; TREE_DEPTH],
            count: 0,
        }
    }

    pub fn push_nonfinal_be(&mut self, leaf_be: [u8; 32]) -> Result<Vec<MerkleNode>> {
        let mut node = fr_from_be(leaf_be)?;
        let index = self.count;
        if index >= (1u64 << TREE_DEPTH) {
            bail!("commitment tree is full");
        }
        let mut archived = vec![MerkleNode {
            key: MerkleNodeKey { level: 0, index },
            hash_be: leaf_be,
        }];
        let mut level = 0usize;
        while level < TREE_DEPTH && ((index >> level) & 1) == 1 {
            let left = self.stack[level].take().ok_or_else(|| {
                anyhow!("streaming frontier stack is incomplete at level {level}")
            })?;
            node = merkle_compress(level as u8, left, node);
            archived.push(MerkleNode {
                key: MerkleNodeKey {
                    level: (level + 1) as u8,
                    index: index >> (level + 1),
                },
                hash_be: fr_to_be(node),
            });
            level += 1;
        }
        if level == TREE_DEPTH {
            bail!("commitment tree is full");
        }
        self.stack[level] = Some(node);
        self.count += 1;
        Ok(archived)
    }

    pub fn finish_with_last_be(
        &self,
        leaf_be: [u8; 32],
    ) -> Result<(CompactFrontier, Vec<MerkleNode>)> {
        let mut filled = [Fr::ZERO; TREE_DEPTH];
        for (level, entry) in self.stack.iter().enumerate() {
            if ((self.count >> level) & 1) == 1 {
                filled[level] = entry.ok_or_else(|| {
                    anyhow!("streaming frontier stack is incomplete at level {level}")
                })?;
            }
        }
        let mut frontier = CompactFrontier {
            filled,
            next_index: self.count,
            root: root_from_filled(&filled, self.count),
        };
        let nodes = frontier.append_be(leaf_be)?;
        Ok((frontier, nodes))
    }
}

impl Default for StreamingFrontierBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub fn frontier_from_leaves(leaves: &[[u8; 32]]) -> Result<CompactFrontier> {
    let Some((last, prefix)) = leaves.split_last() else {
        return Ok(CompactFrontier::new());
    };
    let mut builder = StreamingFrontierBuilder::new();
    for leaf in prefix {
        builder.push_nonfinal_be(*leaf)?;
    }
    builder
        .finish_with_last_be(*last)
        .map(|(frontier, _)| frontier)
}

pub fn required_witness_nodes(position: u64, confirmed_count: u64) -> Result<Vec<MerkleNodeKey>> {
    if position >= confirmed_count {
        bail!("position is not inside the confirmed prefix");
    }
    let mut keys = HashSet::new();
    for level in 0..TREE_DEPTH {
        let sibling_index = (position >> level) ^ 1;
        collect_complete_cover(level as u8, sibling_index, confirmed_count, &mut keys)?;
    }
    let mut keys: Vec<_> = keys.into_iter().collect();
    keys.sort_unstable();
    Ok(keys)
}

pub fn witness_from_nodes(
    position: u64,
    confirmed_count: u64,
    nodes_be: &HashMap<MerkleNodeKey, [u8; 32]>,
) -> Result<Vec<String>> {
    if position >= confirmed_count {
        bail!("position is not inside the confirmed prefix");
    }
    let mut parsed = HashMap::with_capacity(nodes_be.len());
    for (key, value) in nodes_be {
        parsed.insert(*key, fr_from_be(*value)?);
    }
    (0..TREE_DEPTH)
        .map(|level| {
            let sibling_index = (position >> level) ^ 1;
            let sibling = subtree_at_prefix(level as u8, sibling_index, confirmed_count, &parsed)?;
            Ok(format!(
                "0x{}",
                hex::encode(<[u8; 32]>::from(sibling.to_repr()))
            ))
        })
        .collect()
}

/// Recompute the root represented by a compatibility witness. This is the
/// final integrity guard before `/merkle_path` returns PostgreSQL-derived data:
/// a missing or corrupted internal-node row can never yield an unchecked path.
pub fn witness_root_be(
    leaf_be: [u8; 32],
    position: u64,
    siblings_le_hex: &[String],
) -> Result<[u8; 32]> {
    if siblings_le_hex.len() != TREE_DEPTH {
        bail!(
            "Merkle witness has {} siblings, expected {TREE_DEPTH}",
            siblings_le_hex.len()
        );
    }
    let mut node = fr_from_be(leaf_be)?;
    for (level, encoded) in siblings_le_hex.iter().enumerate() {
        let raw = hex::decode(encoded.trim_start_matches("0x"))
            .with_context(|| format!("decode Merkle sibling at level {level}"))?;
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow!("Merkle sibling at level {level} is not 32 bytes"))?;
        let sibling = Option::from(Fr::from_repr(bytes.into()))
            .ok_or_else(|| anyhow!("Merkle sibling at level {level} is not canonical"))?;
        node = if ((position >> level) & 1) == 0 {
            merkle_compress(level as u8, node, sibling)
        } else {
            merkle_compress(level as u8, sibling, node)
        };
    }
    Ok(fr_to_be(node))
}

fn collect_complete_cover(
    level: u8,
    index: u64,
    count: u64,
    keys: &mut HashSet<MerkleNodeKey>,
) -> Result<()> {
    let start = (index as u128) << level;
    let end = start + (1u128 << level);
    let count = count as u128;
    if start >= count {
        return Ok(());
    }
    if end <= count {
        keys.insert(MerkleNodeKey { level, index });
        return Ok(());
    }
    if level == 0 {
        bail!("partial level-zero Merkle node");
    }
    collect_complete_cover(level - 1, index * 2, count as u64, keys)?;
    collect_complete_cover(level - 1, index * 2 + 1, count as u64, keys)
}

fn subtree_at_prefix(
    level: u8,
    index: u64,
    count: u64,
    nodes: &HashMap<MerkleNodeKey, Fr>,
) -> Result<Fr> {
    let start = (index as u128) << level;
    let end = start + (1u128 << level);
    let count128 = count as u128;
    if start >= count128 {
        return Ok(empty_roots()[level as usize]);
    }
    if end <= count128 {
        return nodes
            .get(&MerkleNodeKey { level, index })
            .copied()
            .ok_or_else(|| anyhow!("missing archived Merkle node ({level},{index})"));
    }
    if level == 0 {
        bail!("partial level-zero Merkle node");
    }
    let left = subtree_at_prefix(level - 1, index * 2, count, nodes)?;
    let right = subtree_at_prefix(level - 1, index * 2 + 1, count, nodes)?;
    Ok(merkle_compress(level - 1, left, right))
}

fn root_from_filled(filled: &[Fr; TREE_DEPTH], count: u64) -> Fr {
    let mut node = Fr::ZERO;
    for (level, filled_node) in filled.iter().enumerate() {
        node = if ((count >> level) & 1) == 1 {
            merkle_compress(level as u8, *filled_node, node)
        } else {
            merkle_compress(level as u8, node, empty_roots()[level])
        };
    }
    node
}

pub fn fr_from_be(mut bytes: [u8; 32]) -> Result<Fr> {
    bytes.reverse();
    Option::from(Fr::from_repr(bytes.into())).context("non-canonical BN254 field element")
}

pub fn fr_to_be(value: Fr) -> [u8; 32] {
    let mut bytes: [u8; 32] = value.to_repr().into();
    bytes.reverse();
    bytes
}

fn fr_decimal(value: Fr) -> String {
    Uint::from_big_endian(&fr_to_be(value)).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use privacy_core::commitment_tree::{
        frontier::FrontierTree,
        poseidon::{merkle_compress as reference_compress, poseidon_domain_pair},
        OrchardCommitmentTree,
    };

    fn leaf(value: u64) -> [u8; 32] {
        let mut encoded = [0u8; 32];
        encoded[24..].copy_from_slice(&value.to_be_bytes());
        encoded
    }

    #[test]
    fn allocation_free_poseidon_matches_privacy_core() {
        for domain in [0u64, 1, 31, DOMAIN_FRONTIER] {
            for value in 0..8u64 {
                let left = Fr::from(value);
                let right = Fr::from(value + 17);
                assert_eq!(
                    poseidon_pair(domain, left, right),
                    poseidon_domain_pair(domain, left, right)
                );
                if domain <= u8::MAX as u64 {
                    assert_eq!(
                        merkle_compress(domain as u8, left, right),
                        reference_compress(domain as u8, left, right)
                    );
                }
            }
        }
    }

    #[test]
    fn compact_tree_state_has_a_fixed_depth_only_footprint() {
        assert!(std::mem::size_of::<CompactFrontier>() <= 1_152);
        assert!(std::mem::size_of::<StreamingFrontierBuilder>() <= 1_320);
        assert_eq!(std::mem::size_of::<Vec<MerkleNode>>(), 24);
    }

    #[test]
    fn compact_frontier_matches_reference_for_every_prefix() {
        let mut compact = CompactFrontier::new();
        let mut reference = FrontierTree::new();
        for value in 1..=64u64 {
            compact.append_be(leaf(value)).unwrap();
            reference.insert_be(leaf(value));
            assert_eq!(compact.next_index(), reference.next_index());
            assert_eq!(compact.root_be(), fr_to_be(reference.root()));
            assert_eq!(compact.frontier_commit(), reference.frontier_commit());
        }
    }

    #[test]
    fn streaming_builder_reconstructs_exact_frontier_and_complete_nodes() {
        for count in [
            1u64, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 64, 65, 129,
        ] {
            let mut builder = StreamingFrontierBuilder::new();
            let mut archived = HashMap::new();
            for value in 1..count {
                for node in builder.push_nonfinal_be(leaf(value)).unwrap() {
                    archived.insert(node.key, node.hash_be);
                }
            }
            let (frontier, final_nodes) = builder.finish_with_last_be(leaf(count)).unwrap();
            for node in final_nodes {
                archived.insert(node.key, node.hash_be);
            }

            let mut reference = FrontierTree::new();
            let mut full = OrchardCommitmentTree::new();
            for value in 1..=count {
                reference.insert_be(leaf(value));
                full.append(leaf(value));
            }
            assert_eq!(
                frontier.root_be(),
                fr_to_be(reference.root()),
                "count={count}"
            );
            assert_eq!(
                frontier.frontier_commit(),
                reference.frontier_commit(),
                "count={count}"
            );

            let mut positions = vec![0, count / 2, count - 1];
            positions.sort_unstable();
            positions.dedup();
            for position in positions {
                let required = required_witness_nodes(position, count).unwrap();
                let selected = required
                    .into_iter()
                    .map(|key| (key, archived[&key]))
                    .collect();
                let actual = witness_from_nodes(position, count, &selected).unwrap();
                let expected = full.merkle_path_at(position, count).unwrap().siblings;
                assert_eq!(actual, expected, "count={count} position={position}");
            }
        }
    }

    #[test]
    fn compact_batch_plans_match_reference() {
        let leaves: Vec<_> = (1..=17).map(leaf).collect();
        let mut compact = CompactFrontier::new();
        let mut reference = FrontierTree::new();
        let actual = compact.plan_batches(&leaves, 4).unwrap();
        let expected = reference.plan_batches(&leaves, 4);
        assert_eq!(
            serde_json::to_value(actual).unwrap(),
            serde_json::to_value(expected).unwrap()
        );
    }
}
