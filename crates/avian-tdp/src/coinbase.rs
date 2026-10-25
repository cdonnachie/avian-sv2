//! The coinbase a pool has to build, and what the node checks before it will
//! hash.
//!
//! On a standard mining channel the pool builds the coinbase, not the worker,
//! so every rule in doc/sv2.md's "What a client must reproduce" is the pool's
//! obligation to the node rather than a worker's to the pool. The node
//! rebuilds the header from the template and the submitted coinbase and
//! re-serializes it for a byte comparison, so a coinbase that differs
//! anywhere is refused before any proof of work is computed, and the Template
//! Distribution Protocol has no `SubmitSolution.Error`, so the only trace is a
//! `-debug=sv2` log line.
//!
//! None of this is in the library: a miner never builds a coinbase.

use avian_sv2::block::sha256d;
use avian_sv2::error::{Error, Result};
use avian_sv2::wire::Writer;

use crate::tdp::Template;

/// The BIP141 witness reserved value: the single 32-byte zero item the node
/// requires as `vin[0]`'s whole witness stack.
const WITNESS_RESERVED_VALUE: [u8; 32] = [0u8; 32];

/// The longest operator tag that always fits.
///
/// The node requires a scriptSig of 2 to 100 bytes beginning with
/// `coinbase_prefix`. That prefix is the BIP34 height push, so it is 2 bytes
/// below height 128 and grows to 5 at the top of the range, and this pool adds
/// 8 bytes of extranonce. 100 - 5 - 8 leaves 87, and taking the worst case
/// rather than the current height means a tag accepted at configuration time
/// cannot start failing years later.
pub const MAX_COINBASE_TAG: usize = 87;

/// Where a block's spendable value goes.
///
/// On a solo pool the worker's own address takes it, so this is the money and
/// it comes from the channel rather than from configuration. The fee output is
/// the operator's and defaults to nothing.
#[derive(Debug, Clone, Default)]
pub struct PayoutPlan {
    pub worker_script: Vec<u8>,
    /// Empty for no operator fee.
    pub fee_script: Vec<u8>,
    /// Hundredths of a percent. Zero for no operator fee.
    pub fee_basis_points: u32,
}

/// One output the pool adds, ahead of the template's required ones.
#[derive(Debug, Clone)]
pub struct PoolOutput {
    pub value: u64,
    pub script: Vec<u8>,
}

impl PayoutPlan {
    pub fn solo(worker_script: Vec<u8>) -> Self {
        Self {
            worker_script,
            fee_script: Vec::new(),
            fee_basis_points: 0,
        }
    }

    /// Splits the spendable value between the worker and the operator.
    ///
    /// The fee is truncated down, so the worker is never short-changed by
    /// rounding, and the two always sum to exactly `value_remaining`: a
    /// coinbase that paid out less would silently burn the difference.
    ///
    /// A fee that rounds to zero produces no output at all rather than a
    /// zero-value one, which would be dust the node has no reason to accept.
    pub fn outputs(&self, value_remaining: u64) -> Vec<PoolOutput> {
        let fee = if self.fee_script.is_empty() || self.fee_basis_points == 0 {
            0
        } else {
            // u128 so a large subsidy times 10000 cannot overflow.
            ((value_remaining as u128 * self.fee_basis_points as u128) / 10_000) as u64
        };
        let mut outputs = vec![PoolOutput {
            value: value_remaining - fee,
            script: self.worker_script.clone(),
        }];
        if fee > 0 {
            outputs.push(PoolOutput {
                value: fee,
                script: self.fee_script.clone(),
            });
        }
        outputs
    }
}

/// A coinbase built the way the Template Provider says to build one.
pub struct Coinbase {
    /// Serialized with the witness, which is what `SubmitSolution` carries.
    pub with_witness: Vec<u8>,
    /// Serialized without it, which is what the txid hashes.
    pub without_witness: Vec<u8>,
    pub txid: [u8; 32],
}

impl Coinbase {
    /// Builds the coinbase for a template.
    ///
    /// `outputs` are the pool's own, which go **before** the template's
    /// required ones so the witness commitment stays the highest-indexed
    /// output. `tag` is the operator's label and `extranonce` distinguishes
    /// channels; both go in the scriptSig after `coinbase_prefix`, which the
    /// node requires the scriptSig to start with.
    pub fn build(
        template: &Template,
        outputs: &[PoolOutput],
        tag: &[u8],
        extranonce: &[u8],
    ) -> Result<Self> {
        if outputs.is_empty() {
            return Err(Error::Protocol(
                "a coinbase needs at least one output".into(),
            ));
        }
        let paid: u64 = outputs.iter().map(|output| output.value).sum();
        // Must be exact. Paying less is legal but burns the difference, and a
        // pool that quietly burned part of a block would be a bug nobody
        // noticed for a long time.
        if paid != template.coinbase_tx_value_remaining {
            return Err(Error::Protocol(format!(
                "the pool's outputs pay {paid} and coinbase_tx_value_remaining is {}",
                template.coinbase_tx_value_remaining
            )));
        }

        let script_sig_len = template.coinbase_prefix.len() + tag.len() + extranonce.len();
        if !(2..=100).contains(&script_sig_len) {
            return Err(Error::Protocol(format!(
                "a coinbase scriptSig is 2 to 100 bytes and this one is {script_sig_len}; the \
                 operator tag is {} bytes",
                tag.len()
            )));
        }

        // The pool's outputs take coinbase_tx_value_remaining, which
        // doc/sv2.md says is already net of the founder payment, so nothing is
        // subtracted here. The founder output is one of the required outputs
        // and is copied verbatim below.
        let mut writer = Writer::new();
        for output in outputs {
            writer
                .u64(output.value)
                .varint(output.script.len() as u64)
                .raw(&output.script);
        }
        let pool_outputs = writer.finish();

        let output_count = outputs.len() as u64 + template.coinbase_tx_outputs_count as u64;

        let input = |w: &mut Writer| {
            w.raw(&[0u8; 32]) // null prevout hash
                .u32(0xffff_ffff) // null prevout index
                .varint(script_sig_len as u64)
                .raw(&template.coinbase_prefix)
                .raw(tag)
                .raw(extranonce)
                .u32(template.coinbase_tx_input_sequence);
        };

        let mut without = Writer::new();
        without.u32(template.coinbase_tx_version).varint(1);
        input(&mut without);
        without.varint(output_count);
        without.raw(&pool_outputs);
        // Every output in coinbase_tx_outputs, verbatim and in order. They
        // arrive concatenated with no count of their own, which is why the
        // count is a separate field, and the witness commitment is the
        // highest-indexed of them because consensus reads the last one.
        without.raw(&template.coinbase_tx_outputs);
        without.u32(template.coinbase_tx_locktime);
        let without_witness = without.finish();

        let mut with = Writer::new();
        with.u32(template.coinbase_tx_version)
            // BIP144 marker and flag, then the input count.
            .u8(0x00)
            .u8(0x01)
            .varint(1);
        input(&mut with);
        with.varint(output_count).raw(&pool_outputs);
        with.raw(&template.coinbase_tx_outputs);
        // One witness stack, one item, the 32 reserved zero bytes.
        with.varint(1)
            .varint(WITNESS_RESERVED_VALUE.len() as u64)
            .raw(&WITNESS_RESERVED_VALUE);
        with.u32(template.coinbase_tx_locktime);
        let with_witness = with.finish();

        Ok(Self {
            txid: sha256d(&[&without_witness]),
            with_witness,
            without_witness,
        })
    }
}

/// Folds the template's merkle path onto the coinbase txid.
///
/// The coinbase is always the leftmost leaf, so every sibling in the path is a
/// right-hand one and the order never varies.
pub fn merkle_root(coinbase_txid: &[u8; 32], path: &[[u8; 32]]) -> [u8; 32] {
    let mut current = *coinbase_txid;
    for sibling in path {
        current = sha256d(&[&current, sibling]);
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_solo_plan_pays_the_whole_value_to_the_worker() {
        let plan = PayoutPlan::solo(vec![0x51]);
        let outputs = plan.outputs(5_000_000_000);
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].value, 5_000_000_000);
        assert_eq!(outputs[0].script, vec![0x51]);
    }

    #[test]
    fn a_fee_is_taken_from_the_worker_and_the_two_sum_exactly() {
        let plan = PayoutPlan {
            worker_script: vec![0x51],
            fee_script: vec![0x52],
            fee_basis_points: 100, // one per cent
        };
        let outputs = plan.outputs(5_000_000_000);
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[1].value, 50_000_000);
        assert_eq!(outputs[0].value, 4_950_000_000);
        assert_eq!(
            outputs.iter().map(|o| o.value).sum::<u64>(),
            5_000_000_000,
            "nothing may be burned by rounding"
        );
        // The worker's output is first, so the witness commitment stays the
        // highest-indexed output once the required ones follow.
        assert_eq!(outputs[0].script, vec![0x51]);
    }

    #[test]
    fn a_fee_that_rounds_to_nothing_produces_no_output() {
        let plan = PayoutPlan {
            worker_script: vec![0x51],
            fee_script: vec![0x52],
            fee_basis_points: 1,
        };
        // 1 basis point of 9999 is 0.9999, which truncates to nothing.
        let outputs = plan.outputs(9_999);
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].value, 9_999);
    }

    #[test]
    fn a_fee_with_no_script_is_no_fee() {
        let plan = PayoutPlan {
            worker_script: vec![0x51],
            fee_script: Vec::new(),
            fee_basis_points: 10_000,
        };
        let outputs = plan.outputs(1_000);
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].value, 1_000);
    }

    #[test]
    fn a_fee_cannot_overflow_on_a_large_subsidy() {
        let plan = PayoutPlan {
            worker_script: vec![0x51],
            fee_script: vec![0x52],
            fee_basis_points: 10_000,
        };
        let outputs = plan.outputs(u64::MAX);
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[1].value, u64::MAX);
        assert_eq!(outputs[0].value, 0);
    }

    #[test]
    fn an_empty_path_leaves_the_coinbase_txid_as_the_root() {
        let txid = [7u8; 32];
        assert_eq!(merkle_root(&txid, &[]), txid);
    }

    #[test]
    fn the_coinbase_is_always_the_left_leaf() {
        let txid = [1u8; 32];
        let sibling = [2u8; 32];
        assert_eq!(
            merkle_root(&txid, &[sibling]),
            sha256d(&[&txid, &sibling]),
            "the sibling must be concatenated on the right"
        );
    }
}
