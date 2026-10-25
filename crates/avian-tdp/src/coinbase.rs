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
    /// `extranonce` is appended to `coinbase_prefix` in the scriptSig, which
    /// is the only part of the coinbase a pool may vary per worker. The node
    /// requires a scriptSig of 2 to 100 bytes beginning with
    /// `coinbase_prefix`, which is the BIP34 height push.
    pub fn build(template: &Template, payout_script: &[u8], extranonce: &[u8]) -> Result<Self> {
        let script_sig_len = template.coinbase_prefix.len() + extranonce.len();
        if !(2..=100).contains(&script_sig_len) {
            return Err(Error::Protocol(format!(
                "a coinbase scriptSig is 2 to 100 bytes and this one is {script_sig_len}"
            )));
        }

        // The payout takes coinbase_tx_value_remaining, which doc/sv2.md says
        // is already net of the founder payment, so nothing is subtracted
        // here. The founder output is one of the required outputs and is
        // copied verbatim below.
        let mut outputs = Writer::new();
        outputs
            .u64(template.coinbase_tx_value_remaining)
            .varint(payout_script.len() as u64)
            .raw(payout_script);
        let payout = outputs.finish();

        let output_count = 1 + template.coinbase_tx_outputs_count as u64;

        let input = |w: &mut Writer| {
            w.raw(&[0u8; 32]) // null prevout hash
                .u32(0xffff_ffff) // null prevout index
                .varint(script_sig_len as u64)
                .raw(&template.coinbase_prefix)
                .raw(extranonce)
                .u32(template.coinbase_tx_input_sequence);
        };

        let mut without = Writer::new();
        without.u32(template.coinbase_tx_version).varint(1);
        input(&mut without);
        without.varint(output_count);
        without.raw(&payout);
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
        with.varint(output_count).raw(&payout);
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
