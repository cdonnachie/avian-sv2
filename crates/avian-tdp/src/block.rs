//! What a pool has to build, and what the node checks before it will hash.
//!
//! On a standard mining channel the pool builds the coinbase, not the worker,
//! so every rule in doc/sv2.md's "What a client must reproduce" is the pool's
//! obligation to the node. The node rebuilds the header from the template and
//! the submitted coinbase and re-serializes it for a byte comparison, so a
//! coinbase that differs anywhere is refused before any proof of work is
//! computed — and the Template Distribution Protocol has no
//! `SubmitSolution.Error`, so the only trace is a `-debug=sv2` log line.

use secp256k1::hashes::{sha256, Hash, HashEngine};

use crate::error::{Error, Result};
use crate::tdp::Template;
use crate::wire::Writer;

/// Bitcoin's double SHA256, in its natural byte order. A block hash or txid is
/// displayed with these bytes reversed.
pub fn sha256d(parts: &[&[u8]]) -> [u8; 32] {
    let mut engine = sha256::Hash::engine();
    for part in parts {
        engine.input(part);
    }
    let first = sha256::Hash::from_engine(engine).to_byte_array();
    sha256::Hash::hash(&first).to_byte_array()
}

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

/// The 80 bytes a proof-of-work hash is computed over.
pub fn header(
    version: u32,
    prev_hash: &[u8; 32],
    merkle_root: &[u8; 32],
    ntime: u32,
    nbits: u32,
    nonce: u32,
) -> [u8; 80] {
    let mut writer = Writer::new();
    let bytes = writer
        .u32(version)
        .raw(prev_hash)
        .raw(merkle_root)
        .u32(ntime)
        .u32(nbits)
        .u32(nonce)
        .finish();
    let mut out = [0u8; 80];
    out.copy_from_slice(&bytes);
    out
}

/// Whether a proof-of-work hash is at or under a target.
///
/// Both are 32 bytes in `uint256`'s internal order, which is little-endian, so
/// the comparison runs from the most significant byte down. `aviand` compares
/// `UintToArith256(hash) > bnTarget`, so equality passes.
pub fn meets_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        match hash[i].cmp(&target[i]) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    true
}

/// Divides a target by a power of two, making it that many times harder.
///
/// Used to set a share target below the network target. Shifting rather than
/// dividing keeps this exact and keeps the result a valid `uint256`.
pub fn harder_by(target: &[u8; 32], shift: u32) -> [u8; 32] {
    // Work most-significant first, which is index 31 downwards.
    let mut big = [0u8; 32];
    for i in 0..32 {
        big[i] = target[31 - i];
    }
    for _ in 0..shift {
        let mut carry = 0u8;
        for byte in big.iter_mut() {
            let next = (*byte & 1) << 7;
            *byte = (*byte >> 1) | carry;
            carry = next;
        }
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = big[31 - i];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256d_matches_a_known_digest() {
        // SHA256d of the empty string.
        assert_eq!(
            crate::wire::hex(&sha256d(&[b""])),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
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

    #[test]
    fn a_header_is_eighty_bytes_in_field_order() {
        let bytes = header(0x3200_0000, &[0xaa; 32], &[0xbb; 32], 1, 2, 3);
        assert_eq!(bytes.len(), 80);
        assert_eq!(&bytes[0..4], &0x3200_0000u32.to_le_bytes());
        assert_eq!(&bytes[4..36], &[0xaa; 32]);
        assert_eq!(&bytes[36..68], &[0xbb; 32]);
        assert_eq!(&bytes[68..72], &1u32.to_le_bytes());
    }

    #[test]
    fn a_target_is_compared_as_a_little_endian_integer() {
        let mut target = [0u8; 32];
        target[31] = 0x7f;
        let mut under = [0u8; 32];
        under[31] = 0x7e;
        let mut over = [0u8; 32];
        over[31] = 0x80;

        assert!(meets_target(&under, &target));
        assert!(meets_target(&target, &target), "equality passes");
        assert!(!meets_target(&over, &target));

        // A difference in a low-order byte must not outrank a high-order one.
        let mut low_byte_big = [0u8; 32];
        low_byte_big[0] = 0xff;
        low_byte_big[31] = 0x7e;
        assert!(meets_target(&low_byte_big, &target));
    }

    #[test]
    fn harder_by_shifts_the_whole_integer() {
        let mut target = [0u8; 32];
        target[31] = 0x7f;
        target[30] = 0xff;
        let once = harder_by(&target, 1);
        assert_eq!(once[31], 0x3f);
        assert_eq!(once[30], 0xff);
        assert!(meets_target(&once, &target), "harder is still under");
        assert!(!meets_target(&target, &once));
        assert_eq!(harder_by(&target, 0), target);
    }
}
