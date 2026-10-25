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

/// The scriptSig bounds the node enforces.
pub const MIN_SCRIPT_SIG: usize = 2;
pub const MAX_SCRIPT_SIG: usize = 100;

/// The worst case BIP34 height push: a four-byte minimally-encoded height and
/// its length byte.
///
/// It is 2 bytes below height 128 today. Budgeting for the worst case rather
/// than the current height means a tag accepted at configuration time cannot
/// start failing years later.
pub const MAX_HEIGHT_PUSH: usize = 5;

/// A standard channel's extranonce: the channel id and the job id.
///
/// The pool builds the whole coinbase there, so the worker never sees this as
/// search space; it exists so two channels never hash the same header.
pub const STANDARD_EXTRANONCE: usize = 8;

/// An extended channel's extranonce prefix, which is the pool's half.
///
/// The channel id, so two channels cannot collide however the miner rolls its
/// own half.
pub const EXTENDED_EXTRANONCE_PREFIX: usize = 4;

/// An extended channel's extranonce, which is the miner's half and is the
/// search space the channel exists to give it.
pub const EXTENDED_EXTRANONCE_SIZE: usize = 8;

/// The longest operator tag that always fits, whichever kind of channel it
/// ends up on.
///
/// The scriptSig has three claimants and a hard 100-byte ceiling: the BIP34
/// height push, this tag, and the extranonce. An extended channel's extranonce
/// is the larger of the two at 12 bytes, so that is the one to budget for:
/// 100 - 5 - 12 leaves 83. It was 87 while only standard channels existed and
/// the extranonce was a fixed 8; extended channels take four more for the
/// pool's prefix, so the cap tightens rather than the coinbase overflowing.
pub const MAX_COINBASE_TAG: usize =
    MAX_SCRIPT_SIG - MAX_HEIGHT_PUSH - (EXTENDED_EXTRANONCE_PREFIX + EXTENDED_EXTRANONCE_SIZE);

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
    /// Builds the whole coinbase for a template, witness included.
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
        let parts = Parts::new(template, outputs, tag, extranonce.len())?;

        let mut without = Vec::new();
        without.extend_from_slice(&parts.prefix);
        without.extend_from_slice(extranonce);
        without.extend_from_slice(&parts.suffix);

        Ok(Self {
            txid: sha256d(&[&without]),
            with_witness: add_witness(&without),
            without_witness: without,
        })
    }

    /// Builds the coinbase split an extended channel hands down.
    ///
    /// `extranonce_len` is the total the scriptSig will reserve: the pool's
    /// prefix plus whatever the miner may use. It has to be fixed now, because
    /// it is baked into the scriptSig length byte inside `prefix`.
    pub fn split(
        template: &Template,
        outputs: &[PoolOutput],
        tag: &[u8],
        extranonce_len: usize,
    ) -> Result<CoinbaseSplit> {
        let parts = Parts::new(template, outputs, tag, extranonce_len)?;
        Ok(CoinbaseSplit {
            prefix: parts.prefix,
            suffix: parts.suffix,
            extranonce_len,
        })
    }
}

/// The two halves of the unwitnessed serialization, which both the whole
/// coinbase and the split are assembled from.
///
/// Sharing them is the point: a standard channel's coinbase and an extended
/// channel's split cannot disagree about the bytes, because there is only one
/// piece of code that writes them.
struct Parts {
    prefix: Vec<u8>,
    suffix: Vec<u8>,
}

impl Parts {
    fn new(
        template: &Template,
        outputs: &[PoolOutput],
        tag: &[u8],
        extranonce_len: usize,
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

        let script_sig_len = template.coinbase_prefix.len() + tag.len() + extranonce_len;
        if !(MIN_SCRIPT_SIG..=MAX_SCRIPT_SIG).contains(&script_sig_len) {
            return Err(Error::Protocol(format!(
                "a coinbase scriptSig is {MIN_SCRIPT_SIG} to {MAX_SCRIPT_SIG} bytes and this \
                 one is {script_sig_len}: a {}-byte height push, a {}-byte operator tag and \
                 {extranonce_len} bytes of extranonce",
                template.coinbase_prefix.len(),
                tag.len()
            )));
        }

        let mut prefix = Writer::new();
        prefix
            .u32(template.coinbase_tx_version)
            .varint(1)
            .raw(&[0u8; 32]) // null prevout hash
            .u32(0xffff_ffff) // null prevout index
            // The length counts the extranonce that is not here yet.
            .varint(script_sig_len as u64)
            .raw(&template.coinbase_prefix)
            .raw(tag);
        let prefix = prefix.finish();

        let mut suffix = Writer::new();
        suffix
            .u32(template.coinbase_tx_input_sequence)
            .varint(outputs.len() as u64 + template.coinbase_tx_outputs_count as u64);
        for output in outputs {
            suffix
                .u64(output.value)
                .varint(output.script.len() as u64)
                .raw(&output.script);
        }
        // Every output in coinbase_tx_outputs, verbatim and in order. They
        // arrive concatenated with no count of their own, which is why the
        // count is a separate field, and the witness commitment is the
        // highest-indexed of them because consensus reads the last one.
        suffix
            .raw(&template.coinbase_tx_outputs)
            .u32(template.coinbase_tx_locktime);
        let suffix = suffix.finish();

        Ok(Self { prefix, suffix })
    }
}

/// A coinbase cut in two around the extranonce, **without witness data**.
///
/// This is what an extended channel hands a miner: it inserts its own
/// extranonce between the halves, hashes the three together into a txid, and
/// folds the merkle path itself. Having seen the suffix it can also see every
/// output it is committing to, which is the whole reason extended channels
/// exist and the reason a solo miner should prefer one.
///
/// # Why the missing witness is not a problem
///
/// Stratum v2 defines `coinbase_tx_prefix` and `coinbase_tx_suffix` without
/// the BIP141 marker, flag or witness, while Avian's node requires a specific
/// witness stack and a canonical byte-for-byte reconstruction. doc/sv2.md
/// deferred extended channels over that apparent conflict. It reconciles,
/// because the two requirements never meet:
///
/// - A merkle root is built from **txids**, and a txid excludes witness data.
///   `solution_check.cpp` hashes the coinbase with `GetHash()`, which is the
///   txid, and folds that. So the miner's arithmetic never involves the
///   witness and cannot be affected by its absence.
/// - The canonical re-serialization check applies to what
///   **`SubmitSolution` carries**, which the pool assembles in full, witness
///   included. The miner never submits a coinbase.
/// - The witness commitment is one of the template's required outputs, copied
///   verbatim into the suffix, and commits to the witness root of the other
///   transactions plus the coinbase's own fixed all-zero witness. The
///   extranonce is in the scriptSig and changes none of that.
///
/// Proved against a live node rather than argued: see
/// `tests/extended_coinbase.rs`, which mines a block the extended way and has
/// the node accept it.
#[derive(Debug, Clone)]
pub struct CoinbaseSplit {
    /// Everything up to the extranonce, including the scriptSig length byte,
    /// which already accounts for the extranonce that is not there yet.
    pub prefix: Vec<u8>,
    /// Everything after the extranonce. Carries the outputs, so a miner can
    /// read what it is committing to.
    pub suffix: Vec<u8>,
    /// How many extranonce bytes the prefix's scriptSig length allows for.
    /// Anything else makes the scriptSig length wrong and the coinbase
    /// malformed.
    pub extranonce_len: usize,
}

impl CoinbaseSplit {
    /// The coinbase without witness, which is what the txid hashes.
    pub fn assemble(&self, extranonce: &[u8]) -> Result<Vec<u8>> {
        if extranonce.len() != self.extranonce_len {
            return Err(Error::Protocol(format!(
                "this split expects {} extranonce bytes and was given {}",
                self.extranonce_len,
                extranonce.len()
            )));
        }
        let mut out = Vec::with_capacity(self.prefix.len() + extranonce.len() + self.suffix.len());
        out.extend_from_slice(&self.prefix);
        out.extend_from_slice(extranonce);
        out.extend_from_slice(&self.suffix);
        Ok(out)
    }

    /// The coinbase txid for an extranonce, which is what a miner folds the
    /// merkle path onto.
    pub fn txid(&self, extranonce: &[u8]) -> Result<[u8; 32]> {
        Ok(sha256d(&[&self.assemble(extranonce)?]))
    }

    /// The whole coinbase, witness included, which is what `SubmitSolution`
    /// carries.
    ///
    /// The pool's side of an extended channel: it reassembles what the miner
    /// hashed and adds the witness the miner never saw. Needs nothing but the
    /// split, so a job does not have to retain its template.
    pub fn assemble_with_witness(&self, extranonce: &[u8]) -> Result<Vec<u8>> {
        Ok(add_witness(&self.assemble(extranonce)?))
    }
}

/// Splices the BIP144 marker, flag and witness into an unwitnessed coinbase.
///
/// The marker and flag go after the four-byte version; the witness goes before
/// the four-byte locktime. One implementation, used by the whole-coinbase path
/// and the extended-channel one, so the two cannot disagree about the bytes
/// the node re-serializes and compares.
fn add_witness(without: &[u8]) -> Vec<u8> {
    let mut witness = Writer::new();
    // One witness stack, one item, the 32 reserved zero bytes.
    let witness = witness
        .varint(1)
        .varint(WITNESS_RESERVED_VALUE.len() as u64)
        .raw(&WITNESS_RESERVED_VALUE)
        .finish();

    let mut out = Vec::with_capacity(without.len() + witness.len() + 2);
    out.extend_from_slice(&without[..4]);
    out.extend_from_slice(&[0x00, 0x01]);
    out.extend_from_slice(&without[4..without.len() - 4]);
    out.extend_from_slice(&witness);
    out.extend_from_slice(&without[without.len() - 4..]);
    out
}

/// Folds the template's merkle path onto the coinbase txid.
///
/// Re-exported from the library, where it lives because a miner on an
/// extended channel folds the same path onto a coinbase it assembled itself.
pub use avian_sv2::block::merkle_root;

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

#[cfg(test)]
mod split_tests {
    use super::*;
    use avian_sv2::wire::hex;

    fn template() -> Template {
        Template {
            template_id: 1,
            future_template: false,
            version: 0x3200_0000,
            coinbase_tx_version: 2,
            // The BIP34 height push for height 102.
            coinbase_prefix: vec![0x01, 0x66],
            coinbase_tx_input_sequence: 0xffff_fffe,
            coinbase_tx_value_remaining: 237_500_000_000,
            coinbase_tx_outputs_count: 2,
            // Two plausible required outputs: a founder payment and a witness
            // commitment.
            coinbase_tx_outputs: {
                let mut w = avian_sv2::wire::Writer::new();
                w.u64(1_000)
                    .varint(25)
                    .raw(&[0x76, 0xa9, 0x14])
                    .raw(&[0xab; 20])
                    .raw(&[0x88, 0xac])
                    .u64(0)
                    .varint(38)
                    .raw(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed])
                    .raw(&[0xcd; 32])
                    .finish()
            },
            coinbase_tx_locktime: 102,
            merkle_path: vec![[0x11; 32], [0x22; 32]],
        }
    }

    fn outputs() -> Vec<PoolOutput> {
        PayoutPlan::solo(vec![0x51]).outputs(237_500_000_000)
    }

    /// The whole point: the split and the full build must agree on the txid.
    ///
    /// If they ever diverge, a miner on an extended channel would fold a
    /// merkle root the node will not reproduce, and every share would be
    /// refused for a reason that looks like bad proof of work.
    #[test]
    fn the_split_and_the_whole_coinbase_agree_on_the_txid() {
        let template = template();
        let tag = b"/avian-sv2/";
        for extranonce in [
            vec![0u8; 8],
            vec![0xffu8; 12],
            (0..12u8).collect::<Vec<u8>>(),
        ] {
            let whole = Coinbase::build(&template, &outputs(), tag, &extranonce).unwrap();
            let split = Coinbase::split(&template, &outputs(), tag, extranonce.len()).unwrap();
            assert_eq!(
                hex(&split.assemble(&extranonce).unwrap()),
                hex(&whole.without_witness),
                "the unwitnessed bytes must match for a {}-byte extranonce",
                extranonce.len()
            );
            assert_eq!(split.txid(&extranonce).unwrap(), whole.txid);
        }
    }

    /// A miner changing its extranonce changes the txid and nothing else.
    #[test]
    fn the_extranonce_is_the_only_thing_a_miner_moves() {
        let template = template();
        let split = Coinbase::split(&template, &outputs(), b"/tag/", 12).unwrap();
        let a = split.assemble(&[0u8; 12]).unwrap();
        let b = split.assemble(&[1u8; 12]).unwrap();
        assert_eq!(a.len(), b.len());
        let differing = a.iter().zip(&b).filter(|(x, y)| x != y).count();
        assert_eq!(differing, 12, "only the extranonce bytes may differ");
        assert_ne!(
            split.txid(&[0u8; 12]).unwrap(),
            split.txid(&[1u8; 12]).unwrap()
        );
    }

    /// The suffix carries the outputs, which is what lets a miner see what it
    /// is committing to.
    #[test]
    fn the_suffix_carries_every_output_including_the_commitment() {
        let template = template();
        let split = Coinbase::split(&template, &outputs(), b"", 12).unwrap();
        assert!(
            split
                .suffix
                .windows(4)
                .any(|w| w == [0xaa, 0x21, 0xa9, 0xed]),
            "the witness commitment must be visible in the suffix"
        );
        assert!(
            split
                .suffix
                .windows(template.coinbase_tx_outputs.len())
                .any(|w| w == template.coinbase_tx_outputs),
            "the required outputs must be in the suffix verbatim"
        );
        // And the payout script, so the miner can check it is being paid.
        assert!(split.suffix.windows(1).any(|w| w == [0x51]));
    }

    #[test]
    fn a_wrong_length_extranonce_is_refused_rather_than_silently_wrong() {
        let split = Coinbase::split(&template(), &outputs(), b"", 12).unwrap();
        assert!(split.assemble(&[0u8; 11]).is_err());
        assert!(split.assemble(&[0u8; 13]).is_err());
        assert!(split.assemble(&[0u8; 12]).is_ok());
    }

    #[test]
    fn the_tag_cap_leaves_room_for_the_larger_extranonce() {
        // The cap has to hold for an extended channel, which takes the most.
        let template = template();
        let tag = vec![b'x'; MAX_COINBASE_TAG];
        assert!(Coinbase::split(
            &template,
            &outputs(),
            &tag,
            EXTENDED_EXTRANONCE_PREFIX + EXTENDED_EXTRANONCE_SIZE
        )
        .is_ok());
        assert!(Coinbase::build(&template, &outputs(), &tag, &[0u8; STANDARD_EXTRANONCE]).is_ok());

        // And one byte more does not, once the worst-case height push is
        // allowed for. This template's push is 2 rather than 5, so the
        // arithmetic is checked directly.
        assert_eq!(
            MAX_COINBASE_TAG,
            MAX_SCRIPT_SIG
                - MAX_HEIGHT_PUSH
                - (EXTENDED_EXTRANONCE_PREFIX + EXTENDED_EXTRANONCE_SIZE)
        );
        let over = vec![b'x'; MAX_SCRIPT_SIG];
        assert!(Coinbase::split(&template, &outputs(), &over, 12).is_err());
    }

    /// The witnessed form differs from the unwitnessed one only by the marker,
    /// the flag and the witness, which is what BIP144 says and what the node's
    /// canonical check re-serializes.
    #[test]
    fn the_witnessed_form_is_the_unwitnessed_one_plus_bip144() {
        let whole = Coinbase::build(&template(), &outputs(), b"/t/", &[7u8; 12]).unwrap();
        let bare = &whole.without_witness;
        let full = &whole.with_witness;
        assert_eq!(&full[..4], &bare[..4], "the version is unchanged");
        assert_eq!(&full[4..6], &[0x00, 0x01], "then the marker and flag");
        assert_eq!(
            &full[6..6 + bare.len() - 8],
            &bare[4..bare.len() - 4],
            "then the body unchanged"
        );
        // The witness, then the locktime.
        assert_eq!(
            &full[full.len() - 4..],
            &bare[bare.len() - 4..],
            "the locktime stays last"
        );
        let witness_start = 6 + bare.len() - 8;
        assert_eq!(
            &full[witness_start..full.len() - 4],
            &[&[0x01, 0x20][..], &[0u8; 32][..]].concat(),
            "one stack, one 32-byte zero item"
        );
    }
}
