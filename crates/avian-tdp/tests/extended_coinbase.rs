//! Does the extended-channel coinbase split actually work against `aviand`?
//!
//! doc/sv2.md deferred extended channels over an apparent conflict: Stratum v2
//! defines `coinbase_tx_prefix` and `coinbase_tx_suffix` **without** the BIP141
//! marker, flag or witness data, while Avian's node requires a specific witness
//! stack and a canonical byte-for-byte reconstruction. If a miner cannot
//! compute a merkle root the node will reproduce without the witness, extended
//! channels are impossible and everything built on them is wasted.
//!
//! The claim is that the two requirements never meet, because a merkle root is
//! built from txids and a txid excludes witness data. `solution_check.cpp`
//! supports that in source — it hashes the coinbase with `GetHash()`, the
//! txid, and folds the merkle path onto it — but the node is the only thing
//! that settles it.
//!
//! So this test mines a block the extended way and has the node accept it:
//!
//! 1. the pool splits its coinbase around the extranonce, **without witness**
//! 2. a miner that has only the two halves inserts its extranonce, hashes the
//!    three together into a txid and folds the merkle path itself
//! 3. the miner searches nonces against the header it built
//! 4. the pool reconstructs the whole coinbase **with** the witness and
//!    submits that
//!
//! The merkle path is deliberately non-empty: a block with only a coinbase
//! would make the fold a no-op and prove far less.

use std::time::{Duration, Instant};

use avian_regtest::Node;
use avian_sv2::avian::PowType;
use avian_sv2::{block, wire};
use avian_tdp::coinbase::{
    Coinbase, PayoutPlan, EXTENDED_EXTRANONCE_PREFIX, EXTENDED_EXTRANONCE_SIZE,
};
use avian_tdp::{SessionConfig, TdpSession};

/// A regtest address from a real node, with the script it means.
const WORKER_ADDRESS: &str = "mnPBEVKjU1zz9214C7M7Zp4FuurUAsU6ZS";

fn worker_script() -> Vec<u8> {
    avian_sv2::address::Address::decode(WORKER_ADDRESS, avian_sv2::address::Network::Regtest)
        .expect("the address should decode")
        .script_pubkey()
}

#[test]
fn a_miner_with_only_prefix_and_suffix_can_mine_a_block_the_node_accepts() {
    let Some(node) = Node::start("extended-coinbase", 50, &[]) else {
        eprintln!("skipping: aviand or avian-cli not found");
        return;
    };
    node.mine(101);

    let address = node.rpc(&["getnewaddress"]).expect("getnewaddress");

    for pow in [PowType::X16rt, PowType::MinotaurX] {
        // A transaction in the mempool, so the template has a real merkle path
        // and the fold is doing work. Without this the path is empty and the
        // test would pass even if folding were broken. One per algorithm,
        // because the previous pass mined the last one into a block.
        let funded = node
            .rpc(&["sendtoaddress", &address, "1.0"])
            .expect("sendtoaddress");
        eprintln!("[test] {pow}: mempool transaction {funded}");

        let before = node.height();
        let mut config = SessionConfig::new(node.sv2_addr(), pow);
        config.authority = Some(node.authority());
        config.timeout = Duration::from_secs(30);
        let mut session = TdpSession::open(&config).expect("session");
        let submitter = session.submitter();

        // Read rounds until one has a transaction in it. The node refreshes on
        // an interval, and the first template may predate the mempool entry.
        let deadline = Instant::now() + Duration::from_secs(60);
        let work = loop {
            assert!(
                Instant::now() < deadline,
                "no template included a transaction"
            );
            let work = session.next_work().expect("work");
            if !work.template.merkle_path.is_empty() {
                break work;
            }
        };
        let prev = work.prev_hash.as_ref().expect("SetNewPrevHash").clone();
        assert!(
            !work.template.merkle_path.is_empty(),
            "the merkle path must be non-empty for this test to prove anything"
        );
        eprintln!(
            "[test] {pow} template {} with a {}-hash merkle path",
            work.template.template_id,
            work.template.merkle_path.len()
        );

        // --- the pool's side: split, without witness ---
        let outputs =
            PayoutPlan::solo(worker_script()).outputs(work.template.coinbase_tx_value_remaining);
        let tag = b"/extended/";
        let extranonce_len = EXTENDED_EXTRANONCE_PREFIX + EXTENDED_EXTRANONCE_SIZE;
        let split = Coinbase::split(&work.template, &outputs, tag, extranonce_len)
            .expect("the split should build");
        assert!(
            !split.prefix.windows(2).any(|w| w == [0x00, 0x01])
                || !split
                    .prefix
                    .starts_with(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            "the prefix must not carry a BIP144 marker and flag"
        );

        // --- the miner's side: only the two halves and the path ---
        let mut extranonce = vec![0u8; extranonce_len];
        // The pool's half, then the miner's.
        extranonce[..EXTENDED_EXTRANONCE_PREFIX].copy_from_slice(&7u32.to_le_bytes());

        // What extended channels are for: the miner can read the outputs it is
        // committing to out of the suffix it was given.
        assert!(
            split
                .suffix
                .windows(worker_script().len())
                .any(|w| w == worker_script()),
            "a miner must be able to see its own payout output in the suffix"
        );

        let mut found = None;
        'search: for counter in 0..4_000u64 {
            extranonce[EXTENDED_EXTRANONCE_PREFIX..]
                .copy_from_slice(&counter.to_le_bytes()[..EXTENDED_EXTRANONCE_SIZE]);
            // The miner's own arithmetic: txid from the three pieces, then the
            // merkle root. No witness anywhere.
            let txid = split.txid(&extranonce).expect("txid");
            let merkle_root = avian_tdp::coinbase::merkle_root(&txid, &work.template.merkle_path);

            for nonce in 0..64u32 {
                let header = block::header(
                    work.template.version,
                    &prev.prev_hash,
                    &merkle_root,
                    work.constraints.ntime_min,
                    prev.nbits,
                    nonce,
                );
                let hasher = match pow {
                    PowType::X16rt => avian_pow::PowType::X16rt,
                    PowType::MinotaurX => avian_pow::PowType::MinotaurX,
                };
                let hash = avian_pow::hash(hasher, &header).expect("the hasher");
                if block::meets_target(&hash, &prev.target) {
                    found = Some((extranonce.clone(), nonce, merkle_root));
                    break 'search;
                }
            }
        }
        let (extranonce, nonce, miner_root) = found.expect("a nonce should be found on regtest");

        // --- the pool's side again: the whole coinbase, witness included ---
        let whole = Coinbase::build(&work.template, &outputs, tag, &extranonce)
            .expect("the whole coinbase should build");
        // The miner's root, computed without ever seeing the witness, must
        // equal the one the whole coinbase produces. This is the claim.
        assert_eq!(
            avian_tdp::coinbase::merkle_root(&whole.txid, &work.template.merkle_path),
            miner_root,
            "the miner's merkle root must match the pool's whole coinbase"
        );

        submitter
            .submit(
                work.template.template_id,
                work.template.version,
                work.constraints.ntime_min,
                nonce,
                &whole.with_witness,
            )
            .expect("submit");

        // Only the node settles it. There is no SubmitSolution.Error, so a
        // refused solution shows up as a tip that did not move.
        let deadline = Instant::now() + Duration::from_secs(30);
        while node.height() == before && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(
            node.height(),
            before + 1,
            "the node should have accepted a block mined from a witness-free split. \
             extranonce {}, nonce {nonce}. Its sv2 log:\n{}",
            wire::hex(&extranonce),
            node.sv2_log()
        );

        let tip = node.tip();
        assert_eq!(node.pow_type_of(&tip).as_deref(), Some(pow.name()));
        let block_json = node.rpc(&["getblock", &tip, "2"]).expect("getblock");
        assert!(
            block_json.contains(&wire::hex(&worker_script())),
            "the block must pay the worker"
        );
        // And the mempool transaction really was in it, which is what made the
        // merkle path non-trivial.
        assert!(
            block_json.contains(&funded),
            "the block should contain the mempool transaction {funded}"
        );
        eprintln!(
            "[test] {pow} block {tip} accepted, mined from a prefix/suffix split with a \
             {}-hash merkle path",
            work.template.merkle_path.len()
        );
    }
}
