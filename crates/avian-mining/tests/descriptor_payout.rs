//! A miner that gives a descriptor instead of an address is paid a fresh
//! address per block, and the pool remembers where it got to.
//!
//! The unit tests in avian-sv2 pin the derivation against what the node's
//! `deriveaddresses` prints. This is the other half: that a block the pool
//! actually submits pays that address, that the next block pays the next one,
//! and that the index survives in the ledger file for the pool's next start.
//! On regtest the share target is the network target, so every share is a
//! block and two of them take seconds.

// These tests hash, so they need the hashers the `pow` feature links.
#![cfg(feature = "pow")]

mod common;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use avian_mining::ledger::PayoutLedger;
use avian_mining::ratelimit::RateLimitConfig;
use avian_mining::stats::Snapshot;
use avian_regtest::Node;
use avian_sv2::address::{Descriptor, Network};
use avian_sv2::avian::PowType;
use avian_sv2::client::{Event, MiningClient};
use avian_sv2::wire::{hex, hex_rev};
use common::{find_share, Rig};

/// BIP32 test vector 1's m/0H key as a tpub: the key the unit tests derive
/// against the node with.
const TPUB: &str = "tpubD8eQVK4Kdxg3gHrF62jGP7dKVCoYiEB8dFSpuTawkL5YxTus5j5pf83vaKnii4bc6v2NVEy81P2gYrJczYne3QNNwMTS53p5uzDyHvnw2jm";

fn descriptor_text() -> String {
    format!("wpkh({TPUB}/0/*)")
}

fn scratch(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("avian-descriptor-{}-{name}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

/// Waits for the pool to say a share was a block, and returns its hash.
fn wait_block_found(miner: &mut MiningClient) -> [u8; 32] {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Some(Event::BlockFound {
            block_hash,
            confirmed: false,
            ..
        }) = common::poll_event(miner, Duration::from_millis(300))
        {
            return block_hash;
        }
    }
    panic!("the share should have been a block on regtest, and the pool should have said so");
}

#[test]
fn each_block_pays_the_next_address_and_the_ledger_remembers() {
    let Some(node) = Node::start("descriptor-payout", 87, &[]) else {
        eprintln!("skipping: aviand or avian-cli not found");
        return;
    };
    node.mine(101);
    let state = scratch("ledger");
    let Some(rig) = Rig::attach_full(
        node,
        &[PowType::MinotaurX],
        None,
        (Vec::new(), 0),
        RateLimitConfig::default(),
        Some(state.clone()),
    ) else {
        return;
    };

    let descriptor = Descriptor::parse(&descriptor_text(), Network::Regtest).unwrap();
    let mut config = rig.client_config(PowType::MinotaurX);
    config.user_identity = format!("{}.rig", descriptor_text());
    let mut miner = MiningClient::connect(config).expect("the client should connect");

    for index in 0..2u32 {
        if index > 0 {
            // The last block moved the tip; wait for the pool's work to catch
            // up before taking the job that follows it.
            rig.wait_for_tip(PowType::MinotaurX);
        }
        let job = common::expect_job(&mut miner);
        let (nonce, ntime) = find_share(&job, 200_000).expect("regtest's target is easy");
        miner
            .submit(&job, nonce, ntime)
            .expect("the share should send");
        let hash = wait_block_found(&mut miner);

        // What the chain says the coinbase pays, which is the only answer
        // that matters: the address at this index, and no other.
        let expected = descriptor.address_at(index).unwrap();
        let block = rig
            .node
            .rpc(&["getblock", &hex_rev(&hash), "2"])
            .expect("the node holds the block it just accepted");
        assert!(
            block.contains(&format!("\"hex\": \"{}\"", hex(&expected.script_pubkey()))),
            "block {index} should pay index {index}, {}:\n{block}",
            expected.encode(Network::Regtest)
        );
        if index > 0 {
            let previous = descriptor.address_at(index - 1).unwrap();
            assert!(
                !block.contains(&format!("\"hex\": \"{}\"", hex(&previous.script_pubkey()))),
                "block {index} must not pay the address block {} did",
                index - 1
            );
        }

        // The pool's own record names the key as the miner and the address
        // as what was paid, which is what a page shows for each.
        let algo = rig.pool.algo(PowType::MinotaurX).expect("the algorithm");
        let found = algo.found();
        let last = found.last().expect("the block should be in the found list");
        assert_eq!(last.payout_address, TPUB);
        assert_eq!(last.paid, expected.encode(Network::Regtest));
    }

    // The snapshot says where the next block goes: index 2, since two have
    // been paid, and the channel is marked as paying per block.
    let snapshot = Snapshot::gather(
        rig.pool.started_at(),
        rig.pool.algos(),
        String::new(),
        rig.pool.operator_fee(),
        rig.pool.coinbase_tag().to_string(),
    );
    let channel = snapshot
        .algorithms
        .iter()
        .flat_map(|algo| algo.channels.iter())
        .find(|channel| channel.worker == "rig")
        .expect("the channel is in the snapshot");
    assert!(channel.payout_derived);
    assert_eq!(channel.payout_index, 2);
    assert_eq!(
        channel.payout_next,
        descriptor.address_at(2).unwrap().encode(Network::Regtest)
    );
    assert!(
        TPUB.starts_with(&channel.payout_prefix),
        "{}",
        channel.payout_prefix
    );

    // And the file the next start reads says the same.
    let ledger = PayoutLedger::open(state.clone()).expect("the ledger file is readable");
    assert_eq!(ledger.next_index(&descriptor.canonical()), 2);
    let text = std::fs::read_to_string(&state).unwrap();
    assert!(
        text.contains(&format!("2 {}", descriptor.canonical())),
        "{text}"
    );
    let _ = std::fs::remove_file(&state);
}

#[test]
fn a_descriptor_the_pool_cannot_pay_refuses_the_channel() {
    let Some(rig) = Rig::start("descriptor-refused", 88, &[PowType::MinotaurX], None) else {
        eprintln!("skipping: aviand or avian-cli not found");
        return;
    };
    // Hardened, which a public key cannot derive. The miner is told with a
    // code rather than mined to anything.
    let mut config = rig.client_config(PowType::MinotaurX);
    config.user_identity = format!("wpkh({TPUB}/0'/*).rig");
    config.reconnect.max_attempts = Some(1);
    let refused = match MiningClient::connect(config) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("a hardened path should have been refused"),
    };
    assert!(
        refused.contains("invalid-payout-descriptor"),
        "the refusal should carry the code: {refused}"
    );
}
