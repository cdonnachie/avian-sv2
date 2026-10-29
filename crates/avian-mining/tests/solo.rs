//! Solo mining: the money path.
//!
//! The milestone for this stage is not "a block was mined". It is **a block
//! was mined and it paid the worker's address**, checked against the node's
//! own view of the block it accepted. That is the only part of solo mining
//! that cannot be inferred from the protocol working: every protocol
//! assertion would pass just as happily if the coinbase paid the operator.

mod common;

use std::time::{Duration, Instant};

use avian_mining::ratelimit::RateLimitConfig;
use avian_regtest::Node;
use avian_sv2::address::Network;
use avian_sv2::avian::PowType;
use avian_sv2::client::{ClientConfig, Event, MiningClient};
use common::{
    find_share, poll_event, script_for, Rig, FEE_ADDRESS, FEE_SCRIPT, WORKER_ADDRESS, WORKER_SCRIPT,
};

macro_rules! rig {
    ($tag:expr, $slot:expr, $algos:expr) => {
        match Rig::start($tag, $slot, $algos, None) {
            Some(rig) => rig,
            None => {
                eprintln!("skipping: aviand or avian-cli not found");
                return;
            }
        }
    };
}

/// Opens a channel with a given `user_identity` and reports what came back.
fn connect_as(rig: &Rig, pow: PowType, identity: &str) -> Result<MiningClient, String> {
    let mut config: ClientConfig = rig.client_config(pow);
    config.user_identity = identity.to_string();
    // One attempt: a refused channel must not be retried into a loop.
    config.reconnect = avian_sv2::Backoff::none();
    MiningClient::connect(config).map_err(|e| e.to_string())
}

/// The outputs of the coinbase of a block, as the node reports them:
/// `(value in satoshis, scriptPubKey hex)`.
fn coinbase_outputs(node: &Node, block_hash: &str) -> Vec<(f64, String)> {
    let block = node
        .rpc(&["getblock", block_hash, "2"])
        .expect("getblock verbosity 2");
    // The coinbase is the first transaction. Cut the JSON down to it rather
    // than pulling in a JSON parser for a test.
    let coinbase = block
        .split("\"tx\": [")
        .nth(1)
        .expect("a tx array")
        .split("\n    },")
        .next()
        .expect("the first transaction");
    let vout = coinbase.split("\"vout\": [").nth(1).expect("a vout array");
    let mut outputs = Vec::new();
    for chunk in vout.split("\"value\":").skip(1) {
        let value: f64 = chunk
            .split(',')
            .next()
            .expect("a value")
            .trim()
            .parse()
            .expect("a number");
        let script = chunk
            .split("\"hex\": \"")
            .nth(1)
            .expect("a script hex")
            .split('"')
            .next()
            .expect("a script hex")
            .to_string();
        outputs.push((value, script));
    }
    assert!(!outputs.is_empty(), "a coinbase has outputs");
    outputs
}

/// **The milestone.** A block was mined, and it paid the worker.
#[test]
fn a_mined_block_pays_the_address_the_worker_supplied() {
    let rig = rig!("solo-pays", 40, &[PowType::X16rt, PowType::MinotaurX]);

    for pow in [PowType::X16rt, PowType::MinotaurX] {
        let before = rig.node.height();
        let identity = format!("{WORKER_ADDRESS}.rig-{pow}");
        let mut miner = connect_as(&rig, pow, &identity).expect("the channel should open");

        let job = common::expect_job(&mut miner);
        let (nonce, ntime) = find_share(&job, 400).expect("a share");
        miner.submit(&job, nonce, ntime).expect("submit");
        match poll_event(&mut miner, Duration::from_secs(30)) {
            Some(Event::ShareAccepted { .. }) => {}
            other => panic!("the share was not accepted: {other:?}"),
        }

        let deadline = Instant::now() + Duration::from_secs(30);
        while rig.node.height() == before && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(
            rig.node.height(),
            before + 1,
            "the node should have accepted the block:\n{}",
            rig.node.sv2_log()
        );

        let tip = rig.node.tip();
        let outputs = coinbase_outputs(&rig.node, &tip);
        // The worker's output is first, ahead of the template's required
        // outputs, so the witness commitment stays the highest-indexed one.
        assert_eq!(
            outputs[0].1, WORKER_SCRIPT,
            "the coinbase of {tip} must pay {WORKER_ADDRESS}; outputs were {outputs:?}"
        );
        assert!(
            outputs[0].0 > 0.0,
            "the worker's output must carry the reward, got {:?}",
            outputs[0]
        );
        // And no operator fee, because none was configured.
        assert!(
            !outputs
                .iter()
                .skip(1)
                .any(|(_, script)| script == FEE_SCRIPT),
            "no operator fee was configured, so none should appear: {outputs:?}"
        );
        eprintln!(
            "[test] {pow} block {tip} paid {} AVN to {WORKER_ADDRESS}",
            outputs[0].0
        );
    }
}

/// An address that does not parse refuses the channel, and nothing is mined.
///
/// This is the failure that matters most: a worker that mistypes its address
/// and is quietly mined to somebody else's. It must be a refusal, never a
/// fallback.
#[test]
fn a_malformed_address_refuses_the_channel_and_mines_nothing() {
    let rig = rig!("solo-malformed", 41, &[PowType::X16rt]);
    let before = rig.node.height();

    for identity in [
        "",
        "not-an-address",
        ".just-a-worker-name",
        // One character off a real address, so only the checksum catches it.
        "mnPBEVKjU1zz9214C7M7Zp4FuurUAsU6ZT",
        // A real address with a character dropped, which is what a bad
        // copy-paste looks like.
        "mnPBEVKjU1zz9214C7M7Zp4FuurUAsU6Z.worker",
        // Base58 characters that do not exist.
        "mnPBEVKjU1zz9214C7M7Zp4FuurUAsU0Il",
    ] {
        let error = connect_as(&rig, PowType::X16rt, identity)
            .err()
            .unwrap_or_else(|| panic!("{identity:?} should have been refused"));
        assert!(
            error.contains("invalid-payout-address") || error.contains("missing-payout-address"),
            "{identity:?} was refused with the wrong reason: {error}"
        );
    }

    // Nothing was mined on the way through, and the pool is still serving.
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(rig.node.height(), before, "nothing should have been mined");
    let mut honest = connect_as(
        &rig,
        PowType::X16rt,
        &format!("{WORKER_ADDRESS}.still-working"),
    )
    .expect("an honest miner should still be served");
    common::expect_job(&mut honest);
}

/// An address for another network refuses the channel.
#[test]
fn an_address_for_the_wrong_network_refuses_the_channel() {
    let rig = rig!("solo-network", 42, &[PowType::X16rt]);

    // The same key hash re-encoded under Avian mainnet's version byte, so it
    // is checksum-valid and the only thing wrong with it is the network.
    // Otherwise this would pass for the wrong reason.
    let mainnet = avian_sv2::address::Address::decode(WORKER_ADDRESS, Network::Regtest)
        .unwrap()
        .encode_base58(Network::Main)
        .unwrap();
    assert!(
        mainnet.starts_with('R'),
        "{mainnet} should be an Avian mainnet address"
    );

    let error = connect_as(&rig, PowType::X16rt, &mainnet)
        .err()
        .expect("a mainnet address should be refused on a regtest pool");
    assert!(
        error.contains("wrong-network-address"),
        "refused for the wrong reason: {error}"
    );

    // A bech32 address for another network too, which is the only case the
    // base58 version byte cannot catch off mainnet.
    let bech32_mainnet = "avn1qmyfxjmnhquher0k8lhrpg082rv4j7thpkvmn5g";
    let error = connect_as(&rig, PowType::X16rt, bech32_mainnet)
        .err()
        .expect("a mainnet bech32 address should be refused");
    assert!(
        error.contains("wrong-network-address") || error.contains("invalid-payout-address"),
        "refused for the wrong reason: {error}"
    );
}

/// The operator fee output appears when configured, and the worker still gets
/// the rest.
#[test]
fn the_operator_fee_appears_when_configured() {
    let Some(node) = Node::start("solo-fee", 43, &[]) else {
        eprintln!("skipping: aviand or avian-cli not found");
        return;
    };
    node.mine(101);
    // Two and a half per cent, which is not a round number of satoshis, so a
    // rounding bug would show.
    let Some(rig) = Rig::attach_with(
        node,
        &[PowType::X16rt],
        None,
        (script_for(FEE_ADDRESS), 250),
        RateLimitConfig::default(),
    ) else {
        return;
    };

    let before = rig.node.height();
    let mut miner = connect_as(&rig, PowType::X16rt, WORKER_ADDRESS).expect("channel");
    let job = common::expect_job(&mut miner);
    let (nonce, ntime) = find_share(&job, 400).expect("a share");
    miner.submit(&job, nonce, ntime).expect("submit");
    assert!(matches!(
        poll_event(&mut miner, Duration::from_secs(30)),
        Some(Event::ShareAccepted { .. })
    ));

    let deadline = Instant::now() + Duration::from_secs(30);
    while rig.node.height() == before && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        rig.node.height(),
        before + 1,
        "a block should have been accepted"
    );

    let outputs = coinbase_outputs(&rig.node, &rig.node.tip());
    assert_eq!(outputs[0].1, WORKER_SCRIPT, "the worker is paid first");
    assert_eq!(
        outputs[1].1, FEE_SCRIPT,
        "the operator fee should be the second output: {outputs:?}"
    );

    // The fee is 2.5% of the two together, within a satoshi of rounding.
    let worker = outputs[0].0;
    let fee = outputs[1].0;
    let spendable = worker + fee;
    let share = fee / spendable;
    assert!(
        (0.0249..0.0251).contains(&share),
        "the fee should be about 2.5% of {spendable}, was {fee} ({share})"
    );
    eprintln!("[test] worker {worker} AVN, operator {fee} AVN of {spendable} AVN");
}

/// A flood is refused, tested by flooding, and an honest miner at the
/// configured target is not.
#[test]
fn a_flood_is_rate_limited_and_an_honest_miner_is_not() {
    let Some(node) = Node::start("solo-flood", 44, &[]) else {
        eprintln!("skipping: aviand or avian-cli not found");
        return;
    };
    node.mine(101);
    // A high invalid allowance, so the flood is refused for its rate and the
    // channel is not dropped before that can be observed.
    let limits = RateLimitConfig {
        max_invalid: 100_000,
        ..RateLimitConfig::default()
    };
    // The easiest target there is, so an honest miner finds a share in a
    // handful of nonces while the flood below is mostly waste.
    let Some(rig) = Rig::attach_with(
        node,
        &[PowType::X16rt],
        Some([0xff; 32]),
        (Vec::new(), 0),
        limits,
    ) else {
        return;
    };

    let mut miner = connect_as(&rig, PowType::X16rt, WORKER_ADDRESS).expect("channel");
    let job = common::expect_job(&mut miner);

    // As fast as the socket allows, which is what a hostile worker does. The
    // same nonce every time, so nothing here is useful work: this is purely
    // the cost of being asked.
    for _ in 0..300u32 {
        miner
            .submit_exact(job.job_id, 0, job.ntime_min, job.version)
            .expect("the submission should reach the pool");
    }

    let mut rate_refusals = 0;
    let mut other = 0;
    let deadline = Instant::now() + Duration::from_secs(30);
    while rate_refusals == 0 && Instant::now() < deadline {
        match miner.poll(Duration::from_millis(200)) {
            Ok(Event::ShareRejected { code, .. }) => {
                if code == "too-many-shares" {
                    rate_refusals += 1;
                } else {
                    other += 1;
                }
            }
            Ok(_) => {}
            Err(e) => panic!("the miner failed: {e}"),
        }
    }
    assert!(
        rate_refusals > 0,
        "a flood of 300 submissions should have been rate limited; saw {other} other refusals"
    );
    eprintln!("[test] the flood was refused as too-many-shares after {other} others");

    // An honest miner on its own channel is unaffected: the limit is per
    // channel, and a flooder must not deny service to anyone else.
    let mut honest = connect_as(&rig, PowType::X16rt, &format!("{WORKER_ADDRESS}.honest"))
        .expect("a second channel");
    let honest_job = common::expect_job(&mut honest);
    let (nonce, ntime) = find_share(&honest_job, 50_000).expect("a share at the harder target");
    honest.submit(&honest_job, nonce, ntime).expect("submit");
    match poll_event(&mut honest, Duration::from_secs(30)) {
        Some(Event::ShareAccepted { .. }) => {}
        other => panic!("an honest miner was not served while another flooded: {other:?}"),
    }
}

/// Too many invalid submissions drops the channel, as the node's
/// `-sv2maxrejects` drops a client.
#[test]
fn too_many_invalid_submissions_drops_the_channel() {
    let Some(node) = Node::start("solo-invalid", 45, &[]) else {
        eprintln!("skipping: aviand or avian-cli not found");
        return;
    };
    node.mine(101);
    let limits = RateLimitConfig {
        max_invalid: 5,
        // Generous, so what ends the channel is the invalid count and not the
        // rate.
        burst: 1000.0,
        ceiling_per_second: 1000.0,
        floor_per_second: 1000.0,
        ..RateLimitConfig::default()
    };
    let Some(rig) = Rig::attach_with(node, &[PowType::X16rt], None, (Vec::new(), 0), limits) else {
        return;
    };

    let mut miner = connect_as(&rig, PowType::X16rt, WORKER_ADDRESS).expect("channel");
    let job = common::expect_job(&mut miner);

    // Genuinely bad work, against a job the pool does have. These used to be
    // unknown job ids, which no longer count: an unknown job id means the pool
    // and the miner disagree about state, which is nearly always the pool's
    // end, so it prompts a reissue instead. A wrong version is the miner's
    // fault, is cheap to refuse, and is what this limit is for.
    for i in 0..10u32 {
        let _ = miner.submit_exact(job.job_id, i, job.ntime_min, job.version ^ 0xff);
    }

    let mut refusals = 0;
    let mut dropped = false;
    let deadline = Instant::now() + Duration::from_secs(30);
    while !dropped && Instant::now() < deadline {
        match miner.poll(Duration::from_millis(200)) {
            Ok(Event::ShareRejected { .. }) => refusals += 1,
            Ok(Event::Disconnected { .. }) => dropped = true,
            Ok(_) => {}
            Err(e) => panic!("the miner failed: {e}"),
        }
    }
    assert!(
        dropped,
        "the channel should have been dropped after 5 invalid submissions; saw {refusals} \
         refusals"
    );
    eprintln!("[test] dropped after {refusals} refusals, as -sv2maxrejects does");
}

/// A worker label is kept and does not affect the payout.
#[test]
fn a_worker_label_does_not_change_who_is_paid() {
    let rig = rig!("solo-label", 46, &[PowType::X16rt]);
    let before = rig.node.height();

    let mut miner =
        connect_as(&rig, PowType::X16rt, &format!("{WORKER_ADDRESS}.bitaxe-1")).expect("channel");
    let job = common::expect_job(&mut miner);
    let (nonce, ntime) = find_share(&job, 400).expect("a share");
    miner.submit(&job, nonce, ntime).expect("submit");
    assert!(matches!(
        poll_event(&mut miner, Duration::from_secs(30)),
        Some(Event::ShareAccepted { .. })
    ));

    let deadline = Instant::now() + Duration::from_secs(30);
    while rig.node.height() == before && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(rig.node.height(), before + 1);
    let outputs = coinbase_outputs(&rig.node, &rig.node.tip());
    assert_eq!(
        outputs[0].1, WORKER_SCRIPT,
        "the label must not affect the payout: {outputs:?}"
    );
}

/// The operator tag is in the coinbase scriptSig, after the BIP34 height push.
#[test]
fn the_coinbase_carries_the_operator_tag() {
    let rig = rig!("solo-tag", 47, &[PowType::X16rt]);
    let before = rig.node.height();

    let mut miner = connect_as(&rig, PowType::X16rt, WORKER_ADDRESS).expect("channel");
    let job = common::expect_job(&mut miner);
    let (nonce, ntime) = find_share(&job, 400).expect("a share");
    miner.submit(&job, nonce, ntime).expect("submit");
    assert!(matches!(
        poll_event(&mut miner, Duration::from_secs(30)),
        Some(Event::ShareAccepted { .. })
    ));
    let deadline = Instant::now() + Duration::from_secs(30);
    while rig.node.height() == before && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(rig.node.height(), before + 1);

    let block = rig
        .node
        .rpc(&["getblock", &rig.node.tip(), "2"])
        .expect("getblock");
    let script_sig = block
        .split("\"coinbase\": \"")
        .nth(1)
        .expect("a coinbase scriptSig")
        .split('"')
        .next()
        .expect("a coinbase scriptSig");
    let tag = avian_sv2::wire::hex(b"/avian-sv2-test/");
    assert!(
        script_sig.contains(&tag),
        "the scriptSig {script_sig} should contain the tag {tag}"
    );
    // And it is not at the very start: the BIP34 height push comes first,
    // which the node requires.
    assert!(
        !script_sig.starts_with(&tag),
        "the tag must follow coinbase_prefix, not replace it"
    );
}
