//! Extended channels, end to end.
//!
//! The milestone is a block mined over an **extended** channel, accepted by
//! the node, paying the worker's address, with the miner having assembled the
//! coinbase from prefix and suffix rather than being handed a merkle root.
//!
//! And then the thing extended channels exist for: that the miner can see what
//! it is committing to. On a standard channel it gets a finished merkle root
//! and can only take the pool's word for what is in the block. "We wrote the
//! miner, so it will show you" moves the trust rather than removing it, and
//! stops being true the moment somebody mines Avian with software we did not
//! write.

mod common;

use std::time::{Duration, Instant};

use avian_regtest::Node;
use avian_sv2::avian::PowType;
use avian_sv2::block;
use avian_sv2::client::{Event, MiningClient, MiningJob};
use common::{poll_event, Rig, WORKER_ADDRESS, WORKER_SCRIPT};

fn hasher(pow: PowType) -> avian_pow::PowType {
    match pow {
        PowType::X16rt => avian_pow::PowType::X16rt,
        PowType::MinotaurX => avian_pow::PowType::MinotaurX,
    }
}

/// Searches for a share the way a miner on an extended channel does: roll the
/// extranonce, assemble the coinbase, fold the path, hash the header.
fn find_extended_share(job: &MiningJob, rounds: u32) -> Option<(Vec<u8>, u32)> {
    let extended = job.extended.as_ref()?;
    let hasher = hasher(job.pow_type);
    for counter in 0..rounds {
        let mut extranonce = vec![0u8; extended.extranonce_size];
        let bytes = counter.to_le_bytes();
        let take = bytes.len().min(extranonce.len());
        extranonce[..take].copy_from_slice(&bytes[..take]);
        for nonce in 0..64u32 {
            let header = job.header_for(&extranonce, job.ntime, nonce)?;
            let hash = avian_pow::hash(hasher, &header)?;
            if block::meets_target(&hash, &job.share_target) {
                return Some((extranonce, nonce));
            }
        }
    }
    None
}

fn extended_miner(rig: &Rig, pow: PowType, identity: &str) -> MiningClient {
    let mut config = rig.client_config(pow);
    config.user_identity = identity.to_string();
    config.extended = true;
    let mut client = MiningClient::connect(config).expect("an extended channel should open");
    common::expect_job(&mut client);
    client
}

macro_rules! rig {
    ($tag:expr, $slot:expr, $algos:expr) => {
        match Rig::start($tag, $slot, $algos, 0) {
            Some(rig) => rig,
            None => {
                eprintln!("skipping: aviand or avian-cli not found");
                return;
            }
        }
    };
}

/// The milestone.
#[test]
fn a_miner_mines_a_block_over_an_extended_channel() {
    let rig = rig!("ext-milestone", 60, &[PowType::X16rt, PowType::MinotaurX]);

    for pow in [PowType::X16rt, PowType::MinotaurX] {
        let before = rig.node.height();
        let mut miner = extended_miner(&rig, pow, &format!("{WORKER_ADDRESS}.ext-{pow}"));

        let job = miner.active_job().expect("an active job").clone();
        assert!(
            job.is_extended(),
            "the channel was opened as extended, so its jobs must be"
        );
        let extended = job.extended.as_ref().unwrap();
        assert!(
            !extended.coinbase_prefix.is_empty() && !extended.coinbase_suffix.is_empty(),
            "both halves of the coinbase must arrive"
        );
        assert!(
            extended.extranonce_size > 0,
            "a miner with no extranonce has no search space"
        );
        // The pool sent no merkle root for an extended job, and must not have.
        assert_eq!(
            job.merkle_root, [0u8; 32],
            "an extended job's root is the miner's to compute"
        );

        let (extranonce, nonce) =
            find_extended_share(&job, 400).expect("a share should be findable on regtest");
        miner
            .submit_with(&job, nonce, job.ntime, &extranonce)
            .expect("submit");
        match poll_event(&mut miner, Duration::from_secs(30)) {
            Some(Event::ShareAccepted { .. }) => {}
            other => panic!("the extended share was not accepted: {other:?}"),
        }

        let deadline = Instant::now() + Duration::from_secs(30);
        while rig.node.height() == before && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(
            rig.node.height(),
            before + 1,
            "the node should have accepted a block mined over an extended channel:\n{}",
            rig.node.sv2_log()
        );

        let tip = rig.node.tip();
        assert_eq!(rig.node.pow_type_of(&tip).as_deref(), Some(pow.name()));
        let block_json = rig.node.rpc(&["getblock", &tip, "2"]).expect("getblock");
        assert!(
            block_json.contains(WORKER_SCRIPT),
            "the block must pay {WORKER_ADDRESS}"
        );
        eprintln!(
            "[test] {pow} block {tip} mined over an extended channel, extranonce {}, paying \
             {WORKER_ADDRESS}",
            avian_sv2::wire::hex(&extranonce)
        );
    }
}

/// What extended channels exist for: the miner can see what it commits to.
///
/// A known transaction is put in the mempool, and the miner — from nothing but
/// what it was sent — determines that transaction is in its block, and that
/// its own payout output is in the coinbase. Neither is possible on a standard
/// channel.
#[test]
fn the_miner_can_see_what_it_is_committing_to() {
    let Some(node) = Node::start("ext-visible", 61, &[]) else {
        eprintln!("skipping: aviand or avian-cli not found");
        return;
    };
    node.mine(101);
    let address = node.rpc(&["getnewaddress"]).expect("getnewaddress");
    let funded = node
        .rpc(&["sendtoaddress", &address, "1.0"])
        .expect("sendtoaddress");
    eprintln!("[test] mempool transaction {funded}");

    let Some(rig) = Rig::attach(node, &[PowType::X16rt], 0) else {
        return;
    };
    let mut miner = extended_miner(&rig, PowType::X16rt, WORKER_ADDRESS);

    // Read rounds until one has the transaction in it: the first template may
    // predate the mempool entry.
    let deadline = Instant::now() + Duration::from_secs(60);
    let job = loop {
        assert!(Instant::now() < deadline, "no job included the transaction");
        let job = miner.active_job().expect("a job").clone();
        let extended = job.extended.as_ref().expect("extended");
        if !extended.merkle_path.is_empty() {
            break job;
        }
        common::expect_job(&mut miner);
    };
    let extended = job.extended.as_ref().unwrap();

    // 1. Its own payout output is in the coinbase it is committing to. This is
    //    the claim a solo miner most needs to be able to check: that the pool
    //    is building a coinbase that pays the miner and not itself.
    let worker_script = common::script_for(WORKER_ADDRESS);
    assert!(
        extended.commits_to_script(&worker_script),
        "a miner must be able to see its own payout script in the coinbase suffix"
    );
    // And it would notice if it were not there.
    assert!(
        !extended.commits_to_script(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33]),
        "the check must be able to say no"
    );

    // 2. The mempool transaction is in its block. In a two-transaction block
    //    the single merkle sibling is that transaction's txid, so the miner
    //    can confirm inclusion from the path alone.
    let mut txid = [0u8; 32];
    for (i, byte) in txid.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&funded[i * 2..i * 2 + 2], 16).expect("a txid in hex");
    }
    // A txid is printed reversed, and the merkle path carries internal order.
    txid.reverse();
    assert!(
        extended.path_contains(&txid),
        "the miner should be able to see {funded} in its block from the merkle path {:?}",
        extended
            .merkle_path
            .iter()
            .map(|h| avian_sv2::wire::hex_rev(h))
            .collect::<Vec<_>>()
    );
    assert!(
        !extended.path_contains(&[0x99; 32]),
        "the check must be able to say no"
    );

    // 3. And the miner's own arithmetic agrees with the pool's: it mines a
    //    share on this job and the pool accepts it, which it could not do if
    //    the miner's reading of prefix and suffix were wrong.
    let (extranonce, nonce) = find_extended_share(&job, 400).expect("a share");
    miner
        .submit_with(&job, nonce, job.ntime, &extranonce)
        .expect("submit");
    match poll_event(&mut miner, Duration::from_secs(30)) {
        Some(Event::ShareAccepted { .. }) => {}
        other => panic!("the share was not accepted: {other:?}"),
    }
    eprintln!("[test] the miner verified its payout and its block's contents, then mined it");
}

/// Standard channels keep working alongside, and the two do not interfere.
#[test]
fn standard_and_extended_channels_are_served_side_by_side() {
    let rig = rig!("ext-both", 62, &[PowType::X16rt]);

    let mut standard = {
        let mut config = rig.client_config(PowType::X16rt);
        config.extended = false;
        let mut client = MiningClient::connect(config).expect("a standard channel should open");
        common::expect_job(&mut client);
        client
    };
    let mut extended = extended_miner(&rig, PowType::X16rt, WORKER_ADDRESS);

    let standard_job = standard.active_job().expect("a standard job").clone();
    let extended_job = extended.active_job().expect("an extended job").clone();
    assert!(!standard_job.is_extended());
    assert!(extended_job.is_extended());
    assert_ne!(
        standard_job.merkle_root, [0u8; 32],
        "a standard job must carry a finished merkle root"
    );
    assert_ne!(standard.channel_id(), extended.channel_id());
    assert_eq!(rig.pool.algo(PowType::X16rt).unwrap().channel_count(), 2);

    // Both can mine, and the pool keeps their coinbases apart.
    let (extranonce, nonce) = find_extended_share(&extended_job, 400).expect("a share");
    extended
        .submit_with(&extended_job, nonce, extended_job.ntime, &extranonce)
        .expect("submit");
    assert!(matches!(
        poll_event(&mut extended, Duration::from_secs(30)),
        Some(Event::ShareAccepted { .. })
    ));

    let (nonce, ntime) = common::find_share(&standard_job, 400).expect("a share");
    standard
        .submit(&standard_job, nonce, ntime)
        .expect("submit");
    assert!(matches!(
        poll_event(&mut standard, Duration::from_secs(30)),
        Some(Event::ShareAccepted { .. })
    ));
}

/// `version_rolling_allowed` is false on every extended job, to match
/// `REQUIRES_FIXED_VERSION`.
///
/// The client refuses a job that says otherwise, so reaching an active job at
/// all is half the assertion; a rolled version being refused is the other.
#[test]
fn version_rolling_is_not_allowed_on_an_extended_job() {
    let rig = rig!("ext-rolling", 63, &[PowType::X16rt]);
    let mut miner = extended_miner(&rig, PowType::X16rt, WORKER_ADDRESS);
    let job = miner.active_job().expect("a job").clone();
    let extranonce = vec![0u8; job.extended.as_ref().unwrap().extranonce_size];

    miner
        .submit_exact_with(
            job.job_id,
            0,
            job.ntime,
            job.version ^ 0x0001_0000,
            &extranonce,
        )
        .expect("the submission reaches the pool");
    match poll_event(&mut miner, Duration::from_secs(10)) {
        Some(Event::ShareRejected { code, .. }) => assert_eq!(code, "invalid-version"),
        other => panic!("a rolled version should be refused: {other:?}"),
    }
}

/// An extranonce of the wrong length is refused rather than quietly producing
/// a different merkle root.
#[test]
fn an_extranonce_of_the_wrong_length_is_refused() {
    let rig = rig!("ext-badnonce", 64, &[PowType::X16rt]);
    let mut miner = extended_miner(&rig, PowType::X16rt, WORKER_ADDRESS);
    let job = miner.active_job().expect("a job").clone();
    let size = job.extended.as_ref().unwrap().extranonce_size;

    // The client catches it before the wire, which is what a miner wants.
    let error = miner
        .submit_with(&job, 0, job.ntime, &vec![0u8; size + 1])
        .expect_err("a wrong-length extranonce should be refused locally");
    assert!(
        error.to_string().contains("extranonce"),
        "unexpected error: {error}"
    );

    // And the pool refuses one that reaches it.
    miner
        .submit_exact_with(job.job_id, 0, job.ntime, job.version, &vec![0u8; size - 1])
        .expect("the submission reaches the pool");
    match poll_event(&mut miner, Duration::from_secs(10)) {
        Some(Event::ShareRejected { code, .. }) => assert_eq!(code, "invalid-extranonce"),
        other => panic!("a short extranonce should be refused: {other:?}"),
    }
}

/// A miner asking for more extranonce than the scriptSig has room for is
/// refused, rather than given a channel whose every coinbase the node rejects.
#[test]
fn an_oversized_extranonce_request_refuses_the_channel() {
    let rig = rig!("ext-toobig", 65, &[PowType::X16rt]);
    let mut config = rig.client_config(PowType::X16rt);
    config.user_identity = WORKER_ADDRESS.to_string();
    config.extended = true;
    // Far more than the 100-byte scriptSig can hold alongside the height push,
    // the operator tag and the pool's own prefix.
    config.min_extranonce_size = 200;
    config.reconnect = avian_sv2::Backoff::none();

    let error = match MiningClient::connect(config) {
        Ok(_) => panic!("a 200-byte extranonce should not have been granted"),
        Err(e) => e.to_string(),
    };
    assert!(
        error.contains("min-extranonce-size-too-large"),
        "refused for the wrong reason: {error}"
    );
}
