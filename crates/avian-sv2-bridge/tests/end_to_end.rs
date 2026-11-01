//! The bridge between a real Stratum v2 miner and a scripted Stratum v1 pool.
//!
//! The miner is this project's own `MiningClient`, which is what a miner
//! built for the solo pool uses, so these tests are also the proof that such
//! a miner connects to a bridge without knowing the difference. The pool is
//! `avian_sv1::mock::MockPool`, over a real loopback socket. No hashing:
//! the bridge is built without the `pow` feature here, so every share's
//! hash is the pool's to judge, which is the design.

use std::sync::Arc;
use std::time::{Duration, Instant};

use avian_mining::ratelimit::RateLimitConfig;
use avian_mining::share::MetadataOnlyHasher;
use avian_sv1::difficulty::{self, POW_LIMIT};
use avian_sv1::message::{self, Incoming, Notify};
use avian_sv1::mock::{MockPool, Verdict};
use avian_sv2::block;
use avian_sv2::client::{ClientConfig, Event, MiningClient, MiningJob};
use avian_sv2::{Backoff, PowType};
use avian_sv2_bridge::server::{Bridge, BridgeConfig, BridgeHandle};
use secp256k1::{Keypair, Secp256k1};

const IDENTITY: &str = "RAddr.rig1";

struct Rig {
    pool: MockPool,
    _bridge: BridgeHandle,
    miner: MiningClient,
}

/// A pool, a bridge in front of it, and a miner connected through, with the
/// first job already in hand.
fn rig(extended: bool, min_extranonce_size: u16) -> Rig {
    let pool = MockPool::start();
    let (bridge, authority) = bridge_for(&pool);
    let miner = MiningClient::connect(miner_config(
        &bridge,
        authority,
        extended,
        min_extranonce_size,
    ))
    .expect("the miner should get a channel through the bridge");
    Rig {
        pool,
        _bridge: bridge,
        miner,
    }
}

fn bridge_for(pool: &MockPool) -> (BridgeHandle, secp256k1::XOnlyPublicKey) {
    let secp = Secp256k1::new();
    let authority = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
    let (public, _) = authority.x_only_public_key();
    let bridge = Bridge::new(
        BridgeConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            authority,
            cert_validity: 3600,
            allow_public_bind: false,
            upstreams: vec![(PowType::X16rt, pool.addr())],
            pow_limit: POW_LIMIT,
            password: "x".into(),
            upstream_idle_timeout: Some(Duration::from_secs(30)),
            first_work_timeout: Duration::from_secs(5),
            ntime_roll: 0,
            min_hash_rate: 1000.0,
            max_hash_rate: 1e12,
            rate_limit: RateLimitConfig::default(),
        },
        Arc::new(MetadataOnlyHasher),
    )
    .expect("a valid configuration");
    (Arc::new(bridge).listen().expect("a listener"), public)
}

fn miner_config(
    bridge: &BridgeHandle,
    authority: secp256k1::XOnlyPublicKey,
    extended: bool,
    min_extranonce_size: u16,
) -> ClientConfig {
    let mut config = ClientConfig::new(vec![bridge.addr()], PowType::X16rt);
    config.pool_authority = Some(authority);
    config.user_identity = IDENTITY.into();
    config.nominal_hash_rate = 1_000_000.0;
    config.timeout = Duration::from_secs(5);
    config.reconnect = Backoff::none();
    config.extended = extended;
    config.min_extranonce_size = min_extranonce_size;
    config
}

/// Polls until an event the predicate accepts arrives, or fails naming
/// everything that did.
fn poll_until(miner: &mut MiningClient, what: &str, accept: impl Fn(&Event) -> bool) -> Event {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut seen = Vec::new();
    while Instant::now() < deadline {
        let event = miner
            .poll(Duration::from_millis(200))
            .unwrap_or_else(|e| panic!("poll failed waiting for {what}: {e}"));
        if accept(&event) {
            return event;
        }
        if !matches!(event, Event::Idle) {
            seen.push(event);
        }
    }
    panic!("no {what} within five seconds; saw {seen:?}");
}

fn next_job(miner: &mut MiningClient) -> MiningJob {
    match poll_until(miner, "a job", |e| matches!(e, Event::Job(_))) {
        Event::Job(job) => job,
        _ => unreachable!(),
    }
}

/// The mock's first job, decoded the way the bridge decodes it.
fn mock_notify() -> Notify {
    match message::parse_incoming(&MockPool::notify(MockPool::JOB_ID, true)).unwrap() {
        Incoming::Notify(notify) => notify,
        other => panic!("the mock's notify parsed as {other:?}"),
    }
}

fn expected_target() -> [u8; 32] {
    difficulty::target_from_difficulty(&POW_LIMIT, MockPool::DIFFICULTY).unwrap()
}

#[test]
fn a_standard_channel_gets_the_pools_job_as_a_finished_merkle_root() {
    let mut rig = rig(false, 0);
    let job = next_job(&mut rig.miner);
    let notify = mock_notify();

    assert!(job.extended.is_none());
    assert_eq!(job.version, notify.version);
    assert_eq!(job.nbits, notify.nbits);
    assert_eq!(
        job.prev_hash, notify.prev_hash,
        "the word swap should have been undone"
    );
    // Pinned: the bridge does not know the pool's rule for rolling ntime.
    assert_eq!(job.ntime_min, notify.ntime);
    assert_eq!(job.ntime_max, notify.ntime);
    assert_eq!(job.share_target, expected_target());

    // The root the bridge handed down is coinb1, extranonce1, the bridge's
    // own extranonce2 (a counter from zero, as wide as the pool asked), and
    // coinb2, hashed and folded with the branch.
    let mut coinbase = notify.coinb1.clone();
    coinbase.extend_from_slice(&message::unhex(MockPool::EXTRANONCE1).unwrap());
    coinbase.extend_from_slice(&[0u8; MockPool::EXTRANONCE2_SIZE as usize]);
    coinbase.extend_from_slice(&notify.coinb2);
    let txid = block::sha256d(&[&coinbase]);
    assert_eq!(
        job.merkle_root,
        block::merkle_root(&txid, &notify.merkle_branch)
    );
}

#[test]
fn a_standard_share_is_forwarded_with_the_bridges_extranonce2_and_the_verdict_comes_back() {
    let mut rig = rig(false, 0);
    let job = next_job(&mut rig.miner);
    let sequence = rig.miner.submit(&job, 0xdead_beef, job.ntime).unwrap();

    let event = poll_until(&mut rig.miner, "a verdict", |e| {
        matches!(e, Event::ShareAccepted { .. } | Event::ShareRejected { .. })
    });
    assert!(
        matches!(event, Event::ShareAccepted { sequence_number, accepted_count: 1, .. } if sequence_number == sequence),
        "expected the pool's acceptance back under the miner's sequence number, got {event:?}"
    );

    let submitted = rig.pool.submissions();
    assert_eq!(submitted.len(), 1);
    let params = &submitted[0];
    assert_eq!(
        params[0].as_str(),
        Some(IDENTITY),
        "the identity goes up verbatim"
    );
    assert_eq!(params[1].as_str(), Some(MockPool::JOB_ID));
    assert_eq!(
        params[2].as_str(),
        Some("00000000"),
        "the bridge's extranonce2"
    );
    assert_eq!(params[3].as_str(), Some("6543210f"));
    assert_eq!(params[4].as_str(), Some("deadbeef"));
}

#[test]
fn an_extended_channel_gets_the_coinbase_halves_and_the_pools_extranonce() {
    let mut rig = rig(true, MockPool::EXTRANONCE2_SIZE as u16);
    let job = next_job(&mut rig.miner);
    let notify = mock_notify();

    let extended = job.extended.as_ref().expect("an extended job");
    assert_eq!(extended.coinbase_prefix, notify.coinb1);
    assert_eq!(extended.coinbase_suffix, notify.coinb2);
    assert_eq!(extended.merkle_path, notify.merkle_branch);
    assert_eq!(
        extended.extranonce_prefix,
        message::unhex(MockPool::EXTRANONCE1).unwrap(),
        "extranonce1 is the prefix"
    );
    assert_eq!(
        extended.extranonce_size,
        MockPool::EXTRANONCE2_SIZE as usize,
        "extranonce2 is the miner's half"
    );

    // The miner's extranonce travels up as extranonce2, byte for byte.
    let sequence = rig
        .miner
        .submit_with(&job, 7, job.ntime, &[1, 2, 3, 4])
        .unwrap();
    let event = poll_until(&mut rig.miner, "a verdict", |e| {
        matches!(e, Event::ShareAccepted { .. } | Event::ShareRejected { .. })
    });
    assert!(
        matches!(event, Event::ShareAccepted { sequence_number, .. } if sequence_number == sequence),
        "{event:?}"
    );
    let submitted = rig.pool.submissions();
    assert_eq!(submitted[0][2].as_str(), Some("01020304"));
    assert_eq!(submitted[0][4].as_str(), Some("00000007"));
}

#[test]
fn an_extended_channel_cannot_have_more_extranonce_than_the_pool_reserved() {
    let pool = MockPool::start();
    let (bridge, authority) = bridge_for(&pool);
    // The library's default asks for eight; the mock pool reserved four.
    let error = match MiningClient::connect(miner_config(&bridge, authority, true, 8)) {
        Ok(_) => panic!("the open should have been refused"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("min-extranonce-size-too-large"),
        "{error}"
    );
}

#[test]
fn the_pools_refusal_reaches_the_miner_as_a_stratum_v2_code() {
    let mut rig = rig(false, 0);
    rig.pool
        .set_verdict(Verdict::Reject(23, "low difficulty share".into()));
    let job = next_job(&mut rig.miner);
    let sequence = rig.miner.submit(&job, 1, job.ntime).unwrap();
    let event = poll_until(&mut rig.miner, "a verdict", |e| {
        matches!(e, Event::ShareRejected { .. })
    });
    let Event::ShareRejected {
        sequence_number,
        code,
    } = event
    else {
        unreachable!()
    };
    assert_eq!(sequence_number, sequence);
    assert_eq!(code, "difficulty-too-low");
}

#[test]
fn a_difficulty_change_moves_the_miners_target() {
    let mut rig = rig(false, 0);
    next_job(&mut rig.miner);
    assert_eq!(rig.miner.share_target(), expected_target());

    rig.pool
        .send(r#"{"id":null,"method":"mining.set_difficulty","params":[4096]}"#);
    let wanted = difficulty::target_from_difficulty(&POW_LIMIT, 4096.0).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while rig.miner.share_target() != wanted {
        assert!(Instant::now() < deadline, "the target never moved");
        rig.miner.poll(Duration::from_millis(100)).unwrap();
    }
}

#[test]
fn a_notify_on_the_same_tip_is_an_active_job_and_clean_jobs_forgets_the_old_one() {
    let mut rig = rig(false, 0);
    let first = next_job(&mut rig.miner);

    // Same tip, not clean: a second job, live from the start.
    rig.pool.send(&MockPool::notify("job2", false));
    let second = next_job(&mut rig.miner);
    assert_eq!(second.job_id, first.job_id + 1);
    assert_eq!(second.prev_hash, first.prev_hash);
    assert_ne!(
        second.merkle_root, first.merkle_root,
        "a fresh extranonce2 gives a fresh header"
    );

    // Same tip, clean: the first job is void at the pool, so the bridge no
    // longer holds it and says so rather than forwarding a share the pool
    // would refuse.
    rig.pool.send(&MockPool::notify("job3", true));
    let third = next_job(&mut rig.miner);
    assert_eq!(third.job_id, second.job_id + 1);
    let sequence = rig.miner.submit(&first, 5, first.ntime).unwrap();
    let event = poll_until(&mut rig.miner, "a verdict", |e| {
        matches!(e, Event::ShareRejected { .. })
    });
    assert!(
        matches!(event, Event::ShareRejected { sequence_number, ref code } if sequence_number == sequence && code == "invalid-job-id"),
        "{event:?}"
    );
    assert!(rig.pool.submissions().is_empty(), "nothing went up");

    // The current job still does.
    rig.miner.submit(&third, 6, third.ntime).unwrap();
    poll_until(&mut rig.miner, "an acceptance", |e| {
        matches!(e, Event::ShareAccepted { .. })
    });
    assert_eq!(rig.pool.submissions()[0][1].as_str(), Some("job3"));
}

#[test]
fn the_same_share_twice_is_refused_here_and_not_forwarded_twice() {
    let mut rig = rig(false, 0);
    let job = next_job(&mut rig.miner);
    rig.miner.submit(&job, 9, job.ntime).unwrap();
    poll_until(&mut rig.miner, "an acceptance", |e| {
        matches!(e, Event::ShareAccepted { .. })
    });
    let again = rig.miner.submit(&job, 9, job.ntime).unwrap();
    let event = poll_until(&mut rig.miner, "a refusal", |e| {
        matches!(e, Event::ShareRejected { .. })
    });
    assert!(
        matches!(event, Event::ShareRejected { sequence_number, ref code } if sequence_number == again && code == "duplicate-share"),
        "{event:?}"
    );
    assert_eq!(rig.pool.submissions().len(), 1);
}

#[test]
fn the_pool_hanging_up_ends_the_miners_session() {
    let mut rig = rig(false, 0);
    next_job(&mut rig.miner);
    rig.pool.hang_up();
    poll_until(&mut rig.miner, "a disconnect", |e| {
        matches!(e, Event::Disconnected { .. })
    });
}

#[test]
fn a_worker_the_pool_will_not_authorize_gets_no_channel() {
    let pool = MockPool::start();
    pool.set_authorize(false);
    let (bridge, authority) = bridge_for(&pool);
    let error = match MiningClient::connect(miner_config(&bridge, authority, false, 0)) {
        Ok(_) => panic!("the open should have been refused"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("unauthorized-worker"), "{error}");
}
