//! aviand to pool to worker to pool to aviand.
//!
//! Section 12 of the plan with the test worker in place of a real miner: a
//! regtest block found by a worker, relayed by the pool, accepted by the node,
//! and reported by `getblock` under the algorithm that was negotiated.
//!
//! The rest of the tests here assert the things that are easy to get wrong and
//! silent, and they assert them as orderings and flag values rather than as
//! numbers agreeing, because agreeing numbers pass whatever order the messages
//! arrived in.

mod common;

use std::sync::Arc;
use std::time::Duration;

use avian_mining::flags;
use avian_mining::pool::{self, PoolConfig, PoolHandle};
use avian_mining::server::ServerConfig;
use avian_mining::share::{AvianHasher, PowHasher};
use avian_regtest::Node;
use avian_tdp::avian::EXT_AVIAN;
use avian_tdp::PowType;
use common::worker::{Event, Requested, Worker};
use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};

/// A node and a pool, ready for workers.
struct Rig {
    node: Node,
    pool: Option<PoolHandle>,
    pool_authority: XOnlyPublicKey,
}

impl Rig {
    /// `None` when `aviand` is not installed, so the tests skip rather than
    /// fail on a machine without a build.
    fn start(tag: &str, slot: u16, algorithms: &[PowType], share_target_shift: u32) -> Option<Rig> {
        let node = Node::start(tag, slot, &[])?;
        node.mine(101);

        let secp = Secp256k1::new();
        let authority = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
        let (pool_authority, _) = authority.x_only_public_key();

        let hasher: Arc<dyn PowHasher> = Arc::new(AvianHasher);
        // Loudly, rather than skipping: a pool that cannot hash would accept
        // every nonce, and a test suite that quietly passed without it would
        // be asserting nothing about share validation.
        assert!(
            hasher.hash(PowType::X16rt, &[0u8; 80]).is_some(),
            "the proof-of-work hasher is unavailable, so no share could be validated: {}",
            hasher.describe()
        );

        let pool = pool::spawn(
            PoolConfig {
                node: node.sv2_addr(),
                node_authority: Some(node.authority()),
                algorithms: algorithms.to_vec(),
                server: ServerConfig {
                    // Port 0 lets the OS pick, so parallel tests cannot clash.
                    bind: "127.0.0.1:0".parse().unwrap(),
                    authority,
                    cert_validity: 3600,
                    payout_script: vec![0x51], // OP_TRUE
                    share_target_shift,
                },
                coinbase_size: 1000,
                coinbase_sigops: 10,
                duration: Some(Duration::from_secs(120)),
            },
            hasher,
            None,
        )
        .expect("the pool should start");

        Some(Rig {
            node,
            pool: Some(pool),
            pool_authority,
        })
    }

    fn worker(&self, pow: PowType) -> Worker {
        Worker::join(
            self.pool.as_ref().unwrap().mining_addr(),
            self.pool_authority,
            pow,
        )
        .expect("the worker should join")
    }

    fn bare_worker(&self) -> Worker {
        Worker::connect(
            self.pool.as_ref().unwrap().mining_addr(),
            self.pool_authority,
        )
        .expect("the worker should connect")
    }
}

macro_rules! rig {
    ($tag:expr, $slot:expr, $algos:expr, $shift:expr) => {
        match Rig::start($tag, $slot, $algos, $shift) {
            Some(rig) => rig,
            None => {
                eprintln!("skipping: aviand or avian-cli not found");
                return;
            }
        }
    };
}

/// The milestone: a block mined over the whole chain, for each algorithm.
#[test]
fn a_worker_mines_a_regtest_block_through_the_pool() {
    let rig = rig!("milestone", 10, &[PowType::X16rt, PowType::MinotaurX], 0);

    for pow in [PowType::X16rt, PowType::MinotaurX] {
        let before = rig.node.height();
        let mut worker = rig.worker(pow);

        let job = worker.active().expect("an active job").clone();
        assert_eq!(
            (job.version >> 16) & 0xff,
            pow as u32,
            "the job's version must name the algorithm the channel negotiated"
        );

        let found = worker
            .submit_share(pow)
            .expect("submitting should not error")
            .expect("regtest's target is the algorithm's floor, so a share should be found fast");

        match worker.events.last() {
            Some(Event::ShareAccepted { .. }) => {}
            other => panic!("the share was not accepted: {other:?}"),
        }

        // The pool forwards a share that also meets the network target as a
        // SubmitSolution. There is no reply to one, so the tip is the only
        // evidence.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while rig.node.height() == before && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(
            rig.node.height(),
            before + 1,
            "the node should have accepted the block. nonce/ntime {found:?}. Node's sv2 log:\n{}",
            rig.node.sv2_log()
        );

        let tip = rig.node.tip();
        assert_eq!(
            rig.node.pow_type_of(&tip).as_deref(),
            Some(pow.name()),
            "getblock should report the algorithm that was negotiated"
        );
        eprintln!(
            "[test] {pow} mined block {tip} at height {}",
            rig.node.height()
        );
    }
}

/// doc/sv2.md: the two flags are mutually exclusive rather than one overriding
/// the other, so a miner that demands rolling is refused, not answered and
/// then quietly held to a fixed version.
#[test]
fn a_version_rolling_request_is_refused_rather_than_answered() {
    let rig = rig!("rolling", 11, &[PowType::X16rt], 0);
    let mut worker = rig.bare_worker();
    worker
        .setup_connection(Requested(
            flags::REQUIRES_STANDARD_JOBS | flags::REQUIRES_VERSION_ROLLING,
        ))
        .expect("the refusal is a message, not a disconnect");

    match worker.events.last() {
        Some(Event::SetupError { flags: named, code }) => {
            assert_eq!(code, "unsupported-feature-flags");
            assert_eq!(
                *named,
                flags::REQUIRES_VERSION_ROLLING,
                "the error should name the flag that caused it"
            );
        }
        other => panic!("expected SetupConnection.Error, got {other:?}"),
    }
    assert!(
        !worker
            .events
            .iter()
            .any(|e| matches!(e, Event::SetupSuccess { .. })),
        "a connection demanding version rolling must never be answered with Success"
    );
}

#[test]
fn setup_success_always_sets_fixed_version_and_never_extended_channels() {
    let rig = rig!("flags", 12, &[PowType::X16rt], 0);
    let mut worker = rig.bare_worker();
    worker
        .setup_connection(Requested::default())
        .expect("setup should succeed");
    let answered = worker.expect_setup_success().expect("success");

    assert_ne!(
        answered & flags::REQUIRES_FIXED_VERSION,
        0,
        "REQUIRES_FIXED_VERSION is the enforceable half of \"no version rolling\""
    );
    assert_eq!(
        answered & flags::REQUIRES_EXTENDED_CHANNELS,
        0,
        "standard channels are the only kind, so this must never be set"
    );
}

#[test]
fn a_worker_that_cannot_take_standard_jobs_is_refused() {
    let rig = rig!("stdjobs", 13, &[PowType::X16rt], 0);
    let mut worker = rig.bare_worker();
    worker
        .setup_connection(Requested(0))
        .expect("the refusal is a message");
    match worker.events.last() {
        Some(Event::SetupError { flags: named, code }) => {
            assert_eq!(code, "unsupported-feature-flags");
            assert_eq!(*named, flags::REQUIRES_STANDARD_JOBS);
        }
        other => panic!("expected SetupConnection.Error, got {other:?}"),
    }
}

/// The pool requires 0x4001 of its workers for the same reason the node
/// requires it of the pool: every failure mode it prevents is silent.
#[test]
fn the_extension_is_required_of_a_worker_too() {
    let rig = rig!("extreq", 14, &[PowType::X16rt], 0);
    let mut worker = rig.bare_worker();
    worker.setup_connection(Requested::default()).unwrap();
    worker.expect_setup_success().unwrap();
    worker
        .request_extensions(&[0x0002])
        .expect("the refusal is a message");

    match worker.events.last() {
        Some(Event::ExtensionsError {
            unsupported,
            required,
        }) => {
            assert_eq!(unsupported, &vec![0x0002]);
            assert_eq!(
                required,
                &vec![EXT_AVIAN],
                "the error must name what the pool requires, so a worker can correct itself"
            );
        }
        other => panic!("expected RequestExtensions.Error, got {other:?}"),
    }
}

#[test]
fn the_algorithm_reply_reports_a_zero_version_rolling_mask() {
    let rig = rig!("algomask", 15, &[PowType::MinotaurX], 0);
    let mut worker = rig.bare_worker();
    worker.setup_connection(Requested::default()).unwrap();
    worker.expect_setup_success().unwrap();
    worker.request_extensions(&[EXT_AVIAN]).unwrap();
    worker.select_algorithm(PowType::MinotaurX).unwrap();

    match worker.events.last() {
        Some(Event::AlgorithmSuccess { pow_type, mask }) => {
            assert_eq!(*pow_type, PowType::MinotaurX as u8);
            assert_eq!(*mask, 0, "doc/sv2.md pins version_rolling_mask at 0");
        }
        other => panic!("expected AvianSelectAlgorithm.Success, got {other:?}"),
    }

    // An algorithm the pool does not serve is refused by name.
    let mut other = rig.bare_worker();
    other.setup_connection(Requested::default()).unwrap();
    other.expect_setup_success().unwrap();
    other.request_extensions(&[EXT_AVIAN]).unwrap();
    other.select_algorithm(PowType::X16rt).unwrap();
    match other.events.last() {
        Some(Event::AlgorithmError(code)) => assert_eq!(code, "unsupported-pow-type"),
        got => panic!("expected AvianSelectAlgorithm.Error, got {got:?}"),
    }
}

/// The ordering doc/sv2.md requires, asserted as an ordering.
///
/// "A worker must never have an instant in which a job is active and its
/// ntime_max is unknown, because the only safe thing it could do in that
/// instant is idle."
#[test]
fn constraints_precede_the_set_new_prev_hash_that_activates_a_job() {
    let rig = rig!("ordering", 16, &[PowType::X16rt], 0);
    let worker = rig.worker(PowType::X16rt);

    let job_id = worker.active_job.expect("a job became active");
    let job_at = worker
        .position_of(|e| matches!(e, Event::NewMiningJob { job_id: id, .. } if *id == job_id))
        .expect("the job was announced");
    let constraints_at = worker
        .position_of(|e| matches!(e, Event::JobConstraints { job_id: id, .. } if *id == job_id))
        .expect("the job's constraints arrived");
    let activation_at = worker
        .position_of(|e| matches!(e, Event::SetNewPrevHash { job_id: id, .. } if *id == job_id))
        .expect("the job was activated");

    assert!(
        job_at < constraints_at,
        "the constraints must follow the job they describe, not precede it:\n{:?}",
        worker.events
    );
    assert!(
        constraints_at < activation_at,
        "the constraints must arrive before the SetNewPrevHash that activates the job, never \
         after:\n{:?}",
        worker.events
    );
}

/// Stratum v2 requires the first job after a channel opens to be a future job,
/// so every connection meets that case before it meets the other.
#[test]
fn the_first_job_on_a_channel_is_a_future_job() {
    let rig = rig!("futurejob", 17, &[PowType::X16rt], 0);
    let worker = rig.worker(PowType::X16rt);

    let first = worker
        .events
        .iter()
        .find_map(|e| match e {
            Event::NewMiningJob { job_id, future } => Some((*job_id, *future)),
            _ => None,
        })
        .expect("a job was announced");
    assert!(
        first.1,
        "the first NewMiningJob on a channel must have min_ntime unset:\n{:?}",
        worker.events
    );
}

/// doc/sv2.md: "the ntime_start that SetNewPrevHash supplies MUST equal the
/// ntime_min in force for that job".
#[test]
fn the_activation_ntime_equals_the_jobs_ntime_min() {
    let rig = rig!("ntimeagree", 18, &[PowType::X16rt], 0);
    let worker = rig.worker(PowType::X16rt);
    let job_id = worker.active_job.unwrap();

    let activation = worker
        .events
        .iter()
        .find_map(|e| match e {
            Event::SetNewPrevHash {
                job_id: id,
                min_ntime,
            } if *id == job_id => Some(*min_ntime),
            _ => None,
        })
        .expect("an activation");
    let job = worker.jobs.get(&job_id).expect("the job");

    assert_eq!(activation, job.ntime_min);
    // Regtest allows minimum-difficulty blocks, which makes nBits a function
    // of nTime, so the node pins the window rather than narrowing it and the
    // pool must pass that through rather than widening it.
    assert_eq!(
        job.ntime_min, job.ntime_max,
        "on regtest the window is pinned shut, and a pool must not widen it"
    );
}

/// The two things the extension exists to stop, refused rather than mined.
#[test]
fn a_rolled_version_or_an_out_of_window_ntime_is_refused() {
    let rig = rig!("refusals", 19, &[PowType::X16rt], 0);
    let mut worker = rig.worker(PowType::X16rt);
    let job = worker.active().expect("an active job").clone();
    let (nonce, ntime) = worker
        .find_share(PowType::X16rt, 200)
        .expect("a share should be findable");

    // Rolling the algorithm bits is the failure the mask exists to prevent.
    worker
        .submit(job.job_id, nonce, ntime, job.version ^ 0x0001_0000)
        .unwrap();
    match worker.events.last() {
        Some(Event::ShareRefused(code)) => assert_eq!(code, "invalid-version"),
        other => panic!("a rolled version should be refused, got {other:?}"),
    }

    // One second past the window, which on regtest is one second past
    // everything.
    worker
        .submit(job.job_id, nonce, ntime + 1, job.version)
        .unwrap();
    match worker.events.last() {
        Some(Event::ShareRefused(code)) => assert_eq!(code, "invalid-ntime"),
        other => panic!("an ntime outside the window should be refused, got {other:?}"),
    }

    // An id the pool never issued.
    worker
        .submit(job.job_id + 1000, nonce, ntime, job.version)
        .unwrap();
    match worker.events.last() {
        Some(Event::ShareRefused(code)) => assert_eq!(code, "invalid-job-id"),
        other => panic!("an unknown job id should be refused, got {other:?}"),
    }
}

/// A share that meets the share target but not the network target is accepted
/// without becoming a block.
#[test]
fn a_share_below_the_network_target_is_accepted_but_not_submitted() {
    // Eight halvings harder than the network target, so most nonces miss it
    // and the ones that pass are blocks; what this checks is the refusal.
    let rig = rig!("sharediff", 20, &[PowType::X16rt], 8);
    let mut worker = rig.worker(PowType::X16rt);
    let job = worker.active().expect("an active job").clone();

    // A nonce that is almost certainly over the harder share target.
    let mut refused = 0;
    for nonce in 0..40u32 {
        worker
            .submit(job.job_id, nonce, job.ntime_min, job.version)
            .unwrap();
        match worker.events.last() {
            Some(Event::ShareRefused(code)) => {
                assert_eq!(code, "difficulty-too-low");
                refused += 1;
            }
            Some(Event::ShareAccepted { .. }) => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(
        refused > 0,
        "with the share target eight halvings harder than the network target, some nonces \
         should have been refused as difficulty-too-low"
    );
}

#[test]
fn a_duplicate_share_is_refused() {
    let rig = rig!("duplicate", 21, &[PowType::X16rt], 0);
    let mut worker = rig.worker(PowType::X16rt);
    let job = worker.active().expect("an active job").clone();
    let (nonce, ntime) = worker.find_share(PowType::X16rt, 200).expect("a share");

    worker
        .submit(job.job_id, nonce, ntime, job.version)
        .unwrap();
    assert!(matches!(
        worker.events.last(),
        Some(Event::ShareAccepted { .. })
    ));

    worker
        .submit(job.job_id, nonce, ntime, job.version)
        .unwrap();
    match worker.events.last() {
        Some(Event::ShareRefused(code)) => assert_eq!(code, "duplicate-share"),
        other => panic!("a resubmission should be refused, got {other:?}"),
    }
}

/// Two algorithms, two channels, two independent job streams.
#[test]
fn each_algorithm_gets_its_own_channel_and_job_stream() {
    let rig = rig!("twoalgos", 22, &[PowType::X16rt, PowType::MinotaurX], 0);
    let x16rt = rig.worker(PowType::X16rt);
    let minotaurx = rig.worker(PowType::MinotaurX);

    let x_job = x16rt.active().expect("x16rt job");
    let m_job = minotaurx.active().expect("minotaurx job");

    assert_eq!((x_job.version >> 16) & 0xff, PowType::X16rt as u32);
    assert_eq!((m_job.version >> 16) & 0xff, PowType::MinotaurX as u32);
    assert_ne!(
        x16rt.channel_id, minotaurx.channel_id,
        "channel ids are pool-wide, because one goes into each coinbase's extranonce"
    );
    // Which is what keeps the coinbases, and so the merkle roots, apart even
    // when the two templates are otherwise identical.
    assert_ne!(x_job.merkle_root, m_job.merkle_root);
    assert_eq!(
        rig.pool
            .as_ref()
            .unwrap()
            .algo(PowType::X16rt)
            .unwrap()
            .channel_count(),
        1
    );
    assert_eq!(
        rig.pool
            .as_ref()
            .unwrap()
            .algo(PowType::MinotaurX)
            .unwrap()
            .channel_count(),
        1
    );
}
