//! aviand to pool to miner to pool to aviand, through the library.
//!
//! Section 12 of the plan with `libavian-sv2`'s own Mining Protocol client
//! standing in for a real miner: a regtest block found by hashing, relayed by
//! the pool, accepted by the node, and reported by `getblock` under the
//! algorithm that was negotiated.
//!
//! The client here is the product, not a test double. The test worker that
//! used to live in this directory was promoted into the library, so these
//! tests exercise the thing that was extracted rather than a parallel copy of
//! it. That is the failure mode a refactor like this has: quietly stopping
//! exercising what it moved.
//!
//! The rest of the tests assert the things that are easy to get wrong and
//! silent, and they assert them as orderings and flag values rather than as
//! numbers agreeing, because agreeing numbers pass whatever order the messages
//! arrived in.

mod common;

use std::time::{Duration, Instant};

use avian_sv2::avian::PowType;
use avian_sv2::client::{Event, MiningClient, Trace};
use avian_sv2::flags;
use common::{
    expect_job, find_share, poll_event, position_of, raw_request_extensions, raw_setup, trace, Rig,
    SetupAnswer, AVIAN_EXTENSION,
};

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

/// The milestone, now routed through the library.
#[test]
fn a_miner_mines_a_regtest_block_through_the_pool() {
    let rig = rig!("milestone", 10, &[PowType::X16rt, PowType::MinotaurX], 0);

    for pow in [PowType::X16rt, PowType::MinotaurX] {
        let before = rig.node.height();
        let mut miner = rig.miner(pow);

        let job = miner.active_job().expect("an active job").clone();
        assert_eq!(
            job.pow_type, pow,
            "the job's version must name the algorithm the channel negotiated"
        );

        let (nonce, ntime) = find_share(&job, 400)
            .expect("regtest's target is the algorithm's floor, so a share should come fast");
        miner.submit(&job, nonce, ntime).expect("submit");

        match poll_event(&mut miner, Duration::from_secs(30)) {
            Some(Event::ShareAccepted { .. }) => {}
            other => panic!("the share was not accepted: {other:?}"),
        }

        // The pool forwards a share that also meets the network target as a
        // SubmitSolution. There is no reply to one, so the tip is the only
        // evidence.
        let deadline = Instant::now() + Duration::from_secs(30);
        while rig.node.height() == before && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(
            rig.node.height(),
            before + 1,
            "the node should have accepted the block. nonce {nonce} ntime {ntime}. \
             Node's sv2 log:\n{}",
            rig.node.sv2_log()
        );

        let tip = rig.node.tip();
        assert_eq!(
            rig.node.pow_type_of(&tip).as_deref(),
            Some(pow.name()),
            "getblock should report the algorithm that was negotiated"
        );
        eprintln!(
            "[test] {pow} mined block {tip} at height {} through libavian-sv2",
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
    match raw_setup(
        &rig,
        flags::REQUIRES_STANDARD_JOBS | flags::REQUIRES_VERSION_ROLLING,
    ) {
        SetupAnswer::Error { flags: named, code } => {
            assert_eq!(code, "unsupported-feature-flags");
            assert_eq!(
                named,
                flags::REQUIRES_VERSION_ROLLING,
                "the error should name the flag that caused it"
            );
        }
        SetupAnswer::Success { .. } => {
            panic!("a connection demanding version rolling must never be answered with Success")
        }
    }
}

#[test]
fn setup_success_always_sets_fixed_version_and_never_extended_channels() {
    let rig = rig!("flags", 12, &[PowType::X16rt], 0);
    match raw_setup(&rig, flags::REQUIRES_STANDARD_JOBS) {
        SetupAnswer::Success { flags: answered } => {
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
        SetupAnswer::Error { code, .. } => panic!("expected Success, got {code}"),
    }
}

#[test]
fn a_miner_that_cannot_take_standard_jobs_is_refused() {
    let rig = rig!("stdjobs", 13, &[PowType::X16rt], 0);
    match raw_setup(&rig, 0) {
        SetupAnswer::Error { flags: named, code } => {
            assert_eq!(code, "unsupported-feature-flags");
            assert_eq!(named, flags::REQUIRES_STANDARD_JOBS);
        }
        SetupAnswer::Success { .. } => panic!("expected SetupConnection.Error"),
    }
}

/// The pool requires 0x4001 of its miners for the same reason the node
/// requires it of the pool: every failure mode it prevents is silent.
#[test]
fn the_extension_is_required_of_a_miner_too() {
    let rig = rig!("extreq", 14, &[PowType::X16rt], 0);
    let (unsupported, required, accepted) = raw_request_extensions(&rig, &[0x0002]);
    assert!(!accepted);
    assert_eq!(unsupported, vec![0x0002]);
    assert_eq!(
        required,
        vec![AVIAN_EXTENSION],
        "the error must name what the pool requires, so a miner can correct itself"
    );

    let (accepted_list, _, accepted) = raw_request_extensions(&rig, &[AVIAN_EXTENSION]);
    assert!(accepted);
    assert_eq!(accepted_list, vec![AVIAN_EXTENSION]);
}

/// The client refuses a non-zero mask rather than rolling, and the pool never
/// sends one. Both halves matter: a mask the client ignored would be a silent
/// algorithm switch.
#[test]
fn the_algorithm_reply_reports_a_zero_version_rolling_mask() {
    let rig = rig!("algomask", 15, &[PowType::MinotaurX], 0);
    let miner = rig.miner(PowType::MinotaurX);
    let entries = trace(&miner);
    let mask = entries
        .iter()
        .find_map(|entry| match entry {
            Trace::AlgorithmSuccess { pow_type, mask } => Some((*pow_type, *mask)),
            _ => None,
        })
        .expect("AvianSelectAlgorithm.Success");
    assert_eq!(mask.0, PowType::MinotaurX);
    assert_eq!(mask.1, 0, "doc/sv2.md pins version_rolling_mask at 0");

    // An algorithm the pool does not serve is refused by name, and the client
    // reports the refusal rather than retrying it forever.
    let config = rig.client_config(PowType::X16rt);
    let error = match MiningClient::connect(config) {
        Ok(_) => panic!("x16rt is not served by this pool and should have been refused"),
        Err(e) => e,
    };
    assert!(
        error.to_string().contains("unsupported-pow-type"),
        "unexpected error: {error}"
    );
}

/// The ordering doc/sv2.md requires, asserted as an ordering.
///
/// "A worker must never have an instant in which a job is active and its
/// ntime_max is unknown, because the only safe thing it could do in that
/// instant is idle."
#[test]
fn constraints_precede_the_set_new_prev_hash_that_activates_a_job() {
    let rig = rig!("ordering", 16, &[PowType::X16rt], 0);
    let miner = rig.miner(PowType::X16rt);
    let entries = trace(&miner);
    let job_id = miner.active_job().expect("an active job").job_id;

    let job_at = position_of(
        &entries,
        |e| matches!(e, Trace::NewMiningJob { job_id: id, .. } if *id == job_id),
    )
    .expect("the job was announced");
    let constraints_at = position_of(
        &entries,
        |e| matches!(e, Trace::JobConstraints { job_id: id, .. } if *id == job_id),
    )
    .expect("the job's constraints arrived");
    let activation_at = position_of(
        &entries,
        |e| matches!(e, Trace::SetNewPrevHash { job_id: id, .. } if *id == job_id),
    )
    .expect("the job was activated");

    assert!(
        job_at < constraints_at,
        "the constraints must follow the job they describe:\n{entries:?}"
    );
    assert!(
        constraints_at < activation_at,
        "the constraints must arrive before the SetNewPrevHash that activates the job, never \
         after:\n{entries:?}"
    );
}

/// Stratum v2 requires the first job after a channel opens to be a future job,
/// so every connection meets that case before it meets the other.
#[test]
fn the_first_job_on_a_channel_is_a_future_job() {
    let rig = rig!("futurejob", 17, &[PowType::X16rt], 0);
    let miner = rig.miner(PowType::X16rt);
    let entries = trace(&miner);
    let first = entries
        .iter()
        .find_map(|e| match e {
            Trace::NewMiningJob { job_id, future } => Some((*job_id, *future)),
            _ => None,
        })
        .expect("a job was announced");
    assert!(
        first.1,
        "the first NewMiningJob on a channel must have min_ntime unset:\n{entries:?}"
    );
}

/// doc/sv2.md: "the ntime_start that SetNewPrevHash supplies MUST equal the
/// ntime_min in force for that job".
///
/// The client enforces this itself and errors if it is broken, so reaching an
/// active job at all is half the assertion; this pins the value too.
#[test]
fn the_activation_ntime_equals_the_jobs_ntime_min() {
    let rig = rig!("ntimeagree", 18, &[PowType::X16rt], 0);
    let miner = rig.miner(PowType::X16rt);
    let job = miner.active_job().expect("an active job");
    let entries = trace(&miner);

    let activation = entries
        .iter()
        .find_map(|e| match e {
            Trace::SetNewPrevHash { job_id, min_ntime } if *job_id == job.job_id => {
                Some(*min_ntime)
            }
            _ => None,
        })
        .expect("an activation");
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
    let mut miner = rig.miner(PowType::X16rt);
    let job = miner.active_job().expect("an active job").clone();
    let (nonce, ntime) = find_share(&job, 400).expect("a share should be findable");

    // The client will not roll the version through `submit`, so this goes
    // through `submit_exact`, which is the API for "send precisely this".
    miner
        .submit_exact(job.job_id, nonce, ntime, job.version ^ 0x0001_0000)
        .unwrap();
    match poll_event(&mut miner, Duration::from_secs(10)) {
        Some(Event::ShareRejected { code, .. }) => assert_eq!(code, "invalid-version"),
        other => panic!("a rolled version should be refused, got {other:?}"),
    }

    // The client refuses an out-of-window ntime before it reaches the wire,
    // which is the behaviour a miner wants: there is no point spending a round
    // trip to be told no.
    let refused = miner.submit(&job, nonce, ntime + 1).unwrap_err();
    assert!(
        refused.to_string().contains("outside the job's window"),
        "unexpected error: {refused}"
    );

    // Sent anyway, the pool refuses it.
    miner
        .submit_exact(job.job_id, nonce, ntime + 1, job.version)
        .unwrap();
    match poll_event(&mut miner, Duration::from_secs(10)) {
        Some(Event::ShareRejected { code, .. }) => assert_eq!(code, "invalid-ntime"),
        other => panic!("an ntime outside the window should be refused, got {other:?}"),
    }

    miner
        .submit_exact(job.job_id + 1000, nonce, ntime, job.version)
        .unwrap();
    match poll_event(&mut miner, Duration::from_secs(10)) {
        Some(Event::ShareRejected { code, .. }) => assert_eq!(code, "invalid-job-id"),
        other => panic!("an unknown job id should be refused, got {other:?}"),
    }
}

#[test]
fn a_share_below_the_network_target_is_accepted_but_not_submitted() {
    // Eight halvings harder than the network target, so most nonces miss it;
    // what this checks is the refusal.
    let rig = rig!("sharediff", 20, &[PowType::X16rt], 8);
    let mut miner = rig.miner(PowType::X16rt);
    let job = miner.active_job().expect("an active job").clone();

    let mut refused = 0;
    for nonce in 0..40u32 {
        miner
            .submit_exact(job.job_id, nonce, job.ntime_min, job.version)
            .unwrap();
        match poll_event(&mut miner, Duration::from_secs(10)) {
            Some(Event::ShareRejected { code, .. }) => {
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
    let mut miner = rig.miner(PowType::X16rt);
    let job = miner.active_job().expect("an active job").clone();
    let (nonce, ntime) = find_share(&job, 400).expect("a share");

    miner.submit(&job, nonce, ntime).unwrap();
    assert!(matches!(
        poll_event(&mut miner, Duration::from_secs(10)),
        Some(Event::ShareAccepted { .. })
    ));

    miner.submit(&job, nonce, ntime).unwrap();
    match poll_event(&mut miner, Duration::from_secs(10)) {
        Some(Event::ShareRejected { code, .. }) => assert_eq!(code, "duplicate-share"),
        other => panic!("a resubmission should be refused, got {other:?}"),
    }
}

/// Two algorithms, two channels, two independent job streams.
#[test]
fn each_algorithm_gets_its_own_channel_and_job_stream() {
    let rig = rig!("twoalgos", 22, &[PowType::X16rt, PowType::MinotaurX], 0);
    let x16rt = rig.miner(PowType::X16rt);
    let minotaurx = rig.miner(PowType::MinotaurX);

    let x_job = x16rt.active_job().expect("x16rt job");
    let m_job = minotaurx.active_job().expect("minotaurx job");

    assert_eq!(x_job.pow_type, PowType::X16rt);
    assert_eq!(m_job.pow_type, PowType::MinotaurX);
    assert_ne!(
        x16rt.channel_id(),
        minotaurx.channel_id(),
        "channel ids are pool-wide, because one goes into each coinbase's extranonce"
    );
    // Which is what keeps the coinbases, and so the merkle roots, apart even
    // when the two templates are otherwise identical.
    assert_ne!(x_job.merkle_root, m_job.merkle_root);
    assert_eq!(rig.pool.algo(PowType::X16rt).unwrap().channel_count(), 1);
    assert_eq!(
        rig.pool.algo(PowType::MinotaurX).unwrap().channel_count(),
        1
    );
}

/// Reconnection downstream, as reconnection: the socket is really closed, the
/// pool really sees a peer go away, and the client really does a fresh Noise
/// handshake and opens a new channel.
#[test]
fn a_miner_reconnects_after_the_connection_drops_and_resumes_mining() {
    let rig = rig!("reconnect-down", 23, &[PowType::X16rt], 0);
    let mut miner = rig.miner(PowType::X16rt);

    let first_generation = miner.generation();
    let first_channel = miner.channel_id().expect("a channel");
    let first_job = miner.active_job().expect("a job").clone();
    assert_eq!(first_job.generation, first_generation);

    // A real close, not a simulated one: the pool's side ends with
    // "worker session ended".
    miner.disconnect();
    assert!(!miner.is_connected());
    assert!(
        miner.active_job().is_none(),
        "every job must be dropped on a disconnect, because job ids restart"
    );

    match miner.poll(Duration::from_secs(30)) {
        Ok(Event::Reconnected {
            generation,
            attempts,
        }) => {
            assert_eq!(generation, first_generation + 1);
            assert!(attempts >= 1);
        }
        other => panic!("expected a reconnect, got {other:?}"),
    }
    assert!(miner.is_connected());

    // A new channel, from a fresh handshake and a fresh negotiation.
    let second_channel = miner.channel_id().expect("a channel");
    assert_ne!(
        first_channel, second_channel,
        "a reconnect must open a new channel, not resume the old one"
    );

    // And work resumes: a job arrives and a share is accepted on it.
    let job = expect_job(&mut miner);
    assert_eq!(job.generation, first_generation + 1);
    let (nonce, ntime) = find_share(&job, 400).expect("a share");
    miner.submit(&job, nonce, ntime).expect("submit");
    match poll_event(&mut miner, Duration::from_secs(30)) {
        Some(Event::ShareAccepted { accepted_count, .. }) => assert_eq!(
            accepted_count, 1,
            "the pool's accepted count starts again on a new channel"
        ),
        other => panic!("mining did not resume: {other:?}"),
    }
}

/// A share against a job from before the reconnect is refused, which is why
/// the generation counter exists.
#[test]
fn work_from_before_a_reconnect_cannot_be_submitted() {
    let rig = rig!("reconnect-stale", 24, &[PowType::X16rt], 0);
    let mut miner = rig.miner(PowType::X16rt);
    let stale = miner.active_job().expect("a job").clone();

    miner.disconnect();
    match miner.poll(Duration::from_secs(30)) {
        Ok(Event::Reconnected { .. }) => {}
        other => panic!("expected a reconnect, got {other:?}"),
    }
    expect_job(&mut miner);

    // The client knows the job is gone and says so without a round trip.
    let refused = miner
        .submit(&stale, 0, stale.ntime_min)
        .expect_err("a job from a previous generation is gone");
    assert!(
        refused.to_string().contains("does not survive a reconnect"),
        "unexpected error: {refused}"
    );
}

/// Reconnection upstream: the node goes away and comes back, and the pool
/// re-establishes its Template Distribution session and resumes serving.
#[test]
fn the_pool_reconnects_to_the_node_and_resumes_serving() {
    let Some(node) = avian_regtest::Node::start("reconnect-up", 25, &[]) else {
        eprintln!("skipping: aviand or avian-cli not found");
        return;
    };
    node.mine(101);
    let Some(mut rig) = Rig::attach(node, &[PowType::X16rt], 0) else {
        return;
    };

    let mut miner = rig.miner(PowType::X16rt);
    let before = miner.active_job().expect("a job").clone();

    // Stop the node and bring it back on the same datadir, so it keeps its
    // authority key and the pool's pinned key still matches.
    rig.node.stop();
    rig.node.start_again();
    // A restarted regtest node is in initial block download until the tip
    // moves, and refuses to build templates until then, silently.
    rig.node.mine(1);

    // The pool's upstream thread reconnects on its own and pushes fresh work.
    // The miner sees its old jobs withdrawn and new ones arrive; what it must
    // not see is silence.
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut resumed = None;
    while Instant::now() < deadline {
        match miner.poll(Duration::from_millis(250)) {
            Ok(Event::Job(job)) if job.job_id != before.job_id => {
                resumed = Some(job);
                break;
            }
            Ok(_) => {}
            Err(e) => panic!("the miner failed: {e}"),
        }
    }
    let job = resumed.expect("the pool should have resumed serving after the node came back");

    // And the resumed work is good all the way back to the node: a share on it
    // is accepted, which means the pool rebuilt its session, got a new
    // template, and built a coinbase the node accepts.
    let (nonce, ntime) = find_share(&job, 400).expect("a share");
    miner.submit(&job, nonce, ntime).expect("submit");
    match poll_event(&mut miner, Duration::from_secs(30)) {
        Some(Event::ShareAccepted { .. }) => {}
        other => panic!("the resumed share was not accepted: {other:?}"),
    }
    eprintln!(
        "[test] the pool reconnected to the node and resumed; node at height {}",
        rig.node.height()
    );
}
