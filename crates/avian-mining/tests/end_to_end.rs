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

// These tests hash, so they need the hashers the `pow` feature links.
#![cfg(feature = "pow")]

mod common;

use std::time::{Duration, Instant};

use avian_sv2::avian::EXT_CORE;
use avian_sv2::avian::{PowType, EXT_AVIAN_BLOCKS};
use avian_sv2::block;
use avian_sv2::client::{Event, MiningClient, Trace};
use avian_sv2::flags;
use common::{
    expect_job, find_share, open_standard, open_standard_on, poll_event, position_of, raw_ready,
    raw_request_extensions, raw_setup, trace, Rig, SetupAnswer, AVIAN_EXTENSION, WORKER_ADDRESS,
};
use mining_sv2::{
    CloseChannel, NewMiningJob, OpenMiningChannelError, OpenStandardMiningChannel, UpdateChannel,
    UpdateChannelError, MESSAGE_TYPE_CLOSE_CHANNEL, MESSAGE_TYPE_NEW_MINING_JOB,
    MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR, MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
    MESSAGE_TYPE_UPDATE_CHANNEL, MESSAGE_TYPE_UPDATE_CHANNEL_ERROR,
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
    let rig = rig!("milestone", 10, &[PowType::X16rt, PowType::MinotaurX], None);

    for pow in [PowType::X16rt, PowType::MinotaurX] {
        rig.wait_for_tip(pow);
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
        // SubmitSolution. Its reply would say only that validation took the
        // block, so the tip is the evidence that it connected.
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
    let rig = rig!("rolling", 11, &[PowType::X16rt], None);
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
    let rig = rig!("flags", 12, &[PowType::X16rt], None);
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
    let rig = rig!("stdjobs", 13, &[PowType::X16rt], None);
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
    let rig = rig!("extreq", 14, &[PowType::X16rt], None);
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
    assert_eq!(
        accepted_list,
        vec![AVIAN_EXTENSION],
        "a miner that asks for one extension is told it got one: block \
         notifications are not handed out unasked, which is the whole point of \
         them having their own identifier"
    );
}

/// One connection carries as many channels as the worker opens.
///
/// The pool used to open exactly one, before the message loop, and anything
/// arriving afterwards that was not a share on that channel reached the
/// catch-all arm. A proxy aggregating several rigs is the ordinary reason to
/// want more than one, and the specification has always allowed it.
///
/// The library client is one channel per connection, so this drives the wire
/// directly. Both channels are on the connection's algorithm: `SelectAlgorithm`
/// is still connection-scoped, which is the next thing to change.
#[test]
fn one_connection_carries_several_channels() {
    let rig = rig!("multichan", 94, &[PowType::X16rt], None);
    let mut conn = raw_ready(&rig, PowType::X16rt);

    let (first, before) = open_standard(&mut conn, 1, WORKER_ADDRESS);
    let (second, between) = open_standard(&mut conn, 2, WORKER_ADDRESS);
    assert_ne!(
        first, second,
        "each channel gets an id of its own, or nothing can be routed to it"
    );

    // Both are live, not merely recorded. A channel the pool opened but did
    // not register is one the publisher never reaches, and the only thing
    // that tells the two apart from out here is whether work arrives for it.
    // The frames read past during the second open are where the first
    // channel's job is, which is why the helper hands them back.
    fn note(worked: &mut std::collections::HashSet<u32>, frame: avian_sv2::transport::Frame) {
        if frame.msg_type == MESSAGE_TYPE_NEW_MINING_JOB {
            let mut payload = frame.payload;
            let job: NewMiningJob = binary_sv2::from_bytes(&mut payload).expect("decode job");
            worked.insert(job.channel_id);
        }
    }
    let mut worked = std::collections::HashSet::new();
    for frame in before.into_iter().chain(between) {
        note(&mut worked, frame);
    }
    // The second channel is answered and then served, so its own job is still
    // in flight when its open returns. Drain until both have one.
    let deadline = Instant::now() + Duration::from_secs(10);
    while worked.len() < 2 && Instant::now() < deadline {
        let Ok(frame) = conn.recv() else { break };
        note(&mut worked, frame);
    }
    assert!(
        worked.contains(&first) && worked.contains(&second),
        "both channels should have been pushed work on opening, saw {worked:?} \
         for channels {first} and {second}"
    );

    // Closing one closes one. The pool used to end the whole session on a
    // CloseChannel, which with several channels on a connection would take
    // down every other worker behind a proxy.
    let reason: &[u8] = b"done";
    conn.send(
        EXT_CORE,
        MESSAGE_TYPE_CLOSE_CHANNEL,
        true,
        CloseChannel {
            channel_id: first,
            reason_code: reason.try_into().unwrap(),
        },
    )
    .expect("send close");

    // Probing with UpdateChannel rather than waiting for the next job,
    // because work only arrives on a template refresh and that is a test
    // spent asleep. The closed channel must now be unknown, and saying so
    // proves three things at once: the connection survived the close, the
    // channel really was removed, and the id is being routed rather than
    // assumed.
    let max_target = [0xffu8; 32];
    for id in [first, second] {
        conn.send(
            EXT_CORE,
            MESSAGE_TYPE_UPDATE_CHANNEL,
            true,
            UpdateChannel {
                channel_id: id,
                nominal_hash_rate: 2_000_000.0,
                maximum_target: max_target.as_slice().try_into().unwrap(),
            },
        )
        .expect("send update");
    }

    let mut refused = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let Ok(frame) = conn.recv() else { break };
        if frame.msg_type == MESSAGE_TYPE_UPDATE_CHANNEL_ERROR {
            let mut payload = frame.payload;
            let error: UpdateChannelError =
                binary_sv2::from_bytes(&mut payload).expect("decode update error");
            refused.push(error.channel_id);
        }
    }
    assert_eq!(
        refused,
        vec![first],
        "only the closed channel should be unknown; the survivor must still be \
         served on the same connection"
    );
}

/// Two algorithms on one connection, one per channel.
///
/// `AvianSelectAlgorithm` settles the connection's algorithm and used to
/// settle every channel's with it, because there was only ever one channel.
/// A channel now overrides it with a `pow_type` TLV field on its open, which
/// is what lets a proxy put mixed rigs behind a single upstream connection
/// instead of one connection per algorithm.
///
/// The proof is which job each channel is sent: a job carries the template's
/// version, and the algorithm lives in bits 16-23 of it, so the work itself
/// says which algorithm the pool thinks that channel is on. Nothing else
/// visible from out here distinguishes the two.
#[test]
fn a_channel_can_carry_an_algorithm_the_connection_did_not_select() {
    let rig = rig!(
        "perchanalgo",
        95,
        &[PowType::X16rt, PowType::MinotaurX],
        None
    );
    // The connection selects X16RT, so a channel that says nothing gets it.
    let mut conn = raw_ready(&rig, PowType::X16rt);

    let (inherited, a) = open_standard_on(&mut conn, 1, WORKER_ADDRESS, None);
    let (overridden, b) = open_standard_on(&mut conn, 2, WORKER_ADDRESS, Some(PowType::MinotaurX));
    assert_ne!(inherited, overridden);

    fn note(seen: &mut std::collections::HashMap<u32, u32>, frame: avian_sv2::transport::Frame) {
        if frame.msg_type == MESSAGE_TYPE_NEW_MINING_JOB {
            let mut payload = frame.payload;
            let job: NewMiningJob = binary_sv2::from_bytes(&mut payload).expect("decode job");
            seen.entry(job.channel_id).or_insert(job.version);
        }
    }
    let mut seen = std::collections::HashMap::new();
    for frame in a.into_iter().chain(b) {
        note(&mut seen, frame);
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while seen.len() < 2 && Instant::now() < deadline {
        let Ok(frame) = conn.recv() else { break };
        note(&mut seen, frame);
    }

    let pow_of = |version: u32| ((version >> 16) & 0xff) as u8;
    let inherited_version = *seen
        .get(&inherited)
        .unwrap_or_else(|| panic!("channel {inherited} was never sent work"));
    let overridden_version = *seen
        .get(&overridden)
        .unwrap_or_else(|| panic!("channel {overridden} was never sent work"));

    assert_eq!(
        pow_of(inherited_version),
        PowType::X16rt as u8,
        "a channel that sent no pow_type field must inherit the connection's \
         algorithm, or every miner built before the field changes algorithm \
         on upgrade"
    );
    assert_eq!(
        pow_of(overridden_version),
        PowType::MinotaurX as u8,
        "the channel asked for MinotaurX and must be served MinotaurX work, \
         on the same connection as an X16RT channel"
    );
}

/// An algorithm the pool does not serve is refused, and only that channel is.
#[test]
fn a_channel_asking_for_an_algorithm_the_pool_lacks_is_refused_alone() {
    // X16RT only, so a channel asking for MinotaurX is asking for something
    // the chain defines and this pool was not configured to serve.
    let rig = rig!("perchanrefuse", 96, &[PowType::X16rt], None);
    let mut conn = raw_ready(&rig, PowType::X16rt);

    let (good, _) = open_standard_on(&mut conn, 1, WORKER_ADDRESS, None);

    let mut payload = binary_sv2::to_bytes(OpenStandardMiningChannel {
        request_id: 2,
        user_identity: WORKER_ADDRESS.as_bytes().try_into().unwrap(),
        nominal_hash_rate: 1_000_000.0,
        max_target: [0xffu8; 32].as_slice().try_into().unwrap(),
    })
    .expect("encode");
    avian_sv2::tlv::append(
        &mut payload,
        &[avian_sv2::tlv::Field::u8(
            AVIAN_EXTENSION,
            avian_sv2::avian::TLV_FIELD_POW_TYPE,
            PowType::MinotaurX as u8,
        )],
    )
    .expect("append");
    conn.send_raw(
        EXT_CORE,
        MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
        false,
        &payload,
    )
    .expect("send open");

    let mut code = None;
    let deadline = Instant::now() + Duration::from_secs(10);
    while code.is_none() && Instant::now() < deadline {
        let Ok(frame) = conn.recv() else { break };
        if frame.msg_type == MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR {
            let mut payload = frame.payload;
            let error: OpenMiningChannelError =
                binary_sv2::from_bytes(&mut payload).expect("decode open error");
            code = Some(String::from_utf8_lossy(error.error_code.as_ref()).into_owned());
        }
    }
    assert_eq!(
        code.as_deref(),
        Some("pow-type-not-enabled"),
        "the chain defines MinotaurX, so this is the operator's configuration \
         and not the worker's mistake, and the code has to say which"
    );

    // And the connection stands, with the channel it already had. Refusing a
    // channel is not refusing a connection: behind a proxy, one rig asking
    // for an algorithm the pool does not serve must not disconnect the rest.
    let max_target = [0xffu8; 32];
    conn.send(
        EXT_CORE,
        MESSAGE_TYPE_UPDATE_CHANNEL,
        true,
        UpdateChannel {
            channel_id: good,
            nominal_hash_rate: 2_000_000.0,
            maximum_target: max_target.as_slice().try_into().unwrap(),
        },
    )
    .expect("the connection should still be up");

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        let Ok(frame) = conn.recv() else { break };
        assert_ne!(
            frame.msg_type, MESSAGE_TYPE_UPDATE_CHANNEL_ERROR,
            "the surviving channel must still be known to the pool"
        );
    }
}

/// A message number the pool does not serve, inside an extension it granted,
/// is read past rather than treated as a violation.
///
/// Message numbers inside an extension grow over time, and negotiating an
/// `extension_type` says nothing about which of those numbers either side
/// knows, because the two were built at different times. Without this rule,
/// the first message added to `0x4001` ends the session of every worker built
/// before it, which is exactly what happened when block notifications were
/// first wired up here.
#[test]
fn an_unknown_message_in_a_negotiated_extension_is_ignored() {
    let rig = rig!("unknownmsg", 97, &[PowType::X16rt], None);
    let mut conn = raw_ready(&rig, PowType::X16rt);
    let (first, _) = open_standard(&mut conn, 1, WORKER_ADDRESS);

    // 0x7f of 0x4001: an extension this connection negotiated, and a number
    // no build of this pool serves.
    conn.send_raw(AVIAN_EXTENSION, 0x7f, false, &[1, 2, 3])
        .expect("send an unknown message");

    // Opening a second channel is the proof, because only a live session that
    // is still reading and still routing can answer one. Asserting that no
    // error came back would not be proof: a closed connection sends no errors
    // either.
    let (second, _) = open_standard_on(&mut conn, 2, WORKER_ADDRESS, None);
    assert_ne!(
        first, second,
        "the pool must still be serving this connection after ignoring a \
         message it does not know"
    );
}

/// A message in an extension this connection never negotiated still ends it.
#[test]
fn a_message_in_an_unnegotiated_extension_ends_the_connection() {
    let rig = rig!("unnegotiated", 98, &[PowType::X16rt], None);
    let mut conn = raw_ready(&rig, PowType::X16rt);
    let (_, _) = open_standard(&mut conn, 1, WORKER_ADDRESS);

    // The pool implements 0x4002, and `raw_ready` asked only for 0x4001. That
    // is the case worth pinning: tolerance is owed to a peer built at another
    // time, not to one sending messages for a capability it never negotiated.
    conn.send_raw(
        EXT_AVIAN_BLOCKS,
        avian_sv2::avian::MSG_BLOCK_FOUND,
        true,
        &[],
    )
    .expect("send");

    // The read failing well inside its own timeout is what distinguishes a
    // closed connection from one the pool merely went quiet on. A read that
    // ran to the timeout would mean the frame had been ignored, which is the
    // regression this guards.
    conn.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set a read timeout");
    let start = Instant::now();
    let err = loop {
        match conn.recv() {
            Ok(_) => continue,
            Err(e) => break e,
        }
    };
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "the pool should have closed the connection, but the read only ended \
         after {:?}: {err}",
        start.elapsed()
    );
}

/// Block notifications are optional, separately negotiated, and never
/// volunteered.
///
/// This is the compatibility fix, expressed as a test rather than as a
/// paragraph. They were briefly a message inside the extension every miner is
/// required to negotiate, so a miner built before they existed had no way to
/// decline one, received it, and ended the session as a protocol violation.
/// A miner that does not know about `0x4002` does not ask for it, and the
/// case above proves the pool then does not accept it, so `send_block_found`
/// has nothing to send to.
#[test]
fn block_notifications_are_optional_and_separately_negotiated() {
    let rig = rig!("blocksopt", 93, &[PowType::X16rt], None);

    // Asked for, and granted alongside the required one.
    let (accepted_list, _, accepted) =
        raw_request_extensions(&rig, &[AVIAN_EXTENSION, EXT_AVIAN_BLOCKS]);
    assert!(accepted);
    assert_eq!(accepted_list, vec![AVIAN_EXTENSION, EXT_AVIAN_BLOCKS]);

    // Optional does not mean sufficient. The multi-PoW extension is still
    // required, and asking only for the optional one is the same refusal as
    // asking for something unrelated: every failure 0x4001 prevents is
    // silent, which is why it is required and this is not.
    let (unsupported, required, accepted) = raw_request_extensions(&rig, &[EXT_AVIAN_BLOCKS]);
    assert!(!accepted);
    assert_eq!(
        required,
        vec![AVIAN_EXTENSION],
        "the error names what is missing, so a miner can correct itself"
    );
    assert!(
        unsupported.is_empty(),
        "0x4002 must not be listed as unsupported, because the pool does \
         support it: what it will not do is serve a connection without \
         0x4001. Saying otherwise would send a miner off to implement \
         something it had already got right, got {unsupported:04x?}"
    );
}

/// The client refuses a non-zero mask rather than rolling, and the pool never
/// sends one. Both halves matter: a mask the client ignored would be a silent
/// algorithm switch.
#[test]
fn the_algorithm_reply_reports_a_zero_version_rolling_mask() {
    let rig = rig!("algomask", 15, &[PowType::MinotaurX], None);
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
    let rig = rig!("ordering", 16, &[PowType::X16rt], None);
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
    let rig = rig!("futurejob", 17, &[PowType::X16rt], None);
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
    let rig = rig!("ntimeagree", 18, &[PowType::X16rt], None);
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
    let rig = rig!("refusals", 19, &[PowType::X16rt], None);
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
    // The gap between the two targets is the whole point of a share target:
    // it lets a miner see that it is working without pretending it won. With
    // the shift at zero the two targets are the same and every accepted share
    // is a block, which is what this used to be configured for.
    //
    // This test previously passed a shift of eight and expected refusals,
    // because the share target was being computed harder than the network
    // target rather than easier. It therefore asserted the inverted
    // behaviour, and never checked the property its name describes.
    let rig = rig!("sharediff", 20, &[PowType::X16rt], Some([0xff; 32]));
    let mut miner = rig.miner(PowType::X16rt);
    let job = miner.active_job().expect("an active job").clone();

    // A miner is never sent the network target, so derive it from the nBits
    // the job carries. Regtest's limit is near the top of the range, so the
    // share target saturates and cannot be used to recover it.
    let network_target = block::target_from_nbits(job.nbits);

    // A nonce whose hash clears the share target but not the network target.
    // That is the case with no other way to be observed: the pool accepts it
    // and must not hand it to the node.
    let mut found = None;
    for nonce in 0..2000u32 {
        let header = job.header(job.ntime_min, nonce);
        let hash = avian_pow::hash(avian_pow::PowType::X16rt, &header).expect("a hash");
        if block::meets_target(&hash, &job.share_target)
            && !block::meets_target(&hash, &network_target)
        {
            found = Some(nonce);
            break;
        }
    }
    let nonce = found.expect("a share that is not also a block");

    let before = rig.node.height();
    miner
        .submit_exact(job.job_id, nonce, job.ntime_min, job.version)
        .unwrap();
    match poll_event(&mut miner, Duration::from_secs(10)) {
        Some(Event::ShareAccepted { .. }) => {}
        other => panic!("a share over the share target should be accepted, got {other:?}"),
    }

    // Nothing was forwarded, so the tip is where it was. Polling again also
    // proves no BlockFound arrived, since a block would report one.
    assert!(
        poll_event(&mut miner, Duration::from_millis(500)).is_none(),
        "a share under the network target must not be reported as a block"
    );
    assert_eq!(
        rig.node.height(),
        before,
        "a share under the network target must not reach the node"
    );
}

#[test]
fn a_duplicate_share_is_refused() {
    let rig = rig!("duplicate", 21, &[PowType::X16rt], None);
    let mut miner = rig.miner(PowType::X16rt);
    let job = miner.active_job().expect("an active job").clone();
    let (nonce, ntime) = find_share(&job, 400).expect("a share");

    miner.submit(&job, nonce, ntime).unwrap();
    assert!(matches!(
        poll_event(&mut miner, Duration::from_secs(10)),
        Some(Event::ShareAccepted { .. })
    ));

    miner.submit(&job, nonce, ntime).unwrap();
    // On regtest the share target is the network target, so that first share
    // was also a block and a BlockFound is on its way. Skip past
    // anything that is not a verdict on the resubmission.
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut verdict = None;
    while Instant::now() < deadline && verdict.is_none() {
        match poll_event(&mut miner, Duration::from_millis(300)) {
            Some(Event::ShareRejected { code, .. }) => verdict = Some(code),
            Some(Event::ShareAccepted { .. }) => {
                panic!("a resubmission was accepted twice")
            }
            _ => {}
        }
    }
    assert_eq!(
        verdict.expect("a resubmission should get a verdict"),
        "duplicate-share"
    );
}

/// Two algorithms, two channels, two independent job streams.
#[test]
fn each_algorithm_gets_its_own_channel_and_job_stream() {
    let rig = rig!("twoalgos", 22, &[PowType::X16rt, PowType::MinotaurX], None);
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
    let rig = rig!("reconnect-down", 23, &[PowType::X16rt], None);
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
    let rig = rig!("reconnect-stale", 24, &[PowType::X16rt], None);
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
    let Some(mut rig) = Rig::attach(node, &[PowType::X16rt], None) else {
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
