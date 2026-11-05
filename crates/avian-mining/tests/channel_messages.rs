//! The two core Mining Protocol messages a worker may send that are not a
//! share: `UpdateChannel` and `CloseChannel`.
//!
//! Both used to reach the catch-all arm of the pool's dispatcher and end the
//! session as a protocol violation. That is the same fault `doc/sv2.md`
//! records against the first block notification deployment, where a correctly
//! encoded message killed the session of a peer that did not know it, one
//! layer down: there it was an extension message, here it is a message the
//! specification has always defined and the pool simply did not handle.
//!
//! Two of these three fail against the dispatcher as it was, with
//! "unexpected extension 0x8000 message 0x16 on a mining connection". The
//! close test does not, and cannot: see the note on it.
//!
//! The target itself cannot move on regtest, whatever a worker declares.
//! `ServerConfig::share_target` clamps to the network target, and on regtest
//! one share's worth of work at any believable hash rate is already harder
//! than a regtest block, so the clamp always wins. The arithmetic is covered
//! by the unit tests beside it; what matters here is that the session
//! survives, which is what it did not do.

// These tests hash, so they need the hashers the `pow` feature links.
#![cfg(feature = "pow")]

mod common;

use std::time::{Duration, Instant};

use avian_sv2::avian::PowType;
use avian_sv2::client::{Event, Trace};
use common::{poll_event, position_of, trace, Rig};

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

/// Polls for a while, failing if the pool hangs up. Returns whatever events
/// arrived, so a caller can say what should and should not be among them.
fn poll_for(client: &mut avian_sv2::client::MiningClient, how_long: Duration) -> Vec<Event> {
    let deadline = Instant::now() + how_long;
    let mut seen = Vec::new();
    while Instant::now() < deadline {
        if let Some(event) = poll_event(client, Duration::from_millis(100)) {
            if let Event::Disconnected { reason } = &event {
                panic!("the pool hung up: {reason}");
            }
            seen.push(event);
        }
    }
    seen
}

#[test]
fn an_update_channel_is_answered_and_not_treated_as_a_violation() {
    let rig = rig!("chanmsg-update", 90, &[PowType::X16rt]);
    rig.wait_for_tip(PowType::X16rt);
    let mut client = rig.miner(PowType::X16rt);

    let algo = rig.pool.algo(PowType::X16rt).expect("the x16rt session");
    assert_eq!(algo.channels().len(), 1, "the miner should have a channel");
    let channel_id = algo.channels()[0].id;

    // A tenth of what it declared at open, as a rig that lost a card would
    // report. The pool is free to leave the target where it is; what it may
    // not do is end the session.
    client
        .update_channel(100.0, &[0xff; 32])
        .expect("an update should send");
    poll_for(&mut client, Duration::from_secs(2));

    assert!(client.is_connected(), "the session should have survived");
    let channels = algo.channels();
    assert_eq!(channels.len(), 1, "the channel should still be registered");
    assert_eq!(channels[0].id, channel_id, "and be the same channel");
    assert!(
        !trace(&client)
            .iter()
            .any(|t| matches!(t, Trace::UpdateChannelError(_))),
        "a well-formed update should not be refused"
    );
}

#[test]
fn an_unusable_hash_rate_is_refused_without_ending_the_session() {
    let rig = rig!("chanmsg-nan", 91, &[PowType::X16rt]);
    rig.wait_for_tip(PowType::X16rt);
    let mut client = rig.miner(PowType::X16rt);

    // Not something the clamp can floor into sense, and the one shape the
    // specification has an error code for. It has to come back as that error
    // rather than as a disconnect, which is the only way a worker can tell
    // "fix your declaration" from "the pool is gone".
    client
        .update_channel(f32::NAN, &[0xff; 32])
        .expect("an update should send");
    poll_for(&mut client, Duration::from_secs(2));

    assert!(client.is_connected(), "the session should have survived");
    let entries = trace(&client);
    let refusal = position_of(&entries, |t| matches!(t, Trace::UpdateChannelError(_)))
        .expect("the pool should have refused it");
    match &entries[refusal] {
        Trace::UpdateChannelError(code) => {
            assert_eq!(code, "invalid-nominal-hashrate", "the specified code");
        }
        other => panic!("unexpected trace entry {other:?}"),
    }
    assert_eq!(
        rig.pool
            .algo(PowType::X16rt)
            .expect("the x16rt session")
            .channels()
            .len(),
        1,
        "a refused update must not cost the channel"
    );
}

// Note this one passes against the unfixed dispatcher as well, and is a
// guard rather than a regression test. Ending the session with a protocol
// error unregistered the channel and left the pool serving too, and the pool
// sends the worker nothing either way, so the only thing that tells a clean
// exit from a violation is a log line this cannot read.
#[test]
fn a_close_channel_unregisters_the_channel_and_leaves_the_pool_serving() {
    let rig = rig!("chanmsg-close", 92, &[PowType::X16rt]);
    rig.wait_for_tip(PowType::X16rt);
    let algo = rig.pool.algo(PowType::X16rt).expect("the x16rt session");

    let client = rig.miner(PowType::X16rt);
    assert_eq!(algo.channels().len(), 1, "the miner should have a channel");

    client
        .close_channel("done for the day")
        .expect("a close should send");
    // The pool unregisters on the reader loop ending, so this is not instant.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !algo.channels().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        algo.channels().is_empty(),
        "a closed channel should be unregistered"
    );
    drop(client);

    // The point of answering CloseChannel rather than erroring on it: the
    // worker did the correct thing, so nothing about the pool should have
    // soured. A second miner must be served exactly as the first was.
    let mut second = rig.miner(PowType::X16rt);
    poll_for(&mut second, Duration::from_secs(2));
    assert!(second.is_connected(), "the pool should still be serving");
    assert_eq!(algo.channels().len(), 1, "and have the new channel");
}
