//! A channel must keep usable work while the tip stands still.
//!
//! This is the regression test for a bug that took four minutes of a live
//! testnet miner to show and could never have appeared on regtest, because
//! regtest produces blocks constantly and every tip change issues a fresh
//! job. The condition needed is the one a quiet chain has and a busy one
//! cannot: the tip static for longer than a template lives.
//!
//! The node refreshes each client's template every `-sv2interval` seconds and
//! keeps `-sv2maxtemplates` of them, so a template dies after the product of
//! the two. Both are set low here, because the defaults make this a
//! four-minute test.
//!
//! Three things were wrong and each hid the next: the client filed an active
//! job without adopting it, the pool pruned the job the miner was still using,
//! and `invalid-job-id` counted toward the invalid-share limit so the pool
//! disconnected the miner and the reconnect repaired the symptom.

mod common;

use std::time::{Duration, Instant};

use avian_regtest::Node;
use avian_sv2::avian::PowType;
use avian_sv2::client::Event;
use common::{find_share, Rig};

/// A node whose templates expire quickly, and a tip nobody is going to move.
fn quiet_rig(tag: &str, slot: u16) -> Option<Rig> {
    // interval 1s, 2 templates kept: a template is gone after ~2 seconds, so
    // what took 90 seconds in the field takes a moment here.
    let node = Node::start(tag, slot, &["-sv2interval=1", "-sv2maxtemplates=2"])?;
    node.mine(101);
    Rig::attach(node, &[PowType::MinotaurX], None)
}

macro_rules! quiet {
    ($tag:expr, $slot:expr) => {
        match quiet_rig($tag, $slot) {
            Some(rig) => rig,
            None => {
                eprintln!("skipping: aviand or avian-cli not found");
                return;
            }
        }
    };
}

/// The property, not the mechanism: after sitting still for longer than a
/// template lives, a channel can still submit work and have it accepted.
///
/// Stated this way on purpose. Asserting "a job arrived on every refresh"
/// would pin today's implementation; this survives someone changing how jobs
/// are issued, and it is what the miner actually needs.
#[test]
fn a_channel_keeps_usable_work_while_the_tip_stands_still() {
    let rig = quiet!("refresh-usable", 80);
    let mut miner = rig.miner(PowType::MinotaurX);
    let tip_before = rig.node.tip();

    // Longer than interval * maxtemplates, so the template the first job was
    // built on is certainly gone.
    let settle = Instant::now() + Duration::from_secs(6);
    let mut job = common::expect_job(&mut miner);
    while Instant::now() < settle {
        if let Some(Event::Job(fresh)) = common::poll_event(&mut miner, Duration::from_millis(500))
        {
            job = fresh;
        }
    }

    assert_eq!(
        rig.node.tip(),
        tip_before,
        "this test is meaningless if the tip moved; nothing here should mine"
    );

    let (nonce, ntime) = find_share(&job, 200_000).expect("regtest's share target is easy to hit");
    miner
        .submit(&job, nonce, ntime)
        .expect("the share should send");

    // The share is accepted, or it is refused for a reason that is not the
    // pool having forgotten the job.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut verdict = None;
    while Instant::now() < deadline && verdict.is_none() {
        match common::poll_event(&mut miner, Duration::from_millis(500)) {
            Some(Event::ShareAccepted { .. }) => verdict = Some(Ok(())),
            Some(Event::ShareRejected { code, .. }) => verdict = Some(Err(code)),
            _ => {}
        }
    }
    match verdict {
        Some(Ok(())) => {}
        Some(Err(code)) => panic!(
            "the share was refused {code:?} after the tip stood still; \
             invalid-job-id here is the stranding bug"
        ),
        None => panic!("no verdict on a share submitted against the current job"),
    }
}

/// The mechanism, so a failure says which part broke: a refresh with no tip
/// change must reach the miner as a job it adopts.
#[test]
fn a_template_refresh_reaches_the_miner_as_a_job() {
    let rig = quiet!("refresh-adopted", 81);
    let mut miner = rig.miner(PowType::MinotaurX);
    let first = common::expect_job(&mut miner);
    let tip_before = rig.node.tip();

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut later = None;
    while Instant::now() < deadline && later.is_none() {
        if let Some(Event::Job(job)) = common::poll_event(&mut miner, Duration::from_millis(500)) {
            if job.job_id != first.job_id {
                later = Some(job);
            }
        }
    }

    assert_eq!(
        rig.node.tip(),
        tip_before,
        "the tip moved, so this proves nothing about refreshes"
    );
    let later = later.expect(
        "no second job arrived while the tip stood still: a template refresh is not \
         reaching the miner, which is what stranded a live channel",
    );
    assert!(
        later.job_id != first.job_id,
        "the refresh must be a different job"
    );
    assert!(
        later.ntime_max >= later.ntime_min,
        "a job the miner adopts must have a usable ntime window"
    );
}

/// And the counter that hid it: a share against a job the pool has pruned
/// must not be treated as bad work.
///
/// This is the field scenario exactly. The miner holds a job, the tip stands
/// still, the pool issues newer jobs and prunes that one, and the miner
/// submits against it. A phantom job id cannot be used here because the client
/// refuses to submit against a job it does not hold, which is correct, so the
/// job has to be one that was genuinely valid and is no longer.
#[test]
fn a_pruned_job_does_not_count_as_an_invalid_share() {
    let rig = quiet!("refresh-desync", 82);
    let mut miner = rig.miner(PowType::MinotaurX);
    let stale = common::expect_job(&mut miner);
    let channel = rig
        .pool
        .algo(PowType::MinotaurX)
        .and_then(|algo| algo.channels().first().cloned())
        .expect("the channel should be open");

    // Long enough for the pool to have issued and pruned past this job.
    let settle = Instant::now() + Duration::from_secs(8);
    while Instant::now() < settle {
        let _ = common::poll_event(&mut miner, Duration::from_millis(400));
    }

    let invalid_before = channel.refusals().0;
    let (nonce, ntime) = find_share(&stale, 200_000).expect("an easy target");
    let _ = miner.submit(&stale, nonce, ntime);

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut rejected_for = None;
    while Instant::now() < deadline && rejected_for.is_none() {
        match common::poll_event(&mut miner, Duration::from_millis(300)) {
            Some(Event::ShareRejected { code, .. }) => rejected_for = Some(code),
            Some(Event::ShareAccepted { .. }) => {
                // The pool still had the job. Nothing to assert, and nothing
                // wrong: this test is about what happens when it does not.
                eprintln!("the pool still held the job, so there was no desync to check");
                return;
            }
            _ => {}
        }
    }

    let code = rejected_for.expect("the stale share should have got a verdict");
    assert_eq!(
        code, "invalid-job-id",
        "a pruned job should be refused as an unknown job id"
    );
    assert!(
        channel.desync() >= 1,
        "the pool should have recorded a desynchronisation"
    );
    assert_eq!(
        channel.refusals().0,
        invalid_before,
        "an unknown job id must not count toward too-many-invalid-shares: counting it          disconnects a miner for the pool losing track of it, and the reconnect then          hides the real fault"
    );
    assert!(
        !channel.wants_work(),
        "the pool should have reissued work to the channel, clearing the request"
    );
}
