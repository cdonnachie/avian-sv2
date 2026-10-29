//! `AvianBlockFound` (0x05): a miner being told it found a block.
//!
//! Nothing in the Mining Protocol carries this. A miner is given a share
//! target and never the network target, so it cannot work out that its own
//! share was a block. For a pool paying by share that is unremarkable. For a
//! solo pool it is backwards, because consensus pays the miner directly for
//! exactly these, and the miner was the one piece of software that could not
//! see them.
//!
//! On regtest the share target is the network target, so nearly every share is
//! a block, which makes this cheap to test here and is the one way regtest
//! helps rather than hides.

mod common;

use std::time::{Duration, Instant};

use avian_sv2::avian::PowType;
use avian_sv2::avian::{self, BlockFound};
use avian_sv2::client::Event;
use common::{find_share, Rig};

macro_rules! rig {
    ($tag:expr, $slot:expr) => {
        match Rig::start($tag, $slot, &[PowType::MinotaurX], None) {
            Some(rig) => rig,
            None => {
                eprintln!("skipping: aviand or avian-cli not found");
                return;
            }
        }
    };
}

#[test]
fn the_message_round_trips() {
    // The wire format, before anything depends on it over a socket.
    let original = BlockFound {
        channel_id: 7,
        sequence_number: 1234,
        block_hash: [0xab; 32],
        confirmed: true,
    };
    let encoded = avian::encode_block_found(&original);
    assert_eq!(encoded.len(), 4 + 4 + 32 + 1);
    assert_eq!(avian::decode_block_found(&encoded).unwrap(), original);

    let unconfirmed = BlockFound {
        confirmed: false,
        ..original.clone()
    };
    let encoded = avian::encode_block_found(&unconfirmed);
    assert_eq!(avian::decode_block_found(&encoded).unwrap(), unconfirmed);

    // A BOOL that is neither 0 nor 1 is a malformed payload, not something to
    // coerce: a peer that sends 2 has a bug worth hearing about.
    let mut broken = encoded.clone();
    *broken.last_mut().unwrap() = 2;
    assert!(avian::decode_block_found(&broken).is_err());

    // And a short payload is refused rather than read past.
    assert!(avian::decode_block_found(&encoded[..encoded.len() - 1]).is_err());
}

#[test]
fn a_miner_is_told_when_its_share_was_a_block() {
    let rig = rig!("blockfound-told", 85);
    let mut miner = rig.miner(PowType::MinotaurX);
    let job = common::expect_job(&mut miner);

    let (nonce, ntime) = find_share(&job, 200_000).expect("regtest's target is easy");
    miner
        .submit(&job, nonce, ntime)
        .expect("the share should send");

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut submitted = None;
    while Instant::now() < deadline && submitted.is_none() {
        if let Some(Event::BlockFound {
            sequence_number,
            block_hash,
            confirmed,
        }) = common::poll_event(&mut miner, Duration::from_millis(300))
        {
            submitted = Some((sequence_number, block_hash, confirmed));
        }
    }

    let (sequence, hash, confirmed) = submitted.expect(
        "a share at or under the network target should have produced an AvianBlockFound; \
         without it a solo miner cannot tell it found anything",
    );
    assert!(
        sequence >= 1,
        "the event should name the share it refers to"
    );
    assert_ne!(hash, [0u8; 32], "the event should carry the block's hash");
    assert!(
        !confirmed,
        "the first message is sent when the pool forwards the block, before anything \
         could possibly have confirmed it"
    );
}

#[test]
fn confirmation_comes_from_the_tip_and_not_from_optimism() {
    let rig = rig!("blockfound-confirmed", 86);
    let mut miner = rig.miner(PowType::MinotaurX);
    let job = common::expect_job(&mut miner);

    let (nonce, ntime) = find_share(&job, 200_000).expect("regtest's target is easy");
    miner
        .submit(&job, nonce, ntime)
        .expect("the share should send");

    // The confirmation can only arrive on a SetNewPrevHash, so it needs the
    // tip to actually move. That is the point: the node never says a block was
    // accepted, so the only honest evidence is the hash turning up as the tip.
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut submitted_hash = None;
    let mut confirmed_hash = None;
    while Instant::now() < deadline && confirmed_hash.is_none() {
        if let Some(Event::BlockFound {
            block_hash,
            confirmed,
            ..
        }) = common::poll_event(&mut miner, Duration::from_millis(300))
        {
            if confirmed {
                confirmed_hash = Some(block_hash);
            } else {
                submitted_hash = Some(block_hash);
            }
        }
    }

    let submitted = submitted_hash.expect("the submitted message should have arrived first");
    let confirmed = confirmed_hash.expect(
        "the block should have been confirmed once it became the tip; confirmation that \
         never arrives means the pool is not matching the tip against what it submitted",
    );
    assert_eq!(
        submitted, confirmed,
        "the confirmation must name the same block that was submitted"
    );

    // And the node agrees it is the tip, which is what "confirmed" claims.
    let mut printed = confirmed;
    printed.reverse();
    let hex: String = printed.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        rig.node.tip(),
        hex,
        "the pool said this hash was the tip, so the node had better agree"
    );

    // The pool's own count should agree too, and it is the only count it can
    // prove.
    let algo = rig.pool.algo(PowType::MinotaurX).expect("the algorithm");
    assert!(
        algo.confirmed() >= 1,
        "the pool should have counted a confirmed block"
    );
    assert!(
        algo.blocks() >= algo.confirmed(),
        "confirmed blocks cannot outnumber submitted ones"
    );
}
