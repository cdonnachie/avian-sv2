//! The upstream half on its own: a Template Distribution session per
//! algorithm against a live node, with no Mining Protocol involved.
//!
//! The Mining Protocol side, and the end-to-end chain through it, are in
//! `avian-mining`'s tests.

use std::time::{Duration, Instant};

use avian_regtest::Node;
use avian_tdp::{PowType, SessionConfig, TdpSession};

macro_rules! node {
    ($tag:expr, $slot:expr) => {
        match Node::start($tag, $slot, &[]) {
            Some(node) => node,
            None => {
                eprintln!("skipping: aviand or avian-cli not found, set AVIAND and AVIAN_CLI");
                return;
            }
        }
    };
}

#[test]
fn both_algorithms_receive_templates_from_a_live_node() {
    let node = node!("tdp-both-algos", 0);
    node.mine(101);
    let tip = node.tip();

    for pow in [PowType::X16rt, PowType::MinotaurX] {
        let mut config = SessionConfig::new(node.sv2_addr(), pow);
        // Verification, not trust on first use: the key file is right there.
        config.authority = Some(node.authority());
        config.timeout = Duration::from_secs(30);

        let mut session = TdpSession::open(&config).expect("session");
        assert!(session.identity().verified);
        assert_eq!(
            session.version_rolling_mask(),
            0,
            "doc/sv2.md pins this at 0"
        );

        let work = session.next_work().expect("work");
        assert_eq!(
            work.template.pow_type().expect("pow_type"),
            pow,
            "NewTemplate.version bits 16-23 must name the algorithm that was selected"
        );
        let prev = work.prev_hash.as_ref().expect("SetNewPrevHash");
        assert_eq!(
            avian_sv2::wire::hex_rev(&prev.prev_hash),
            tip,
            "the template must be built on the current tip"
        );
        assert_eq!(work.constraints.template_id, work.template.template_id);
        assert_eq!(
            work.constraints.ntime_min, prev.ntime_start,
            "doc/sv2.md guarantees these agree"
        );
        // Regtest allows minimum-difficulty blocks, which makes nBits a
        // function of nTime, so the node pins the window rather than narrowing
        // it.
        assert_eq!(work.constraints.ntime_min, work.constraints.ntime_max);
        assert!(work.constraints.within_one_epoch());

        let data = session
            .request_transaction_data(work.template.template_id)
            .expect("RequestTransactionData");
        assert_eq!(data.template_id, work.template.template_id);

        match session.request_transaction_data(work.template.template_id + 1000) {
            Err(avian_tdp::Error::Refused(message)) => assert!(
                message.contains("template-id-not-found"),
                "unexpected refusal: {message}"
            ),
            other => panic!("an unknown template id should be refused, got {other:?}"),
        }
    }
}

#[test]
fn a_tip_change_pushes_fresh_work() {
    let node = node!("tdp-tip-change", 1);
    node.mine(101);

    let mut config = SessionConfig::new(node.sv2_addr(), PowType::X16rt);
    config.authority = Some(node.authority());
    let mut session = TdpSession::open(&config).expect("session");

    let first = session.next_work().expect("first round");
    node.mine(1);
    let tip = node.tip();

    // The node refreshes on an interval as well as on a tip change, so read
    // until the round that carries the new tip rather than assuming it is the
    // next one.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        assert!(Instant::now() < deadline, "no round carried the new tip");
        let work = session.next_work().expect("round");
        let prev = work.prev_hash.as_ref().expect("SetNewPrevHash");
        if avian_sv2::wire::hex_rev(&prev.prev_hash) == tip {
            assert!(work.tip_changed);
            assert_ne!(work.template.template_id, first.template.template_id);
            break;
        }
        // Until then every round is an in-place refresh on the old tip, and
        // aviand sends SetNewPrevHash on those too, which is what the
        // tip_changed flag exists to tell apart.
        assert!(!work.tip_changed);
    }
}
