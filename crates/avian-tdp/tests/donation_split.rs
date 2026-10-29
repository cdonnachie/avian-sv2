//! What a miner's donation actually does to the coinbase.
//!
//! The unit tests in avian-sv2 cover parsing the `donate/<percent>/` prefix
//! into basis points. This is the other half: that those basis points, handed
//! to PayoutPlan, move exactly the money the miner asked for and no more.
//!
//! It lives here because it needs both crates and avian-tdp is the one that
//! depends on the other.

use avian_sv2::address::{parse_identity, Network};
use avian_tdp::coinbase::PayoutPlan;

/// A regtest address from a real node, as the other tests here use.
const ADDRESS: &str = "mnPBEVKjU1zz9214C7M7Zp4FuurUAsU6ZS";

/// 5000 AVN, in the smallest unit.
const SUBSIDY: u64 = 5_000_000_000;

fn plan_for(identity: &str) -> PayoutPlan {
    let id = parse_identity(identity, Network::Regtest).expect("identity parses");
    PayoutPlan {
        worker_script: id.address.script_pubkey(),
        fee_script: vec![0x51],
        fee_basis_points: id.donation_basis_points,
    }
}

#[test]
fn no_prefix_pays_the_miner_everything() {
    let outputs = plan_for(&format!("{ADDRESS}.rig")).outputs(SUBSIDY);
    assert_eq!(outputs.len(), 1, "a lone output, with no dust beside it");
    assert_eq!(outputs[0].value, SUBSIDY);
}

#[test]
fn a_donation_moves_exactly_what_was_asked() {
    for (percent, donated) in [
        ("1", 50_000_000u64),
        ("2", 100_000_000),
        ("0.5", 25_000_000),
        ("0.01", 500_000),
        ("12.34", 617_000_000),
    ] {
        let outputs = plan_for(&format!("donate/{percent}/{ADDRESS}.rig")).outputs(SUBSIDY);
        assert_eq!(outputs.len(), 2, "for {percent}%");
        assert_eq!(outputs[1].value, donated, "the {percent}% donation");
        assert_eq!(outputs[0].value, SUBSIDY - donated, "the miner's share");
        assert_eq!(
            outputs[0].value + outputs[1].value,
            SUBSIDY,
            "{percent}% must not burn the difference"
        );
    }
}

#[test]
fn a_donation_too_small_to_pay_produces_no_output() {
    // 0.01% of a hundred units rounds to nothing. The alternative is a
    // zero-value output, which is dust a node has no reason to accept.
    let outputs = plan_for(&format!("donate/0.01/{ADDRESS}")).outputs(100);
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].value, 100, "and the miner keeps all of it");
}

#[test]
fn rounding_always_favours_the_miner() {
    // A value chosen so the fee does not divide evenly. The truncated
    // remainder must land with the miner, never with the pool, and never
    // nowhere.
    let odd = SUBSIDY + 7;
    let outputs = plan_for(&format!("donate/3.33/{ADDRESS}")).outputs(odd);
    let donated = outputs[1].value;
    let kept = outputs[0].value;
    assert_eq!(kept + donated, odd, "nothing may be burned");
    let exact = (odd as u128 * 333) / 10_000;
    assert_eq!(donated as u128, exact, "the fee is truncated, not rounded up");
}
