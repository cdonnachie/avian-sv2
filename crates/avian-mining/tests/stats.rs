//! The stats endpoint, fetched over HTTP from a pool that is actually serving.
//!
//! The unit tests in `stats.rs` cover the arithmetic and the escaping. These
//! cover the thing a deployment depends on: that a renderer polling the port
//! gets JSON describing real channels, that the endpoint is read-only, and
//! that it does not leak a full payout address.

// These tests hash, so they need the hashers the `pow` feature links.
#![cfg(feature = "pow")]

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use avian_mining::ratelimit::RateLimitConfig;
use avian_mining::stats::{self, Snapshot};
use avian_regtest::Node;
use avian_sv2::avian::PowType;
use avian_sv2::client::MiningClient;
use common::{script_for, Rig, FEE_ADDRESS, WORKER_ADDRESS};

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

/// A deliberately minimal HTTP client: the endpoint is meant to be reachable
/// by anything that can open a socket, so this does not use one that would
/// paper over a malformed response.
fn request(addr: SocketAddr, line: &str) -> (String, String) {
    let mut stream = TcpStream::connect(addr).expect("the stats port should accept");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .write_all(format!("{line}\r\nHost: test\r\n\r\n").as_bytes())
        .expect("the request should write");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("the response should read");
    let (head, body) = response
        .split_once("\r\n\r\n")
        .unwrap_or((response.as_str(), ""));
    (head.to_string(), body.to_string())
}

/// The key the endpoint should publish, checked below. Any base58 string
/// will do here: what matters is that whatever the pool was given comes back
/// out, because a miner pastes it into --sv2-authority and a wrong one is
/// worse than none.
const PUBLISHED_KEY: &str = "9cZsf3kvbayTC4M2bamzCoHkmcSneX68fb7Yc3JEfwtEsk2cXDA";

fn serve(rig: &Rig) -> stats::StatsHandle {
    let algos: Vec<_> = rig.pool.algos().to_vec();
    let started_at = rig.pool.started_at();
    let authority = PUBLISHED_KEY.to_string();
    let operator_fee = rig.pool.operator_fee();
    stats::serve("127.0.0.1:0".parse().unwrap(), move || {
        Snapshot::gather(started_at, &algos, authority.clone(), operator_fee)
    })
    .expect("the stats listener should bind")
}

#[test]
fn a_connected_miner_appears_on_the_endpoint() {
    let rig = rig!("stats-miner", 70, &[PowType::MinotaurX]);
    let handle = serve(&rig);
    let _miner = rig
        .pool
        .algo(PowType::MinotaurX)
        .map(|_| rig.miner(PowType::MinotaurX));

    let (head, body) = request(handle.addr(), "GET /stats HTTP/1.1");
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    assert!(
        head.contains("Content-Type: application/json"),
        "the pool must serve JSON, never HTML: {head}"
    );
    assert!(body.contains("\"miners\": 1"), "{body}");
    assert!(body.contains("\"algorithm\": \"minotaurx\""), "{body}");
    assert!(body.contains("\"worker\": \"test-rig\""), "{body}");
    assert!(body.contains("\"upstream_connected\": true"), "{body}");
    assert!(body.contains("\"current_job_id\": 1"), "{body}");
    // A refusal for a job the channel no longer holds is not a rejection,
    // and it is reported under its own name so the page can say so.
    assert!(body.contains("\"desync\": 0"), "{body}");
    // No donate/ prefix: nothing offered, and so nothing to pay.
    assert!(body.contains("\"donation_bp\": 0"), "{body}");
    assert!(body.contains("\"donation_paid\": false"), "{body}");
    // No fee and no address: the page can say the pool charges nothing, and
    // must not show a miner how to donate, since an offer would go nowhere.
    assert!(body.contains("\"operator_fee_bp\": 0"), "{body}");
    assert!(body.contains("\"donations_accepted\": false"), "{body}");
    // Stated rather than left to be assumed by whoever reads the page.
    assert!(body.contains("\"vardiff\": false"), "{body}");
    assert!(body.contains("there is no persistence"), "{body}");
}

#[test]
fn the_endpoint_shows_a_prefix_and_not_a_payout_address() {
    let rig = rig!("stats-privacy", 71, &[PowType::MinotaurX]);
    let handle = serve(&rig);
    let _miner = rig.miner(PowType::MinotaurX);

    let (_head, body) = request(handle.addr(), "GET /stats HTTP/1.1");
    assert!(
        !body.contains(WORKER_ADDRESS),
        "the full payout address leaked onto the stats endpoint: {body}"
    );
    let prefix = &WORKER_ADDRESS[..8];
    assert!(
        body.contains(&format!("\"payout_prefix\": \"{prefix}\"")),
        "a recognisable prefix should still be there: {body}"
    );
}

/// A worker that offers a donation to a pool with nowhere to send it keeps
/// the lot, and the endpoint has to say that is what happened: the offer is
/// reported, and so is the fact that it went nowhere.
#[test]
fn an_offer_with_nowhere_to_go_is_reported_as_unpaid() {
    let rig = rig!("stats-donation-offered", 75, &[PowType::MinotaurX]);
    let handle = serve(&rig);
    let mut config = rig.client_config(PowType::MinotaurX);
    config.user_identity = format!("donate/2/{WORKER_ADDRESS}.test-rig");
    let _miner = MiningClient::connect(config).expect("the client should connect");

    let (_head, body) = request(handle.addr(), "GET /stats HTTP/1.1");
    assert!(body.contains("\"donation_bp\": 200"), "{body}");
    assert!(body.contains("\"donation_paid\": false"), "{body}");
}

/// The same offer to a pool with a fee address is paid, and the offer is
/// reported as what the worker asked for, not folded into the fee.
#[test]
fn an_offer_with_a_fee_address_is_reported_as_paid() {
    let Some(node) = Node::start("stats-donation-paid", 76, &[]) else {
        eprintln!("skipping: aviand or avian-cli not found");
        return;
    };
    node.mine(101);
    let Some(rig) = Rig::attach_with(
        node,
        &[PowType::MinotaurX],
        None,
        (script_for(FEE_ADDRESS), 250),
        RateLimitConfig::default(),
    ) else {
        return;
    };
    let handle = serve(&rig);
    let mut config = rig.client_config(PowType::MinotaurX);
    config.user_identity = format!("donate/0.5/{WORKER_ADDRESS}.test-rig");
    let _miner = MiningClient::connect(config).expect("the client should connect");

    let (_head, body) = request(handle.addr(), "GET /stats HTTP/1.1");
    // 0.5%, as offered: the 2.5% fee is not added into it.
    assert!(body.contains("\"donation_bp\": 50"), "{body}");
    assert!(body.contains("\"donation_paid\": true"), "{body}");
    // And the fee itself, from the configuration the coinbase uses.
    assert!(body.contains("\"operator_fee_bp\": 250"), "{body}");
    assert!(body.contains("\"donations_accepted\": true"), "{body}");
}

/// The donations-only setup: an address and no fee. The endpoint says both,
/// because that is what lets a page print "this pool charges nothing" and,
/// beside it, how to leave something anyway.
#[test]
fn a_pool_that_charges_nothing_can_still_accept_a_donation() {
    let Some(node) = Node::start("stats-donations-only", 77, &[]) else {
        eprintln!("skipping: aviand or avian-cli not found");
        return;
    };
    node.mine(101);
    let Some(rig) = Rig::attach_with(
        node,
        &[PowType::MinotaurX],
        None,
        (script_for(FEE_ADDRESS), 0),
        RateLimitConfig::default(),
    ) else {
        return;
    };
    let handle = serve(&rig);
    let mut config = rig.client_config(PowType::MinotaurX);
    config.user_identity = format!("donate/1/{WORKER_ADDRESS}.test-rig");
    let _miner = MiningClient::connect(config).expect("the client should connect");

    let (_head, body) = request(handle.addr(), "GET /stats HTTP/1.1");
    assert!(body.contains("\"operator_fee_bp\": 0"), "{body}");
    assert!(body.contains("\"donations_accepted\": true"), "{body}");
    assert!(body.contains("\"donation_bp\": 100"), "{body}");
    assert!(body.contains("\"donation_paid\": true"), "{body}");
}

#[test]
fn the_endpoint_is_read_only() {
    let rig = rig!("stats-readonly", 72, &[PowType::MinotaurX]);
    let handle = serve(&rig);

    for line in [
        "POST /stats HTTP/1.1",
        "PUT /stats HTTP/1.1",
        "DELETE /stats HTTP/1.1",
    ] {
        let (head, _body) = request(handle.addr(), line);
        assert!(
            head.starts_with("HTTP/1.1 405"),
            "{line} should be refused, got {head}"
        );
    }
    let (head, _) = request(handle.addr(), "GET /../../etc/passwd HTTP/1.1");
    assert!(head.starts_with("HTTP/1.1 404"), "{head}");
}

#[test]
fn shares_move_the_counters_and_an_estimate_appears() {
    let rig = rig!("stats-shares", 73, &[PowType::MinotaurX]);
    let handle = serve(&rig);
    // Connected by hand rather than with rig.miner, which takes the first job
    // and drops it. A second job only arrives when the tip moves, so waiting
    // for one here would just time out.
    let mut miner = MiningClient::connect(rig.client_config(PowType::MinotaurX))
        .expect("the client should connect");
    let job = common::expect_job(&mut miner);
    let (nonce, ntime) =
        common::find_share(&job, 200_000).expect("regtest's target is easy enough to hit");
    miner
        .submit(&job, nonce, ntime)
        .expect("the share should send");
    // Let the pool account for it.
    std::thread::sleep(Duration::from_millis(500));

    let (_head, body) = request(handle.addr(), "GET /stats HTTP/1.1");
    assert!(
        !body.contains("\"accepted\": 0"),
        "a submitted share should have moved the counter off zero: {body}"
    );
    assert!(body.contains("\"estimated_hashrate\""), "{body}");
    assert!(body.contains("\"share_target\""), "{body}");
    // Published verbatim, so a miner can paste it straight into
    // --sv2-authority without the operator reading it out of a log.
    assert!(
        body.contains(&format!("\"authority_public_key\": \"{PUBLISHED_KEY}\"")),
        "{body}"
    );
    // blocks_submitted, not blocks_found: SubmitSolution has no reply, so the
    // pool cannot know what the node did with it.
    assert!(body.contains("\"blocks_submitted\""), "{body}");
    assert!(!body.contains("blocks_found"), "{body}");
    // The gap between submitted and confirmed goes out as hashes, so a
    // service with a node can resolve what the pool cannot.
    assert!(body.contains("\"unconfirmed\": ["), "{body}");
}

#[test]
fn the_listener_stops_when_the_handle_is_dropped() {
    let rig = rig!("stats-drop", 74, &[PowType::MinotaurX]);
    let addr = {
        let handle = serve(&rig);
        let addr = handle.addr();
        let (head, _) = request(addr, "GET /healthz HTTP/1.1");
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        addr
    };
    // A port that outlived its pool would serve a frozen snapshot for ever.
    std::thread::sleep(Duration::from_millis(300));
    let refused = TcpStream::connect_timeout(&addr, Duration::from_millis(500))
        .and_then(|mut s| {
            s.write_all(b"GET /stats HTTP/1.1\r\n\r\n")?;
            let mut body = String::new();
            s.read_to_string(&mut body)?;
            Ok(body)
        })
        .map(|body| body.contains("uptime_seconds"))
        .unwrap_or(false);
    assert!(!refused, "the stats listener outlived its handle");
}
