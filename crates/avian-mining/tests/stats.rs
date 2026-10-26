//! The stats endpoint, fetched over HTTP from a pool that is actually serving.
//!
//! The unit tests in `stats.rs` cover the arithmetic and the escaping. These
//! cover the thing a deployment depends on: that a renderer polling the port
//! gets JSON describing real channels, that the endpoint is read-only, and
//! that it does not leak a full payout address.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use avian_mining::stats::{self, Snapshot};
use avian_sv2::avian::PowType;
use avian_sv2::client::MiningClient;
use common::{Rig, WORKER_ADDRESS};

macro_rules! rig {
    ($tag:expr, $slot:expr, $algos:expr) => {
        match Rig::start($tag, $slot, $algos, 0) {
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

fn serve(rig: &Rig) -> stats::StatsHandle {
    let algos: Vec<_> = rig.pool.algos().to_vec();
    let started_at = rig.pool.started_at();
    stats::serve("127.0.0.1:0".parse().unwrap(), move || {
        Snapshot::gather(started_at, &algos)
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
    // blocks_submitted, not blocks_found: SubmitSolution has no reply, so the
    // pool cannot know what the node did with it.
    assert!(body.contains("\"blocks_submitted\""), "{body}");
    assert!(!body.contains("blocks_found"), "{body}");
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
