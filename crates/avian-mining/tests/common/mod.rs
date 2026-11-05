//! Shared test support. A subdirectory, so cargo does not compile it as a
//! test binary of its own.
//!
//! There is no test worker here any more: the Mining Protocol client was
//! promoted into the library, so these tests drive the library rather than a
//! parallel implementation of it. What is left is a rig that starts a node and
//! a pool, a nonce search, and a raw connection for the few cases that have to
//! send something the library would refuse to send.

#![allow(dead_code)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use avian_mining::pool::{self, PoolConfig, PoolHandle};
use avian_mining::ratelimit::RateLimitConfig;
use avian_mining::server::ServerConfig;
use avian_mining::share::{AvianHasher, PowHasher};
use avian_regtest::Node;
use avian_sv2::address::Network;
use avian_sv2::avian::{
    self, PowType, EXT_AVIAN, EXT_CORE, EXT_NEGOTIATION, MSG_REQUEST_EXTENSIONS,
    MSG_SELECT_ALGORITHM, MSG_SELECT_ALGORITHM_SUCCESS,
};
use avian_sv2::block;
use avian_sv2::client::{ClientConfig, Event, MiningClient, MiningJob, Trace};
use avian_sv2::transport::Connection;
use avian_sv2::wire::{self, Reader, Writer};
use avian_sv2::Backoff;
use mining_sv2::{
    OpenStandardMiningChannel, OpenStandardMiningChannelSuccess,
    MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR, MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
    MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
};

use common_messages_sv2::{
    Protocol, SetupConnection, MESSAGE_TYPE_SETUP_CONNECTION, MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
    MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
};
use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};

/// A node and a pool, ready for miners.
pub struct Rig {
    pub node: Node,
    pub pool: PoolHandle,
    pub pool_authority: XOnlyPublicKey,
}

impl Rig {
    /// `None` when `aviand` is not installed, so the tests skip rather than
    /// fail on a machine without a build.
    pub fn start(
        tag: &str,
        slot: u16,
        algorithms: &[PowType],
        share_target: Option<[u8; 32]>,
    ) -> Option<Rig> {
        let node = Node::start(tag, slot, &[])?;
        node.mine(101);
        Self::attach(node, algorithms, share_target)
    }

    pub fn attach(
        node: Node,
        algorithms: &[PowType],
        share_target: Option<[u8; 32]>,
    ) -> Option<Rig> {
        Self::attach_with(
            node,
            algorithms,
            share_target,
            (Vec::new(), 0),
            RateLimitConfig::default(),
        )
    }

    /// With an operator fee and submission limits, for the tests about those.
    pub fn attach_with(
        node: Node,
        algorithms: &[PowType],
        share_target: Option<[u8; 32]>,
        fee: (Vec<u8>, u32),
        rate_limit: RateLimitConfig,
    ) -> Option<Rig> {
        let secp = Secp256k1::new();
        let authority = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
        let (pool_authority, _) = authority.x_only_public_key();

        let hasher: Arc<dyn PowHasher> = Arc::new(AvianHasher);
        // Loudly, rather than skipping: a pool that cannot hash would accept
        // every nonce, and a suite that quietly passed without it would be
        // asserting nothing about share validation.
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
                    // The tests all bind loopback, so this never matters to
                    // them; it is named so a new field cannot be forgotten.
                    allow_public_bind: false,
                    // Port 0 lets the OS pick, so parallel tests cannot clash.
                    bind: "127.0.0.1:0".parse().unwrap(),
                    authority,
                    cert_validity: 3600,
                    network: Network::Regtest,
                    fee_script: fee.0,
                    fee_basis_points: fee.1,
                    coinbase_tag: b"/avian-sv2-test/".to_vec(),
                    shares_per_minute: 4.5,
                    min_hash_rate: 1000.0,
                    max_hash_rate: 1e12,
                    share_target_override: share_target,
                    rate_limit,
                },
                coinbase_size: 1000,
                coinbase_sigops: 10,
                duration: Some(Duration::from_secs(180)),
                upstream_backoff: Backoff {
                    initial: Duration::from_millis(100),
                    max: Duration::from_secs(2),
                    factor: 2,
                    max_attempts: None,
                },
            },
            hasher,
            None,
        )
        .expect("the pool should start");

        Some(Rig {
            node,
            pool,
            pool_authority,
        })
    }

    pub fn client_config(&self, pow: PowType) -> ClientConfig {
        let mut config = ClientConfig::new(vec![self.pool.mining_addr()], pow);
        config.pool_authority = Some(self.pool_authority);
        config.user_identity = format!("{}.test-rig", worker_address());
        config.timeout = Duration::from_secs(30);
        // Standard, because the tests that predate extended channels are
        // about standard ones and should keep testing those. The library
        // default is extended, which is what a solo miner should want; the
        // tests in extended.rs opt back in.
        config.extended = false;
        config.reconnect = Backoff {
            initial: Duration::from_millis(50),
            max: Duration::from_millis(500),
            factor: 2,
            max_attempts: Some(60),
        };
        config
    }

    /// Waits until the pool's work for `pow` builds on the node's tip.
    ///
    /// A block found on one algorithm moves the tip for every algorithm, and
    /// the pool hears of it one Template Distribution session at a time. A
    /// channel opened inside that window is handed the template that still
    /// stands at the pool, which the node has already retired, and its share
    /// comes back `unknown-template`. On regtest, where the next block is a
    /// few nonces away, a test that mines one algorithm after another lives
    /// entirely inside that window unless it waits here first.
    pub fn wait_for_tip(&self, pow: PowType) {
        let tip = self.node.tip();
        let algo = self.pool.algo(pow).expect("the pool serves this algorithm");
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if algo.prev_hash().map(|hash| wire::hex_rev(&hash)) == Some(tip.clone()) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the pool's {pow} work never caught up with the tip {tip}");
    }

    /// A client with an active job, which is where most tests start.
    pub fn miner(&self, pow: PowType) -> MiningClient {
        let mut client =
            MiningClient::connect(self.client_config(pow)).expect("the client should connect");
        expect_job(&mut client);
        client
    }
}

/// Polls until a job arrives, or panics with the trace.
pub fn expect_job(client: &mut MiningClient) -> MiningJob {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        match client.poll(Duration::from_millis(250)) {
            Ok(Event::Job(job)) => return job,
            Ok(_) => {}
            Err(e) => panic!("the client failed: {e}\ntrace: {:?}", trace(client)),
        }
    }
    panic!("no job arrived\ntrace: {:?}", trace(client));
}

/// Polls until something other than `Idle`, or `None` on timeout.
pub fn poll_event(client: &mut MiningClient, within: Duration) -> Option<Event> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        match client.poll(Duration::from_millis(100)) {
            Ok(Event::Idle) => {}
            Ok(event) => return Some(event),
            Err(e) => panic!("the client failed: {e}"),
        }
    }
    None
}

pub fn trace(client: &MiningClient) -> Vec<Trace> {
    client.trace().cloned().collect()
}

/// The position of the first trace entry matching a predicate.
pub fn position_of(entries: &[Trace], matches: impl Fn(&Trace) -> bool) -> Option<usize> {
    entries.iter().position(matches)
}

/// Searches nonces for one meeting the job's share target.
///
/// The miner's half of the boundary: the library hands over a job and builds
/// the header, and the hashing is the caller's. Here that is `avian-pow`,
/// standing in for a real miner's own optimised code, which is exactly why
/// `avian-pow` is not in the library.
///
/// Avian has no cheap pre-filter, so this is the only way to search: hash and
/// look. On regtest the target is the algorithm's own floor, so a handful of
/// nonces is enough and the bound only exists so a broken build fails instead
/// of looping.
pub fn find_share(job: &MiningJob, attempts: u32) -> Option<(u32, u32)> {
    let hasher = match job.pow_type {
        PowType::X16rt => avian_pow::PowType::X16rt,
        PowType::MinotaurX => avian_pow::PowType::MinotaurX,
    };
    // The window is pinned shut on regtest, because nBits there is a function
    // of nTime, so there is exactly one legal ntime.
    let ntime = job.ntime_min;
    for nonce in 0..attempts {
        let header = job.header(ntime, nonce);
        let hash = avian_pow::hash(hasher, &header)?;
        if block::meets_target(&hash, &job.share_target) {
            return Some((nonce, ntime));
        }
    }
    None
}

/// The pool's answer to a `SetupConnection` with the given flags.
///
/// The library's client always sends the right ones, so the tests that check
/// what a pool does with the wrong ones go straight at the transport. That is
/// the honest place for them: a product client should not offer a way to
/// misbehave.
pub enum SetupAnswer {
    Success { flags: u32 },
    Error { flags: u32, code: String },
}

fn raw_connect(rig: &Rig) -> Connection {
    Connection::connect(
        rig.pool.mining_addr(),
        Some(rig.pool_authority),
        Duration::from_secs(10),
    )
    .expect("handshake")
}

fn send_setup(conn: &mut Connection, flags: u32) {
    let host = b"0.0.0.0";
    let empty: &[u8] = b"";
    conn.send(
        EXT_CORE,
        MESSAGE_TYPE_SETUP_CONNECTION,
        false,
        SetupConnection {
            protocol: Protocol::MiningProtocol,
            min_version: 2,
            max_version: 2,
            flags,
            endpoint_host: host.as_slice().try_into().unwrap(),
            endpoint_port: 0,
            vendor: empty.try_into().unwrap(),
            hardware_version: empty.try_into().unwrap(),
            firmware: empty.try_into().unwrap(),
            device_id: empty.try_into().unwrap(),
        },
    )
    .expect("send");
}

pub fn raw_setup(rig: &Rig, flags: u32) -> SetupAnswer {
    let mut conn = raw_connect(rig);
    send_setup(&mut conn, flags);
    let frame = conn.recv().expect("reply");
    let mut r = Reader::new(&frame.payload);
    match frame.msg_type {
        MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS => {
            let _used_version = r.u16().unwrap();
            SetupAnswer::Success {
                flags: r.u32().unwrap(),
            }
        }
        MESSAGE_TYPE_SETUP_CONNECTION_ERROR => SetupAnswer::Error {
            flags: r.u32().unwrap(),
            code: r.text().unwrap(),
        },
        other => panic!("unexpected reply 0x{other:02x} to SetupConnection"),
    }
}

/// What the pool answers a `RequestExtensions` asking for `wanted`:
/// (unsupported or accepted, required, accepted?).
pub fn raw_request_extensions(rig: &Rig, wanted: &[u16]) -> (Vec<u16>, Vec<u16>, bool) {
    let mut conn = raw_connect(rig);
    send_setup(&mut conn, avian_sv2::flags::REQUIRES_STANDARD_JOBS);
    conn.recv_expect(EXT_CORE, MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS)
        .expect("setup success");

    let mut w = Writer::new();
    let payload = w.u16(1).seq_u16(wanted).finish();
    conn.send_raw(EXT_NEGOTIATION, MSG_REQUEST_EXTENSIONS, false, &payload)
        .expect("send");
    let frame = conn.recv().expect("reply");
    if frame.msg_type == avian_sv2::avian::MSG_REQUEST_EXTENSIONS_SUCCESS {
        let success = avian_sv2::avian::decode_request_extensions_success(&frame.payload).unwrap();
        (success.extensions, vec![], true)
    } else {
        let error = avian_sv2::avian::decode_request_extensions_error(&frame.payload).unwrap();
        (error.unsupported, error.required, false)
    }
}

pub const AVIAN_EXTENSION: u16 = EXT_AVIAN;

/// A raw connection taken as far as a miner takes one before it opens a
/// channel: handshake, `SetupConnection`, `RequestExtensions`,
/// `AvianSelectAlgorithm`.
///
/// The library client is one channel per connection, so a test that wants two
/// has to drive the wire itself.
pub fn raw_ready(rig: &Rig, pow: PowType) -> Connection {
    let mut conn = raw_connect(rig);
    send_setup(&mut conn, avian_sv2::flags::REQUIRES_STANDARD_JOBS);
    conn.recv_expect(EXT_CORE, MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS)
        .expect("setup success");

    let mut w = Writer::new();
    let payload = w.u16(1).seq_u16(&[EXT_AVIAN]).finish();
    conn.send_raw(EXT_NEGOTIATION, MSG_REQUEST_EXTENSIONS, false, &payload)
        .expect("send extensions");
    conn.recv_expect(EXT_NEGOTIATION, avian::MSG_REQUEST_EXTENSIONS_SUCCESS)
        .expect("extensions success");

    conn.send_raw(
        EXT_AVIAN,
        MSG_SELECT_ALGORITHM,
        false,
        &avian::encode_select_algorithm(pow),
    )
    .expect("send select");
    conn.recv_expect(EXT_AVIAN, MSG_SELECT_ALGORITHM_SUCCESS)
        .expect("select success");
    conn
}

/// Opens one standard channel on an already-ready connection.
///
/// Returns the channel id the pool assigned, and every frame read past while
/// waiting for the answer. Those are not noise: on a connection that already
/// has a channel they are that channel's target and work, and a caller that
/// drops them has silently thrown away the evidence it was about to assert
/// on.
pub fn open_standard(
    conn: &mut Connection,
    request_id: u32,
    identity: &str,
) -> (u32, Vec<avian_sv2::transport::Frame>) {
    open_standard_on(conn, request_id, identity, None)
}

/// The same, with an explicit algorithm for this channel alone, sent as the
/// `pow_type` TLV field on the open.
///
/// `None` sends no field at all, which is what a miner built before the field
/// existed does, and must still mean the connection's algorithm.
pub fn open_standard_on(
    conn: &mut Connection,
    request_id: u32,
    identity: &str,
    pow: Option<PowType>,
) -> (u32, Vec<avian_sv2::transport::Frame>) {
    let max_target = [0xffu8; 32];
    let mut payload = binary_sv2::to_bytes(OpenStandardMiningChannel {
        request_id,
        user_identity: identity.as_bytes().try_into().unwrap(),
        nominal_hash_rate: 1_000_000.0,
        max_target: max_target.as_slice().try_into().unwrap(),
    })
    .expect("encode open");
    if let Some(pow) = pow {
        avian_sv2::tlv::append(
            &mut payload,
            &[avian_sv2::tlv::Field::u8(
                EXT_AVIAN,
                avian_sv2::avian::TLV_FIELD_POW_TYPE,
                pow as u8,
            )],
        )
        .expect("append pow_type");
    }
    conn.send_raw(
        EXT_CORE,
        MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
        false,
        &payload,
    )
    .expect("send open");
    // Not recv_expect: the success is followed immediately by SetTarget and
    // a job, so by the time a second channel is opened there is already other
    // traffic in flight. Read past whatever is not the answer to this open.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut skipped = Vec::new();
    while Instant::now() < deadline {
        let frame = conn.recv().expect("open reply");
        match frame.msg_type {
            MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS => {
                let mut payload = frame.payload;
                let success: OpenStandardMiningChannelSuccess =
                    binary_sv2::from_bytes(&mut payload).expect("decode open success");
                return (success.channel_id, skipped);
            }
            MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR => {
                panic!("the pool refused the channel: {}", frame.describe())
            }
            _ => skipped.push(frame),
        }
    }
    panic!("the pool never answered the channel open")
}

/// A regtest address for the test miner to be paid at, with its scriptPubKey.
///
/// From a real node, so the script the pool derives can be compared against
/// what the node itself says the address means.
pub const WORKER_ADDRESS: &str = "mnPBEVKjU1zz9214C7M7Zp4FuurUAsU6ZS";
pub const WORKER_SCRIPT: &str = "76a9144b505a74657fb2b28c4741f5983b6ea88ea1fe0688ac";

/// A second one, for the operator fee.
pub const FEE_ADDRESS: &str = "2N7bauzAGSJTusSf3TUDQzpSDs6hH5qFGjs";
pub const FEE_SCRIPT: &str = "a9149d6b8c5b9c3743e6016c0baf56f4f90432977b4687";

pub fn worker_address() -> &'static str {
    WORKER_ADDRESS
}

pub fn script_for(address: &str) -> Vec<u8> {
    avian_sv2::address::Address::decode(address, Network::Regtest)
        .expect("a test address should decode")
        .script_pubkey()
}
