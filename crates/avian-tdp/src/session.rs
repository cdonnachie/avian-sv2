//! One Template Distribution session: one connection, one algorithm.
//!
//! A session knows nothing about mining channels or workers; it produces
//! rounds of work for one algorithm and nothing else, so a Mining Protocol
//! server can own one per algorithm without this module growing a notion of a
//! worker.
//!
//! The one thing it does hand out is a [`SolutionSubmitter`], because a
//! solution is found on a worker's thread while this session's own thread is
//! blocked in [`TdpSession::next_work`]. The submitter holds the connection's
//! sending half, which shares no state with the receiving half.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common_messages_sv2::{
    Protocol, SetupConnection, MESSAGE_TYPE_SETUP_CONNECTION, MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
    MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
};
use secp256k1::XOnlyPublicKey;
use template_distribution_sv2::{CoinbaseOutputConstraints, RequestTransactionData};

use crate::tdp::{
    decode_setup_connection_error, decode_setup_connection_success, decode_transaction_data_error,
    explain_transaction_data_error, PrevHash, Template, TransactionData,
    MESSAGE_TYPE_COINBASE_OUTPUT_CONSTRAINTS, MESSAGE_TYPE_NEW_TEMPLATE,
    MESSAGE_TYPE_REQUEST_TRANSACTION_DATA, MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_ERROR,
    MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS, MESSAGE_TYPE_SET_NEW_PREV_HASH,
    MESSAGE_TYPE_SUBMIT_SOLUTION,
};
use avian_sv2::avian::{
    self, PowType, EXT_AVIAN, EXT_CORE, EXT_NEGOTIATION, MSG_REQUEST_EXTENSIONS,
    MSG_REQUEST_EXTENSIONS_ERROR, MSG_REQUEST_EXTENSIONS_SUCCESS, MSG_SELECT_ALGORITHM,
    MSG_SELECT_ALGORITHM_ERROR, MSG_SELECT_ALGORITHM_SUCCESS, MSG_TIME_CONSTRAINTS,
};
use avian_sv2::error::{Error, Result};
use avian_sv2::reconnect::{self, Backoff};
use avian_sv2::transport::{Connection, ConnectionReader, ConnectionWriter, Frame, ServerIdentity};
use avian_sv2::wire::Writer;

pub const PROTOCOL_VERSION: u16 = 2;

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub addr: SocketAddr,
    /// `None` is trust on first use. Verification is the default everywhere a
    /// key path is available.
    pub authority: Option<XOnlyPublicKey>,
    pub pow: PowType,
    pub coinbase_output_max_additional_size: u32,
    pub coinbase_output_max_additional_sigops: u16,
    pub timeout: Duration,
}

impl SessionConfig {
    pub fn new(addr: SocketAddr, pow: PowType) -> Self {
        Self {
            addr,
            authority: None,
            pow,
            // Room for one payout output plus a little slack, which is all a
            // standard-channel pool adds. The node reserves this in the block
            // assembler, so declaring less than will be used produces a
            // submission that fails the canonical re-serialization check, with
            // nothing on the wire to say so.
            coinbase_output_max_additional_size: 1000,
            coinbase_output_max_additional_sigops: 10,
            timeout: Duration::from_secs(60),
        }
    }
}

/// One round of work.
///
/// doc/sv2.md says `SetNewPrevHash` "accompanies a template built on a tip the
/// client has not seen" and that an in-place refresh "sends only `NewTemplate`
/// and `AvianTimeConstraints`". `aviand` does not behave that way:
/// `TemplateProvider::SendTemplate` sends all three on every round
/// unconditionally. So `prev_hash` is always present in practice, and the
/// presence of one says nothing about whether the tip moved. Use
/// [`Work::tip_changed`], which compares the hash.
///
/// It is still an `Option`, because the documented behaviour is what a
/// third-party Template Provider would implement, and a round with no
/// `SetNewPrevHash` is not an error.
#[derive(Debug, Clone)]
pub struct Work {
    pub template: Template,
    pub prev_hash: Option<PrevHash>,
    pub constraints: avian::TimeConstraints,
    /// Whether the tip actually changed, by comparing the hash rather than by
    /// the presence of a `SetNewPrevHash`.
    pub tip_changed: bool,
}

/// Holds whichever connection's writer is current.
///
/// A `SubmitSolution` is sent from a worker's thread while the session's own
/// thread is blocked in [`TdpSession::next_work`], so the submitter cannot
/// borrow the session. It also has to survive a reconnect: the pool hands one
/// submitter to each algorithm at startup and never hands out another, so the
/// slot is what gets re-pointed when the connection is replaced.
#[derive(Clone, Default)]
pub struct SubmitterSlot(Arc<Mutex<Option<Arc<Mutex<ConnectionWriter>>>>>);

impl SubmitterSlot {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn submitter(&self) -> SolutionSubmitter {
        SolutionSubmitter { slot: self.clone() }
    }

    /// Whether a connection is installed. False between a drop and the
    /// reconnect that replaces it, which is what "upstream unhealthy" means
    /// for the stats endpoint.
    fn connected(&self) -> bool {
        self.0.lock().map(|slot| slot.is_some()).unwrap_or(false)
    }

    fn install(&self, writer: Arc<Mutex<ConnectionWriter>>) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = Some(writer);
        }
    }

    fn clear(&self) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = None;
        }
    }
}

/// Sends `SubmitSolution` on a session whose work loop is running elsewhere.
#[derive(Clone)]
pub struct SolutionSubmitter {
    slot: SubmitterSlot,
}

impl SolutionSubmitter {
    /// `coinbase` is the coinbase transaction serialized with its witness.
    ///
    /// There is no reply. doc/sv2.md: the Template Distribution Protocol has
    /// no `SubmitSolution.Error`, so a refused solution leaves no trace on the
    /// wire and only a `-debug=sv2` log line on the node.
    ///
    /// Fails if the session is between connections, which is the honest
    /// answer: a solution for a template from the previous connection has
    /// nowhere to go, because template ids do not survive a reconnect.
    /// Whether the session currently holds a connection. The stats endpoint
    /// reports this as upstream health; a pool with no upstream can still
    /// serve jobs it already has, but it cannot forward a block.
    pub fn is_connected(&self) -> bool {
        self.slot.connected()
    }

    pub fn submit(
        &self,
        template_id: u64,
        version: u32,
        ntime: u32,
        nonce: u32,
        coinbase: &[u8],
    ) -> Result<()> {
        let writer = self
            .slot
            .0
            .lock()
            .map_err(|_| Error::Protocol("the submitter slot is poisoned".into()))?
            .clone()
            .ok_or_else(|| {
                Error::Protocol(
                    "the Template Distribution session is not connected, so this solution                      cannot be submitted"
                        .into(),
                )
            })?;

        let mut w = Writer::new();
        w.u64(template_id).u32(version).u32(ntime).u32(nonce);
        let payload = w.bytes_u16(coinbase).finish();
        let mut writer = writer
            .lock()
            .map_err(|_| Error::Protocol("the session's writer is poisoned".into()))?;
        writer.send_raw(EXT_CORE, MESSAGE_TYPE_SUBMIT_SOLUTION, false, &payload)
    }
}

pub struct TdpSession {
    reader: ConnectionReader,
    writer: Arc<Mutex<ConnectionWriter>>,
    slot: SubmitterSlot,
    identity: ServerIdentity,
    pow: PowType,
    version_rolling_mask: u32,
    tip: Option<PrevHash>,
}

impl TdpSession {
    /// Walks a fresh connection all the way to the point of receiving work:
    /// handshake, `SetupConnection`, `RequestExtensions`,
    /// `AvianSelectAlgorithm`, `CoinbaseOutputConstraints`.
    pub fn open(config: &SessionConfig) -> Result<Self> {
        Self::open_into(config, &SubmitterSlot::new())
    }

    /// Opens a session that publishes its writer into a caller-owned slot, so
    /// a submitter handed out once keeps working across reconnects.
    pub fn open_into(config: &SessionConfig, slot: &SubmitterSlot) -> Result<Self> {
        let mut conn = Connection::connect(config.addr, config.authority, config.timeout)?;
        let identity = conn.identity().clone();

        setup_connection(&mut conn)?;
        request_extensions(&mut conn)?;
        let version_rolling_mask = select_algorithm(&mut conn, config.pow)?;
        conn.send(
            EXT_CORE,
            MESSAGE_TYPE_COINBASE_OUTPUT_CONSTRAINTS,
            false,
            CoinbaseOutputConstraints {
                coinbase_output_max_additional_size: config.coinbase_output_max_additional_size,
                coinbase_output_max_additional_sigops: config.coinbase_output_max_additional_sigops,
            },
        )?;

        let (reader, writer) = conn.split();
        slot.install(writer.clone());
        Ok(Self {
            reader,
            writer,
            slot: slot.clone(),
            identity,
            pow: config.pow,
            version_rolling_mask,
            tip: None,
        })
    }

    pub fn pow(&self) -> PowType {
        self.pow
    }

    pub fn version_rolling_mask(&self) -> u32 {
        self.version_rolling_mask
    }

    pub fn identity(&self) -> &ServerIdentity {
        &self.identity
    }

    pub fn tip(&self) -> Option<&PrevHash> {
        self.tip.as_ref()
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.reader.set_read_timeout(timeout)
    }

    pub fn submitter(&self) -> SolutionSubmitter {
        self.slot.submitter()
    }

    /// Reads one whole round of work.
    ///
    /// `AvianTimeConstraints` is what terminates the round: it is the only
    /// message guaranteed after every template, so a caller cannot assume a
    /// fixed number of messages per round.
    pub fn next_work(&mut self) -> Result<Work> {
        let mut frame = self
            .reader
            .recv_expect(EXT_CORE, MESSAGE_TYPE_NEW_TEMPLATE)?;
        let template = Template::decode(&mut frame.payload)?;

        let mut prev_hash = None;
        let mut tip_changed = false;
        loop {
            let mut frame = self.reader.recv()?;
            match (frame.extension_type, frame.msg_type) {
                (EXT_CORE, MESSAGE_TYPE_SET_NEW_PREV_HASH) => {
                    let decoded = PrevHash::decode(&mut frame.payload)?;
                    tip_changed = self
                        .tip
                        .as_ref()
                        .map_or(true, |tip| tip.prev_hash != decoded.prev_hash);
                    self.tip = Some(decoded.clone());
                    prev_hash = Some(decoded);
                }
                (EXT_AVIAN, MSG_TIME_CONSTRAINTS) => {
                    let constraints = avian::decode_time_constraints(&frame.payload)?;
                    if constraints.template_id != template.template_id {
                        return Err(Error::Protocol(format!(
                            "AvianTimeConstraints is for template {} but the template was {}",
                            constraints.template_id, template.template_id
                        )));
                    }
                    return Ok(Work {
                        template,
                        prev_hash,
                        constraints,
                        tip_changed,
                    });
                }
                _ => {
                    return Err(Error::Protocol(format!(
                        "unexpected {} alongside a template",
                        frame.describe()
                    )))
                }
            }
        }
    }

    pub fn request_transaction_data(&mut self, template_id: u64) -> Result<TransactionData> {
        self.writer
            .lock()
            .map_err(|_| Error::Protocol("the session's writer is poisoned".into()))?
            .send(
                EXT_CORE,
                MESSAGE_TYPE_REQUEST_TRANSACTION_DATA,
                false,
                RequestTransactionData { template_id },
            )?;

        let mut frame = self.reader.recv()?;
        match (frame.extension_type, frame.msg_type) {
            (EXT_CORE, MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS) => {
                TransactionData::decode(&mut frame.payload)
            }
            (EXT_CORE, MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_ERROR) => {
                let (id, code) = decode_transaction_data_error(&frame.payload)?;
                Err(Error::Refused(format!(
                    "RequestTransactionData for template {id}: {code} ({})",
                    explain_transaction_data_error(&code)
                )))
            }
            _ => Err(Error::Protocol(format!(
                "unexpected reply to RequestTransactionData: {}",
                frame.describe()
            ))),
        }
    }

    pub fn recv_raw(&mut self) -> Result<Frame> {
        self.reader.recv()
    }
}

fn setup_connection(conn: &mut Connection) -> Result<u16> {
    // Template Distribution defines no feature flags, and aviand rejects any
    // non-zero value with unsupported-feature-flags.
    let host = b"127.0.0.1";
    let vendor = b"avian-sv2-pool";
    let empty: &[u8] = b"";
    conn.send(
        EXT_CORE,
        MESSAGE_TYPE_SETUP_CONNECTION,
        false,
        SetupConnection {
            protocol: Protocol::TemplateDistributionProtocol,
            min_version: PROTOCOL_VERSION,
            max_version: PROTOCOL_VERSION,
            flags: 0,
            endpoint_host: host.as_slice().try_into()?,
            endpoint_port: 0,
            vendor: vendor.as_slice().try_into()?,
            hardware_version: empty.try_into()?,
            firmware: empty.try_into()?,
            device_id: empty.try_into()?,
        },
    )?;

    let frame = conn.recv()?;
    match (frame.extension_type, frame.msg_type) {
        (EXT_CORE, MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS) => {
            let (used_version, flags) = decode_setup_connection_success(&frame.payload)?;
            if used_version != PROTOCOL_VERSION {
                return Err(Error::Protocol(format!(
                    "the node chose protocol version {used_version}, not {PROTOCOL_VERSION}"
                )));
            }
            if flags != 0 {
                return Err(Error::Protocol(format!(
                    "the node set flags 0x{flags:08x}, but Template Distribution defines none"
                )));
            }
            Ok(used_version)
        }
        (EXT_CORE, MESSAGE_TYPE_SETUP_CONNECTION_ERROR) => {
            let (flags, code) = decode_setup_connection_error(&frame.payload)?;
            Err(Error::Refused(format!(
                "SetupConnection: {code} (flags 0x{flags:08x})"
            )))
        }
        _ => Err(Error::Protocol(format!(
            "unexpected reply to SetupConnection: {}",
            frame.describe()
        ))),
    }
}

/// Negotiates `0x4001`.
///
/// Not optional: the node runs `-sv2extensionpolicy=require` by default and
/// disconnects a client that never asks, with nothing on the wire to explain
/// it.
fn request_extensions(conn: &mut Connection) -> Result<Vec<u16>> {
    let payload = avian::encode_request_extensions(1, &[EXT_AVIAN]);
    conn.send_raw(EXT_NEGOTIATION, MSG_REQUEST_EXTENSIONS, false, &payload)?;

    let frame = conn.recv()?;
    match (frame.extension_type, frame.msg_type) {
        (EXT_NEGOTIATION, MSG_REQUEST_EXTENSIONS_SUCCESS) => {
            let success = avian::decode_request_extensions_success(&frame.payload)?;
            if !success.extensions.contains(&EXT_AVIAN) {
                return Err(Error::Protocol(format!(
                    "RequestExtensions.Success did not include 0x{EXT_AVIAN:04x}: {:04x?}",
                    success.extensions
                )));
            }
            Ok(success.extensions)
        }
        (EXT_NEGOTIATION, MSG_REQUEST_EXTENSIONS_ERROR) => {
            let error = avian::decode_request_extensions_error(&frame.payload)?;
            Err(Error::Refused(format!(
                "RequestExtensions: unsupported {:04x?}, required {:04x?}",
                error.unsupported, error.required
            )))
        }
        _ => Err(Error::Protocol(format!(
            "unexpected reply to RequestExtensions: {}",
            frame.describe()
        ))),
    }
}

fn select_algorithm(conn: &mut Connection, pow: PowType) -> Result<u32> {
    let payload = avian::encode_select_algorithm(pow);
    conn.send_raw(EXT_AVIAN, MSG_SELECT_ALGORITHM, false, &payload)?;

    let frame = conn.recv()?;
    match (frame.extension_type, frame.msg_type) {
        (EXT_AVIAN, MSG_SELECT_ALGORITHM_SUCCESS) => {
            let success = avian::decode_select_algorithm_success(&frame.payload)?;
            if success.pow_type != pow {
                return Err(Error::Protocol(format!(
                    "asked for {pow} and was given {}",
                    success.pow_type
                )));
            }
            // doc/sv2.md: always 0, with no option to change it. A client that
            // accepted a non-zero mask here would roll bits 16-23 and move its
            // share to the other algorithm's proof-of-work limit.
            if success.version_rolling_mask != 0 {
                return Err(Error::Protocol(format!(
                    "version_rolling_mask is 0x{:08x}, and this version of the extension \
                     specifies 0",
                    success.version_rolling_mask
                )));
            }
            Ok(success.version_rolling_mask)
        }
        (EXT_AVIAN, MSG_SELECT_ALGORITHM_ERROR) => Err(Error::Refused(format!(
            "AvianSelectAlgorithm: {}",
            avian::decode_select_algorithm_error(&frame.payload)?
        ))),
        _ => Err(Error::Protocol(format!(
            "unexpected reply to AvianSelectAlgorithm: {}",
            frame.describe()
        ))),
    }
}

/// A [`TdpSession`] that re-establishes itself when the node goes away.
///
/// The pool's upstream direction. The downstream one is
/// [`avian_sv2::client::MiningClient`], which does the same for a miner.
///
/// **Nothing survives a reconnect.** A new session means new `template_id`s,
/// so every template the pool was holding is unsubmittable and every job built
/// from one has to be withdrawn. That is why [`Round::Reconnected`] exists as
/// an event rather than being hidden: the caller has to act on it.
pub struct ReconnectingSession {
    config: SessionConfig,
    backoff: Backoff,
    slot: SubmitterSlot,
    session: Option<TdpSession>,
    generation: u64,
}

/// What one call to [`ReconnectingSession::next_work`] produced.
///
/// The variants are very different sizes, and boxing the big one would only
/// move an allocation onto the common path: a round of work arrives many times
/// per minute and a reconnect almost never.
#[allow(clippy::large_enum_variant)]
pub enum Round {
    Work {
        generation: u64,
        work: Work,
    },
    /// The session is new. Discard every template and job from before.
    Reconnected {
        generation: u64,
        attempts: u32,
    },
}

impl ReconnectingSession {
    pub fn open(config: SessionConfig, backoff: Backoff) -> Result<Self> {
        let mut session = Self {
            config,
            backoff,
            slot: SubmitterSlot::new(),
            session: None,
            generation: 0,
        };
        session.establish()?;
        Ok(session)
    }

    pub fn pow(&self) -> PowType {
        self.config.pow
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Valid across reconnects, which is the whole point of the slot.
    pub fn submitter(&self) -> SolutionSubmitter {
        self.slot.submitter()
    }

    pub fn is_connected(&self) -> bool {
        self.session.is_some()
    }

    pub fn version_rolling_mask(&self) -> u32 {
        self.session
            .as_ref()
            .map_or(0, TdpSession::version_rolling_mask)
    }

    pub fn identity_verified(&self) -> bool {
        self.session.as_ref().is_some_and(|s| s.identity().verified)
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        match &self.session {
            Some(session) => session.set_read_timeout(timeout),
            None => Ok(()),
        }
    }

    /// Reads one round of work, reconnecting if the node went away.
    ///
    /// A reconnect is reported rather than hidden, and no work comes with it:
    /// the caller gets [`Round::Reconnected`], withdraws what it was holding,
    /// and calls again for the first template of the new session.
    pub fn next_work(&mut self) -> Result<Round> {
        loop {
            if self.session.is_none() {
                let attempts = self.establish()?;
                return Ok(Round::Reconnected {
                    generation: self.generation,
                    attempts,
                });
            }
            let session = self.session.as_mut().expect("a session");
            match session.next_work() {
                Ok(work) => {
                    return Ok(Round::Work {
                        generation: self.generation,
                        work,
                    })
                }
                // A read timeout is the caller's own deadline firing, not a
                // dead connection, so it goes back to the caller rather than
                // provoking a reconnect.
                Err(e) if reconnect::is_read_timeout(&e) => return Err(e),
                Err(e) if reconnect::is_transient(&e) => {
                    self.session = None;
                    self.slot.clear();
                }
                Err(e) => return Err(e),
            }
        }
    }

    pub fn request_transaction_data(&mut self, template_id: u64) -> Result<TransactionData> {
        self.session
            .as_mut()
            .ok_or_else(|| Error::Protocol("not connected".into()))?
            .request_transaction_data(template_id)
    }

    fn establish(&mut self) -> Result<u32> {
        let config = self.config.clone();
        let slot = self.slot.clone();
        let mut attempts_used = 0;
        let session = reconnect::with_retry(
            &self.backoff,
            |attempt| {
                attempts_used = attempt;
                // with_retry decides whether to try again: a refused
                // SetupConnection or a certificate that does not verify fails
                // the same way forever, and retrying would turn a
                // configuration mistake into a silent hang.
                TdpSession::open_into(&config, &slot)
            },
            |_, _, _| {},
        )?;
        self.generation += 1;
        self.session = Some(session);
        Ok(attempts_used)
    }
}
