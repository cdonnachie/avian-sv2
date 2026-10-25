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

use crate::avian::{
    self, PowType, EXT_AVIAN, EXT_CORE, EXT_NEGOTIATION, MSG_REQUEST_EXTENSIONS,
    MSG_REQUEST_EXTENSIONS_ERROR, MSG_REQUEST_EXTENSIONS_SUCCESS, MSG_SELECT_ALGORITHM,
    MSG_SELECT_ALGORITHM_ERROR, MSG_SELECT_ALGORITHM_SUCCESS, MSG_TIME_CONSTRAINTS,
};
use crate::error::{Error, Result};
use crate::tdp::{
    decode_setup_connection_error, decode_setup_connection_success, decode_transaction_data_error,
    explain_transaction_data_error, PrevHash, Template, TransactionData,
    MESSAGE_TYPE_COINBASE_OUTPUT_CONSTRAINTS, MESSAGE_TYPE_NEW_TEMPLATE,
    MESSAGE_TYPE_REQUEST_TRANSACTION_DATA, MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_ERROR,
    MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS, MESSAGE_TYPE_SET_NEW_PREV_HASH,
    MESSAGE_TYPE_SUBMIT_SOLUTION,
};
use crate::transport::{Connection, ConnectionReader, ConnectionWriter, Frame, ServerIdentity};
use crate::wire::Writer;

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

/// Sends `SubmitSolution` on a session whose work loop is running elsewhere.
#[derive(Clone)]
pub struct SolutionSubmitter {
    writer: Arc<Mutex<ConnectionWriter>>,
}

impl SolutionSubmitter {
    /// `coinbase` is the coinbase transaction serialized with its witness.
    ///
    /// There is no reply. doc/sv2.md: the Template Distribution Protocol has
    /// no `SubmitSolution.Error`, so a refused solution leaves no trace on the
    /// wire and only a `-debug=sv2` log line on the node.
    pub fn submit(
        &self,
        template_id: u64,
        version: u32,
        ntime: u32,
        nonce: u32,
        coinbase: &[u8],
    ) -> Result<()> {
        let mut writer = Writer::new();
        writer.u64(template_id).u32(version).u32(ntime).u32(nonce);
        let payload = writer.bytes_u16(coinbase).finish();
        self.writer
            .lock()
            .map_err(|_| Error::Protocol("the session's writer is poisoned".into()))?
            .send_raw(EXT_CORE, MESSAGE_TYPE_SUBMIT_SOLUTION, false, &payload)
    }
}

pub struct TdpSession {
    reader: ConnectionReader,
    writer: Arc<Mutex<ConnectionWriter>>,
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
        Ok(Self {
            reader,
            writer,
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
        SolutionSubmitter {
            writer: self.writer.clone(),
        }
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
