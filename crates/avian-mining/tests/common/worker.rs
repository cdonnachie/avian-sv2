//! A minimal Stratum v2 Mining Protocol client.
//!
//! Test support, not a miner and not a product. It does enough to open a
//! standard channel, receive jobs, search nonces and submit shares, so that
//! the pool has something to be driven by. It is also a second reader of the
//! pool's wire format, which is the only way to tell whether the pool's
//! ordering and flags are what it believes they are.
//!
//! It records every message it receives in order, because the properties worth
//! asserting here are orderings: that the time constraints arrive before the
//! `SetNewPrevHash` that activates a job, and that the first job on a channel
//! is a future job. Asserting the numbers agree would pass whatever order they
//! arrived in.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use avian_mining::flags;
use avian_tdp::avian::{
    self, PowType, EXT_AVIAN, EXT_NEGOTIATION, MSG_JOB_TIME_CONSTRAINTS, MSG_REQUEST_EXTENSIONS,
    MSG_REQUEST_EXTENSIONS_ERROR, MSG_REQUEST_EXTENSIONS_SUCCESS, MSG_SELECT_ALGORITHM,
    MSG_SELECT_ALGORITHM_ERROR, MSG_SELECT_ALGORITHM_SUCCESS,
};
use avian_tdp::block;
use avian_tdp::error::{Error, Result};
use avian_tdp::transport::{Connection, ConnectionReader, ConnectionWriter};
use avian_tdp::wire::{Reader, Writer};
use binary_sv2::{from_bytes, Sv2Option, U256};
use common_messages_sv2::{
    Protocol, SetupConnection, MESSAGE_TYPE_SETUP_CONNECTION, MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
    MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
};
use mining_sv2::{
    OpenStandardMiningChannel, SubmitSharesStandard, CHANNEL_BIT_OPEN_STANDARD_MINING_CHANNEL,
    CHANNEL_BIT_SUBMIT_SHARES_STANDARD, MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH,
    MESSAGE_TYPE_NEW_MINING_JOB, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR,
    MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL, MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
    MESSAGE_TYPE_SET_TARGET, MESSAGE_TYPE_SUBMIT_SHARES_ERROR, MESSAGE_TYPE_SUBMIT_SHARES_STANDARD,
    MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
};
use secp256k1::XOnlyPublicKey;

const EXT_CORE: u16 = 0x0000;

/// What arrived, in the order it arrived.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    SetupSuccess {
        flags: u32,
    },
    SetupError {
        flags: u32,
        code: String,
    },
    ExtensionsSuccess(Vec<u16>),
    ExtensionsError {
        unsupported: Vec<u16>,
        required: Vec<u16>,
    },
    AlgorithmSuccess {
        pow_type: u8,
        mask: u32,
    },
    AlgorithmError(String),
    OpenSuccess {
        channel_id: u32,
    },
    OpenError(String),
    SetTarget,
    NewMiningJob {
        job_id: u32,
        future: bool,
    },
    JobConstraints {
        job_id: u32,
        ntime_min: u32,
        ntime_max: u32,
    },
    SetNewPrevHash {
        job_id: u32,
        min_ntime: u32,
    },
    ShareAccepted {
        accepted: u32,
    },
    ShareRefused(String),
}

#[derive(Debug, Clone)]
pub struct Job {
    pub job_id: u32,
    pub version: u32,
    pub merkle_root: [u8; 32],
    pub ntime_min: u32,
    pub ntime_max: u32,
    pub future: bool,
}

pub struct Worker {
    reader: ConnectionReader,
    writer: Arc<Mutex<ConnectionWriter>>,
    pub events: Vec<Event>,
    pub channel_id: u32,
    pub target: [u8; 32],
    pub jobs: HashMap<u32, Job>,
    pub active_job: Option<u32>,
    pub prev_hash: Option<[u8; 32]>,
    pub nbits: u32,
    sequence: u32,
}

/// What a worker asks for in `SetupConnection.flags`, so a test can ask for
/// the wrong thing on purpose.
#[derive(Debug, Clone, Copy)]
pub struct Requested(pub u32);

impl Default for Requested {
    fn default() -> Self {
        Self(flags::REQUIRES_STANDARD_JOBS)
    }
}

impl Worker {
    /// Connects and completes the Noise handshake, verifying the pool's
    /// certificate against its authority key.
    pub fn connect(addr: SocketAddr, pool_authority: XOnlyPublicKey) -> Result<Self> {
        let conn = Connection::connect(addr, Some(pool_authority), Duration::from_secs(30))?;
        let (reader, writer) = conn.split();
        Ok(Self {
            reader,
            writer,
            events: Vec::new(),
            channel_id: 0,
            target: [0xff; 32],
            jobs: HashMap::new(),
            active_job: None,
            prev_hash: None,
            nbits: 0,
            sequence: 0,
        })
    }

    pub fn setup_connection(&mut self, requested: Requested) -> Result<()> {
        let host = b"127.0.0.1";
        let vendor = b"avian-test-worker";
        let empty: &[u8] = b"";
        self.send(
            EXT_CORE,
            MESSAGE_TYPE_SETUP_CONNECTION,
            false,
            SetupConnection {
                protocol: Protocol::MiningProtocol,
                min_version: 2,
                max_version: 2,
                flags: requested.0,
                endpoint_host: host.as_slice().try_into()?,
                endpoint_port: 0,
                vendor: vendor.as_slice().try_into()?,
                hardware_version: empty.try_into()?,
                firmware: empty.try_into()?,
                device_id: empty.try_into()?,
            },
        )?;
        self.read_one()
    }

    pub fn request_extensions(&mut self, wanted: &[u16]) -> Result<()> {
        let mut w = Writer::new();
        let payload = w.u16(1).seq_u16(wanted).finish();
        self.send_raw(EXT_NEGOTIATION, MSG_REQUEST_EXTENSIONS, false, &payload)?;
        self.read_one()
    }

    pub fn select_algorithm(&mut self, pow: PowType) -> Result<()> {
        self.send_raw(
            EXT_AVIAN,
            MSG_SELECT_ALGORITHM,
            false,
            &avian::encode_select_algorithm(pow),
        )?;
        self.read_one()
    }

    pub fn open_channel(&mut self) -> Result<()> {
        let identity = b"test-worker";
        self.send(
            EXT_CORE,
            MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
            CHANNEL_BIT_OPEN_STANDARD_MINING_CHANNEL,
            OpenStandardMiningChannel {
                request_id: 42,
                user_identity: identity.as_slice().try_into()?,
                nominal_hash_rate: 1.0,
                // The easiest target there is, so the pool's own choice is
                // never clamped by ours.
                max_target: U256::try_from([0xffu8; 32].as_slice())?,
            },
        )?;
        self.read_one()
    }

    /// The whole happy path up to holding an active job.
    pub fn join(addr: SocketAddr, pool_authority: XOnlyPublicKey, pow: PowType) -> Result<Self> {
        let mut worker = Self::connect(addr, pool_authority)?;
        worker.setup_connection(Requested::default())?;
        worker.expect_setup_success()?;
        worker.request_extensions(&[EXT_AVIAN])?;
        worker.select_algorithm(pow)?;
        worker.open_channel()?;
        // Success, SetTarget, then the first round of work.
        worker.read_until_active()?;
        Ok(worker)
    }

    pub fn expect_setup_success(&mut self) -> Result<u32> {
        match self.events.last() {
            Some(Event::SetupSuccess { flags }) => Ok(*flags),
            other => Err(Error::Protocol(format!(
                "expected SetupConnection.Success, got {other:?}"
            ))),
        }
    }

    /// Reads until a job is active, meaning a `SetNewPrevHash` has named it.
    pub fn read_until_active(&mut self) -> Result<u32> {
        for _ in 0..32 {
            if let Some(job_id) = self.active_job {
                if self.jobs.contains_key(&job_id) {
                    return Ok(job_id);
                }
            }
            self.read_one()?;
        }
        Err(Error::Protocol("no job became active".into()))
    }

    /// Reads until one more round of work has fully arrived.
    pub fn read_next_job(&mut self) -> Result<u32> {
        let before = self.jobs.len();
        for _ in 0..32 {
            self.read_one()?;
            if self.jobs.len() > before {
                if let Some(Event::JobConstraints { job_id, .. }) = self.events.last() {
                    return Ok(*job_id);
                }
            }
        }
        Err(Error::Protocol("no further job arrived".into()))
    }

    pub fn active(&self) -> Option<&Job> {
        self.jobs.get(&self.active_job?)
    }

    /// Searches nonces for a header meeting `target`.
    ///
    /// Avian has no cheap pre-filter, so this is the only way to search: hash
    /// and look. On regtest the target is the algorithm's own floor, so a
    /// handful of nonces is enough and the bound only exists so a broken build
    /// fails instead of looping.
    pub fn find_share(&self, pow: PowType, attempts: u32) -> Option<(u32, u32)> {
        let job = self.active()?;
        let prev = self.prev_hash?;
        let hasher = match pow {
            PowType::X16rt => avian_pow::PowType::X16rt,
            PowType::MinotaurX => avian_pow::PowType::MinotaurX,
        };
        // The window is pinned shut on regtest, because nBits there is a
        // function of nTime, so there is exactly one legal ntime.
        let ntime = job.ntime_min;
        for nonce in 0..attempts {
            let header = block::header(
                job.version,
                &prev,
                &job.merkle_root,
                ntime,
                self.nbits,
                nonce,
            );
            let hash = avian_pow::hash(hasher, &header)?;
            if block::meets_target(&hash, &self.target) {
                return Some((nonce, ntime));
            }
        }
        None
    }

    pub fn submit(&mut self, job_id: u32, nonce: u32, ntime: u32, version: u32) -> Result<()> {
        self.sequence += 1;
        let sequence = self.sequence;
        let channel_id = self.channel_id;
        self.send(
            EXT_CORE,
            MESSAGE_TYPE_SUBMIT_SHARES_STANDARD,
            CHANNEL_BIT_SUBMIT_SHARES_STANDARD,
            SubmitSharesStandard {
                channel_id,
                sequence_number: sequence,
                job_id,
                nonce,
                ntime,
                version,
            },
        )?;
        self.read_one()
    }

    /// Submits the active job as it was given, which is what a conforming
    /// worker does.
    pub fn submit_share(&mut self, pow: PowType) -> Result<Option<(u32, u32)>> {
        let Some((nonce, ntime)) = self.find_share(pow, 200) else {
            return Ok(None);
        };
        let job = self.active().expect("an active job").clone();
        self.submit(job.job_id, nonce, ntime, job.version)?;
        Ok(Some((nonce, ntime)))
    }

    /// Reads and records exactly one message.
    pub fn read_one(&mut self) -> Result<()> {
        let mut frame = self.reader.recv()?;
        let event = match (frame.extension_type, frame.msg_type) {
            (EXT_CORE, MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS) => {
                let mut r = Reader::new(&frame.payload);
                let _used_version = r.u16()?;
                Event::SetupSuccess { flags: r.u32()? }
            }
            (EXT_CORE, MESSAGE_TYPE_SETUP_CONNECTION_ERROR) => {
                let mut r = Reader::new(&frame.payload);
                Event::SetupError {
                    flags: r.u32()?,
                    code: r.text()?,
                }
            }
            (EXT_NEGOTIATION, MSG_REQUEST_EXTENSIONS_SUCCESS) => {
                let success = avian::decode_request_extensions_success(&frame.payload)?;
                Event::ExtensionsSuccess(success.extensions)
            }
            (EXT_NEGOTIATION, MSG_REQUEST_EXTENSIONS_ERROR) => {
                let error = avian::decode_request_extensions_error(&frame.payload)?;
                Event::ExtensionsError {
                    unsupported: error.unsupported,
                    required: error.required,
                }
            }
            (EXT_AVIAN, MSG_SELECT_ALGORITHM_SUCCESS) => {
                let success = avian::decode_select_algorithm_success(&frame.payload)?;
                Event::AlgorithmSuccess {
                    pow_type: success.pow_type as u8,
                    mask: success.version_rolling_mask,
                }
            }
            (EXT_AVIAN, MSG_SELECT_ALGORITHM_ERROR) => {
                Event::AlgorithmError(avian::decode_select_algorithm_error(&frame.payload)?)
            }
            (EXT_CORE, MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS) => {
                let success: mining_sv2::OpenStandardMiningChannelSuccess =
                    from_bytes(&mut frame.payload)?;
                self.channel_id = success.channel_id;
                self.target.copy_from_slice(success.target.as_ref());
                Event::OpenSuccess {
                    channel_id: success.channel_id,
                }
            }
            (EXT_CORE, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR) => {
                let error: mining_sv2::OpenMiningChannelError = from_bytes(&mut frame.payload)?;
                Event::OpenError(String::from_utf8_lossy(error.error_code.as_ref()).into_owned())
            }
            (EXT_CORE, MESSAGE_TYPE_SET_TARGET) => {
                let set: mining_sv2::SetTarget = from_bytes(&mut frame.payload)?;
                self.target.copy_from_slice(set.maximum_target.as_ref());
                Event::SetTarget
            }
            (EXT_CORE, MESSAGE_TYPE_NEW_MINING_JOB) => {
                let job: mining_sv2::NewMiningJob = from_bytes(&mut frame.payload)?;
                let min_ntime: Sv2Option<u32> = job.min_ntime;
                let start = min_ntime.into_inner();
                let mut merkle_root = [0u8; 32];
                merkle_root.copy_from_slice(job.merkle_root.as_ref());
                let future = start.is_none();
                self.jobs.insert(
                    job.job_id,
                    Job {
                        job_id: job.job_id,
                        version: job.version,
                        merkle_root,
                        // Filled in by the constraints that follow.
                        ntime_min: start.unwrap_or(0),
                        ntime_max: start.unwrap_or(0),
                        future,
                    },
                );
                Event::NewMiningJob {
                    job_id: job.job_id,
                    future,
                }
            }
            (EXT_AVIAN, MSG_JOB_TIME_CONSTRAINTS) => {
                if !frame.channel_msg {
                    return Err(Error::Protocol(
                        "AvianJobTimeConstraints must set the channel_msg bit, so it travels \
                         under 0xc001"
                            .into(),
                    ));
                }
                let bounds = avian::decode_job_time_constraints(&frame.payload)?;
                if let Some(job) = self.jobs.get_mut(&bounds.job_id) {
                    job.ntime_min = bounds.ntime_min;
                    job.ntime_max = bounds.ntime_max;
                }
                Event::JobConstraints {
                    job_id: bounds.job_id,
                    ntime_min: bounds.ntime_min,
                    ntime_max: bounds.ntime_max,
                }
            }
            (EXT_CORE, MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH) => {
                let set: mining_sv2::SetNewPrevHash = from_bytes(&mut frame.payload)?;
                let mut prev = [0u8; 32];
                prev.copy_from_slice(set.prev_hash.as_ref());
                self.prev_hash = Some(prev);
                self.nbits = set.nbits;
                self.active_job = Some(set.job_id);
                if let Some(job) = self.jobs.get_mut(&set.job_id) {
                    job.future = false;
                }
                Event::SetNewPrevHash {
                    job_id: set.job_id,
                    min_ntime: set.min_ntime,
                }
            }
            (EXT_CORE, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS) => {
                let success: mining_sv2::SubmitSharesSuccess = from_bytes(&mut frame.payload)?;
                Event::ShareAccepted {
                    accepted: success.new_submits_accepted_count,
                }
            }
            (EXT_CORE, MESSAGE_TYPE_SUBMIT_SHARES_ERROR) => {
                let error: mining_sv2::SubmitSharesError = from_bytes(&mut frame.payload)?;
                Event::ShareRefused(String::from_utf8_lossy(error.error_code.as_ref()).into_owned())
            }
            _ => {
                return Err(Error::Protocol(format!(
                    "the pool sent an unexpected {}",
                    frame.describe()
                )))
            }
        };
        self.events.push(event);
        Ok(())
    }

    /// The positions of the events matching a predicate, for ordering
    /// assertions.
    pub fn position_of(&self, matches: impl Fn(&Event) -> bool) -> Option<usize> {
        self.events.iter().position(matches)
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.reader.set_read_timeout(timeout)
    }

    fn send<T: binary_sv2::Serialize + binary_sv2::GetSize>(
        &mut self,
        extension_type: u16,
        msg_type: u8,
        channel_msg: bool,
        message: T,
    ) -> Result<()> {
        self.writer
            .lock()
            .map_err(|_| Error::Protocol("the worker's writer is poisoned".into()))?
            .send(extension_type, msg_type, channel_msg, message)
    }

    fn send_raw(
        &mut self,
        extension_type: u16,
        msg_type: u8,
        channel_msg: bool,
        payload: &[u8],
    ) -> Result<()> {
        self.writer
            .lock()
            .map_err(|_| Error::Protocol("the worker's writer is poisoned".into()))?
            .send_raw(extension_type, msg_type, channel_msg, payload)
    }
}
