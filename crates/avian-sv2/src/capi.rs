//! The `extern "C"` surface, for `cpuminer-opt` and a ccminer fork.
//!
//! The boundary is section 10 of the plan's neutral `AvianMiningJob`: the C
//! side sees jobs and submits shares, and never sees Noise, framing or a
//! Stratum v2 type. Everything here is a plain `#[repr(C)]` struct, a
//! primitive, or an opaque handle.
//!
//! Three rules this surface keeps, because a C caller cannot be made to read
//! Rust docs:
//!
//! - No Rust type crosses the boundary, and nothing allocated here is freed
//!   there. Strings are copied into caller-owned fixed buffers rather than
//!   handed out as pointers with a lifetime.
//! - No panic crosses the boundary. Every entry point catches one and turns it
//!   into [`AVIAN_SV2_ERROR`], because unwinding into C is undefined.
//! - A null pointer is an error, not a crash.
//!
//! The matching declarations are in `include/avian_sv2.h`, written by hand and
//! kept honest by `ctest/session.c`, which is compiled against it and run
//! against a real pool.

use std::ffi::{c_char, c_float, c_int, c_uint, c_void, CStr};
use std::net::ToSocketAddrs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Duration;

use crate::avian::PowType;
use crate::block;
use crate::client::{ClientConfig, Event, MiningClient, MiningJob};
use crate::reconnect::Backoff;

pub const AVIAN_SV2_OK: c_int = 0;
pub const AVIAN_SV2_TIMEOUT: c_int = 1;
pub const AVIAN_SV2_DISCONNECTED: c_int = 2;
pub const AVIAN_SV2_ERROR: c_int = -1;
pub const AVIAN_SV2_INVALID_ARGUMENT: c_int = -2;

pub const AVIAN_SV2_POW_X16RT: c_int = 0;
pub const AVIAN_SV2_POW_MINOTAURX: c_int = 1;

pub const AVIAN_SV2_EVENT_NONE: c_int = 0;
pub const AVIAN_SV2_EVENT_JOB: c_int = 1;
pub const AVIAN_SV2_EVENT_JOBS_INVALIDATED: c_int = 2;
pub const AVIAN_SV2_EVENT_SHARE_ACCEPTED: c_int = 3;
pub const AVIAN_SV2_EVENT_SHARE_REJECTED: c_int = 4;
pub const AVIAN_SV2_EVENT_RECONNECTED: c_int = 5;
pub const AVIAN_SV2_EVENT_DISCONNECTED: c_int = 6;

/// How much room a message or error code gets in an event.
pub const AVIAN_SV2_MESSAGE_LEN: usize = 256;

/// A job, in the neutral form of plan section 10.
///
/// `network_target` from that struct is absent, and its absence is the
/// contract: a standard-channel worker is told only its share target. Whether
/// a share is also a block is the pool's determination, because only the pool
/// holds the template, and the pool forwards a winning one itself.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AvianMiningJob {
    pub job_id: c_uint,
    /// Which connection this job came from. A reconnect bumps it and job ids
    /// start again, so work in flight from an earlier generation must be
    /// thrown away.
    pub generation: u64,
    pub pow_type: c_int,
    pub version: c_uint,
    pub prev_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    /// Where to start, which is `ntime_min`.
    pub ntime: c_uint,
    pub ntime_min: c_uint,
    pub ntime_max: c_uint,
    pub nbits: c_uint,
    pub share_target: [u8; 32],
}

impl AvianMiningJob {
    fn empty() -> Self {
        Self {
            job_id: 0,
            generation: 0,
            pow_type: -1,
            version: 0,
            prev_hash: [0; 32],
            merkle_root: [0; 32],
            ntime: 0,
            ntime_min: 0,
            ntime_max: 0,
            nbits: 0,
            share_target: [0; 32],
        }
    }

    fn from(job: &MiningJob) -> Self {
        Self {
            job_id: job.job_id,
            generation: job.generation,
            pow_type: job.pow_type as c_int,
            version: job.version,
            prev_hash: job.prev_hash,
            merkle_root: job.merkle_root,
            ntime: job.ntime,
            ntime_min: job.ntime_min,
            ntime_max: job.ntime_max,
            nbits: job.nbits,
            share_target: job.share_target,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AvianSv2Event {
    pub kind: c_int,
    /// Meaningful when `kind` is `AVIAN_SV2_EVENT_JOB`.
    pub job: AvianMiningJob,
    pub sequence_number: c_uint,
    pub accepted_count: c_uint,
    pub generation: u64,
    /// NUL-terminated. The refusal code for a rejected share, or the reason
    /// for a disconnect.
    pub message: [c_char; AVIAN_SV2_MESSAGE_LEN],
}

impl AvianSv2Event {
    fn empty() -> Self {
        Self {
            kind: AVIAN_SV2_EVENT_NONE,
            job: AvianMiningJob::empty(),
            sequence_number: 0,
            accepted_count: 0,
            generation: 0,
            message: [0; AVIAN_SV2_MESSAGE_LEN],
        }
    }

    fn set_message(&mut self, text: &str) {
        let bytes = text.as_bytes();
        let room = AVIAN_SV2_MESSAGE_LEN - 1;
        let take = bytes.len().min(room);
        for (slot, byte) in self.message.iter_mut().zip(&bytes[..take]) {
            *slot = *byte as c_char;
        }
        self.message[take] = 0;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AvianSv2ClientConfig {
    /// `"host:port"`, NUL-terminated. Loopback only.
    pub pool: *const c_char,
    /// The pool's authority public key as the operator published it: either
    /// the base58 form a Stratum v2 miner configuration takes, or 64 hex
    /// characters. Null is trust on first use, which leaves the session
    /// encrypted but says nothing about whether the peer is the pool you
    /// meant.
    pub authority_hex: *const c_char,
    pub pow_type: c_int,
    /// May be null.
    pub user_identity: *const c_char,
    pub nominal_hash_rate: c_float,
    pub timeout_ms: c_uint,
    /// 0 for the defaults: 250ms doubling to 30s.
    pub backoff_initial_ms: c_uint,
    pub backoff_max_ms: c_uint,
    /// 0 retries forever, which is what a miner wants.
    pub max_reconnects: c_uint,
}

/// The opaque handle. A `MiningClient` plus the last error, since a C caller
/// has no `Result`.
pub struct AvianSv2Client {
    client: MiningClient,
    last_error: std::ffi::CString,
}

fn pow_from_c(value: c_int) -> Option<PowType> {
    match value {
        AVIAN_SV2_POW_X16RT => Some(PowType::X16rt),
        AVIAN_SV2_POW_MINOTAURX => Some(PowType::MinotaurX),
        _ => None,
    }
}

unsafe fn text(pointer: *const c_char) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    CStr::from_ptr(pointer).to_str().ok().map(str::to_owned)
}

fn build_config(raw: &AvianSv2ClientConfig) -> Result<ClientConfig, &'static str> {
    let pool = unsafe { text(raw.pool) }.ok_or("pool must be a NUL-terminated UTF-8 string")?;
    let addr = pool
        .to_socket_addrs()
        .map_err(|_| "pool could not be resolved")?
        .next()
        .ok_or("pool resolved to nothing")?;
    if !addr.ip().is_loopback() {
        return Err("this library connects to loopback only");
    }
    let pow = pow_from_c(raw.pow_type).ok_or("pow_type must be 0 (x16rt) or 1 (minotaurx)")?;

    let mut config = ClientConfig::new(addr, pow);
    if let Some(hex) = unsafe { text(raw.authority_hex) } {
        // Either form, because an operator may publish either and a miner
        // should not have to care which: base58 is what SRI-derived miner
        // configurations take, hex is what this project logged first.
        let key = crate::address::decode_authority_key(&hex)
            .ok()
            .or_else(|| crate::authority::from_hex(&hex).ok())
            .ok_or("authority is neither a base58 nor a hex public key")?;
        config.pool_authority = Some(key);
    }
    if let Some(identity) = unsafe { text(raw.user_identity) } {
        config.user_identity = identity;
    }
    if raw.nominal_hash_rate > 0.0 {
        config.nominal_hash_rate = raw.nominal_hash_rate;
    }
    if raw.timeout_ms > 0 {
        config.timeout = Duration::from_millis(raw.timeout_ms as u64);
    }
    let mut backoff = Backoff::default();
    if raw.backoff_initial_ms > 0 {
        backoff.initial = Duration::from_millis(raw.backoff_initial_ms as u64);
    }
    if raw.backoff_max_ms > 0 {
        backoff.max = Duration::from_millis(raw.backoff_max_ms as u64);
    }
    if raw.max_reconnects > 0 {
        backoff.max_attempts = Some(raw.max_reconnects);
    }
    config.reconnect = backoff;
    Ok(config)
}

/// Connects, negotiates and opens a channel. Returns null on failure, with
/// `status` set and the reason available from
/// [`avian_sv2_last_connect_error`].
///
/// # Safety
/// `config` must point to a valid `AvianSv2ClientConfig` whose string members
/// are null or NUL-terminated. `status` may be null.
#[no_mangle]
pub unsafe extern "C" fn avian_sv2_client_connect(
    config: *const AvianSv2ClientConfig,
    status: *mut c_int,
) -> *mut AvianSv2Client {
    let set = |value: c_int| {
        if !status.is_null() {
            *status = value;
        }
    };
    if config.is_null() {
        set(AVIAN_SV2_INVALID_ARGUMENT);
        store_connect_error("config is null");
        return std::ptr::null_mut();
    }
    let raw = *config;

    let result = catch_unwind(AssertUnwindSafe(|| {
        let config = build_config(&raw).map_err(|e| (AVIAN_SV2_INVALID_ARGUMENT, e.to_string()))?;
        MiningClient::connect(config).map_err(|e| (AVIAN_SV2_ERROR, e.to_string()))
    }));

    match result {
        Ok(Ok(client)) => {
            set(AVIAN_SV2_OK);
            store_connect_error("");
            Box::into_raw(Box::new(AvianSv2Client {
                client,
                last_error: std::ffi::CString::default(),
            }))
        }
        Ok(Err((code, message))) => {
            set(code);
            store_connect_error(&message);
            std::ptr::null_mut()
        }
        Err(_) => {
            set(AVIAN_SV2_ERROR);
            store_connect_error("panicked while connecting");
            std::ptr::null_mut()
        }
    }
}

// A connect failure has no handle to hang an error off, so it goes here. One
// slot per thread, which is the usual C convention and avoids a lock.
thread_local! {
    static CONNECT_ERROR: std::cell::RefCell<std::ffi::CString> =
        std::cell::RefCell::new(std::ffi::CString::default());
}

fn store_connect_error(message: &str) {
    let sanitized = message.replace('\0', " ");
    if let Ok(value) = std::ffi::CString::new(sanitized) {
        CONNECT_ERROR.with(|slot| *slot.borrow_mut() = value);
    }
}

/// Why the last [`avian_sv2_client_connect`] on this thread failed.
/// NUL-terminated, owned by the library, valid until the next connect call on
/// the same thread.
#[no_mangle]
pub extern "C" fn avian_sv2_last_connect_error() -> *const c_char {
    CONNECT_ERROR.with(|slot| slot.borrow().as_ptr())
}

/// Reads one event, waiting at most `timeout_ms`.
///
/// Returns `AVIAN_SV2_TIMEOUT` and an event of kind `NONE` when nothing
/// arrived, which is the normal case while hashing. A dropped connection
/// surfaces as `AVIAN_SV2_DISCONNECTED` with a `DISCONNECTED` event; the next
/// call reconnects and reports `RECONNECTED`. A caller may treat both as "keep
/// going" so long as it throws away jobs whose `generation` is no longer
/// current.
///
/// # Safety
/// `client` must be a handle from [`avian_sv2_client_connect`] that has not
/// been freed, and `event` must point to writable storage for one
/// `AvianSv2Event`.
#[no_mangle]
pub unsafe extern "C" fn avian_sv2_client_poll(
    client: *mut AvianSv2Client,
    timeout_ms: c_uint,
    event: *mut AvianSv2Event,
) -> c_int {
    if client.is_null() || event.is_null() {
        return AVIAN_SV2_INVALID_ARGUMENT;
    }
    let handle = &mut *client;
    let mut out = AvianSv2Event::empty();

    let polled = catch_unwind(AssertUnwindSafe(|| {
        handle.client.poll(Duration::from_millis(timeout_ms as u64))
    }));

    let code = match polled {
        Err(_) => {
            handle.set_error("panicked while polling");
            AVIAN_SV2_ERROR
        }
        Ok(Err(e)) => {
            handle.set_error(&e.to_string());
            out.set_message(&e.to_string());
            AVIAN_SV2_ERROR
        }
        Ok(Ok(Event::Idle)) => {
            out.kind = AVIAN_SV2_EVENT_NONE;
            AVIAN_SV2_TIMEOUT
        }
        Ok(Ok(Event::Job(job))) => {
            out.kind = AVIAN_SV2_EVENT_JOB;
            out.generation = job.generation;
            out.job = AvianMiningJob::from(&job);
            AVIAN_SV2_OK
        }
        Ok(Ok(Event::JobsInvalidated { generation })) => {
            out.kind = AVIAN_SV2_EVENT_JOBS_INVALIDATED;
            out.generation = generation;
            AVIAN_SV2_OK
        }
        Ok(Ok(Event::ShareAccepted {
            sequence_number,
            accepted_count,
            ..
        })) => {
            out.kind = AVIAN_SV2_EVENT_SHARE_ACCEPTED;
            out.sequence_number = sequence_number;
            out.accepted_count = accepted_count;
            AVIAN_SV2_OK
        }
        Ok(Ok(Event::ShareRejected {
            sequence_number,
            code,
        })) => {
            out.kind = AVIAN_SV2_EVENT_SHARE_REJECTED;
            out.sequence_number = sequence_number;
            out.set_message(&code);
            AVIAN_SV2_OK
        }
        Ok(Ok(Event::Disconnected { reason })) => {
            out.kind = AVIAN_SV2_EVENT_DISCONNECTED;
            out.set_message(&reason);
            AVIAN_SV2_DISCONNECTED
        }
        Ok(Ok(Event::Reconnected {
            generation,
            attempts,
        })) => {
            out.kind = AVIAN_SV2_EVENT_RECONNECTED;
            out.generation = generation;
            out.accepted_count = attempts;
            AVIAN_SV2_OK
        }
    };
    *event = out;
    code
}

/// Submits a share for the job you were handed.
///
/// Takes the job rather than its id, because a job id is only unique within a
/// generation: a reconnect restarts them, so submitting by id alone would let
/// a nonce found for job 1 of one connection be applied to job 1 of the next.
/// The version is taken from the job, not from the caller.
///
/// # Safety
/// `client` must be a live handle from [`avian_sv2_client_connect`], and `job`
/// must point to a job obtained from [`avian_sv2_client_poll`].
#[no_mangle]
pub unsafe extern "C" fn avian_sv2_client_submit(
    client: *mut AvianSv2Client,
    job: *const AvianMiningJob,
    nonce: c_uint,
    ntime: c_uint,
) -> c_int {
    if client.is_null() || job.is_null() {
        return AVIAN_SV2_INVALID_ARGUMENT;
    }
    let handle = &mut *client;
    let Some(job) = handle
        .client
        .job((*job).job_id)
        .cloned()
        .filter(|known| known.generation == (*job).generation && known.job_id == (*job).job_id)
    else {
        handle.set_error("that job is not current on this connection");
        return AVIAN_SV2_INVALID_ARGUMENT;
    };
    match catch_unwind(AssertUnwindSafe(|| {
        handle.client.submit(&job, nonce, ntime)
    })) {
        Ok(Ok(_)) => AVIAN_SV2_OK,
        Ok(Err(e)) => {
            handle.set_error(&e.to_string());
            if handle.client.is_connected() {
                AVIAN_SV2_INVALID_ARGUMENT
            } else {
                AVIAN_SV2_DISCONNECTED
            }
        }
        Err(_) => {
            handle.set_error("panicked while submitting");
            AVIAN_SV2_ERROR
        }
    }
}

/// Closes the connection, so the next poll reconnects. For failover, and for
/// a test that wants to watch a real reconnection.
///
/// # Safety
/// `client` must be a live handle from [`avian_sv2_client_connect`].
#[no_mangle]
pub unsafe extern "C" fn avian_sv2_client_disconnect(client: *mut AvianSv2Client) -> c_int {
    if client.is_null() {
        return AVIAN_SV2_INVALID_ARGUMENT;
    }
    let handle = &mut *client;
    match catch_unwind(AssertUnwindSafe(|| handle.client.disconnect())) {
        Ok(()) => AVIAN_SV2_OK,
        Err(_) => AVIAN_SV2_ERROR,
    }
}

/// The last error on this handle, NUL-terminated, owned by the library.
///
/// # Safety
/// `client` must be a live handle from [`avian_sv2_client_connect`].
#[no_mangle]
pub unsafe extern "C" fn avian_sv2_last_error(client: *const AvianSv2Client) -> *const c_char {
    if client.is_null() {
        return c"".as_ptr();
    }
    (*client).last_error.as_ptr()
}

/// Frees a handle. Null is accepted and ignored.
///
/// # Safety
/// `client` must be a handle from [`avian_sv2_client_connect`] that has not
/// already been freed, and must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn avian_sv2_client_free(client: *mut AvianSv2Client) {
    if !client.is_null() {
        drop(Box::from_raw(client));
    }
}

/// Assembles the 80 header bytes for a job at an `ntime` and `nonce`.
///
/// Does not hash them: that is the caller's, and the whole reason the caller
/// is a miner.
///
/// # Safety
/// `job` must point to a valid `AvianMiningJob` and `out` to 80 writable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn avian_sv2_build_header(
    job: *const AvianMiningJob,
    ntime: c_uint,
    nonce: c_uint,
    out: *mut u8,
) -> c_int {
    if job.is_null() || out.is_null() {
        return AVIAN_SV2_INVALID_ARGUMENT;
    }
    let job = &*job;
    let header = block::header(
        job.version,
        &job.prev_hash,
        &job.merkle_root,
        ntime,
        job.nbits,
        nonce,
    );
    std::ptr::copy_nonoverlapping(header.as_ptr(), out, header.len());
    AVIAN_SV2_OK
}

/// Whether a 32-byte proof-of-work hash is at or under a 32-byte target.
///
/// Both are in `uint256`'s internal little-endian order, which is what
/// `aviand` produces and what a job's `share_target` carries. Returns 1, 0, or
/// a negative status on a null argument.
///
/// # Safety
/// `hash` and `target` must each point to 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn avian_sv2_meets_target(hash: *const u8, target: *const u8) -> c_int {
    if hash.is_null() || target.is_null() {
        return AVIAN_SV2_INVALID_ARGUMENT;
    }
    let mut h = [0u8; 32];
    let mut t = [0u8; 32];
    std::ptr::copy_nonoverlapping(hash, h.as_mut_ptr(), 32);
    std::ptr::copy_nonoverlapping(target, t.as_mut_ptr(), 32);
    block::meets_target(&h, &t) as c_int
}

/// The library version, NUL-terminated and statically allocated.
#[no_mangle]
pub extern "C" fn avian_sv2_version() -> *const c_char {
    // Built at compile time with the NUL already on it.
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

impl AvianSv2Client {
    fn set_error(&mut self, message: &str) {
        let sanitized = message.replace('\0', " ");
        if let Ok(value) = std::ffi::CString::new(sanitized) {
            self.last_error = value;
        }
    }
}

// Keeps the unused-import warning away on a build with no tests.
const _: Option<*const c_void> = None;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_null_handle_is_an_error_and_not_a_crash() {
        unsafe {
            let mut event = AvianSv2Event::empty();
            assert_eq!(
                avian_sv2_client_poll(std::ptr::null_mut(), 0, &mut event),
                AVIAN_SV2_INVALID_ARGUMENT
            );
            assert_eq!(
                avian_sv2_client_submit(std::ptr::null_mut(), std::ptr::null(), 0, 0),
                AVIAN_SV2_INVALID_ARGUMENT
            );
            assert_eq!(
                avian_sv2_build_header(std::ptr::null(), 0, 0, std::ptr::null_mut()),
                AVIAN_SV2_INVALID_ARGUMENT
            );
            assert_eq!(
                avian_sv2_meets_target(std::ptr::null(), std::ptr::null()),
                AVIAN_SV2_INVALID_ARGUMENT
            );
            // Freeing null is defined, like free(3).
            avian_sv2_client_free(std::ptr::null_mut());
            assert!(!avian_sv2_last_error(std::ptr::null()).is_null());
        }
    }

    #[test]
    fn a_non_loopback_pool_is_refused() {
        let pool = std::ffi::CString::new("8.8.8.8:34254").unwrap();
        let config = AvianSv2ClientConfig {
            pool: pool.as_ptr(),
            authority_hex: std::ptr::null(),
            pow_type: AVIAN_SV2_POW_X16RT,
            user_identity: std::ptr::null(),
            nominal_hash_rate: 1.0,
            timeout_ms: 100,
            backoff_initial_ms: 0,
            backoff_max_ms: 0,
            max_reconnects: 1,
        };
        let mut status = AVIAN_SV2_OK;
        let handle = unsafe { avian_sv2_client_connect(&config, &mut status) };
        assert!(handle.is_null());
        assert_eq!(status, AVIAN_SV2_INVALID_ARGUMENT);
        let reason = unsafe { CStr::from_ptr(avian_sv2_last_connect_error()) };
        assert!(reason.to_str().unwrap().contains("loopback"));
    }

    #[test]
    fn the_c_header_matches_this_module() {
        // The header is written by hand, so the constants are checked here and
        // the struct layouts are checked by compiling ctest/session.c against
        // it with static assertions on the sizes.
        let header = include_str!("../include/avian_sv2.h");
        for (name, value) in [
            ("AVIAN_SV2_OK", AVIAN_SV2_OK),
            ("AVIAN_SV2_TIMEOUT", AVIAN_SV2_TIMEOUT),
            ("AVIAN_SV2_DISCONNECTED", AVIAN_SV2_DISCONNECTED),
            ("AVIAN_SV2_ERROR", AVIAN_SV2_ERROR),
            ("AVIAN_SV2_INVALID_ARGUMENT", AVIAN_SV2_INVALID_ARGUMENT),
            ("AVIAN_SV2_EVENT_JOB", AVIAN_SV2_EVENT_JOB),
            (
                "AVIAN_SV2_EVENT_JOBS_INVALIDATED",
                AVIAN_SV2_EVENT_JOBS_INVALIDATED,
            ),
            (
                "AVIAN_SV2_EVENT_SHARE_ACCEPTED",
                AVIAN_SV2_EVENT_SHARE_ACCEPTED,
            ),
            (
                "AVIAN_SV2_EVENT_SHARE_REJECTED",
                AVIAN_SV2_EVENT_SHARE_REJECTED,
            ),
            ("AVIAN_SV2_EVENT_RECONNECTED", AVIAN_SV2_EVENT_RECONNECTED),
            ("AVIAN_SV2_EVENT_DISCONNECTED", AVIAN_SV2_EVENT_DISCONNECTED),
        ] {
            let wanted = format!("#define {name} {value}");
            assert!(
                header.contains(&wanted),
                "include/avian_sv2.h is missing or disagrees about `{wanted}`"
            );
        }
        assert!(header.contains(&format!(
            "#define AVIAN_SV2_MESSAGE_LEN {AVIAN_SV2_MESSAGE_LEN}"
        )));
    }
}
