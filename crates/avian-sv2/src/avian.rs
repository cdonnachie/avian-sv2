//! Avian's extension, `extension_type = 0x4001`, and the Extensions
//! Negotiation extension `0x0001` it is negotiated through.
//!
//! Field layouts are from doc/sv2.md section "The Avian extension", which is
//! the authoritative wire specification, cross-checked against
//! test/functional/test_framework/sv2.py.

use std::fmt;

use crate::error::{Error, Result};
use crate::wire::{Reader, Writer};

pub const EXT_CORE: u16 = 0x0000;
pub const EXT_NEGOTIATION: u16 = 0x0001;
/// Experimental, and a mainnet release blocker until a registry allocation
/// replaces it. doc/sv2.md says so in as many words.
pub const EXT_AVIAN: u16 = 0x4001;

pub const MSG_REQUEST_EXTENSIONS: u8 = 0x00;
pub const MSG_REQUEST_EXTENSIONS_SUCCESS: u8 = 0x01;
pub const MSG_REQUEST_EXTENSIONS_ERROR: u8 = 0x02;

pub const MSG_SELECT_ALGORITHM: u8 = 0x00;
pub const MSG_SELECT_ALGORITHM_SUCCESS: u8 = 0x01;
pub const MSG_SELECT_ALGORITHM_ERROR: u8 = 0x02;
pub const MSG_TIME_CONSTRAINTS: u8 = 0x03;
/// The Mining Protocol form of the time constraints, which travels as a
/// channel message under `0xc001`. A Template Provider never sends it, so this
/// client never sees one; it is here because Stage 3 is the side that does.
pub const MSG_JOB_TIME_CONSTRAINTS: u8 = 0x04;

/// `AvianBlockFound`, upstream to downstream, on the Mining Protocol.
///
/// A channel message, so bit 15 of `extension_type` is set.
///
/// This one is not really Avian's: nothing about it concerns multiple
/// algorithms or time bounds, and any solo pool on any chain has the same gap.
/// It is deliberately excluded from the registry submission for that reason,
/// and belongs in core Stratum v2. It lives here because the gap is real now
/// and the specification process is not fast.
pub const MSG_BLOCK_FOUND: u8 = 0x05;

/// X16RT rederives its hash chain every 128 seconds.
pub const TIME_MASK: u32 = 0xffff_ff80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowType {
    X16rt = 0,
    MinotaurX = 1,
}

impl PowType {
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(PowType::X16rt),
            1 => Ok(PowType::MinotaurX),
            other => Err(Error::Payload(format!("unknown pow_type {other}"))),
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "x16rt" => Some(PowType::X16rt),
            "minotaurx" => Some(PowType::MinotaurX),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            PowType::X16rt => "x16rt",
            PowType::MinotaurX => "minotaurx",
        }
    }
}

impl fmt::Display for PowType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// The algorithm a template's `nVersion` declares: bits 16-23.
pub fn pow_type_from_version(version: u32) -> Result<PowType> {
    PowType::from_u8(((version >> 16) & 0xff) as u8)
}

// Extensions Negotiation, extension 0x0001.

pub fn encode_request_extensions(request_id: u16, wanted: &[u16]) -> Vec<u8> {
    Writer::new().u16(request_id).seq_u16(wanted).finish()
}

#[derive(Debug, Clone)]
pub struct RequestExtensionsSuccess {
    pub request_id: u16,
    pub extensions: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct RequestExtensionsError {
    pub request_id: u16,
    pub unsupported: Vec<u16>,
    /// What this node requires regardless of what was asked for, which is how
    /// a client that negotiated the wrong extension can correct itself.
    pub required: Vec<u16>,
}

pub fn decode_request_extensions_success(payload: &[u8]) -> Result<RequestExtensionsSuccess> {
    let mut r = Reader::new(payload);
    let out = RequestExtensionsSuccess {
        request_id: r.u16()?,
        extensions: r.seq_u16()?,
    };
    r.done()?;
    Ok(out)
}

pub fn decode_request_extensions_error(payload: &[u8]) -> Result<RequestExtensionsError> {
    let mut r = Reader::new(payload);
    let out = RequestExtensionsError {
        request_id: r.u16()?,
        unsupported: r.seq_u16()?,
        required: r.seq_u16()?,
    };
    r.done()?;
    Ok(out)
}

// The Avian extension, 0x4001.

pub fn encode_select_algorithm(pow_type: PowType) -> Vec<u8> {
    Writer::new().u8(pow_type as u8).finish()
}

#[derive(Debug, Clone, Copy)]
pub struct SelectAlgorithmSuccess {
    pub pow_type: PowType,
    /// Always 0 in this version of the extension, with no option to change it.
    pub version_rolling_mask: u32,
}

pub fn decode_select_algorithm_success(payload: &[u8]) -> Result<SelectAlgorithmSuccess> {
    let mut r = Reader::new(payload);
    let out = SelectAlgorithmSuccess {
        pow_type: PowType::from_u8(r.u8()?)?,
        version_rolling_mask: r.u32()?,
    };
    r.done()?;
    Ok(out)
}

pub fn decode_select_algorithm_error(payload: &[u8]) -> Result<String> {
    let mut r = Reader::new(payload);
    let code = r.text()?;
    r.done()?;
    Ok(code)
}

/// `AvianTimeConstraints`: the inclusive ntime window for one template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeConstraints {
    pub template_id: u64,
    pub ntime_min: u32,
    pub ntime_max: u32,
}

impl TimeConstraints {
    /// True when the window stays inside one X16RT 128-second epoch, which it
    /// must for an X16RT template: the hash chain is derived from
    /// `SHA256d(nTime & 0xffffff80)`, so crossing the boundary silently
    /// computes a different hash function.
    pub fn within_one_epoch(&self) -> bool {
        self.ntime_min & TIME_MASK == self.ntime_max & TIME_MASK
    }

    pub fn pinned(&self) -> bool {
        self.ntime_min == self.ntime_max
    }
}

impl fmt::Display for TimeConstraints {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AvianTimeConstraints(template_id: {}, ntime_min: {}, ntime_max: {}, span: {}s)",
            self.template_id,
            self.ntime_min,
            self.ntime_max,
            self.ntime_max.saturating_sub(self.ntime_min)
        )
    }
}

pub fn decode_time_constraints(payload: &[u8]) -> Result<TimeConstraints> {
    let mut r = Reader::new(payload);
    let out = TimeConstraints {
        template_id: r.u64()?,
        ntime_min: r.u32()?,
        ntime_max: r.u32()?,
    };
    r.done()?;
    Ok(out)
}

/// `AvianJobTimeConstraints`: the same window keyed on a channel and job.
///
/// A channel message, so it travels under `0xc001`. Nothing here sends or
/// receives one; it is the Mining Protocol half of the extension, and Stage 3
/// needs the codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobTimeConstraints {
    pub channel_id: u32,
    pub job_id: u32,
    pub ntime_min: u32,
    pub ntime_max: u32,
}

/// A share that was a block, and later whether it became the tip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockFound {
    pub channel_id: u32,
    /// The `SubmitShares` sequence number this refers to, so a miner can say
    /// which of its shares it was.
    pub sequence_number: u32,
    /// In uint256's internal order, which is the reverse of how a block hash
    /// is printed.
    pub block_hash: [u8; 32],
    /// False when the pool forwarded it, true once that hash became the tip.
    ///
    /// There is no false-after-the-fact: a pool cannot tell a block that lost
    /// a race from one still propagating, so the absence of a second message
    /// is unresolved rather than failure.
    pub confirmed: bool,
}

pub fn encode_block_found(b: &BlockFound) -> Vec<u8> {
    Writer::new()
        .u32(b.channel_id)
        .u32(b.sequence_number)
        .u256(&b.block_hash)
        .boolean(b.confirmed)
        .finish()
}

pub fn decode_block_found(payload: &[u8]) -> Result<BlockFound> {
    let mut r = Reader::new(payload);
    let out = BlockFound {
        channel_id: r.u32()?,
        sequence_number: r.u32()?,
        block_hash: r.u256()?,
        confirmed: r.boolean()?,
    };
    r.done()?;
    Ok(out)
}

pub fn encode_job_time_constraints(c: &JobTimeConstraints) -> Vec<u8> {
    Writer::new()
        .u32(c.channel_id)
        .u32(c.job_id)
        .u32(c.ntime_min)
        .u32(c.ntime_max)
        .finish()
}

pub fn decode_job_time_constraints(payload: &[u8]) -> Result<JobTimeConstraints> {
    let mut r = Reader::new(payload);
    let out = JobTimeConstraints {
        channel_id: r.u32()?,
        job_id: r.u32()?,
        ntime_min: r.u32()?,
        ntime_max: r.u32()?,
    };
    r.done()?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_algorithm_is_one_byte() {
        assert_eq!(encode_select_algorithm(PowType::X16rt), vec![0x00]);
        assert_eq!(encode_select_algorithm(PowType::MinotaurX), vec![0x01]);
    }

    #[test]
    fn request_extensions_asks_for_0x4001() {
        assert_eq!(
            encode_request_extensions(1, &[EXT_AVIAN]),
            vec![0x01, 0x00, 0x01, 0x00, 0x01, 0x40]
        );
    }

    #[test]
    fn job_time_constraints_round_trip() {
        let c = JobTimeConstraints {
            channel_id: 1,
            job_id: 2,
            ntime_min: 1_700_000_000,
            ntime_max: 1_700_000_127,
        };
        assert_eq!(
            decode_job_time_constraints(&encode_job_time_constraints(&c)).unwrap(),
            c
        );
    }

    #[test]
    fn version_names_the_algorithm_in_bits_16_to_23() {
        assert_eq!(pow_type_from_version(0x2000_0000).unwrap(), PowType::X16rt);
        assert_eq!(
            pow_type_from_version(0x2001_0000).unwrap(),
            PowType::MinotaurX
        );
        assert!(pow_type_from_version(0x20ff_0000).is_err());
    }
}
