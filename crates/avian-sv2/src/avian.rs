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
/// Allocated in Avian's own registry rather than Stratum v2's.
///
/// An `extension_type` need only be unique among peers that can share a
/// connection, and an Avian connection and a Bitcoin one never do. That is
/// the Stratum v2 maintainers' own position, given when this extension was
/// submitted upstream and declined as out of scope
/// (stratum-mining/sv2-spec#250), so this is not an experimental squat and
/// not a mainnet blocker. `0x4000`-`0x4fff` is Avian's allocated space and
/// `0x5000`-`0x7fff` is what it keeps experimental. See doc/sv2.md.
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

/// The reply the Template Distribution Protocol does not define.
///
/// Its own message table ends at `SubmitSolution` with no `.Success` and no
/// `.Error`, so a client that submits a block learns nothing from the
/// protocol: not that the node took it, not why it did not, not even that it
/// was heard. These two are Avian's, inside an extension both ends have
/// negotiated, so no stock dispatch of the spec's numbers is touched and a
/// peer built before them reads past them.
///
/// Neither can be relied on by its absence. There is no way to ask which
/// message numbers inside a negotiated extension a peer implements, so
/// silence from a node that never sends them looks exactly like silence from
/// one that refused without saying so. Positive information only.
pub const MSG_SUBMIT_SOLUTION_SUCCESS: u8 = 0x05;
pub const MSG_SUBMIT_SOLUTION_ERROR: u8 = 0x06;

/// Block notifications, their own extension and optional.
///
/// [`EXT_AVIAN`] is required, and a required extension cannot carry an
/// optional capability: negotiating it is mandatory, so a client has no way
/// to decline one message inside it. These were briefly message `0x05` there
/// during development, which is how that was noticed. A client that does not
/// know about `0x4002` does not ask for it and so is never sent one, which
/// fixes it structurally rather than by documentation.
///
/// Nothing about telling a miner what became of its share concerns multiple
/// algorithms or time bounds either, so it had no business inside an
/// identifier allocated for those.
pub const EXT_AVIAN_BLOCKS: u16 = 0x4002;

/// `BlockFound`, upstream to downstream, on the Mining Protocol.
///
/// Message `0x00` of [`EXT_AVIAN_BLOCKS`], not of [`EXT_AVIAN`]. A channel
/// message, so bit 15 of the extension type is set and it travels under
/// `0xc002`.
pub const MSG_BLOCK_FOUND: u8 = 0x00;

/// TLV field `0x01` of [`EXT_AVIAN`]: the proof of work one channel carries.
///
/// A `U8`, the same values `AvianSelectAlgorithm` uses, appended to
/// `OpenStandardMiningChannel` or `OpenExtendedMiningChannel`. It overrides
/// the connection's algorithm for that channel alone.
///
/// A TLV field rather than a message, because section 3.4.1 requires the
/// frame's `extension_type` to stay `0x0000` for a message the core protocol
/// defined, and because a separate message would have to be matched to an
/// open by `request_id` and could race it. Absent, which is what every peer
/// built before this sends, means the connection's algorithm, so nothing has
/// to change for a miner that mines one thing.
pub const TLV_FIELD_POW_TYPE: u8 = 0x01;

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

/// `AvianSubmitSolution.Success`: validation took the block.
///
/// Not that it won. A block that loses a race is accepted here too and then
/// orphaned; what settles that is whether the next `SetNewPrevHash` carries
/// this hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubmitSolutionSuccess {
    pub template_id: u64,
    /// In uint256's internal order, which is the reverse of how a block hash
    /// is printed. It also says which submission is being answered, because
    /// `template_id` cannot: several nonces may be in flight against one
    /// template.
    pub block_hash: [u8; 32],
}

pub fn encode_submit_solution_success(s: &SubmitSolutionSuccess) -> Vec<u8> {
    Writer::new()
        .u64(s.template_id)
        .u256(&s.block_hash)
        .finish()
}

pub fn decode_submit_solution_success(payload: &[u8]) -> Result<SubmitSolutionSuccess> {
    let mut r = Reader::new(payload);
    let out = SubmitSolutionSuccess {
        template_id: r.u64()?,
        block_hash: r.u256()?,
    };
    r.done()?;
    Ok(out)
}

/// `AvianSubmitSolution.Error`: the node refused the solution, and why.
///
/// No block hash, and that is deliberate rather than an omission: most
/// refusals happen before the proof-of-work hash is computed, because that
/// hash costs more than every check before it put together. So there is
/// nothing to name the submission with, and a submitter with several nonces
/// in flight learns the reason but not which nonce. The reason is the part it
/// can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitSolutionError {
    pub template_id: u64,
    /// One of the codes in doc/sv2.md, which are the same strings the node
    /// writes to its own log.
    pub error_code: String,
}

pub fn encode_submit_solution_error(e: &SubmitSolutionError) -> Vec<u8> {
    Writer::new()
        .u64(e.template_id)
        .bytes_u8(e.error_code.as_bytes())
        .finish()
}

pub fn decode_submit_solution_error(payload: &[u8]) -> Result<SubmitSolutionError> {
    let mut r = Reader::new(payload);
    let out = SubmitSolutionError {
        template_id: r.u64()?,
        error_code: r.text()?,
    };
    r.done()?;
    Ok(out)
}

/// What a refusal code means, for a log line an operator has to act on.
///
/// `consensus-rejected` is the one that is not the submitter's fault: it means
/// the node's own Stratum v2 checks and its consensus rules disagree.
pub fn explain_submit_solution_error(code: &str) -> &'static str {
    match code {
        "unknown-template" => "the node has dropped that template",
        "version-mismatch" => "nVersion was not the template's, and rolling is not allowed",
        "bad-algo-id" => "nVersion bits 16-23 name no algorithm this chain defines",
        "ntime-out-of-range" => "ntime was outside the window AvianTimeConstraints gave",
        "ntime-wrong-epoch" => "ntime crossed the end of the template's X16RT epoch",
        "coinbase-too-large" => "the coinbase exceeded the advertised size or weight",
        "coinbase-malformed" => "the coinbase did not deserialize",
        "coinbase-non-canonical" => "the coinbase re-serialized to different bytes",
        "coinbase-bad-scriptsig" => "the scriptSig did not start with the BIP34 height push",
        "coinbase-bad-fields" => "version, locktime or input sequence differed from the template",
        "coinbase-bad-witness" => "vin[0] carried no BIP141 reserved witness value",
        "missing-required-output" => "an output the template required was absent",
        "bad-commitment" => "the witness commitment was wrong or not the highest-indexed output",
        "value-too-high" => "the coinbase paid more than the template allowed",
        "too-many-sigops" => "the coinbase exceeded the advertised sigop budget",
        "block-too-large" => "template plus coinbase exceeded the block limit",
        "pow-insufficient" => "the hash did not meet this algorithm's network target",
        "consensus-rejected" => {
            "the node's own checks and its consensus rules disagree, \
             which is a node bug rather than anything this side did"
        }
        _ => "an error code this build does not know",
    }
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
    fn submit_solution_replies_round_trip() {
        let ok = SubmitSolutionSuccess {
            template_id: 7,
            block_hash: [0xab; 32],
        };
        let wire = encode_submit_solution_success(&ok);
        // U64 then U256, which is 40 bytes and nothing else: the node's
        // AvianSubmitSolutionSuccess has to agree byte for byte.
        assert_eq!(wire.len(), 40);
        assert_eq!(&wire[..8], &7u64.to_le_bytes());
        assert_eq!(decode_submit_solution_success(&wire).unwrap(), ok);

        let err = SubmitSolutionError {
            template_id: 9,
            error_code: "pow-insufficient".into(),
        };
        let wire = encode_submit_solution_error(&err);
        // STR0_255, so one length byte then the text.
        assert_eq!(wire[8], 16);
        assert_eq!(decode_submit_solution_error(&wire).unwrap(), err);
    }

    #[test]
    fn every_refusal_code_the_node_sends_is_explained() {
        // doc/sv2.md calls these normative, so an unknown one here means the
        // two sides have drifted. The fallback exists for a newer node, not
        // for a code this build was shipped alongside.
        for code in [
            "unknown-template",
            "version-mismatch",
            "bad-algo-id",
            "ntime-out-of-range",
            "ntime-wrong-epoch",
            "coinbase-too-large",
            "coinbase-malformed",
            "coinbase-non-canonical",
            "coinbase-bad-scriptsig",
            "coinbase-bad-fields",
            "coinbase-bad-witness",
            "missing-required-output",
            "bad-commitment",
            "value-too-high",
            "too-many-sigops",
            "block-too-large",
            "pow-insufficient",
            "consensus-rejected",
        ] {
            assert_ne!(
                explain_submit_solution_error(code),
                "an error code this build does not know",
                "{code} has no explanation"
            );
        }
        assert_eq!(
            explain_submit_solution_error("invented-later"),
            "an error code this build does not know"
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
