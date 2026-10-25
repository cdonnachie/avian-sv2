//! The stock Template Distribution messages, decoded through SRI's codecs and
//! copied into owned structs.
//!
//! SRI's `NewTemplate`, `SetNewPrevHash` and `RequestTransactionDataSuccess`
//! borrow from the buffer they were decoded out of, which would tie every
//! caller to the lifetime of one frame. These are the same fields owned, so a
//! session can hold its current template across reads.

use std::fmt;

use binary_sv2::from_bytes;
use template_distribution_sv2::{NewTemplate, RequestTransactionDataSuccess, SetNewPrevHash};

pub use template_distribution_sv2::{
    MESSAGE_TYPE_COINBASE_OUTPUT_CONSTRAINTS, MESSAGE_TYPE_NEW_TEMPLATE,
    MESSAGE_TYPE_REQUEST_TRANSACTION_DATA, MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_ERROR,
    MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS, MESSAGE_TYPE_SET_NEW_PREV_HASH,
    MESSAGE_TYPE_SUBMIT_SOLUTION,
};

use crate::avian::{pow_type_from_version, PowType};
use crate::error::{Error, Result};
use crate::wire::{hex, hex_rev, Reader};

#[derive(Debug, Clone)]
pub struct Template {
    pub template_id: u64,
    pub future_template: bool,
    pub version: u32,
    pub coinbase_tx_version: u32,
    pub coinbase_prefix: Vec<u8>,
    pub coinbase_tx_input_sequence: u32,
    pub coinbase_tx_value_remaining: u64,
    pub coinbase_tx_outputs_count: u32,
    pub coinbase_tx_outputs: Vec<u8>,
    pub coinbase_tx_locktime: u32,
    pub merkle_path: Vec<[u8; 32]>,
}

impl Template {
    /// The algorithm the template's `nVersion` declares, in bits 16-23.
    pub fn pow_type(&self) -> Result<PowType> {
        pow_type_from_version(self.version)
    }

    pub fn decode(payload: &mut [u8]) -> Result<Self> {
        let message: NewTemplate = from_bytes(payload)?;
        Ok(Self {
            template_id: message.template_id,
            future_template: message.future_template,
            version: message.version,
            coinbase_tx_version: message.coinbase_tx_version,
            coinbase_prefix: message.coinbase_prefix.as_ref().to_vec(),
            coinbase_tx_input_sequence: message.coinbase_tx_input_sequence,
            coinbase_tx_value_remaining: message.coinbase_tx_value_remaining,
            coinbase_tx_outputs_count: message.coinbase_tx_outputs_count,
            coinbase_tx_outputs: message.coinbase_tx_outputs.as_ref().to_vec(),
            coinbase_tx_locktime: message.coinbase_tx_locktime,
            merkle_path: message
                .merkle_path
                .into_inner()
                .into_iter()
                .map(|hash| {
                    let mut out = [0u8; 32];
                    out.copy_from_slice(hash.as_ref());
                    out
                })
                .collect(),
        })
    }
}

impl fmt::Display for Template {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let algo = match self.pow_type() {
            Ok(pow) => pow.name().to_string(),
            Err(_) => format!("unknown ({})", (self.version >> 16) & 0xff),
        };
        writeln!(f, "NewTemplate")?;
        writeln!(f, "  template_id                 {}", self.template_id)?;
        writeln!(f, "  future_template             {}", self.future_template)?;
        writeln!(
            f,
            "  version                     0x{:08x}  (pow_type bits 16-23: {algo})",
            self.version
        )?;
        writeln!(
            f,
            "  coinbase_tx_version         0x{:08x}",
            self.coinbase_tx_version
        )?;
        writeln!(
            f,
            "  coinbase_prefix             {}  ({} bytes, BIP34 height push)",
            hex(&self.coinbase_prefix),
            self.coinbase_prefix.len()
        )?;
        writeln!(
            f,
            "  coinbase_tx_input_sequence   0x{:08x}",
            self.coinbase_tx_input_sequence
        )?;
        writeln!(
            f,
            "  coinbase_tx_value_remaining  {} sat  (already net of the founder payment)",
            self.coinbase_tx_value_remaining
        )?;
        writeln!(
            f,
            "  coinbase_tx_outputs_count    {}",
            self.coinbase_tx_outputs_count
        )?;
        writeln!(
            f,
            "  coinbase_tx_outputs          {} bytes{}",
            self.coinbase_tx_outputs.len(),
            if self.has_witness_commitment() {
                ", last output carries the aa21a9ed commitment"
            } else {
                ""
            }
        )?;
        writeln!(
            f,
            "  coinbase_tx_locktime         {}",
            self.coinbase_tx_locktime
        )?;
        write!(
            f,
            "  merkle_path                  {} hashes",
            self.merkle_path.len()
        )?;
        for hash in &self.merkle_path {
            write!(f, "\n                               {}", hex_rev(hash))?;
        }
        Ok(())
    }
}

impl Template {
    /// Whether the required outputs end with a BIP141 witness commitment,
    /// which consensus reads from the highest-indexed output bearing the
    /// `aa21a9ed` magic. Parsing the outputs properly is Stage 3's job; this
    /// only reports whether the magic is present at all.
    fn has_witness_commitment(&self) -> bool {
        self.coinbase_tx_outputs
            .windows(4)
            .any(|w| w == [0xaa, 0x21, 0xa9, 0xed])
    }
}

#[derive(Debug, Clone)]
pub struct PrevHash {
    pub template_id: u64,
    pub prev_hash: [u8; 32],
    /// doc/sv2.md and the functional tests call this `ntime_start`; the
    /// Stratum v2 spec and SRI call it `header_timestamp`. Same field.
    pub ntime_start: u32,
    pub nbits: u32,
    pub target: [u8; 32],
}

impl PrevHash {
    pub fn decode(payload: &mut [u8]) -> Result<Self> {
        let message: SetNewPrevHash = from_bytes(payload)?;
        let mut prev_hash = [0u8; 32];
        prev_hash.copy_from_slice(message.prev_hash.as_ref());
        let mut target = [0u8; 32];
        target.copy_from_slice(message.target.as_ref());
        Ok(Self {
            template_id: message.template_id,
            prev_hash,
            ntime_start: message.header_timestamp,
            nbits: message.n_bits,
            target,
        })
    }
}

impl fmt::Display for PrevHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "SetNewPrevHash")?;
        writeln!(f, "  template_id    {}", self.template_id)?;
        writeln!(f, "  prev_hash      {}", hex_rev(&self.prev_hash))?;
        writeln!(
            f,
            "  ntime_start    {}  (header_timestamp in the Sv2 spec)",
            self.ntime_start
        )?;
        writeln!(f, "  nbits          0x{:08x}", self.nbits)?;
        write!(f, "  target         {}", hex_rev(&self.target))
    }
}

#[derive(Debug, Clone)]
pub struct TransactionData {
    pub template_id: u64,
    pub excess_data: Vec<u8>,
    pub transaction_list: Vec<Vec<u8>>,
}

impl TransactionData {
    pub fn decode(payload: &mut [u8]) -> Result<Self> {
        let message: RequestTransactionDataSuccess = from_bytes(payload)?;
        Ok(Self {
            template_id: message.template_id,
            excess_data: message.excess_data.as_ref().to_vec(),
            transaction_list: message
                .transaction_list
                .into_inner()
                .into_iter()
                .map(|tx| tx.as_ref().to_vec())
                .collect(),
        })
    }
}

impl fmt::Display for TransactionData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "RequestTransactionData.Success")?;
        writeln!(f, "  template_id       {}", self.template_id)?;
        writeln!(f, "  excess_data       {} bytes", self.excess_data.len())?;
        write!(
            f,
            "  transaction_list  {} transactions",
            self.transaction_list.len()
        )?;
        for tx in &self.transaction_list {
            write!(f, "\n                    {} bytes", tx.len())?;
        }
        Ok(())
    }
}

/// `RequestTransactionData.Error` is hand-decoded: SRI's typed form would do,
/// but the error path wants the code as a `String` either way.
pub fn decode_transaction_data_error(payload: &[u8]) -> Result<(u64, String)> {
    let mut r = Reader::new(payload);
    let template_id = r.u64()?;
    let code = r.text()?;
    r.done()?;
    Ok((template_id, code))
}

/// The error codes doc/sv2.md names for a template that is gone.
pub fn explain_transaction_data_error(code: &str) -> &'static str {
    match code {
        "stale-template" | "stale-template-id" => "that work has expired",
        "template-id-not-found" => "no such template id was ever issued",
        _ => "unrecognized error code",
    }
}

pub fn decode_setup_connection_error(payload: &[u8]) -> Result<(u32, String)> {
    let mut r = Reader::new(payload);
    let flags = r.u32()?;
    let code = r.text()?;
    r.done()?;
    Ok((flags, code))
}

pub fn decode_setup_connection_success(payload: &[u8]) -> Result<(u16, u32)> {
    let mut r = Reader::new(payload);
    let used_version = r.u16()?;
    let flags = r.u32()?;
    r.done()?;
    Ok((used_version, flags))
}

pub fn require(condition: bool, message: impl Into<String>) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Error::Protocol(message.into()))
    }
}
