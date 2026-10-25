//! Avian addresses, and the `user_identity` a miner opens a channel with.
//!
//! This is the module with money attached. On a solo pool the miner's address
//! goes straight into the coinbase and consensus pays them directly, so a
//! decoding bug does not produce an error, it produces someone else's money.
//! Everything here therefore fails closed: an address that does not parse,
//! fails its checksum, or belongs to another network is an error and never a
//! default.
//!
//! The version bytes are Avian's, from `src/kernel/chainparams.cpp`, not
//! Bitcoin's. Avian mainnet is 60 and 122, where Bitcoin is 0 and 5.
//!
//! It lives in the library rather than in the pool because both ends want it:
//! the pool to turn an identity into a script, and a miner to find out its own
//! address is malformed before it opens a channel and is refused. It contains
//! no hashing beyond SHA256 for the checksum, which was already here.

use std::fmt;

use crate::block::sha256d;

/// The base58 alphabet, which notably excludes `0`, `O`, `I`, `l` and `.`.
const BASE58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BECH32: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// The longest `user_identity` worth looking at. `STR0_255` allows 255, and
/// nothing legitimate approaches it.
pub const MAX_IDENTITY: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Main,
    Testnet,
    Testnet4,
    Signet,
    Regtest,
}

impl Network {
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "main" | "mainnet" => Some(Network::Main),
            "test" | "testnet" => Some(Network::Testnet),
            "testnet4" => Some(Network::Testnet4),
            "signet" => Some(Network::Signet),
            "regtest" => Some(Network::Regtest),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Network::Main => "main",
            Network::Testnet => "testnet",
            Network::Testnet4 => "testnet4",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
        }
    }

    /// `base58Prefixes[PUBKEY_ADDRESS]`.
    pub fn pubkey_prefix(self) -> u8 {
        match self {
            Network::Main => 60,
            _ => 111,
        }
    }

    /// `base58Prefixes[SCRIPT_ADDRESS]`.
    pub fn script_prefix(self) -> u8 {
        match self {
            Network::Main => 122,
            _ => 196,
        }
    }

    pub fn bech32_hrp(self) -> &'static str {
        match self {
            Network::Main => "avn",
            Network::Testnet | Network::Signet => "tavn",
            Network::Testnet4 => "tavn4",
            Network::Regtest => "avnrt",
        }
    }

    /// Whether another network's base58 addresses are indistinguishable from
    /// this one's.
    ///
    /// Everything except mainnet shares 111 and 196, so a testnet address on a
    /// regtest pool cannot be detected and will be accepted. That is a
    /// property of Avian's chain parameters, not of this code, and it is why
    /// the bech32 human-readable part is the only reliable network tag off
    /// mainnet.
    pub fn base58_is_ambiguous(self) -> bool {
        self != Network::Main
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressKind {
    P2pkh,
    P2sh,
    /// Segwit v0: a 20-byte key hash or a 32-byte script hash.
    WitnessV0,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub kind: AddressKind,
    /// 20 bytes for P2PKH, P2SH and P2WPKH; 32 for P2WSH.
    pub program: Vec<u8>,
}

/// Why an address was refused.
///
/// Each maps to a distinct error code so a miner is told what is wrong with
/// its address rather than just that something is. There is a cost to that:
/// see the README, the Stratum v2 specification defines no
/// `OpenMiningChannel.Error` code for any of this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    Empty,
    TooLong(usize),
    NotBase58(char),
    /// A base58 payload that is not version plus 20 bytes plus checksum.
    BadLength(usize),
    BadChecksum,
    /// Decoded cleanly, but for another network.
    WrongNetwork {
        found: u8,
        expected_pubkey: u8,
        expected_script: u8,
    },
    /// A bech32 address whose human-readable part belongs to another network.
    WrongBech32Hrp {
        found: String,
        expected: &'static str,
    },
    BadBech32,
    /// Segwit v1 and later. Refused rather than guessed at.
    UnsupportedWitnessVersion(u8),
    UnsupportedProgramLength(usize),
}

impl AddressError {
    /// The `OpenMiningChannel.Error` code this becomes.
    pub fn code(&self) -> &'static str {
        match self {
            AddressError::Empty => "missing-payout-address",
            AddressError::WrongNetwork { .. } | AddressError::WrongBech32Hrp { .. } => {
                "wrong-network-address"
            }
            AddressError::UnsupportedWitnessVersion(_)
            | AddressError::UnsupportedProgramLength(_) => "unsupported-address-type",
            _ => "invalid-payout-address",
        }
    }
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressError::Empty => write!(f, "no payout address in user_identity"),
            AddressError::TooLong(n) => write!(f, "user_identity is {n} bytes"),
            AddressError::NotBase58(c) => write!(f, "{c:?} is not a base58 character"),
            AddressError::BadLength(n) => write!(f, "a base58 payload of {n} bytes"),
            AddressError::BadChecksum => write!(f, "the checksum does not match"),
            AddressError::WrongNetwork {
                found,
                expected_pubkey,
                expected_script,
            } => write!(
                f,
                "address version {found}, and this chain uses {expected_pubkey} or \
                 {expected_script}"
            ),
            AddressError::WrongBech32Hrp { found, expected } => {
                write!(
                    f,
                    "address prefix {found:?}, and this chain uses {expected:?}"
                )
            }
            AddressError::BadBech32 => write!(f, "not a valid bech32 address"),
            AddressError::UnsupportedWitnessVersion(v) => {
                write!(f, "witness version {v} is not supported")
            }
            AddressError::UnsupportedProgramLength(n) => {
                write!(f, "a {n}-byte witness program is not supported")
            }
        }
    }
}

impl Address {
    /// Decodes an address and checks it belongs to `network`.
    pub fn decode(text: &str, network: Network) -> Result<Address, AddressError> {
        if text.is_empty() {
            return Err(AddressError::Empty);
        }
        if text.len() > MAX_IDENTITY {
            return Err(AddressError::TooLong(text.len()));
        }
        // Which decoder to use is decided by the human-readable part, not by
        // looking for a separator: a base58 address may well contain a '1',
        // and an early version of this chose bech32 for every address that
        // did.
        if looks_like_bech32(text) {
            return decode_bech32(text, network);
        }
        decode_base58(text, network)
    }

    /// The `scriptPubKey` that pays this address.
    pub fn script_pubkey(&self) -> Vec<u8> {
        let mut script = Vec::with_capacity(25);
        match self.kind {
            AddressKind::P2pkh => {
                // OP_DUP OP_HASH160 <20> ... OP_EQUALVERIFY OP_CHECKSIG
                script.extend_from_slice(&[0x76, 0xa9, 0x14]);
                script.extend_from_slice(&self.program);
                script.extend_from_slice(&[0x88, 0xac]);
            }
            AddressKind::P2sh => {
                // OP_HASH160 <20> ... OP_EQUAL
                script.extend_from_slice(&[0xa9, 0x14]);
                script.extend_from_slice(&self.program);
                script.push(0x87);
            }
            AddressKind::WitnessV0 => {
                // OP_0 <len> ...
                script.push(0x00);
                script.push(self.program.len() as u8);
                script.extend_from_slice(&self.program);
            }
        }
        script
    }

    /// Re-encodes as base58. Only for P2PKH and P2SH; segwit has no base58
    /// form.
    pub fn encode_base58(&self, network: Network) -> Option<String> {
        let version = match self.kind {
            AddressKind::P2pkh => network.pubkey_prefix(),
            AddressKind::P2sh => network.script_prefix(),
            AddressKind::WitnessV0 => return None,
        };
        let mut payload = vec![version];
        payload.extend_from_slice(&self.program);
        Some(base58check_encode(&payload))
    }
}

/// Every human-readable part Avian uses, so an address for another network is
/// recognised as bech32 and refused as the wrong network rather than being
/// put through base58 and refused as gibberish.
const BECH32_HRPS: [&str; 4] = ["avnrt", "tavn4", "tavn", "avn"];

fn looks_like_bech32(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    BECH32_HRPS
        .iter()
        .any(|hrp| lower.starts_with(&format!("{hrp}1")))
}

fn decode_base58(text: &str, network: Network) -> Result<Address, AddressError> {
    let payload = base58check_decode(text)?;
    if payload.len() != 21 {
        return Err(AddressError::BadLength(payload.len()));
    }
    let version = payload[0];
    let program = payload[1..].to_vec();
    let kind = if version == network.pubkey_prefix() {
        AddressKind::P2pkh
    } else if version == network.script_prefix() {
        AddressKind::P2sh
    } else {
        return Err(AddressError::WrongNetwork {
            found: version,
            expected_pubkey: network.pubkey_prefix(),
            expected_script: network.script_prefix(),
        });
    };
    Ok(Address { kind, program })
}

pub fn base58_decode(text: &str) -> Result<Vec<u8>, AddressError> {
    let mut number: Vec<u8> = Vec::with_capacity(text.len());
    for character in text.chars() {
        let digit = BASE58
            .iter()
            .position(|c| *c as char == character)
            .ok_or(AddressError::NotBase58(character))? as u32;
        // number = number * 58 + digit, big-endian.
        let mut carry = digit;
        for byte in number.iter_mut().rev() {
            let value = *byte as u32 * 58 + carry;
            *byte = (value & 0xff) as u8;
            carry = value >> 8;
        }
        while carry > 0 {
            number.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // Every leading '1' is a leading zero byte.
    let leading = text.chars().take_while(|c| *c == '1').count();
    let mut out = vec![0u8; leading];
    out.extend_from_slice(&number);
    Ok(out)
}

pub fn base58_encode(bytes: &[u8]) -> String {
    let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let mut carry = *byte as u32;
        for digit in digits.iter_mut() {
            let value = (*digit as u32) << 8 | carry;
            *digit = (value % 58) as u8;
            carry = value / 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let leading = bytes.iter().take_while(|b| **b == 0).count();
    let mut out = String::with_capacity(leading + digits.len());
    for _ in 0..leading {
        out.push('1');
    }
    for digit in digits.iter().rev() {
        out.push(BASE58[*digit as usize] as char);
    }
    out
}

/// Decodes base58check and strips the four checksum bytes.
pub fn base58check_decode(text: &str) -> Result<Vec<u8>, AddressError> {
    let raw = base58_decode(text)?;
    if raw.len() < 5 {
        return Err(AddressError::BadLength(raw.len()));
    }
    let (payload, checksum) = raw.split_at(raw.len() - 4);
    let expected = sha256d(&[payload]);
    if checksum != &expected[..4] {
        return Err(AddressError::BadChecksum);
    }
    Ok(payload.to_vec())
}

pub fn base58check_encode(payload: &[u8]) -> String {
    let checksum = sha256d(&[payload]);
    let mut full = payload.to_vec();
    full.extend_from_slice(&checksum[..4]);
    base58_encode(&full)
}

fn bech32_polymod(values: &[u8]) -> u32 {
    const GENERATOR: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut checksum = 1u32;
    for value in values {
        let top = checksum >> 25;
        checksum = (checksum & 0x1ff_ffff) << 5 ^ (*value as u32);
        for (i, generator) in GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                checksum ^= generator;
            }
        }
    }
    checksum
}

fn bech32_hrp_expanded(hrp: &str) -> Vec<u8> {
    let mut out: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
    out.push(0);
    out.extend(hrp.bytes().map(|b| b & 31));
    out
}

fn decode_bech32(text: &str, network: Network) -> Result<Address, AddressError> {
    // Mixed case is invalid in bech32, and the two cases must not be mixed.
    let has_lower = text.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = text.chars().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(AddressError::BadBech32);
    }
    let lower = text.to_ascii_lowercase();
    let at = lower.rfind('1').ok_or(AddressError::BadBech32)?;
    let (hrp, data) = lower.split_at(at);
    let data = &data[1..];
    if hrp.is_empty() || data.len() < 6 {
        return Err(AddressError::BadBech32);
    }
    if hrp != network.bech32_hrp() {
        return Err(AddressError::WrongBech32Hrp {
            found: hrp.to_string(),
            expected: network.bech32_hrp(),
        });
    }

    let mut values = Vec::with_capacity(data.len());
    for character in data.bytes() {
        let value = BECH32
            .iter()
            .position(|c| *c == character)
            .ok_or(AddressError::BadBech32)? as u8;
        values.push(value);
    }

    let mut checked = bech32_hrp_expanded(hrp);
    checked.extend_from_slice(&values);
    let constant = bech32_polymod(&checked);
    let witness_version = values[0];
    // Segwit v0 uses bech32, v1 and later use bech32m with a different
    // constant. Only v0 is supported, so only the bech32 constant is accepted,
    // and a taproot address is refused by version rather than silently failing
    // its checksum.
    if witness_version != 0 {
        return Err(AddressError::UnsupportedWitnessVersion(witness_version));
    }
    if constant != 1 {
        return Err(AddressError::BadBech32);
    }

    let program =
        convert_bits(&values[1..values.len() - 6], 5, 8, false).ok_or(AddressError::BadBech32)?;
    if program.len() != 20 && program.len() != 32 {
        return Err(AddressError::UnsupportedProgramLength(program.len()));
    }
    Ok(Address {
        kind: AddressKind::WitnessV0,
        program,
    })
}

fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::new();
    let max = (1u32 << to) - 1;
    for value in data {
        let value = *value as u32;
        if (value >> from) != 0 {
            return None;
        }
        accumulator = (accumulator << from) | value;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((accumulator >> bits) & max) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((accumulator << (to - bits)) & max) as u8);
        }
    } else if bits >= from || ((accumulator << (to - bits)) & max) != 0 {
        return None;
    }
    Some(out)
}

/// What a miner puts in `OpenStandardMiningChannel.user_identity`.
///
/// The observed convention, carried over from Stratum v1 and what a miner's
/// UI calls "User", is `address.workername`:
/// `bc1q…lnl43dd.bitaxe-1`. A bare address with no label is accepted too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub address: Address,
    /// Whatever followed the first `.`. Empty when there was none. For the
    /// operator's benefit only: it never affects the payout.
    pub worker: String,
    /// The address exactly as the miner wrote it, for logging.
    pub address_text: String,
}

/// Splits `user_identity` and decodes the address half.
///
/// The split is on the **first** `.`, not the last. No Avian address can
/// contain a dot: neither the base58 alphabet nor the bech32 charset includes
/// one. So the first dot is the unambiguous end of the address, and splitting
/// there additionally tolerates a dotted worker label such as
/// `address.rig.1`, which splitting on the last dot would mis-read as an
/// address of `address.rig` and refuse.
pub fn parse_identity(identity: &str, network: Network) -> Result<Identity, AddressError> {
    let identity = identity.trim();
    if identity.len() > MAX_IDENTITY {
        return Err(AddressError::TooLong(identity.len()));
    }
    let (address_text, worker) = match identity.find('.') {
        Some(at) => (&identity[..at], &identity[at + 1..]),
        None => (identity, ""),
    };
    Ok(Identity {
        address: Address::decode(address_text, network)?,
        worker: worker.to_string(),
        address_text: address_text.to_string(),
    })
}

/// The pool's authority public key in the form a miner's configuration takes.
///
/// `base58check([0x01, 0x00] ++ x-only key)`, which is what SRI's `key_utils`
/// produces and what a Stratum v2 miner expects to paste in. Getting this
/// wrong is a pool nobody can connect to, and the symptom is a handshake that
/// does not complete, so a test pins it against `key_utils` itself.
pub fn encode_authority_key(key: &secp256k1::XOnlyPublicKey) -> String {
    let mut payload = Vec::with_capacity(34);
    // A two-byte little-endian key version of 1.
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.extend_from_slice(&key.serialize());
    base58check_encode(&payload)
}

/// The inverse, for an operator pasting a key back in.
pub fn decode_authority_key(text: &str) -> Result<secp256k1::XOnlyPublicKey, AddressError> {
    let payload = base58check_decode(text)?;
    if payload.len() != 34 {
        return Err(AddressError::BadLength(payload.len()));
    }
    if u16::from_le_bytes([payload[0], payload[1]]) != 1 {
        return Err(AddressError::BadChecksum);
    }
    secp256k1::XOnlyPublicKey::from_slice(&payload[2..]).map_err(|_| AddressError::BadChecksum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::hex;

    // Addresses and their scriptPubKeys from a real regtest node, via
    // `getnewaddress` and `getaddressinfo`. Ground truth: if this module
    // disagrees with these, it is wrong, whatever it thinks.
    const REGTEST_P2PKH: &str = "mnPBEVKjU1zz9214C7M7Zp4FuurUAsU6ZS";
    const REGTEST_P2PKH_SCRIPT: &str = "76a9144b505a74657fb2b28c4741f5983b6ea88ea1fe0688ac";
    const REGTEST_P2SH: &str = "2N7bauzAGSJTusSf3TUDQzpSDs6hH5qFGjs";
    const REGTEST_P2SH_SCRIPT: &str = "a9149d6b8c5b9c3743e6016c0baf56f4f90432977b4687";
    const REGTEST_BECH32: &str = "avnrt1qmyfxjmnhquher0k8lhrpg082rv4j7thpf3suvx";
    const REGTEST_BECH32_SCRIPT: &str = "0014d912696e77072f91bec7fdc6143cea1b2b2f2ee1";

    #[test]
    fn the_scripts_match_what_the_node_says() {
        for (text, expected) in [
            (REGTEST_P2PKH, REGTEST_P2PKH_SCRIPT),
            (REGTEST_P2SH, REGTEST_P2SH_SCRIPT),
            (REGTEST_BECH32, REGTEST_BECH32_SCRIPT),
        ] {
            let address = Address::decode(text, Network::Regtest)
                .unwrap_or_else(|e| panic!("{text} should decode: {e}"));
            assert_eq!(hex(&address.script_pubkey()), expected, "for {text}");
        }
    }

    #[test]
    fn base58_round_trips_through_the_nodes_own_address() {
        let address = Address::decode(REGTEST_P2PKH, Network::Regtest).unwrap();
        assert_eq!(
            address.encode_base58(Network::Regtest).as_deref(),
            Some(REGTEST_P2PKH)
        );
        let p2sh = Address::decode(REGTEST_P2SH, Network::Regtest).unwrap();
        assert_eq!(
            p2sh.encode_base58(Network::Regtest).as_deref(),
            Some(REGTEST_P2SH)
        );
    }

    #[test]
    fn a_mainnet_address_is_refused_on_regtest() {
        // Built by re-encoding the regtest hash160 under mainnet's version
        // byte, so it is checksum-valid and the only thing wrong with it is
        // the network. Otherwise this would pass for the wrong reason.
        let address = Address::decode(REGTEST_P2PKH, Network::Regtest).unwrap();
        let mainnet = address.encode_base58(Network::Main).unwrap();
        assert!(
            mainnet.starts_with('R'),
            "an Avian mainnet P2PKH address starts with R, got {mainnet}"
        );
        assert_eq!(
            Address::decode(&mainnet, Network::Regtest),
            Err(AddressError::WrongNetwork {
                found: 60,
                expected_pubkey: 111,
                expected_script: 196,
            })
        );
        // And it decodes on the network it belongs to.
        assert_eq!(
            Address::decode(&mainnet, Network::Main).unwrap().program,
            address.program
        );
    }

    #[test]
    fn a_bech32_address_for_another_network_is_refused() {
        assert!(matches!(
            Address::decode(REGTEST_BECH32, Network::Main),
            Err(AddressError::WrongBech32Hrp { .. })
        ));
    }

    #[test]
    fn a_mutated_address_fails_its_checksum() {
        // Every single-character change the alphabet allows must be caught.
        let original = REGTEST_P2PKH;
        let mut caught = 0;
        for position in 0..original.len() {
            for replacement in BASE58.iter().map(|b| *b as char) {
                let mut mutated: Vec<char> = original.chars().collect();
                if mutated[position] == replacement {
                    continue;
                }
                mutated[position] = replacement;
                let mutated: String = mutated.into_iter().collect();
                assert!(
                    Address::decode(&mutated, Network::Regtest).is_err(),
                    "{mutated} differs from {original} by one character and was accepted"
                );
                caught += 1;
            }
        }
        assert!(
            caught > 1000,
            "the sweep should have been large, was {caught}"
        );
    }

    #[test]
    fn rubbish_is_refused_rather_than_guessed_at() {
        for text in [
            "",
            "not an address",
            "0OIl",
            "mnPBEVKjU1zz9214C7M7Zp4FuurUAsU6Z",   // truncated
            "mnPBEVKjU1zz9214C7M7Zp4FuurUAsU6ZSS", // extended
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",  // a Bitcoin mainnet address
        ] {
            assert!(
                Address::decode(text, Network::Regtest).is_err(),
                "{text:?} was accepted"
            );
        }
    }

    #[test]
    fn a_witness_version_above_zero_is_refused_by_version() {
        // Segwit v1 and later use bech32m, whose checksum constant differs,
        // and none is implemented here. The version is checked before the
        // checksum so that a taproot user is told their address type is
        // unsupported rather than that it is malformed. Both are refusals, so
        // deciding on the version first costs nothing and says more.
        //
        // This is not a real Avian taproot address and is not claimed to be:
        // it is a v1 witness program under the regtest prefix, which is
        // exactly what the version check has to catch.
        let text = "avnrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
        match Address::decode(text, Network::Regtest) {
            Err(AddressError::UnsupportedWitnessVersion(1)) => {}
            other => panic!("expected an unsupported-version refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_identity_splits_into_an_address_and_a_label() {
        let plain = parse_identity(REGTEST_P2PKH, Network::Regtest).unwrap();
        assert_eq!(plain.worker, "");
        assert_eq!(plain.address_text, REGTEST_P2PKH);

        let labelled =
            parse_identity(&format!("{REGTEST_P2PKH}.bitaxe-1"), Network::Regtest).unwrap();
        assert_eq!(labelled.worker, "bitaxe-1");
        assert_eq!(labelled.address, plain.address);

        // Splitting on the first dot, so a dotted label survives.
        let dotted = parse_identity(&format!("{REGTEST_P2PKH}.rig.1"), Network::Regtest).unwrap();
        assert_eq!(dotted.worker, "rig.1");
        assert_eq!(dotted.address, plain.address);

        // An empty label is odd but not a reason to refuse.
        let empty = parse_identity(&format!("{REGTEST_P2PKH}."), Network::Regtest).unwrap();
        assert_eq!(empty.worker, "");
    }

    #[test]
    fn a_bad_address_with_a_good_label_is_still_refused() {
        assert!(parse_identity("not-an-address.bitaxe-1", Network::Regtest).is_err());
        assert!(parse_identity(".bitaxe-1", Network::Regtest).is_err());
        assert!(parse_identity("", Network::Regtest).is_err());
    }

    #[test]
    fn error_codes_distinguish_the_cases_a_miner_must_act_on() {
        let wrong_network = Address::decode(
            &Address::decode(REGTEST_P2PKH, Network::Regtest)
                .unwrap()
                .encode_base58(Network::Main)
                .unwrap(),
            Network::Regtest,
        )
        .unwrap_err();
        assert_eq!(wrong_network.code(), "wrong-network-address");
        assert_eq!(
            Address::decode("rubbish", Network::Regtest)
                .unwrap_err()
                .code(),
            "invalid-payout-address"
        );
        assert_eq!(
            Address::decode("", Network::Regtest).unwrap_err().code(),
            "missing-payout-address"
        );
    }

    #[test]
    fn base58_handles_leading_zero_bytes() {
        assert_eq!(base58_encode(&[0, 0, 1]), "112");
        assert_eq!(base58_decode("112").unwrap(), vec![0, 0, 1]);
        assert_eq!(base58_encode(&[]), "");
    }
}

#[cfg(test)]
mod key_format_tests {
    use super::*;

    /// The authority key string must be exactly what SRI's `key_utils`
    /// produces, because that is what a miner's configuration parses.
    ///
    /// Pinned against `key_utils` itself rather than against a hardcoded
    /// expectation, so it cannot drift into agreeing with only itself. That is
    /// the same reason `key_utils` is a dev-dependency and not a real one:
    /// the format is worth testing against, the crate is not worth shipping.
    #[test]
    fn it_matches_sri() {
        use std::str::FromStr;

        let secp = secp256k1::Secp256k1::new();
        for seed in 1u8..=8 {
            let secret = secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap();
            let keypair = secp256k1::Keypair::from_secret_key(&secp, &secret);
            let (xonly, _) = keypair.x_only_public_key();

            let ours = encode_authority_key(&xonly);
            let theirs = key_utils::Secp256k1PublicKey(xonly).to_string();
            assert_eq!(ours, theirs, "for key seed {seed}");

            // And SRI parses what we print, which is the direction that
            // actually matters.
            let parsed = key_utils::Secp256k1PublicKey::from_str(&ours)
                .unwrap_or_else(|e| panic!("key_utils could not parse {ours}: {e:?}"));
            assert_eq!(parsed.0, xonly);

            // So do we.
            assert_eq!(decode_authority_key(&ours).unwrap(), xonly);
        }
    }

    #[test]
    fn the_printed_length_is_what_a_miner_expects() {
        // The observed value from a working miner configuration was 51
        // characters. base58check over 34 bytes lands at 51 or 52 depending
        // on leading zeroes, so this pins the order of magnitude rather than
        // an exact number.
        let secp = secp256k1::Secp256k1::new();
        let secret = secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &secret);
        let (xonly, _) = keypair.x_only_public_key();
        let encoded = encode_authority_key(&xonly);
        assert!(
            (50..=53).contains(&encoded.len()),
            "{encoded} is {} characters",
            encoded.len()
        );
    }
}
