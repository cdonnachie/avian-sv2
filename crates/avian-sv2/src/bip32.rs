//! BIP32 public derivation, for a miner that wants a fresh address per block.
//!
//! A miner may hand the pool an extended public key instead of an address,
//! wrapped in a descriptor that says which script to pay (see `address`). The
//! pool then derives child key `i` for the block it is working on and moves
//! to `i + 1` once that block is found, so no address appears on the chain
//! twice. Only the public half is ever here: an xpub derives addresses and
//! nothing else, and a pool that held anything more would be a custodian.
//!
//! Unhardened derivation only, which is all an xpub can do. The arithmetic is
//! BIP32's: `I = HMAC-SHA512(chain_code, ser_P(K) || ser32(i))`, the child key
//! is `point(I_L) + K` and the child chain code is `I_R`. The one in 2^127
//! cases where `I_L` is out of range or the sum is the point at infinity are
//! an error here rather than a skipped index, so the caller decides.
//!
//! The version bytes are Avian's, which are Bitcoin's: `xpub` on mainnet and
//! `tpub` on every test chain, from `src/kernel/chainparams.cpp`.

use std::fmt;

use secp256k1::hashes::{hash160, sha512, Hash, HashEngine, Hmac, HmacEngine};
use secp256k1::{PublicKey, Scalar, Secp256k1};

use crate::address::{base58check_decode, base58check_encode, AddressError, Network};

/// The bit that marks a hardened child, which an extended public key cannot
/// derive.
pub const HARDENED: u32 = 0x8000_0000;

/// The serialized length of an extended key, before the checksum.
const SERIALIZED_LEN: usize = 78;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedPubKey {
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: u32,
    pub chain_code: [u8; 32],
    pub key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bip32Error {
    /// Not base58check, or the checksum failed. The reason as text, because
    /// `AddressError` carries this type and the two cannot each hold the
    /// other by value.
    Encoding(String),
    /// Decoded, but not the 78 bytes an extended key serializes to.
    BadLength(usize),
    /// An extended key for another chain, or a private one.
    WrongVersion { found: [u8; 4], expected: [u8; 4] },
    /// The 33 bytes at the end are not a point on the curve.
    BadKey,
    /// A hardened index, which needs the private key.
    Hardened(u32),
    /// Derivation at this index produced an invalid key. BIP32 says to skip
    /// to the next; this reports it and lets the caller choose.
    Unlucky(u32),
}

impl fmt::Display for Bip32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Bip32Error::Encoding(e) => write!(f, "not an extended key: {e}"),
            Bip32Error::BadLength(n) => write!(f, "an extended key is 78 bytes, this is {n}"),
            Bip32Error::WrongVersion { found, expected } => write!(
                f,
                "extended key version {:02x}{:02x}{:02x}{:02x}, and this chain's public \
                 keys use {:02x}{:02x}{:02x}{:02x}",
                found[0],
                found[1],
                found[2],
                found[3],
                expected[0],
                expected[1],
                expected[2],
                expected[3]
            ),
            Bip32Error::BadKey => write!(f, "the key bytes are not a point on the curve"),
            Bip32Error::Hardened(i) => write!(
                f,
                "index {} is hardened, which a public key cannot derive",
                i & !HARDENED
            ),
            Bip32Error::Unlucky(i) => {
                write!(f, "derivation at index {i} produced an invalid key")
            }
        }
    }
}

impl From<AddressError> for Bip32Error {
    fn from(e: AddressError) -> Self {
        Bip32Error::Encoding(e.to_string())
    }
}

/// `base58Prefixes[EXT_PUBLIC_KEY]` for the chain.
pub fn version_bytes(network: Network) -> [u8; 4] {
    match network {
        Network::Main => [0x04, 0x88, 0xB2, 0x1E],
        Network::Testnet | Network::Testnet4 | Network::Signet | Network::Regtest => {
            [0x04, 0x35, 0x87, 0xCF]
        }
    }
}

impl ExtendedPubKey {
    /// Decodes an `xpub` (or `tpub`) and checks it belongs to this chain.
    pub fn decode(text: &str, network: Network) -> Result<Self, Bip32Error> {
        let payload = base58check_decode(text)?;
        if payload.len() != SERIALIZED_LEN {
            return Err(Bip32Error::BadLength(payload.len()));
        }
        let mut found = [0u8; 4];
        found.copy_from_slice(&payload[0..4]);
        let expected = version_bytes(network);
        if found != expected {
            return Err(Bip32Error::WrongVersion { found, expected });
        }
        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&payload[5..9]);
        let child_number = u32::from_be_bytes([payload[9], payload[10], payload[11], payload[12]]);
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&payload[13..45]);
        let key = PublicKey::from_slice(&payload[45..78]).map_err(|_| Bip32Error::BadKey)?;
        Ok(Self {
            depth: payload[4],
            parent_fingerprint,
            child_number,
            chain_code,
            key,
        })
    }

    /// The base58check form, with this chain's version bytes.
    pub fn encode(&self, network: Network) -> String {
        let mut payload = Vec::with_capacity(SERIALIZED_LEN);
        payload.extend_from_slice(&version_bytes(network));
        payload.push(self.depth);
        payload.extend_from_slice(&self.parent_fingerprint);
        payload.extend_from_slice(&self.child_number.to_be_bytes());
        payload.extend_from_slice(&self.chain_code);
        payload.extend_from_slice(&self.key.serialize());
        base58check_encode(&payload)
    }

    /// `HASH160` of the compressed key: the program of a P2PKH or P2WPKH
    /// output paying it.
    pub fn pubkey_hash(&self) -> [u8; 20] {
        hash160::Hash::hash(&self.key.serialize()).to_byte_array()
    }

    /// The first four bytes of `pubkey_hash`, which is how a child names its
    /// parent.
    pub fn fingerprint(&self) -> [u8; 4] {
        let hash = self.pubkey_hash();
        [hash[0], hash[1], hash[2], hash[3]]
    }

    /// One unhardened step.
    pub fn derive(&self, index: u32) -> Result<Self, Bip32Error> {
        if index & HARDENED != 0 {
            return Err(Bip32Error::Hardened(index));
        }
        let mut engine = HmacEngine::<sha512::Hash>::new(&self.chain_code);
        engine.input(&self.key.serialize());
        engine.input(&index.to_be_bytes());
        let i = Hmac::<sha512::Hash>::from_engine(engine).to_byte_array();

        let mut left = [0u8; 32];
        left.copy_from_slice(&i[..32]);
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&i[32..]);

        // Both failures are the same astronomically unlikely event: I_L is
        // not a valid scalar, or K + point(I_L) is the point at infinity.
        let tweak = Scalar::from_be_bytes(left).map_err(|_| Bip32Error::Unlucky(index))?;
        let key = self
            .key
            .add_exp_tweak(&Secp256k1::verification_only(), &tweak)
            .map_err(|_| Bip32Error::Unlucky(index))?;

        Ok(Self {
            depth: self.depth.wrapping_add(1),
            parent_fingerprint: self.fingerprint(),
            child_number: index,
            chain_code,
            key,
        })
    }

    /// Several unhardened steps, left to right.
    pub fn derive_path(&self, path: &[u32]) -> Result<Self, Bip32Error> {
        let mut key = self.clone();
        for &index in path {
            key = key.derive(index)?;
        }
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP32 test vector 1, seed 000102030405060708090a0b0c0d0e0f. The key
    // for m/0H and the key for m/0H/1, which is one unhardened step from it.
    const M_0H: &str = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw";
    const M_0H_1: &str = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ";

    #[test]
    fn the_bip32_vector_derives() {
        let parent = ExtendedPubKey::decode(M_0H, Network::Main).unwrap();
        assert_eq!(parent.depth, 1);
        assert_eq!(parent.child_number, HARDENED);
        let child = parent.derive(1).unwrap();
        assert_eq!(child.encode(Network::Main), M_0H_1);
        assert_eq!(child.depth, 2);
        assert_eq!(child.child_number, 1);
        assert_eq!(child.parent_fingerprint, parent.fingerprint());
        // The same key by the path form.
        assert_eq!(parent.derive_path(&[1]).unwrap(), child);
    }

    #[test]
    fn a_key_round_trips_through_its_own_encoding() {
        let key = ExtendedPubKey::decode(M_0H, Network::Main).unwrap();
        assert_eq!(key.encode(Network::Main), M_0H);
        // Re-versioned for a test chain it decodes there and nowhere else.
        let tpub = key.encode(Network::Regtest);
        assert!(tpub.starts_with("tpub"), "{tpub}");
        assert_eq!(
            ExtendedPubKey::decode(&tpub, Network::Regtest).unwrap(),
            key
        );
    }

    #[test]
    fn a_key_for_another_chain_is_refused() {
        match ExtendedPubKey::decode(M_0H, Network::Regtest) {
            Err(Bip32Error::WrongVersion { found, expected }) => {
                assert_eq!(found, [0x04, 0x88, 0xB2, 0x1E]);
                assert_eq!(expected, [0x04, 0x35, 0x87, 0xCF]);
            }
            other => panic!("expected a version error, got {other:?}"),
        }
    }

    #[test]
    fn a_private_key_is_refused_as_the_wrong_version() {
        // Test vector 1's m/0H xprv. The pool must never accept one: it is the
        // wrong version for an xpub and the message says so, which is as far
        // as the pool can go in protecting someone who pasted the wrong half.
        let xprv = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";
        assert!(matches!(
            ExtendedPubKey::decode(xprv, Network::Main),
            Err(Bip32Error::WrongVersion { .. })
        ));
    }

    #[test]
    fn a_hardened_index_is_refused() {
        let key = ExtendedPubKey::decode(M_0H, Network::Main).unwrap();
        assert_eq!(
            key.derive(HARDENED | 2),
            Err(Bip32Error::Hardened(HARDENED | 2))
        );
        assert_eq!(
            key.derive_path(&[0, HARDENED]),
            Err(Bip32Error::Hardened(HARDENED))
        );
    }

    #[test]
    fn garbage_is_refused_before_any_arithmetic() {
        assert!(matches!(
            ExtendedPubKey::decode("xpub-not-really", Network::Main),
            Err(Bip32Error::Encoding(_))
        ));
        // A valid base58check string of the wrong size: a regtest address.
        assert!(matches!(
            ExtendedPubKey::decode("mnPBEVKjU1zz9214C7M7Zp4FuurUAsU6ZS", Network::Regtest),
            Err(Bip32Error::BadLength(21))
        ));
    }
}
