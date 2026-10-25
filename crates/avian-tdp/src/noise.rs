//! The Noise NX handshake and the frame cipher above it.
//!
//! This is here reluctantly. SRI's `noise_sv2` implements this already, and
//! correctly, but it cannot complete a handshake with `aviand`: the two
//! disagree on handshake act 1 by one `MixHash` over an empty payload. See
//! [`Variant`]. `codec_sv2`'s Noise encoder and decoder cannot be reused
//! either, because the only way to obtain a `TransportEncryptState` is from
//! `noise_sv2`'s own handshake: `NoiseEngine` has no public constructor.
//!
//! So this is a transcription of `src/sv2/noise.cpp` and
//! `test/functional/test_framework/sv2.py`, with the Noise state machine
//! written out and every primitive taken from an existing crate:
//! `chacha20poly1305` for the AEAD, `secp256k1` for the ElligatorSwift ECDH
//! and the Schnorr verification, and `secp256k1::hashes` for SHA256 and HMAC.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use secp256k1::ellswift::{ElligatorSwift, ElligatorSwiftParty};
use secp256k1::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use secp256k1::{Keypair, Message, PublicKey, Secp256k1, XOnlyPublicKey};

use crate::error::{Error, Result};

/// Every byte of this string, capitalization included, is part of the wire
/// contract: one wrong character gives a different transcript hash and the
/// handshake fails with no useful diagnostic.
const NOISE_PROTOCOL_NAME: &[u8] = b"Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256";

pub const MAC_SIZE: usize = 16;
pub const ELLSWIFT_SIZE: usize = 64;
pub const CERT_SIZE: usize = 74;
pub const HEADER_SIZE: usize = 6;
pub const ENCRYPTED_HEADER_SIZE: usize = HEADER_SIZE + MAC_SIZE;
pub const MAX_PLAINTEXT_CHUNK: usize = 65519;
pub const HANDSHAKE_MSG1_SIZE: usize = ELLSWIFT_SIZE;
pub const HANDSHAKE_MSG2_SIZE: usize =
    ELLSWIFT_SIZE + (ELLSWIFT_SIZE + MAC_SIZE) + (CERT_SIZE + MAC_SIZE);

/// Which reading of handshake act 1 to use.
///
/// The Stratum v2 specification, section 4.5.1.1, has the initiator call
/// `MixHash(e.public_key)` and then `EncryptAndHash()` on an empty payload,
/// noting that with no key yet "this effectively reduces down to `MixHash()`
/// on empty data". It adds no bytes to the wire and one hash to the
/// transcript.
///
/// `aviand` omits it. `HandshakeState::WriteMsg1` in `src/sv2/noise.cpp` is
/// `MixHash` alone, and `ReadMsg1` matches, so the node is self-consistent and
/// interoperates with `test_framework/sv2.py`, which omits it too. It does not
/// interoperate with anything that follows the specification, including SRI:
/// the chaining key agrees, but `h` diverges, and `h` is the AEAD associated
/// data, so the first decryption in message 2 fails its MAC check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Variant {
    /// What `aviand` implements today, and the only thing it accepts.
    #[default]
    Avian,
    /// What the specification says, and what SRI's `noise_sv2` does.
    Sv2Spec,
}

fn hkdf2(salt: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let temp = hmac(salt, ikm);
    let out1 = hmac(&temp, &[0x01]);
    let mut second = Vec::with_capacity(33);
    second.extend_from_slice(&out1);
    second.push(0x02);
    let out2 = hmac(&temp, &second);
    (out1, out2)
}

fn hmac(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut engine = HmacEngine::<sha256::Hash>::new(key);
    engine.input(message);
    Hmac::<sha256::Hash>::from_engine(engine).to_byte_array()
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut engine = sha256::Hash::engine();
    for part in parts {
        engine.input(part);
    }
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// One Noise cipher: a key and a message counter.
pub struct CipherState {
    cipher: ChaCha20Poly1305,
    nonce: u64,
}

impl CipherState {
    fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(&key.into()),
            nonce: 0,
        }
    }

    // Four zero bytes then the counter little-endian.
    fn nonce96(&self) -> Nonce {
        let mut out = [0u8; 12];
        out[4..].copy_from_slice(&self.nonce.to_le_bytes());
        out.into()
    }

    pub fn encrypt(&mut self, plain: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let out = self
            .cipher
            .encrypt(&self.nonce96(), Payload { msg: plain, aad })
            .map_err(|_| Error::Payload("AEAD encryption failed".into()))?;
        self.nonce += 1;
        Ok(out)
    }

    pub fn decrypt(&mut self, cipher: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let out = self
            .cipher
            .decrypt(&self.nonce96(), Payload { msg: cipher, aad });
        // Advance even on failure, as the node does: a forged frame consumes
        // its nonce, so a peer cannot probe the same counter repeatedly.
        self.nonce += 1;
        out.map_err(|_| Error::Protocol("MAC check failed".into()))
    }
}

/// The Noise chaining key and transcript hash.
struct SymmetricState {
    h: [u8; 32],
    ck: [u8; 32],
    cipher: Option<CipherState>,
}

impl SymmetricState {
    fn new() -> Self {
        // The protocol name is longer than 32 bytes, so h starts as its hash
        // rather than the zero-padded name.
        let h = sha256(&[NOISE_PROTOCOL_NAME]);
        let mut state = Self {
            h,
            ck: h,
            cipher: None,
        };
        // MixHash over an empty prologue, which reduces to hashing h again.
        state.mix_hash(&[]);
        state
    }

    fn mix_hash(&mut self, data: &[u8]) {
        self.h = sha256(&[&self.h, data]);
    }

    fn mix_key(&mut self, ikm: &[u8]) {
        let (ck, temp_k) = hkdf2(&self.ck, ikm);
        self.ck = ck;
        self.cipher = Some(CipherState::new(temp_k));
    }

    /// Noise degrades `EncryptAndHash` to `MixHash` before a key exists. Only
    /// the empty payload of handshake act 1 takes that path.
    fn encrypt_and_hash(&mut self, plain: &[u8]) -> Result<Vec<u8>> {
        match self.cipher.as_mut() {
            None => {
                self.mix_hash(plain);
                Ok(plain.to_vec())
            }
            Some(cipher) => {
                let aad = self.h;
                let out = cipher.encrypt(plain, &aad)?;
                self.mix_hash(&out);
                Ok(out)
            }
        }
    }

    fn decrypt_and_hash(&mut self, cipher_text: &[u8]) -> Result<Vec<u8>> {
        match self.cipher.as_mut() {
            None => {
                self.mix_hash(cipher_text);
                Ok(cipher_text.to_vec())
            }
            Some(cipher) => {
                // h is the associated data, so it is captured before the
                // ciphertext is mixed in.
                let aad = self.h;
                let out = cipher.decrypt(cipher_text, &aad)?;
                self.mix_hash(cipher_text);
                Ok(out)
            }
        }
    }

    /// c1 carries initiator-to-responder traffic, c2 the reverse.
    fn split(&self) -> (CipherState, CipherState) {
        let (k1, k2) = hkdf2(&self.ck, &[]);
        (CipherState::new(k1), CipherState::new(k2))
    }
}

/// The server's certificate, as it appears in handshake message 2.
#[derive(Debug, Clone, Copy)]
pub struct Certificate {
    pub version: u16,
    pub valid_from: u32,
    pub not_valid_after: u32,
    pub signature: [u8; 64],
}

impl Certificate {
    fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() != CERT_SIZE {
            return Err(Error::Payload(format!(
                "certificate is {} bytes, expected {CERT_SIZE}",
                raw.len()
            )));
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&raw[10..]);
        Ok(Self {
            version: u16::from_le_bytes([raw[0], raw[1]]),
            valid_from: u32::from_le_bytes([raw[2], raw[3], raw[4], raw[5]]),
            not_valid_after: u32::from_le_bytes([raw[6], raw[7], raw[8], raw[9]]),
            signature,
        })
    }

    /// `SHA256(version || valid_from || not_valid_after || static_key)`, a
    /// single SHA256 rather than Bitcoin's usual double hash.
    fn digest(&self, static_xonly: &[u8; 32]) -> [u8; 32] {
        sha256(&[
            &self.version.to_le_bytes(),
            &self.valid_from.to_le_bytes(),
            &self.not_valid_after.to_le_bytes(),
            static_xonly,
        ])
    }

    fn verify(&self, static_xonly: &[u8; 32], authority: &XOnlyPublicKey, now: u32) -> Result<()> {
        if self.version != 0 {
            return Err(Error::Protocol(format!(
                "unknown certificate version {}",
                self.version
            )));
        }
        if !(self.valid_from <= now && now <= self.not_valid_after) {
            return Err(Error::Protocol(format!(
                "certificate is valid from {} to {}, and it is now {now}",
                self.valid_from, self.not_valid_after
            )));
        }
        let signature = secp256k1::schnorr::Signature::from_slice(&self.signature)?;
        let message = Message::from_digest(self.digest(static_xonly));
        Secp256k1::verification_only()
            .verify_schnorr(&signature, &message, authority)
            .map_err(|_| Error::Protocol("certificate is not signed by the authority key".into()))
    }
}

/// The initiator half of the Noise NX handshake.
pub struct Handshake {
    state: SymmetricState,
    ephemeral: Keypair,
    ephemeral_ellswift: [u8; 64],
    variant: Variant,
}

/// What the handshake established.
pub struct Session {
    pub send: CipherState,
    pub recv: CipherState,
    /// The x coordinate of the server's static key.
    pub remote_static: [u8; 32],
    pub certificate: Certificate,
    /// True when the certificate's signature was checked against an authority
    /// key, rather than the certificate being accepted on first use.
    pub verified: bool,
}

impl Handshake {
    pub fn new(variant: Variant) -> Self {
        let secp = Secp256k1::new();
        let ephemeral = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
        let ephemeral_ellswift = ElligatorSwift::from_pubkey(ephemeral.public_key()).to_array();
        Self {
            state: SymmetricState::new(),
            ephemeral,
            ephemeral_ellswift,
            variant,
        }
    }

    /// Handshake message 1: the ephemeral key's ElligatorSwift encoding.
    pub fn write_msg1(&mut self) -> Result<[u8; HANDSHAKE_MSG1_SIZE]> {
        self.state.mix_hash(&self.ephemeral_ellswift);
        if self.variant == Variant::Sv2Spec {
            // Adds nothing to the wire; the empty ciphertext is hashed in.
            self.state.encrypt_and_hash(&[])?;
        }
        Ok(self.ephemeral_ellswift)
    }

    /// Handshake message 2: the server's ephemeral key, its static key and its
    /// certificate.
    pub fn read_msg2(
        mut self,
        message: &[u8],
        authority: Option<&XOnlyPublicKey>,
        now: u32,
    ) -> Result<Session> {
        if message.len() != HANDSHAKE_MSG2_SIZE {
            return Err(Error::Payload(format!(
                "handshake message 2 is {} bytes, expected {HANDSHAKE_MSG2_SIZE}",
                message.len()
            )));
        }

        let their_ephemeral: [u8; 64] = message[..ELLSWIFT_SIZE].try_into().unwrap();
        self.state.mix_hash(&their_ephemeral);
        self.state.mix_key(&self.ecdh(&their_ephemeral));

        let at = ELLSWIFT_SIZE;
        let their_static = self
            .state
            .decrypt_and_hash(&message[at..at + ELLSWIFT_SIZE + MAC_SIZE])?;
        let their_static: [u8; 64] = their_static
            .try_into()
            .map_err(|_| Error::Payload("static key is not 64 bytes".into()))?;
        self.state.mix_key(&self.ecdh(&their_static));

        let at = at + ELLSWIFT_SIZE + MAC_SIZE;
        let certificate = Certificate::decode(&self.state.decrypt_and_hash(&message[at..])?)?;

        // The certificate signs the x-only form of the static key, so recover
        // it from the ElligatorSwift encoding just decrypted.
        let remote_static = PublicKey::from_ellswift(ElligatorSwift::from_array(their_static))
            .x_only_public_key()
            .0
            .serialize();

        if let Some(authority) = authority {
            certificate.verify(&remote_static, authority, now)?;
        }

        let (send, recv) = self.state.split();
        Ok(Session {
            send,
            recv,
            remote_static,
            certificate,
            verified: authority.is_some(),
        })
    }

    /// BIP324's `v2_ecdh`, down to the `bip324_ellswift_xonly_ecdh` tag and
    /// the role-dependent key ordering. We are always the initiator, so our
    /// key is always first, which is what `ElligatorSwiftParty::A` means.
    fn ecdh(&self, theirs: &[u8; 64]) -> [u8; 32] {
        ElligatorSwift::shared_secret(
            ElligatorSwift::from_array(self.ephemeral_ellswift),
            ElligatorSwift::from_array(*theirs),
            self.ephemeral.secret_key(),
            ElligatorSwiftParty::A,
            None,
        )
        .to_secret_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashed_protocol_name_matches_sri() {
        // noise_sv2::NOISE_HASHED_PROTOCOL_NAME_CHACHA. If this ever differs,
        // the divergence is wider than one MixHash.
        assert_eq!(
            sha256(&[NOISE_PROTOCOL_NAME]),
            [
                46, 180, 120, 129, 32, 142, 158, 238, 31, 102, 159, 103, 198, 110, 231, 14, 169,
                234, 136, 9, 13, 80, 63, 232, 48, 220, 75, 200, 62, 41, 191, 16
            ]
        );
    }

    #[test]
    fn the_two_variants_differ_only_in_h() {
        // The chaining key is untouched by the extra MixHash, which is why the
        // symptom is a MAC failure rather than a garbled plaintext.
        let mut avian = Handshake::new(Variant::Avian);
        let mut spec = Handshake::new(Variant::Sv2Spec);
        spec.ephemeral_ellswift = avian.ephemeral_ellswift;
        spec.state = SymmetricState::new();

        avian.write_msg1().unwrap();
        spec.write_msg1().unwrap();
        assert_eq!(avian.state.ck, spec.state.ck);
        assert_ne!(avian.state.h, spec.state.h);
        assert_eq!(spec.state.h, sha256(&[&avian.state.h, &[]]));
    }

    #[test]
    fn nonce_is_four_zeroes_then_a_little_endian_counter() {
        let mut state = CipherState::new([7u8; 32]);
        assert_eq!(state.nonce96().as_slice(), &[0u8; 12]);
        state.nonce = 1;
        assert_eq!(
            state.nonce96().as_slice(),
            &[0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]
        );
    }
}
