//! The authority key the server certificate is checked against.
//!
//! `aviand` writes its authority *private* key as 32 raw bytes to
//! `<datadir>/<chain>/sv2_authority_key` on first run. An operator running the
//! pool beside the node has that file, so the pool can derive the public key
//! rather than trusting the server on first use.

use std::path::{Path, PathBuf};

use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

use crate::error::{Error, Result};

/// Derives the authority x-only public key from the node's private key file.
pub fn from_private_key_file(path: &Path) -> Result<XOnlyPublicKey> {
    let raw = std::fs::read(path)?;
    if raw.len() != 32 {
        return Err(Error::Payload(format!(
            "{} is {} bytes, expected a 32-byte raw private key",
            path.display(),
            raw.len()
        )));
    }
    let secret = SecretKey::from_slice(&raw)?;
    let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
    Ok(XOnlyPublicKey::from_keypair(&keypair).0)
}

pub fn from_hex(text: &str) -> Result<XOnlyPublicKey> {
    let text = text.trim();
    if text.len() != 64 {
        return Err(Error::Payload(format!(
            "an x-only public key is 64 hex characters, got {}",
            text.len()
        )));
    }
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
            .map_err(|_| Error::Payload("public key is not hex".into()))?;
    }
    Ok(XOnlyPublicKey::from_slice(&bytes)?)
}

/// Where the key file sits under a datadir, given the chain's subdirectory.
pub fn default_key_path(datadir: &Path, chain_subdir: &str) -> PathBuf {
    let mut path = datadir.to_path_buf();
    if !chain_subdir.is_empty() {
        path.push(chain_subdir);
    }
    path.push("sv2_authority_key");
    path
}
