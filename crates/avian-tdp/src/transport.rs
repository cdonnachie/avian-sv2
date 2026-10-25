//! Frames over a blocking socket.
//!
//! The header is `framing_sv2::header::Header`, SRI's, which carries any
//! `extension_type` including `0x4001` and the `0xc001` channel-message form.
//! The cipher layer is [`crate::noise`], which exists only because SRI's
//! handshake cannot talk to `aviand`; see [`crate::noise::Variant`].
//!
//! Each frame is one AEAD operation for the 6-byte header followed by the
//! payload in chunks of at most 65519 bytes, each its own AEAD operation on
//! the same cipher. They consume consecutive nonces, so they have to stay in
//! order.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use binary_sv2::{to_bytes, GetSize, Serialize};
use framing_sv2::header::Header;
use secp256k1::XOnlyPublicKey;

use crate::error::{Error, Result};
use crate::noise::{
    Certificate, CipherState, Handshake, Variant, ENCRYPTED_HEADER_SIZE, HANDSHAKE_MSG2_SIZE,
    MAC_SIZE, MAX_PLAINTEXT_CHUNK,
};

pub const CHANNEL_MSG_BIT: u16 = 0x8000;

/// One decoded frame, owned.
#[derive(Debug, Clone)]
pub struct Frame {
    /// With the `channel_msg` bit already cleared, which is how an extension
    /// is looked up: `0xc001` and `0x4001` are the same extension.
    pub extension_type: u16,
    pub channel_msg: bool,
    pub msg_type: u8,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn is(&self, extension_type: u16, msg_type: u8) -> bool {
        self.extension_type == extension_type && self.msg_type == msg_type
    }

    pub fn describe(&self) -> String {
        let ext = self.extension_type | if self.channel_msg { CHANNEL_MSG_BIT } else { 0 };
        format!(
            "extension 0x{:04x} message 0x{:02x} ({} byte payload)",
            ext,
            self.msg_type,
            self.payload.len()
        )
    }
}

/// What the server proved about itself during the handshake.
#[derive(Debug, Clone)]
pub struct ServerIdentity {
    /// The x coordinate of the server's static key.
    pub static_key: [u8; 32],
    pub certificate: Certificate,
    /// True when the certificate was checked against an authority key rather
    /// than accepted on first use.
    pub verified: bool,
}

pub struct Connection {
    stream: TcpStream,
    send: CipherState,
    recv: CipherState,
    identity: ServerIdentity,
}

impl Connection {
    /// Connects and completes the Noise NX handshake, using the handshake
    /// variant `aviand` implements.
    pub fn connect(
        addr: SocketAddr,
        authority: Option<XOnlyPublicKey>,
        timeout: Duration,
    ) -> Result<Self> {
        Self::connect_with_variant(addr, authority, timeout, Variant::default())
    }

    /// Connects with an explicit handshake variant.
    ///
    /// `Variant::Sv2Spec` is the specification's reading and will not complete
    /// against `aviand` today. It is here so that the day the node is fixed
    /// this client needs a flag rather than a patch, and so the divergence can
    /// be demonstrated rather than asserted.
    pub fn connect_with_variant(
        addr: SocketAddr,
        authority: Option<XOnlyPublicKey>,
        timeout: Duration,
        variant: Variant,
    ) -> Result<Self> {
        let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        stream.set_nodelay(true)?;

        let mut handshake = Handshake::new(variant);
        stream.write_all(&handshake.write_msg1()?)?;

        let mut reply = [0u8; HANDSHAKE_MSG2_SIZE];
        read_exact(&mut stream, &mut reply)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::Protocol("the system clock is before the epoch".into()))?
            .as_secs() as u32;
        let session = handshake.read_msg2(&reply, authority.as_ref(), now)?;

        Ok(Self {
            stream,
            send: session.send,
            recv: session.recv,
            identity: ServerIdentity {
                static_key: session.remote_static,
                certificate: session.certificate,
                verified: session.verified,
            },
        })
    }

    pub fn identity(&self) -> &ServerIdentity {
        &self.identity
    }

    pub fn peer_addr(&self) -> Result<SocketAddr> {
        Ok(self.stream.peer_addr()?)
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        Ok(self.stream.set_read_timeout(timeout)?)
    }

    /// Sends a message SRI's binary codec knows how to serialize.
    pub fn send<T: Serialize + GetSize>(
        &mut self,
        extension_type: u16,
        msg_type: u8,
        channel_msg: bool,
        message: T,
    ) -> Result<()> {
        let payload = to_bytes(message)?;
        self.send_raw(extension_type, msg_type, channel_msg, &payload)
    }

    /// Sends an already-serialized payload under any `extension_type`.
    pub fn send_raw(
        &mut self,
        extension_type: u16,
        msg_type: u8,
        channel_msg: bool,
        payload: &[u8],
    ) -> Result<()> {
        let extension_type = if channel_msg {
            extension_type | CHANNEL_MSG_BIT
        } else {
            extension_type & !CHANNEL_MSG_BIT
        };
        let header = encode_header(extension_type, msg_type, payload.len())?;

        let mut out = self.send.encrypt(&header, &[])?;
        for chunk in payload.chunks(MAX_PLAINTEXT_CHUNK) {
            out.extend_from_slice(&self.send.encrypt(chunk, &[])?);
        }
        // Chunks of one frame must not be interleaved with another frame's, so
        // the whole thing goes out in one write.
        self.stream.write_all(&out)?;
        Ok(())
    }

    /// Reads one whole frame, blocking until it arrives.
    pub fn recv(&mut self) -> Result<Frame> {
        let mut encrypted_header = [0u8; ENCRYPTED_HEADER_SIZE];
        read_exact(&mut self.stream, &mut encrypted_header)?;
        let header = Header::from_bytes(&self.recv.decrypt(&encrypted_header, &[])?)?;

        let length = header.payload_length();
        let mut payload = Vec::with_capacity(length);
        while payload.len() < length {
            let chunk = (length - payload.len()).min(MAX_PLAINTEXT_CHUNK);
            let mut encrypted = vec![0u8; chunk + MAC_SIZE];
            read_exact(&mut self.stream, &mut encrypted)?;
            payload.extend_from_slice(&self.recv.decrypt(&encrypted, &[])?);
        }

        Ok(Frame {
            extension_type: header.ext_type_without_channel_msg(),
            channel_msg: header.channel_msg(),
            msg_type: header.msg_type(),
            payload,
        })
    }

    /// Reads one frame, requiring it to be the one named.
    pub fn recv_expect(&mut self, extension_type: u16, msg_type: u8) -> Result<Frame> {
        let frame = self.recv()?;
        if !frame.is(extension_type, msg_type) {
            return Err(Error::Protocol(format!(
                "expected extension 0x{extension_type:04x} message 0x{msg_type:02x}, got {}",
                frame.describe()
            )));
        }
        Ok(frame)
    }
}

/// The six header bytes: `extension_type`, `msg_type`, `msg_length`.
///
/// `Header::from_len` is crate-private in `framing_sv2`, so the bytes are
/// written here; `Header::from_bytes` parses them back on the way in.
pub fn encode_header(extension_type: u16, msg_type: u8, length: usize) -> Result<[u8; 6]> {
    let length = u32::try_from(length)
        .ok()
        .filter(|len| *len < 1 << 24)
        .ok_or_else(|| Error::Payload(format!("payload of {length} bytes does not fit a frame")))?;
    let mut out = [0u8; 6];
    out[0..2].copy_from_slice(&extension_type.to_le_bytes());
    out[2] = msg_type;
    out[3..6].copy_from_slice(&length.to_le_bytes()[..3]);
    Ok(out)
}

fn read_exact(stream: &mut TcpStream, into: &mut [u8]) -> Result<()> {
    stream.read_exact(into).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            Error::Protocol("the node closed the Stratum v2 connection".into())
        } else {
            Error::Io(e)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_channel_message_header_round_trips_through_sri() {
        let bytes = encode_header(0x4001 | CHANNEL_MSG_BIT, 0x04, 16).unwrap();
        let header = Header::from_bytes(&bytes).unwrap();
        assert_eq!(header.ext_type(), 0xc001);
        assert_eq!(header.ext_type_without_channel_msg(), 0x4001);
        assert!(header.channel_msg());
        assert_eq!(header.msg_type(), 0x04);
        assert_eq!(header.payload_length(), 16);
    }

    #[test]
    fn an_extension_header_round_trips_through_sri() {
        let bytes = encode_header(0x4001, 0x00, 1).unwrap();
        let header = Header::from_bytes(&bytes).unwrap();
        assert_eq!(header.ext_type(), 0x4001);
        assert!(!header.channel_msg());
        assert_eq!(header.payload_length(), 1);
    }
}
