//! The Noise NX handshake and the framing above it, over a blocking socket.
//!
//! Both halves are SRI's: `noise_sv2` does the handshake and the ciphers,
//! `codec_sv2` does the frame encryption and chunking, and `framing_sv2` does
//! the 6-byte header, which carries any `extension_type` including `0x4001`
//! and the `0xc001` channel-message form.
//!
//! What this adds is a blocking socket loop and an owned [`Frame`], so a
//! caller is not holding a borrow of the decoder's buffer while it decides
//! what to do next.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use binary_sv2::{GetSize, Serialize};
use codec_sv2::{
    Decoded, Decrypted, HandshakeMessage, InitiatorSent, MessageFrame, NoiseDecoder, NoiseEncoder,
    SerializedFrame, TransportDecryptState, TransportEncryptState,
};
use noise_sv2::{Initiator, INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE};
use secp256k1::XOnlyPublicKey;

use crate::error::{Error, Result};

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
///
/// Thin because `noise_sv2` verifies the certificate inside `step_2` and
/// returns only the ciphers, so neither the server's static key nor the
/// certificate's validity window is available to report.
#[derive(Debug, Clone)]
pub struct ServerIdentity {
    /// True when the certificate was checked against an authority key rather
    /// than accepted on first use. `noise_sv2` returns `Ok` either way, and
    /// says so: the engine it returns "carries no indication of which case
    /// applies", so this is the only record.
    pub verified: bool,
}

pub struct Connection {
    stream: TcpStream,
    encoder: NoiseEncoder,
    decoder: NoiseDecoder,
    encrypt: TransportEncryptState,
    // Taken for the duration of a decode: SRI's decoder consumes the state and
    // hands it back only on a round that did not fail, because after a failed
    // decryption the nonce no longer follows the peer's bytes.
    decrypt: Option<TransportDecryptState>,
    identity: ServerIdentity,
}

impl Connection {
    /// Connects and completes the Noise NX handshake.
    ///
    /// `authority` is the pool authority x-only public key. Passing `None` is
    /// trust on first use: the handshake still runs, but nothing says the key
    /// that signed the certificate is the one that should have.
    pub fn connect(
        addr: SocketAddr,
        authority: Option<XOnlyPublicKey>,
        timeout: Duration,
    ) -> Result<Self> {
        let stream = TcpStream::connect_timeout(&addr, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        stream.set_nodelay(true)?;

        let verified = authority.is_some();
        let mut encoder = NoiseEncoder::new();

        let handshake = codec_sv2::Handshake::initiator(Initiator::new(authority));
        let (message, handshake) = handshake.step_0()?;
        let mut partial = Partial {
            stream,
            decoder: NoiseDecoder::new(),
        };
        partial.write_handshake(&mut encoder, message)?;

        let mut reply = [0u8; INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE];
        partial.read_handshake(&mut reply)?;
        let Partial { stream, decoder } = partial;

        // step_2 is where the certificate is checked: the validity window
        // against the clock, and the signature against `authority` when one
        // was given. A bad certificate fails here, not later.
        let (encrypt, decrypt) = handshake.step_2(reply)?.split();

        Ok(Self {
            stream,
            encoder,
            decoder,
            encrypt,
            decrypt: Some(decrypt),
            identity: ServerIdentity { verified },
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
        let frame = MessageFrame::from_message(message, msg_type, extension_type, channel_msg)?;
        let bytes = self.encoder.encode_transport(frame, &mut self.encrypt)?;
        self.stream.write_all(bytes.as_ref())?;
        Ok(())
    }

    /// Sends an already-serialized payload under any `extension_type`.
    ///
    /// This is the path the Avian extension and the Extensions Negotiation
    /// extension take, since SRI defines neither.
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
        let mut bytes = encode_header(extension_type, msg_type, payload.len())?.to_vec();
        bytes.extend_from_slice(payload);

        let frame = SerializedFrame::from_bytes(bytes)?;
        let out = self.encoder.encode_transport(frame, &mut self.encrypt)?;
        self.stream.write_all(out.as_ref())?;
        Ok(())
    }

    /// Reads one whole frame, blocking until it arrives.
    pub fn recv(&mut self) -> Result<Frame> {
        loop {
            let state = self.decrypt.take().ok_or_else(|| {
                Error::Protocol("the connection was torn down by a failed decryption".into())
            })?;
            match self.decoder.next_transport_frame(state)? {
                Decrypted::Frame(mut frame, state) => {
                    self.decrypt = Some(state);
                    let header = frame.header();
                    return Ok(Frame {
                        extension_type: header.ext_type_without_channel_msg(),
                        channel_msg: header.channel_msg(),
                        msg_type: header.msg_type(),
                        payload: frame.payload().to_vec(),
                    });
                }
                Decrypted::Incomplete(_, state) => {
                    self.decrypt = Some(state);
                    read_window(&mut self.stream, &mut self.decoder)?;
                }
            }
        }
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

// The handshake needs the stream and the decoder before the Connection exists.
struct Partial {
    stream: TcpStream,
    decoder: NoiseDecoder,
}

impl Partial {
    fn write_handshake(
        &mut self,
        encoder: &mut NoiseEncoder,
        message: HandshakeMessage,
    ) -> Result<()> {
        let bytes = encoder.encode_handshake(message);
        self.stream.write_all(bytes.as_ref())?;
        Ok(())
    }

    fn read_handshake(&mut self, into: &mut [u8]) -> Result<()> {
        loop {
            match self.decoder.next_handshake_frame::<InitiatorSent>()? {
                Decoded::Frame(message) => {
                    let payload = message.payload();
                    if payload.len() != into.len() {
                        return Err(Error::Payload(format!(
                            "handshake message 2 is {} bytes, expected {}",
                            payload.len(),
                            into.len()
                        )));
                    }
                    into.copy_from_slice(payload);
                    return Ok(());
                }
                Decoded::Incomplete(_) => read_window(&mut self.stream, &mut self.decoder)?,
            }
        }
    }
}

/// Fills the decoder's read window exactly.
///
/// `writable()` hands back the window the decoder will accept and has already
/// counted those bytes as present, so a short read leaves it decrypting
/// whatever the buffer held. Nothing recovers from that, which is why a
/// failure here is terminal for the connection.
fn read_window(stream: &mut TcpStream, decoder: &mut NoiseDecoder) -> Result<()> {
    // An empty window means the bytes are already buffered: go round again.
    let window = decoder.writable();
    if window.is_empty() {
        return Ok(());
    }
    stream.read_exact(window).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            Error::Protocol("the node closed the Stratum v2 connection".into())
        } else {
            Error::Io(e)
        }
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use framing_sv2::header::Header;

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
