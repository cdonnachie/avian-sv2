//! The Noise NX handshake and the framing above it, over a blocking socket.
//!
//! Both halves are SRI's: `noise_sv2` does the handshake and the ciphers,
//! `codec_sv2` does the frame encryption and chunking, and `framing_sv2` does
//! the 6-byte header, which carries any `extension_type` including `0x4001`
//! and the `0xc001` channel-message form.
//!
//! What this adds is a blocking socket loop, an owned [`Frame`] so a caller is
//! not holding a borrow of the decoder's buffer, and both roles: [`Connection::connect`]
//! is the initiator a pool is to a node, [`Connection::accept`] the responder
//! it is to a worker.
//!
//! A [`Connection`] splits into halves. The two directions share no state —
//! each has its own cipher, nonce counter and buffer — so one thread can block
//! on reads while another sends. That is what lets a Mining Protocol server
//! push a job onto a worker's socket from the thread that received the
//! template, and what lets a worker thread submit a solution over the Template
//! Distribution connection the work loop is blocked on.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use binary_sv2::{GetSize, Serialize};
use codec_sv2::{
    Decoded, Decrypted, HandshakeMessage, InitiatorSent, MessageFrame, NoiseDecoder, NoiseEncoder,
    SerializedFrame, TransportDecryptState, TransportEncryptState,
};
use noise_sv2::{Initiator, Responder, INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE};
use secp256k1::{Keypair, XOnlyPublicKey};

use crate::error::{Error, Result};

pub const CHANNEL_MSG_BIT: u16 = 0x8000;

/// How long a certificate the pool issues is good for. The node's own default
/// is 365 days; this is the same order and is not configurable because nothing
/// on a loopback pool benefits from a shorter one.
pub const DEFAULT_CERT_VALIDITY_SECS: u32 = 365 * 24 * 60 * 60;

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

/// The sending half.
pub struct ConnectionWriter {
    stream: TcpStream,
    encoder: NoiseEncoder,
    encrypt: TransportEncryptState,
}

impl ConnectionWriter {
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

    pub fn shutdown(&self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

/// The receiving half.
pub struct ConnectionReader {
    stream: TcpStream,
    decoder: NoiseDecoder,
    // Taken for the duration of a decode: SRI's decoder consumes the state and
    // hands it back only on a round that did not fail, because after a failed
    // decryption the nonce no longer follows the peer's bytes.
    decrypt: Option<TransportDecryptState>,
}

impl ConnectionReader {
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

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        Ok(self.stream.set_read_timeout(timeout)?)
    }

    /// Waits up to `timeout` for a byte to be available, without consuming it.
    ///
    /// This exists because a read timeout cannot be used to poll. SRI's
    /// decoder counts the bytes of `writable()` as present before they are
    /// read, so a `read_exact` that times out part way leaves it decrypting
    /// whatever the buffer held, and there is no way back from that. Peeking
    /// touches no decoder state, so a caller can ask "is there anything?" as
    /// often as it likes and only then commit to a blocking read.
    ///
    /// A peer that sends one byte and stops still blocks the following read
    /// for the connection's own timeout. That is a slowloris against this one
    /// connection and nothing else, and it is why the timeout exists.
    pub fn wait_readable(&self, timeout: Duration) -> Result<bool> {
        let previous = self.stream.read_timeout()?;
        self.stream.set_read_timeout(Some(timeout))?;
        let mut byte = [0u8; 1];
        let ready = match self.stream.peek(&mut byte) {
            Ok(0) => Err(Error::Protocol(
                "the peer closed the Stratum v2 connection".into(),
            )),
            Ok(_) => Ok(true),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Ok(false)
            }
            Err(e) => Err(Error::Io(e)),
        };
        self.stream.set_read_timeout(previous)?;
        ready
    }
}

pub struct Connection {
    reader: ConnectionReader,
    writer: ConnectionWriter,
    identity: ServerIdentity,
}

impl Connection {
    /// Connects and completes the Noise NX handshake as the initiator.
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
        Self::assemble(stream, encoder, decoder, encrypt, decrypt, verified)
    }

    /// Completes the Noise NX handshake as the responder on an accepted
    /// socket.
    ///
    /// `authority` is the keypair the certificate is signed with. The static
    /// key is generated per connection by `noise_sv2::Responder`, which is
    /// what NX means: the initiator learns only that the static key it was
    /// handed was endorsed by the authority. There is no client
    /// authentication, so this is transport security and not access control.
    pub fn accept(stream: TcpStream, authority: &Keypair, cert_validity: u32) -> Result<Self> {
        stream.set_nodelay(true)?;
        let mut encoder = NoiseEncoder::new();
        let mut partial = Partial {
            stream,
            decoder: NoiseDecoder::new(),
        };

        let mut first = [0u8; noise_sv2::ELLSWIFT_ENCODING_SIZE];
        partial.read_handshake(&mut first)?;

        let handshake = codec_sv2::Handshake::responder(Responder::new(*authority, cert_validity));
        let (message, transport) = handshake.step_1(first)?;
        partial.write_handshake(&mut encoder, message)?;

        let Partial { stream, decoder } = partial;
        let (encrypt, decrypt) = transport.split();
        // A responder authenticates itself to the initiator and learns nothing
        // about the initiator, so there is nothing for it to have verified.
        Self::assemble(stream, encoder, decoder, encrypt, decrypt, false)
    }

    fn assemble(
        stream: TcpStream,
        encoder: NoiseEncoder,
        decoder: NoiseDecoder,
        encrypt: TransportEncryptState,
        decrypt: TransportDecryptState,
        verified: bool,
    ) -> Result<Self> {
        // The two halves need independent handles so one can block on reads
        // while the other writes. They share the underlying socket, which is
        // what makes that safe: the kernel serializes each direction.
        let write_half = stream.try_clone()?;
        Ok(Self {
            reader: ConnectionReader {
                stream,
                decoder,
                decrypt: Some(decrypt),
            },
            writer: ConnectionWriter {
                stream: write_half,
                encoder,
                encrypt,
            },
            identity: ServerIdentity { verified },
        })
    }

    pub fn identity(&self) -> &ServerIdentity {
        &self.identity
    }

    pub fn peer_addr(&self) -> Result<SocketAddr> {
        Ok(self.reader.stream.peer_addr()?)
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.reader.set_read_timeout(timeout)
    }

    /// Splits into a reader and a writer behind a mutex.
    ///
    /// The mutex is on the writer because more than one thread sends on a
    /// Mining Protocol connection: the thread that received a template pushes
    /// jobs, and the thread reading from the worker answers its submissions.
    pub fn split(self) -> (ConnectionReader, Arc<Mutex<ConnectionWriter>>) {
        (self.reader, Arc::new(Mutex::new(self.writer)))
    }

    pub fn send<T: Serialize + GetSize>(
        &mut self,
        extension_type: u16,
        msg_type: u8,
        channel_msg: bool,
        message: T,
    ) -> Result<()> {
        self.writer
            .send(extension_type, msg_type, channel_msg, message)
    }

    pub fn send_raw(
        &mut self,
        extension_type: u16,
        msg_type: u8,
        channel_msg: bool,
        payload: &[u8],
    ) -> Result<()> {
        self.writer
            .send_raw(extension_type, msg_type, channel_msg, payload)
    }

    pub fn recv(&mut self) -> Result<Frame> {
        self.reader.recv()
    }

    pub fn recv_expect(&mut self, extension_type: u16, msg_type: u8) -> Result<Frame> {
        self.reader.recv_expect(extension_type, msg_type)
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

    /// Reads the handshake message the other role is waiting to send.
    ///
    /// The length is fixed by which role we are, and `into` carries it: 234
    /// bytes of message 2 for an initiator, 64 of message 1 for a responder.
    fn read_handshake(&mut self, into: &mut [u8]) -> Result<()> {
        loop {
            let decoded = if into.len() == INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE {
                self.decoder.next_handshake_frame::<InitiatorSent>()?
            } else {
                self.decoder.next_handshake_frame::<Responder>()?
            };
            match decoded {
                Decoded::Frame(message) => {
                    let payload = message.payload();
                    if payload.len() != into.len() {
                        return Err(Error::Payload(format!(
                            "handshake message is {} bytes, expected {}",
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
            Error::Protocol("the peer closed the Stratum v2 connection".into())
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
