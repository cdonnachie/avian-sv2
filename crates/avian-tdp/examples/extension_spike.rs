//! Can SRI's crates carry Avian's extension, and can they talk to aviand?
//!
//! The question that had to be settled before anything was built on SRI was
//! whether `codec_sv2` can frame a message under `extension_type = 0x4001`, or
//! whether it assumes `extension_type == 0`. Running it turned up a second,
//! larger answer. Five parts:
//!
//!   A  SRI's codec round-trips 0x4001 and 0xc001 frames, encrypted, between
//!      an SRI initiator and an SRI responder. Answers the original question.
//!   B  SRI's `noise_sv2` initiator against the live node. Fails.
//!   C  the same handshake with aviand's reading of act 1. Succeeds, and then
//!      sends and receives real 0x4001 frames.
//!   D  the specification's reading against the live node. Fails exactly as B
//!      does, which is what pins the cause to that one MixHash.
//!
//! Usage: extension_spike <datadir> [host:port]

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;

use avian_tdp::avian::{
    self, EXT_AVIAN, EXT_CORE, EXT_NEGOTIATION, MSG_JOB_TIME_CONSTRAINTS, MSG_REQUEST_EXTENSIONS,
    MSG_REQUEST_EXTENSIONS_SUCCESS, MSG_SELECT_ALGORITHM, MSG_SELECT_ALGORITHM_ERROR,
    MSG_SELECT_ALGORITHM_SUCCESS, MSG_TIME_CONSTRAINTS,
};
use avian_tdp::noise::Variant;
use avian_tdp::transport::{Connection, CHANNEL_MSG_BIT};
use avian_tdp::{authority, chain_subdir, PowType};

fn main() {
    let mut args = std::env::args().skip(1);
    let datadir = PathBuf::from(
        args.next()
            .expect("usage: extension_spike <datadir> [host:port]"),
    );
    let addr: SocketAddr = args
        .next()
        .unwrap_or_else(|| "127.0.0.1:18447".to_string())
        .to_socket_addrs()
        .expect("bad address")
        .next()
        .expect("no address");

    part_a();
    part_b(addr);
    part_c(&datadir, addr).expect("part C failed");
    part_d(addr);
}

/// A: does SRI's codec carry a 0x4001 frame at all?
///
/// Two SRI roles, so the handshake is between SRI and itself and the only
/// thing under test is the codec. Both frames go through `NoiseEncoder` and
/// come back through `NoiseDecoder`, so this is the encrypted path, not just
/// a header round-trip.
fn part_a() {
    use codec_sv2::{Decrypted, Handshake, NoiseDecoder, NoiseEncoder, SerializedFrame};
    use noise_sv2::{Initiator, Responder};
    use secp256k1::{Keypair, Secp256k1};

    println!("A. SRI's codec with extension_type 0x4001 and 0xc001");

    let secp = Secp256k1::new();
    let authority = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
    let (xonly, _) = authority.x_only_public_key();

    let initiator = Handshake::initiator(Initiator::new(Some(xonly)));
    let responder = Handshake::responder(Responder::new(authority, 3600));
    let (msg1, initiator) = initiator.step_0().unwrap();
    let (msg2, responder_transport) = responder
        .step_1(msg1.payload().try_into().unwrap())
        .unwrap();
    let (mut encrypt, _) = initiator
        .step_2(msg2.payload().try_into().unwrap())
        .unwrap()
        .split();
    // The responder decrypts what the initiator encrypts, so the two halves
    // come from opposite ends of the handshake.
    let (_, decrypt) = responder_transport.split();

    let mut encoder = NoiseEncoder::new();
    let mut decoder = NoiseDecoder::new();
    let mut decrypt = Some(decrypt);

    for (extension_type, msg_type, payload) in [
        (EXT_AVIAN, MSG_SELECT_ALGORITHM, vec![0x01u8]),
        (
            EXT_AVIAN | CHANNEL_MSG_BIT,
            MSG_JOB_TIME_CONSTRAINTS,
            avian::encode_job_time_constraints(&avian::JobTimeConstraints {
                channel_id: 7,
                job_id: 9,
                ntime_min: 1_700_000_000,
                ntime_max: 1_700_000_127,
            }),
        ),
    ] {
        let mut bytes =
            avian_tdp::transport::encode_header(extension_type, msg_type, payload.len())
                .unwrap()
                .to_vec();
        bytes.extend_from_slice(&payload);
        let frame = SerializedFrame::from_bytes(bytes).unwrap();
        let wire = encoder.encode_transport(frame, &mut encrypt).unwrap();

        // Hand the ciphertext straight to the decoder.
        let wire: Vec<u8> = AsRef::<[u8]>::as_ref(&wire).to_vec();
        let mut at = 0;
        let got = loop {
            match decoder
                .next_transport_frame(decrypt.take().unwrap())
                .unwrap()
            {
                Decrypted::Frame(frame, state) => {
                    decrypt = Some(state);
                    break frame;
                }
                Decrypted::Incomplete(_, state) => {
                    decrypt = Some(state);
                    let window = decoder.writable();
                    let take = window.len();
                    window.copy_from_slice(&wire[at..at + take]);
                    at += take;
                }
            }
        };
        let header = got.header();
        println!(
            "   sent 0x{:04x}/0x{:02x}, decoded ext 0x{:04x} (without channel bit 0x{:04x}, \
             channel_msg {}) msg 0x{:02x}, {} byte payload",
            extension_type,
            msg_type,
            header.ext_type(),
            header.ext_type_without_channel_msg(),
            header.channel_msg(),
            header.msg_type(),
            header.payload_length()
        );
        assert_eq!(header.ext_type(), extension_type);
        assert_eq!(header.msg_type(), msg_type);
        assert_eq!(header.payload_length(), payload.len());
    }
    println!("   codec_sv2 carries a custom extension_type unchanged, encrypted path included.\n");
}

/// B: SRI's handshake against the live node.
fn part_b(addr: SocketAddr) {
    use codec_sv2::{Decoded, Handshake, NoiseDecoder, NoiseEncoder};
    use noise_sv2::{Initiator, INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE};
    use std::io::{Read, Write};

    println!("B. SRI's noise_sv2 initiator against aviand at {addr}");
    let mut stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(10)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    let mut encoder = NoiseEncoder::new();
    let mut decoder = NoiseDecoder::new();
    // No authority key: the point is that this fails before any certificate
    // check, so trust on first use removes that as an explanation.
    let handshake = Handshake::initiator(Initiator::without_pk().unwrap());
    let (msg1, handshake) = handshake.step_0().unwrap();
    stream
        .write_all(encoder.encode_handshake(msg1).as_ref())
        .unwrap();

    let mut reply = [0u8; INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE];
    loop {
        match decoder
            .next_handshake_frame::<codec_sv2::InitiatorSent>()
            .unwrap()
        {
            Decoded::Frame(message) => {
                reply.copy_from_slice(message.payload());
                break;
            }
            Decoded::Incomplete(_) => {
                let window = decoder.writable();
                if !window.is_empty() {
                    stream.read_exact(window).unwrap();
                }
            }
        }
    }
    println!(
        "   the node answered with all {} bytes of message 2",
        reply.len()
    );
    match handshake.step_2(reply) {
        Ok(_) => println!("   handshake completed"),
        Err(e) => println!("   handshake FAILED: {e:?}"),
    }
    println!();
}

/// C: aviand's reading of act 1, then real 0x4001 traffic.
fn part_c(datadir: &Path, addr: SocketAddr) -> avian_tdp::Result<()> {
    println!("C. the same handshake with aviand's reading of act 1");
    let key_path = authority::default_key_path(datadir, chain_subdir("regtest"));
    let pubkey = authority::from_private_key_file(&key_path)?;

    let mut conn = Connection::connect_with_variant(
        addr,
        Some(pubkey),
        Duration::from_secs(30),
        Variant::Avian,
    )?;
    let id = conn.identity();
    println!(
        "   handshake completed, certificate verified against the authority key in {}",
        key_path.display()
    );
    println!(
        "   server static key {}, certificate version {} valid {}..{}",
        avian_tdp::wire::hex(&id.static_key),
        id.certificate.version,
        id.certificate.valid_from,
        id.certificate.not_valid_after
    );

    setup_connection(&mut conn)?;

    // A frame under extension 0x0001.
    conn.send_raw(
        EXT_NEGOTIATION,
        MSG_REQUEST_EXTENSIONS,
        false,
        &avian::encode_request_extensions(1, &[EXT_AVIAN]),
    )?;
    let frame = conn.recv_expect(EXT_NEGOTIATION, MSG_REQUEST_EXTENSIONS_SUCCESS)?;
    println!(
        "   sent 0x0001/0x00, got RequestExtensions.Success extensions {:#06x?}",
        avian::decode_request_extensions_success(&frame.payload)?.extensions
    );

    // A frame under extension 0x4001.
    conn.send_raw(
        EXT_AVIAN,
        MSG_SELECT_ALGORITHM,
        false,
        &avian::encode_select_algorithm(PowType::X16rt),
    )?;
    let frame = conn.recv_expect(EXT_AVIAN, MSG_SELECT_ALGORITHM_SUCCESS)?;
    let success = avian::decode_select_algorithm_success(&frame.payload)?;
    println!(
        "   sent 0x4001/0x00, got AvianSelectAlgorithm.Success pow_type {} \
         version_rolling_mask 0x{:08x}",
        success.pow_type, success.version_rolling_mask
    );

    // An unsolicited frame under 0x4001.
    conn.send(
        EXT_CORE,
        avian_tdp::tdp::MESSAGE_TYPE_COINBASE_OUTPUT_CONSTRAINTS,
        false,
        template_distribution_sv2::CoinbaseOutputConstraints {
            coinbase_output_max_additional_size: 1000,
            coinbase_output_max_additional_sigops: 10,
        },
    )?;
    println!("   reading until an unsolicited 0x4001 frame arrives");
    loop {
        let frame = conn.recv()?;
        println!("     {}", frame.describe());
        if frame.is(EXT_AVIAN, MSG_TIME_CONSTRAINTS) {
            println!("     {}", avian::decode_time_constraints(&frame.payload)?);
            break;
        }
    }

    // A frame under 0x4001 carrying a payload the node has no use for. The
    // point is the header: a second AvianSelectAlgorithm is refused because
    // the algorithm is immutable once bound, so the refusal proves the node
    // parsed a 0x4001 header and reached the body. It needs its own
    // connection, because the node drops a client after refusing one.
    let mut probe = Connection::connect_with_variant(
        addr,
        Some(pubkey),
        Duration::from_secs(30),
        Variant::Avian,
    )?;
    setup_connection(&mut probe)?;
    probe.send_raw(
        EXT_NEGOTIATION,
        MSG_REQUEST_EXTENSIONS,
        false,
        &avian::encode_request_extensions(1, &[EXT_AVIAN]),
    )?;
    probe.recv_expect(EXT_NEGOTIATION, MSG_REQUEST_EXTENSIONS_SUCCESS)?;
    probe.send_raw(EXT_AVIAN, MSG_SELECT_ALGORITHM, false, &[0xff, 0xff, 0xff])?;
    match probe.recv() {
        Ok(frame) if frame.is(EXT_AVIAN, MSG_SELECT_ALGORITHM_ERROR) => println!(
            "   sent 0x4001/0x00 with a 3-byte arbitrary payload, got \
             AvianSelectAlgorithm.Error \"{}\"",
            avian::decode_select_algorithm_error(&frame.payload)?
        ),
        Ok(frame) => println!("   unexpected {}", frame.describe()),
        // What actually happens: the node logs "sent a malformed
        // AvianSelectAlgorithm: trailing bytes after message" and drops the
        // client. Still the evidence wanted, since reaching that handler at
        // all means the 0x4001 header was parsed and routed.
        Err(e) => println!(
            "   sent 0x4001/0x00 with a 3-byte arbitrary payload; the node routed it to the \
             AvianSelectAlgorithm handler, rejected the body and closed the connection ({e}). \
             Its log says \"sent a malformed AvianSelectAlgorithm: trailing bytes after message\"."
        ),
    }
    println!();
    Ok(())
}

/// D: the specification's reading, against the live node.
fn part_d(addr: SocketAddr) {
    println!("D. the specification's reading of act 1 against aviand");
    match Connection::connect_with_variant(addr, None, Duration::from_secs(10), Variant::Sv2Spec) {
        Ok(_) => println!("   handshake completed"),
        Err(e) => println!("   handshake FAILED: {e}"),
    }
    println!("\n0x4001 is not the problem: SRI's codec carries it. aviand's handshake act 1 is.");
}

fn setup_connection(conn: &mut Connection) -> avian_tdp::Result<()> {
    let host = b"127.0.0.1";
    let vendor = b"avian-sv2-spike";
    let empty: &[u8] = b"";
    conn.send(
        EXT_CORE,
        common_messages_sv2::MESSAGE_TYPE_SETUP_CONNECTION,
        false,
        common_messages_sv2::SetupConnection {
            protocol: common_messages_sv2::Protocol::TemplateDistributionProtocol,
            min_version: 2,
            max_version: 2,
            flags: 0,
            endpoint_host: host.as_slice().try_into()?,
            endpoint_port: 0,
            vendor: vendor.as_slice().try_into()?,
            hardware_version: empty.try_into()?,
            firmware: empty.try_into()?,
            device_id: empty.try_into()?,
        },
    )?;
    conn.recv_expect(
        EXT_CORE,
        common_messages_sv2::MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
    )?;
    Ok(())
}
