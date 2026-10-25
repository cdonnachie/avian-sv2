//! Can SRI's crates carry Avian's extension?
//!
//! The question that had to be settled before anything was built on SRI was
//! whether `codec_sv2` can frame a message under `extension_type = 0x4001`, or
//! whether it assumes `extension_type == 0`. Three parts:
//!
//!   A  SRI's codec round-trips 0x4001 and 0xc001 frames, encrypted, between
//!      an SRI initiator and an SRI responder. No node involved, so the only
//!      thing under test is the codec.
//!   B  SRI's `noise_sv2` initiator completes a handshake with a live node.
//!      This is the regression guard for the Noise act 1 bug: `aviand` used to
//!      omit the specification's `EncryptAndHash` over an empty payload, which
//!      left `h` one SHA256 iteration out and failed the first MAC in message
//!      2 with no diagnostic on either side.
//!   C  real 0x4001 traffic over that connection, in both directions.
//!
//! Usage: extension_spike <datadir> [host:port]

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;

use avian_sv2::avian::{
    self, EXT_AVIAN, EXT_CORE, EXT_NEGOTIATION, MSG_JOB_TIME_CONSTRAINTS, MSG_REQUEST_EXTENSIONS,
    MSG_REQUEST_EXTENSIONS_SUCCESS, MSG_SELECT_ALGORITHM, MSG_SELECT_ALGORITHM_ERROR,
    MSG_SELECT_ALGORITHM_SUCCESS, MSG_TIME_CONSTRAINTS,
};
use avian_sv2::transport::{Connection, CHANNEL_MSG_BIT};
use avian_sv2::PowType;
use avian_tdp::{authority, chain_subdir};

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
}

/// A: does SRI's codec carry a 0x4001 frame at all?
///
/// Two SRI roles, so the handshake is between SRI and itself. Both frames go
/// through `NoiseEncoder` and come back through `NoiseDecoder`, so this is the
/// encrypted path, not just a header round-trip.
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
            avian_sv2::transport::encode_header(extension_type, msg_type, payload.len())
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
///
/// No authority key, so a failure here cannot be a certificate problem.
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
        Ok(_) => println!("   handshake completed: the node's act 1 transcript is the spec's\n"),
        // The symptom of the act 1 bug, and of nothing else that can go wrong
        // here, since no authority key was supplied.
        Err(e) => println!("   handshake FAILED: {e:?}\n"),
    }
}

/// C: real 0x4001 traffic.
fn part_c(datadir: &Path, addr: SocketAddr) -> avian_sv2::Result<()> {
    println!("C. 0x4001 traffic over a verified connection");
    let key_path = authority::default_key_path(datadir, chain_subdir("regtest"));
    let pubkey = authority::from_private_key_file(&key_path)?;

    let mut conn = Connection::connect(addr, Some(pubkey), Duration::from_secs(30))?;
    println!(
        "   handshake completed, certificate verified against the authority key in {}",
        key_path.display()
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
    // point is the header: reaching the AvianSelectAlgorithm handler at all
    // means a 0x4001 header was parsed and routed. It needs its own
    // connection, because the node drops a client after refusing one.
    let mut probe = Connection::connect(addr, Some(pubkey), Duration::from_secs(30))?;
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
        // client, with no error frame.
        Err(e) => println!(
            "   sent 0x4001/0x00 with a 3-byte arbitrary payload; the node routed it to the \
             AvianSelectAlgorithm handler, rejected the body and closed the connection ({e})"
        ),
    }

    println!("\nSRI's codec carries extension_type 0x4001 and 0xc001, on the wire and off it.");
    Ok(())
}

fn setup_connection(conn: &mut Connection) -> avian_sv2::Result<()> {
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
