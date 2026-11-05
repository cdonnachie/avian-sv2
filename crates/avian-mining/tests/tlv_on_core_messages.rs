//! The two assumptions a TLV field on a core message rests on.
//!
//! Section 3.4.3 says an extension may append TLV fields to the end of a
//! message somebody else defined, and that a peer which does not know them
//! reads the message as it always did. Both halves of that are claims about
//! the codec, not about the specification, and neither is written down
//! anywhere in `binary_sv2`:
//!
//! 1. decoding a message ignores whatever follows its own fields, and
//! 2. there is a way to find out where its own fields ended.
//!
//! Without the first, appending a field breaks every existing peer. Without
//! the second, a field can be written and never found. They are tested here
//! against the real `mining_sv2` messages rather than assumed, because the
//! per-channel algorithm design is built on top of both.

use avian_sv2::tlv::{self, Field};
use binary_sv2::GetSize;
use mining_sv2::{OpenExtendedMiningChannel, OpenStandardMiningChannel};

static MAX_TARGET: [u8; 32] = [0xff; 32];

fn standard_open() -> OpenStandardMiningChannel<'static> {
    OpenStandardMiningChannel {
        request_id: 1u32,
        user_identity: b"worker".as_slice().try_into().unwrap(),
        nominal_hash_rate: 1000.0,
        max_target: MAX_TARGET.as_slice().try_into().unwrap(),
    }
}

#[test]
fn a_trailing_tlv_region_does_not_stop_a_message_decoding() {
    // The compatibility claim: a peer built before the field existed reads
    // the message exactly as it did before, and never looks past it.
    let mut bytes = binary_sv2::to_bytes(standard_open()).expect("encode");
    let base_len = bytes.len();
    tlv::append(&mut bytes, &[Field::u8(0x4001, 0x01, 2)]).expect("append");
    assert_eq!(bytes.len(), base_len + tlv::HEADER_LEN + 1);

    let decoded: OpenStandardMiningChannel =
        binary_sv2::from_bytes(&mut bytes[..]).expect("a trailing TLV region must be ignored");
    assert_eq!(decoded.nominal_hash_rate, 1000.0);
    assert_eq!(decoded.user_identity.as_ref(), b"worker");
}

#[test]
fn get_size_finds_where_the_message_ends_and_the_fields_begin() {
    // The other half: the decoder will not say how much it consumed, so the
    // boundary comes from asking the decoded message how long it is. If that
    // ever disagreed with what was written, a field would be looked for at
    // the wrong offset and read as garbage rather than as missing, which is
    // the worse of the two failures.
    let mut bytes = binary_sv2::to_bytes(standard_open()).expect("encode");
    let base_len = bytes.len();

    let sent = vec![
        Field::u8(0x4001, 0x01, 2),
        Field::new(0x4002, 0x01, b"x".to_vec()),
    ];
    tlv::append(&mut bytes, &sent).expect("append");

    // Scoped, because the decoded message borrows the buffer it came from
    // and the offset is all that is needed afterwards.
    let size = {
        let decoded: OpenStandardMiningChannel =
            binary_sv2::from_bytes(&mut bytes[..]).expect("decode");
        decoded.get_size()
    };
    assert_eq!(
        size, base_len,
        "get_size must agree with what to_bytes wrote, or the TLV region is cut in the wrong place"
    );

    let fields = tlv::parse(&bytes[size..]).expect("parse");
    assert_eq!(fields, sent);
    assert_eq!(
        tlv::find(&fields, 0x4001, 0x01).unwrap().as_u8().unwrap(),
        2
    );
}

#[test]
fn the_same_holds_for_an_extended_channel_open() {
    // Extended opens carry a field the standard one does not, so get_size
    // has something to get wrong here that it does not there.
    let open = OpenExtendedMiningChannel {
        request_id: 7,
        user_identity: b"someone.with.a.longer.name".as_slice().try_into().unwrap(),
        nominal_hash_rate: 12345.0,
        max_target: MAX_TARGET.as_slice().try_into().unwrap(),
        min_extranonce_size: 8,
    };
    let mut bytes = binary_sv2::to_bytes(open).expect("encode");
    let base_len = bytes.len();
    tlv::append(&mut bytes, &[Field::u8(0x4001, 0x01, 1)]).expect("append");

    let size = {
        let decoded: OpenExtendedMiningChannel =
            binary_sv2::from_bytes(&mut bytes[..]).expect("decode");
        assert_eq!(decoded.min_extranonce_size, 8);
        decoded.get_size()
    };
    assert_eq!(size, base_len);

    let fields = tlv::parse(&bytes[size..]).expect("parse");
    assert_eq!(
        tlv::find(&fields, 0x4001, 0x01).unwrap().as_u8().unwrap(),
        1
    );
}

#[test]
fn a_message_with_no_tlv_region_parses_to_no_fields() {
    // The ordinary case, and the one every peer sends today: nothing after
    // the message, which must read as "no fields" rather than as an error.
    let mut bytes = binary_sv2::to_bytes(standard_open()).expect("encode");
    let size = {
        let decoded: OpenStandardMiningChannel =
            binary_sv2::from_bytes(&mut bytes[..]).expect("decode");
        decoded.get_size()
    };
    assert!(tlv::parse(&bytes[size..]).unwrap().is_empty());
}
