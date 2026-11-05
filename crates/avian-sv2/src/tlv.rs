//! Type-Length-Value fields, as Stratum v2 section 3.4.3 defines them.
//!
//! A TLV field is how an extension adds data to a message someone else
//! defined, without changing that message's layout or its frame's
//! `extension_type`. The fields ride at the end of the payload, after
//! everything the base message specifies, so a peer that knows nothing about
//! them reads the message exactly as it always did and stops.
//!
//! # A note on byte order
//!
//! Section 3.4.3's worked example encodes the type triple and the length
//! big-endian: it shows extension `0x0002`, field `0x01`, length 10 as
//! `00 02 01 00 0A`. That contradicts section 3.1, which says that multibyte
//! data types are **always** little-endian and lists `U16` as such, and 3.4.3
//! itself describes these fields as `U16` and `U8`.
//!
//! This implements little-endian, because 3.1 is the normative statement
//! about what `U16` means and 3.4.3's example is a worked illustration that
//! disagrees with it. [`SPEC_EXAMPLE_FIELD`] pins the example's own field so
//! the discrepancy stays visible rather than becoming folklore.
//!
//! Nothing in the reference implementation settles it: the SRI crates do not
//! implement TLV at all, so there is no second opinion to defer to. It is
//! worth an issue upstream.

use crate::error::{Error, Result};
use crate::wire::{Reader, Writer};

/// The fixed cost of a field: two bytes of `extension_type`, one of
/// `field_type`, two of length.
pub const HEADER_LEN: usize = 5;

/// One TLV field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    /// The extension that defined this field. Not the frame's
    /// `extension_type`, which stays with whoever defined the base message.
    pub extension_type: u16,
    /// Which of that extension's fields this is.
    pub field_type: u8,
    /// Empty when the length was zero, which 3.4.3 allows.
    pub value: Vec<u8>,
}

impl Field {
    pub fn new(extension_type: u16, field_type: u8, value: impl Into<Vec<u8>>) -> Self {
        Self {
            extension_type,
            field_type,
            value: value.into(),
        }
    }

    /// The byte it encodes to when the value is a single `U8`, which is the
    /// shape most selector fields take.
    pub fn u8(extension_type: u16, field_type: u8, value: u8) -> Self {
        Self::new(extension_type, field_type, vec![value])
    }

    /// Reads this field's value as a single `U8`, refusing any other length.
    ///
    /// A field that is the wrong size is a disagreement about what the
    /// extension says, not something to read the first byte of and hope.
    pub fn as_u8(&self) -> Result<u8> {
        match self.value.as_slice() {
            [byte] => Ok(*byte),
            other => Err(Error::Protocol(format!(
                "TLV field 0x{:04x}:0x{:02x} should carry one byte and carries {}",
                self.extension_type,
                self.field_type,
                other.len()
            ))),
        }
    }
}

/// The field from section 3.4.3's example, in this module's byte order.
///
/// Extension `0x0002`, field `0x01`, value `"Worker_001"`. The spec renders
/// the same field as `00 02 01 00 0A ...`; see the module documentation for
/// why this differs, and change both together if that is ever resolved the
/// other way.
pub const SPEC_EXAMPLE_BYTES: &[u8] = &[
    0x02, 0x00, // extension_type 0x0002, little-endian
    0x01, // field_type
    0x0a, 0x00, // length 10, little-endian
    0x57, 0x6f, 0x72, 0x6b, 0x65, 0x72, 0x5f, 0x30, 0x30, 0x31, // "Worker_001"
];

/// Serializes `fields` and appends them to `payload`.
///
/// The caller passes the message's own bytes, already serialized, because
/// 3.4.3 requires TLV fields to come after everything the base message
/// defines. Fields are sorted by `extension_type` here rather than refused,
/// since that ordering is this encoder's job to get right and nothing is lost
/// by doing it. Order **within** one extension is preserved exactly as given,
/// because only the extension knows what its own order should be.
pub fn append(payload: &mut Vec<u8>, fields: &[Field]) -> Result<()> {
    let mut ordered: Vec<&Field> = fields.iter().collect();
    // Stable, so fields of one extension keep the caller's order.
    ordered.sort_by_key(|field| field.extension_type);

    for field in ordered {
        if field.value.len() > u16::MAX as usize {
            return Err(Error::Protocol(format!(
                "TLV field 0x{:04x}:0x{:02x} is {} bytes and the length is a U16",
                field.extension_type,
                field.field_type,
                field.value.len()
            )));
        }
        let mut w = Writer::new();
        w.u16(field.extension_type)
            .u8(field.field_type)
            .u16(field.value.len() as u16)
            .raw(&field.value);
        payload.extend_from_slice(&w.finish());
    }
    Ok(())
}

/// Parses a whole TLV region, which is whatever a message's own fields left.
///
/// Unknown `extension_type`s are returned rather than refused. Skipping them
/// is the caller's business, because only the caller knows what it
/// negotiated, and that tolerance is the entire point of the encoding: a peer
/// must be able to read past a field meant for somebody else.
pub fn parse(bytes: &[u8]) -> Result<Vec<Field>> {
    let mut r = Reader::new(bytes);
    let mut fields: Vec<Field> = Vec::new();
    let mut remaining = bytes.len();

    while remaining > 0 {
        if remaining < HEADER_LEN {
            return Err(Error::Protocol(format!(
                "a TLV field needs {HEADER_LEN} bytes of header and {remaining} are left"
            )));
        }
        let extension_type = r.u16()?;
        let field_type = r.u8()?;
        let length = r.u16()? as usize;
        remaining -= HEADER_LEN;

        if length > remaining {
            return Err(Error::Protocol(format!(
                "TLV field 0x{extension_type:04x}:0x{field_type:02x} claims {length} bytes \
                 and {remaining} are left"
            )));
        }
        let value = r.take(length)?.to_vec();
        remaining -= length;

        // 3.4.3 requires the fields be ordered by extension_type. Enforced
        // rather than tolerated, because a receiver is allowed to stop
        // looking once it is past the extension it wants, and one that does
        // would silently miss a field sent out of order.
        if let Some(previous) = fields.last() {
            if extension_type < previous.extension_type {
                return Err(Error::Protocol(format!(
                    "TLV fields must be ordered by extension_type and 0x{extension_type:04x} \
                     follows 0x{:04x}",
                    previous.extension_type
                )));
            }
        }
        fields.push(Field {
            extension_type,
            field_type,
            value,
        });
    }
    Ok(fields)
}

/// The first field an extension contributed, if it sent one.
pub fn find(fields: &[Field], extension_type: u16, field_type: u8) -> Option<&Field> {
    fields
        .iter()
        .find(|field| field.extension_type == extension_type && field.field_type == field_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_field_round_trips() {
        let fields = vec![Field::new(0x4001, 0x01, b"hello".to_vec())];
        let mut payload = Vec::new();
        append(&mut payload, &fields).unwrap();
        assert_eq!(payload.len(), HEADER_LEN + 5);
        assert_eq!(parse(&payload).unwrap(), fields);
    }

    #[test]
    fn the_spec_example_encodes_to_its_own_bytes() {
        // Section 3.4.3's example field, which is the only worked example
        // there is. The bytes differ from the ones printed beside it, in the
        // two multibyte fields and only there; see the module docs.
        let field = Field::new(0x0002, 0x01, b"Worker_001".to_vec());
        let mut payload = Vec::new();
        append(&mut payload, std::slice::from_ref(&field)).unwrap();
        assert_eq!(payload, SPEC_EXAMPLE_BYTES);
        assert_eq!(parse(SPEC_EXAMPLE_BYTES).unwrap(), vec![field]);
    }

    #[test]
    fn a_zero_length_field_has_no_value() {
        let fields = vec![Field::new(0x4001, 0x07, Vec::new())];
        let mut payload = Vec::new();
        append(&mut payload, &fields).unwrap();
        assert_eq!(payload, vec![0x01, 0x40, 0x07, 0x00, 0x00]);
        assert_eq!(parse(&payload).unwrap(), fields);
    }

    #[test]
    fn nothing_parses_to_nothing() {
        // A message with no TLV region is the ordinary case, not an error.
        assert!(parse(&[]).unwrap().is_empty());
    }

    #[test]
    fn fields_are_written_in_extension_order() {
        let mut payload = Vec::new();
        append(
            &mut payload,
            &[
                Field::u8(0x4002, 0x01, 9),
                Field::u8(0x0002, 0x01, 7),
                Field::u8(0x4001, 0x01, 8),
            ],
        )
        .unwrap();
        let order: Vec<u16> = parse(&payload)
            .unwrap()
            .iter()
            .map(|field| field.extension_type)
            .collect();
        assert_eq!(order, vec![0x0002, 0x4001, 0x4002]);
    }

    #[test]
    fn one_extensions_fields_keep_the_order_they_were_given() {
        // Only the extension knows what its own order means, so the sort must
        // be stable or an encoder here silently reorders someone else's
        // fields into something their spec does not describe.
        let mut payload = Vec::new();
        append(
            &mut payload,
            &[
                Field::u8(0x4001, 0x03, 3),
                Field::u8(0x4001, 0x01, 1),
                Field::u8(0x4001, 0x02, 2),
            ],
        )
        .unwrap();
        let order: Vec<u8> = parse(&payload)
            .unwrap()
            .iter()
            .map(|field| field.field_type)
            .collect();
        assert_eq!(order, vec![0x03, 0x01, 0x02]);
    }

    #[test]
    fn an_unknown_extension_is_returned_and_not_refused() {
        // The caller skips what it did not negotiate. Refusing here would
        // defeat the encoding: a proxy carrying a field for somebody else
        // must be able to read past it.
        let mut payload = Vec::new();
        append(&mut payload, &[Field::u8(0x7fff, 0x01, 1)]).unwrap();
        let fields = parse(&payload).unwrap();
        assert_eq!(fields.len(), 1);
        assert!(find(&fields, 0x4001, 0x01).is_none());
        assert!(find(&fields, 0x7fff, 0x01).is_some());
    }

    #[test]
    fn a_truncated_header_is_refused() {
        let mut payload = Vec::new();
        append(&mut payload, &[Field::u8(0x4001, 0x01, 1)]).unwrap();
        payload.pop();
        assert!(parse(&payload).is_err());
        assert!(parse(&payload[..3]).is_err());
    }

    #[test]
    fn a_length_past_the_end_is_refused() {
        // The one that matters: a length field is attacker-controlled, and
        // believing it is how a parser reads off the end of a buffer.
        let payload = vec![0x01, 0x40, 0x01, 0xff, 0xff, 0x00];
        let err = parse(&payload).unwrap_err().to_string();
        assert!(err.contains("65535"), "{err}");
    }

    #[test]
    fn fields_out_of_extension_order_are_refused() {
        let payload = vec![
            0x02, 0x40, 0x01, 0x01, 0x00, 0x09, // 0x4002 first
            0x01, 0x40, 0x01, 0x01, 0x00, 0x08, // then 0x4001
        ];
        let err = parse(&payload).unwrap_err().to_string();
        assert!(err.contains("ordered by extension_type"), "{err}");
    }

    #[test]
    fn a_selector_field_is_one_byte_and_says_so_when_it_is_not() {
        assert_eq!(Field::u8(0x4001, 0x01, 42).as_u8().unwrap(), 42);
        let wrong = Field::new(0x4001, 0x01, vec![1, 2]);
        assert!(wrong.as_u8().unwrap_err().to_string().contains("one byte"));
    }
}
