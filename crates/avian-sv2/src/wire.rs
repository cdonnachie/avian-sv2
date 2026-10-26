//! Field-level serialization for the messages SRI does not define.
//!
//! SRI's binary codec covers the core and Template Distribution messages, but
//! not the Extensions Negotiation extension (0x0001) or Avian's (0x4001), so
//! those are encoded here. All integers are little-endian.

use crate::error::{Error, Result};

/// A cursor over a payload.
///
/// Every field is taken through here so that a short or over-long message
/// errors instead of quietly decoding as something else.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.data.len() {
            return Err(Error::Payload(format!(
                "payload is {} bytes short",
                self.pos + n - self.data.len()
            )));
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn uint(&mut self, size: usize) -> Result<u64> {
        let mut buf = [0u8; 8];
        buf[..size].copy_from_slice(self.take(size)?);
        Ok(u64::from_le_bytes(buf))
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.uint(1)? as u8)
    }

    pub fn u16(&mut self) -> Result<u16> {
        Ok(self.uint(2)? as u16)
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(self.uint(4)? as u32)
    }

    pub fn u64(&mut self) -> Result<u64> {
        self.uint(8)
    }

    /// A STR0_255: a one-byte length then that many UTF-8 bytes.
    pub fn text(&mut self) -> Result<String> {
        let len = self.u8()? as usize;
        let raw = self.take(len)?;
        String::from_utf8(raw.to_vec())
            .map_err(|_| Error::Payload("string field is not valid UTF-8".into()))
    }

    /// A SEQ0_64K of U16.
    pub fn seq_u16(&mut self) -> Result<Vec<u16>> {
        let count = self.u16()? as usize;
        (0..count).map(|_| self.u16()).collect()
    }

    /// A U256: thirty-two raw bytes, in uint256's internal order like
    /// everything else on this wire.
    pub fn u256(&mut self) -> Result<[u8; 32]> {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.take(32)?);
        Ok(out)
    }

    /// A BOOL. Anything but 0 and 1 is a malformed payload rather than
    /// something to coerce, because a peer that sends 2 has a bug worth
    /// hearing about.
    pub fn boolean(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(Error::Payload(format!(
                "a BOOL field carried {other}, which is neither 0 nor 1"
            ))),
        }
    }

    pub fn done(self) -> Result<()> {
        if self.pos != self.data.len() {
            return Err(Error::Payload(format!(
                "{} trailing bytes in payload",
                self.data.len() - self.pos
            )));
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct Writer(Vec<u8>);

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn raw(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.extend_from_slice(bytes);
        self
    }

    /// A B0_255: a one-byte length then the bytes.
    pub fn u256(&mut self, value: &[u8; 32]) -> &mut Self {
        self.0.extend_from_slice(value);
        self
    }

    pub fn boolean(&mut self, value: bool) -> &mut Self {
        self.0.push(u8::from(value));
        self
    }

    pub fn bytes_u8(&mut self, bytes: &[u8]) -> &mut Self {
        self.u8(bytes.len() as u8).raw(bytes)
    }

    /// A B0_64K: a two-byte length then the bytes.
    pub fn bytes_u16(&mut self, bytes: &[u8]) -> &mut Self {
        self.u16(bytes.len() as u16).raw(bytes)
    }

    /// Bitcoin's compact size. Used for transaction serialization, not for
    /// Stratum v2, which has no variable-length integer.
    pub fn varint(&mut self, value: u64) -> &mut Self {
        match value {
            0..=0xfc => self.u8(value as u8),
            0xfd..=0xffff => self.u8(0xfd).u16(value as u16),
            0x1_0000..=0xffff_ffff => self.u8(0xfe).u32(value as u32),
            _ => self.u8(0xff).u64(value),
        }
    }

    pub fn seq_u16(&mut self, items: &[u16]) -> &mut Self {
        self.u16(items.len() as u16);
        for item in items {
            self.u16(*item);
        }
        self
    }

    pub fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hex of the reversed bytes, which is how Bitcoin-family hashes are displayed.
pub fn hex_rev(bytes: &[u8]) -> String {
    bytes.iter().rev().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_rejects_a_short_payload() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert!(r.u32().is_err());
    }

    #[test]
    fn reader_rejects_trailing_bytes() {
        let mut r = Reader::new(&[1, 2, 3]);
        r.u16().unwrap();
        assert!(r.done().is_err());
    }

    #[test]
    fn integers_are_little_endian() {
        let mut w = Writer::new();
        let payload = w.u16(1).seq_u16(&[0x4001]).finish();
        assert_eq!(payload, vec![0x01, 0x00, 0x01, 0x00, 0x01, 0x40]);

        let mut r = Reader::new(&payload);
        assert_eq!(r.u16().unwrap(), 1);
        assert_eq!(r.seq_u16().unwrap(), vec![0x4001]);
        r.done().unwrap();
    }
}
