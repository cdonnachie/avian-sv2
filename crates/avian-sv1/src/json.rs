//! Just enough JSON for Stratum v1.
//!
//! Hand written, for the reason the stats endpoint's encoder is hand written:
//! this tree's dependency list is the Stratum v2 reference codecs plus
//! `secp256k1` and `cc`, and a line-delimited protocol with seven message
//! shapes does not justify adding a general-purpose JSON library to a
//! workspace that otherwise has none.
//!
//! The parser is recursive descent with a depth limit. The far side is a pool
//! the operator chose, which is not the same as a pool this code should trust
//! to be well behaved: a bridge that can be put into unbounded recursion by
//! its upstream is a bridge that takes every miner down with it.

use std::fmt::Write as _;

use avian_sv2::error::{Error, Result};

/// Nesting deeper than this is refused rather than recursed into. Stratum v1's
/// deepest real message is `mining.subscribe`'s reply, at four.
const MAX_DEPTH: usize = 16;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// JSON has one number type. Stratum v1 uses it for small integers (an id,
    /// `extranonce2_size`) and for a difficulty that is frequently
    /// fractional, so both go through `f64` and the accessors below narrow.
    Number(f64),
    String(String),
    Array(Vec<Value>),
    /// Insertion-ordered pairs rather than a map: these objects have at most
    /// four keys, a linear scan beats hashing them, and round-tripping keeps
    /// the order the peer sent.
    Object(Vec<(String, Value)>),
}

impl Value {
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(text) => Some(text),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(flag) => Some(*flag),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Number(number) => Some(*number),
            _ => None,
        }
    }

    /// A number that is actually a non-negative integer, which is what every
    /// integer-shaped field in Stratum v1 is. A fractional or negative value
    /// is `None` rather than a silent truncation.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Number(number)
                if *number >= 0.0 && number.fract() == 0.0 && *number <= u64::MAX as f64 =>
            {
                Some(*number as u64)
            }
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The value for a key, or `None` for a missing key or a non-object.
    ///
    /// A missing key and a present `null` are deliberately different: Stratum
    /// v1 answers a successful call with `"error": null`, so "absent" and
    /// "explicitly nothing" have to be distinguishable.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(pairs) => pairs
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    pub fn to_json(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(true) => out.push_str("true"),
            Value::Bool(false) => out.push_str("false"),
            Value::Number(number) => {
                // An integral value goes out without a fractional part, so an
                // id reads as `1` and not `1.0`. A pool that reflects the id
                // back as a string comparison would otherwise never match.
                if number.fract() == 0.0 && number.abs() < 1e15 {
                    let _ = write!(out, "{}", *number as i64);
                } else {
                    let _ = write!(out, "{number}");
                }
            }
            Value::String(text) => write_string(text, out),
            Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Value::Object(pairs) => {
                out.push('{');
                for (i, (name, value)) in pairs.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_string(name, out);
                    out.push(':');
                    value.write(out);
                }
                out.push('}');
            }
        }
    }
}

/// Escapes what JSON requires escaped and nothing else.
///
/// Unlike the stats endpoint's encoder this keeps non-ASCII rather than
/// dropping it: a worker name travels through a bridge to an operator's
/// database, so mangling it here would mangle their accounting. UTF-8 is
/// valid JSON as it stands, so it needs no escape.
fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Parses one complete JSON value, and refuses anything after it.
pub fn parse(text: &str) -> Result<Value> {
    let mut parser = Parser {
        bytes: text.as_bytes(),
        at: 0,
    };
    parser.skip_whitespace();
    let value = parser.value(0)?;
    parser.skip_whitespace();
    if parser.at != parser.bytes.len() {
        return Err(Error::Payload(format!(
            "trailing bytes after the JSON value, at offset {}",
            parser.at
        )));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn fail<T>(&self, what: &str) -> Result<T> {
        Err(Error::Payload(format!("{what} at offset {}", self.at)))
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<()> {
        if self.peek() == Some(byte) {
            self.at += 1;
            Ok(())
        } else {
            self.fail(&format!("expected {:?}", byte as char))
        }
    }

    fn literal(&mut self, word: &str) -> Result<()> {
        if self.bytes[self.at..].starts_with(word.as_bytes()) {
            self.at += word.len();
            Ok(())
        } else {
            self.fail(&format!("expected {word}"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value> {
        if depth > MAX_DEPTH {
            return self.fail(&format!("nested deeper than {MAX_DEPTH}"));
        }
        match self.peek() {
            Some(b'n') => {
                self.literal("null")?;
                Ok(Value::Null)
            }
            Some(b't') => {
                self.literal("true")?;
                Ok(Value::Bool(true))
            }
            Some(b'f') => {
                self.literal("false")?;
                Ok(Value::Bool(false))
            }
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b'[') => self.array(depth),
            Some(b'{') => self.object(depth),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => self.fail("not the start of a JSON value"),
            None => self.fail("the input ended where a value was expected"),
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_whitespace();
            items.push(self.value(depth + 1)?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Value::Array(items));
                }
                _ => return self.fail("expected ',' or ']' in an array"),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value> {
        self.expect(b'{')?;
        let mut pairs = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Value::Object(pairs));
        }
        loop {
            self.skip_whitespace();
            let name = self.string()?;
            self.skip_whitespace();
            self.expect(b':')?;
            self.skip_whitespace();
            let value = self.value(depth + 1)?;
            pairs.push((name, value));
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Value::Object(pairs));
                }
                _ => return self.fail("expected ',' or '}' in an object"),
            }
        }
    }

    fn number(&mut self) -> Result<Value> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        while matches!(
            self.peek(),
            Some(b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
        ) {
            self.at += 1;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.at])
            .map_err(|_| Error::Payload("a number with non-UTF-8 bytes in it".into()))?;
        match text.parse::<f64>() {
            // Infinity and NaN cannot be written back as JSON, so a number
            // that overflows is refused here rather than at encode time.
            Ok(number) if number.is_finite() => Ok(Value::Number(number)),
            _ => Err(Error::Payload(format!("{text:?} is not a JSON number"))),
        }
    }

    fn string(&mut self) -> Result<String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return self.fail("the input ended inside a string"),
                Some(b'"') => {
                    self.at += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.at += 1;
                    let escape = match self.peek() {
                        Some(byte) => byte,
                        None => return self.fail("the input ended inside an escape"),
                    };
                    self.at += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape()?),
                        other => {
                            return self.fail(&format!("unknown escape \\{}", other as char));
                        }
                    }
                }
                Some(_) => {
                    // Copy whole UTF-8 characters rather than bytes, so a
                    // multi-byte character survives intact.
                    let rest = std::str::from_utf8(&self.bytes[self.at..])
                        .map_err(|_| Error::Payload("a string with invalid UTF-8 in it".into()))?;
                    let ch = rest.chars().next().expect("rest is non-empty");
                    out.push(ch);
                    self.at += ch.len_utf8();
                }
            }
        }
    }

    /// `\uXXXX`, including the surrogate pair a character above the basic
    /// plane is written as. Nothing in Stratum v1 needs this, but a worker
    /// name arrives from whatever a miner's configuration file held, and
    /// refusing the whole message over an emoji would drop that miner's work.
    fn unicode_escape(&mut self) -> Result<char> {
        let first = self.hex4()?;
        if !(0xD800..0xDC00).contains(&first) {
            return char::from_u32(u32::from(first))
                .ok_or_else(|| Error::Payload(format!("\\u{first:04x} is not a character")));
        }
        // A high surrogate has to be followed by `\uDC00`-`\uDFFF`.
        self.expect(b'\\')?;
        self.expect(b'u')?;
        let second = self.hex4()?;
        if !(0xDC00..0xE000).contains(&second) {
            return self.fail("a high surrogate not followed by a low surrogate");
        }
        let combined =
            0x1_0000 + ((u32::from(first) - 0xD800) << 10) + (u32::from(second) - 0xDC00);
        char::from_u32(combined)
            .ok_or_else(|| Error::Payload(format!("\\u{first:04x}\\u{second:04x} is not a char")))
    }

    fn hex4(&mut self) -> Result<u16> {
        let end = self.at + 4;
        if end > self.bytes.len() {
            return self.fail("a \\u escape cut short");
        }
        let text = std::str::from_utf8(&self.bytes[self.at..end])
            .map_err(|_| Error::Payload("a \\u escape with non-UTF-8 bytes".into()))?;
        let value = u16::from_str_radix(text, 16)
            .map_err(|_| Error::Payload(format!("{text:?} is not four hex digits")))?;
        self.at = end;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_subscribe_reply_parses_to_its_three_parts() {
        // The shape a real pool answers mining.subscribe with.
        let line = r#"{"id":1,"result":[[["mining.set_difficulty","x"],
                        ["mining.notify","x"]],"a1b2c3d4",4],"error":null}"#;
        let value = parse(line).expect("a subscribe reply should parse");
        assert_eq!(value.get("id").and_then(Value::as_u64), Some(1));
        let result = value
            .get("result")
            .and_then(Value::as_array)
            .expect("result");
        assert_eq!(result[1].as_str(), Some("a1b2c3d4"));
        assert_eq!(result[2].as_u64(), Some(4));
        // Present and null, which is not the same as absent.
        assert!(value.get("error").expect("error is present").is_null());
        assert!(value.get("nonesuch").is_none());
    }

    #[test]
    fn a_fractional_difficulty_survives_as_a_float() {
        let value = parse(r#"{"method":"mining.set_difficulty","params":[0.015625]}"#)
            .expect("set_difficulty should parse");
        let params = value
            .get("params")
            .and_then(Value::as_array)
            .expect("params");
        assert_eq!(params[0].as_f64(), Some(0.015625));
        // Not an integer, so the integer accessor declines rather than
        // truncating a difficulty to zero.
        assert_eq!(params[0].as_u64(), None);
    }

    #[test]
    fn an_integer_is_written_without_a_fractional_part() {
        // A pool matching its own id by string would never match `1.0`.
        let value = Value::Object(vec![("id".into(), Value::Number(1.0))]);
        assert_eq!(value.to_json(), r#"{"id":1}"#);
    }

    #[test]
    fn a_worker_name_round_trips_through_both_halves() {
        // Non-ASCII is kept rather than dropped: it is someone's account name
        // in someone's database.
        let name = "rig\"one\\two\tthree ünï 😀";
        let encoded = Value::String(name.into()).to_json();
        let decoded = parse(&encoded).expect("the encoder's own output should parse");
        assert_eq!(decoded.as_str(), Some(name));
    }

    #[test]
    fn a_surrogate_pair_decodes_to_one_character() {
        let value = parse(r#""😀""#).expect("a surrogate pair should parse");
        assert_eq!(value.as_str(), Some("😀"));
    }

    #[test]
    fn a_lone_high_surrogate_is_refused() {
        assert!(parse(r#""\ud83d""#).is_err());
    }

    #[test]
    fn runaway_nesting_is_refused_rather_than_recursed_into() {
        let deep = format!("{}{}", "[".repeat(256), "]".repeat(256));
        let error = parse(&deep).expect_err("256 levels should be refused");
        assert!(
            error.to_string().contains("nested deeper"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn trailing_bytes_are_refused() {
        // Two JSON values on one line is a framing bug worth seeing.
        assert!(parse(r#"{"id":1} {"id":2}"#).is_err());
    }

    #[test]
    fn the_obvious_malformed_cases_are_errors_and_not_panics() {
        for bad in [
            "",
            "{",
            "}",
            "[",
            "[,]",
            r#"{"a"}"#,
            r#"{"a":}"#,
            r#""unterminated"#,
            "01x2",
            r#"{"a":1,}"#,
            "tru",
            r#""\q""#,
            "1e999",
        ] {
            assert!(parse(bad).is_err(), "{bad:?} should not parse");
        }
    }
}
