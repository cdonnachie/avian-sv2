//! The Stratum v1 messages a bridge needs, and nothing else.
//!
//! Stratum v1 was never specified so much as implemented, and what a pool
//! sends is whatever the pool it was copied from sent. This module takes the
//! seven shapes every pool in the field agrees on and refuses to guess at the
//! rest: a method this client does not handle comes back named, so it can be
//! logged, rather than silently dropped or silently misread.
//!
//! Everything here is parsing and rendering. Nothing is sent and nothing is
//! translated into a Stratum v2 job; that is the bridge's work. The one
//! piece of translation that does belong here is byte order, because it is a
//! property of the wire format rather than of the bridge, and it is the piece
//! that cannot be derived from anything: see [`Notify::prev_hash`].

use avian_sv2::error::{Error, Result};

use crate::json::{self, Value};

/// What `mining.subscribe` answers with, and what `mining.set_extranonce`
/// replaces: the pool's half of the extranonce and how many bytes the miner
/// may use. On the Stratum v2 side these are an extended channel's
/// `extranonce_prefix` and `extranonce_size`, under other names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    pub extranonce1: Vec<u8>,
    pub extranonce2_size: usize,
}

/// One `mining.notify`, decoded. Field for field it is an extended Stratum v2
/// job: `coinb1`/`coinb2` are a `CoinbaseSplit`'s prefix and suffix and
/// `merkle_branch` is its merkle path, which is why a bridge is cheap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notify {
    /// Opaque, and echoed back verbatim in `mining.submit`. Pools use hex,
    /// decimal and the occasional string; it is never interpreted.
    pub job_id: String,
    /// In this tree's order, which is `uint256`'s internal little-endian
    /// order: the header field, byte for byte.
    ///
    /// Not the order it arrived in. On the wire a `mining.notify` carries the
    /// previous hash as eight 32-bit words with the bytes of each word
    /// reversed, a quirk inherited from the first pool implementation and
    /// copied by every one since. Swapping the bytes within each word is its
    /// own inverse, so [`swap_words`] goes both ways and is applied once here.
    /// If this were wrong every share would fail against the pool at once,
    /// which is the one good property of a byte-order bug.
    pub prev_hash: [u8; 32],
    pub coinb1: Vec<u8>,
    pub coinb2: Vec<u8>,
    /// Each entry in the order it is folded, which is the same order a
    /// Stratum v2 `merkle_path` is in.
    pub merkle_branch: Vec<[u8; 32]>,
    pub version: u32,
    pub nbits: u32,
    pub ntime: u32,
    /// When true every earlier job is void and a share against one will be
    /// refused: a new tip. When false the pool refreshed the template on the
    /// same tip and earlier jobs still count. The same distinction as a
    /// Stratum v2 `SetNewPrevHash` against a `NewMiningJob`, which is what it
    /// becomes.
    pub clean_jobs: bool,
}

/// One line from the pool, sorted into what the client does with it.
#[derive(Debug, Clone, PartialEq)]
pub enum Incoming {
    /// The answer to a request this client sent, by the id it sent.
    Reply {
        id: u64,
        result: Value,
        /// Stratum v1 reports failure as `[code, message, data]`, or as a
        /// bare string from some pools, or as `null` for success. Flattened
        /// to text, because the only thing a bridge can do with it is pass
        /// it on to the miner.
        error: Option<String>,
    },
    Notify(Notify),
    SetDifficulty(f64),
    SetExtranonce(Subscription),
    /// `client.reconnect`. Honoured only when the host is the one already
    /// connected to, which is the bridge's decision rather than this layer's,
    /// because a pool that can redirect its miners anywhere is a pool that
    /// can be used to hijack them.
    Reconnect {
        host: String,
        port: u16,
    },
    /// A notification this client does not act on, by name, so a log can say
    /// what the pool wanted. `mining.ping` and `client.show_message` land
    /// here.
    Unhandled {
        method: String,
    },
}

/// Sorts one line into an [`Incoming`].
///
/// A line that is not an object, or is an object with neither a `method` nor
/// an `id`, is a protocol error rather than `Unhandled`: `Unhandled` is for a
/// well-formed notification this client chooses to ignore, not for a pool
/// that has stopped speaking Stratum.
pub fn parse_incoming(line: &str) -> Result<Incoming> {
    let value = json::parse(line)?;
    if value.get("method").is_none() && value.get("id").is_none() {
        return Err(Error::Protocol(
            "a line with neither a method nor an id is not Stratum".into(),
        ));
    }

    if let Some(method) = value.get("method").and_then(Value::as_str) {
        let empty = Vec::new();
        let params = value
            .get("params")
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        return match method {
            "mining.notify" => Ok(Incoming::Notify(parse_notify(params)?)),
            "mining.set_difficulty" => {
                let difficulty = params
                    .first()
                    .and_then(Value::as_f64)
                    .ok_or_else(|| Error::Payload("set_difficulty without a number".into()))?;
                Ok(Incoming::SetDifficulty(difficulty))
            }
            "mining.set_extranonce" => {
                let extranonce1 = params
                    .first()
                    .and_then(Value::as_str)
                    .ok_or_else(|| Error::Payload("set_extranonce without extranonce1".into()))
                    .and_then(unhex)?;
                let extranonce2_size = params
                    .get(1)
                    .and_then(Value::as_u64)
                    .ok_or_else(|| Error::Payload("set_extranonce without a size".into()))?;
                Ok(Incoming::SetExtranonce(Subscription {
                    extranonce1,
                    extranonce2_size: extranonce2_size as usize,
                }))
            }
            "client.reconnect" => {
                let host = params
                    .first()
                    .and_then(Value::as_str)
                    .ok_or_else(|| Error::Payload("reconnect without a host".into()))?
                    .to_string();
                let port = params
                    .get(1)
                    .and_then(Value::as_u64)
                    .filter(|port| *port <= u64::from(u16::MAX))
                    .ok_or_else(|| Error::Payload("reconnect without a usable port".into()))?;
                Ok(Incoming::Reconnect {
                    host,
                    port: port as u16,
                })
            }
            other => Ok(Incoming::Unhandled {
                method: other.to_string(),
            }),
        };
    }

    // No method, so an id: a reply. A pool answering with a null id is
    // answering nothing this client asked, and gets refused as such.
    let id = value
        .get("id")
        .and_then(Value::as_u64)
        .ok_or_else(|| Error::Protocol("a reply whose id is not a number".into()))?;
    let result = value.get("result").cloned().unwrap_or(Value::Null);
    let error = value.get("error").and_then(error_text);
    Ok(Incoming::Reply { id, result, error })
}

fn parse_notify(params: &[Value]) -> Result<Notify> {
    // Positional, and all nine are required. A pool that sends fewer has
    // changed the protocol, and guessing which one it dropped would mean
    // building a block out of the wrong fields.
    if params.len() < 9 {
        return Err(Error::Payload(format!(
            "mining.notify carries 9 parameters and this one has {}",
            params.len()
        )));
    }
    let text = |index: usize, name: &str| -> Result<&str> {
        params[index]
            .as_str()
            .ok_or_else(|| Error::Payload(format!("notify {name} is not a string")))
    };

    let merkle_branch = params[4]
        .as_array()
        .ok_or_else(|| Error::Payload("notify merkle_branch is not an array".into()))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .ok_or_else(|| Error::Payload("a merkle_branch entry is not a string".into()))
                .and_then(unhex32)
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(Notify {
        job_id: text(0, "job_id")?.to_string(),
        prev_hash: swap_words(unhex32(text(1, "prevhash")?)?),
        coinb1: unhex(text(2, "coinb1")?)?,
        coinb2: unhex(text(3, "coinb2")?)?,
        merkle_branch,
        version: u32_from_hex(text(5, "version")?)?,
        nbits: u32_from_hex(text(6, "nbits")?)?,
        ntime: u32_from_hex(text(7, "ntime")?)?,
        clean_jobs: params[8]
            .as_bool()
            .ok_or_else(|| Error::Payload("notify clean_jobs is not a bool".into()))?,
    })
}

/// The reply to `mining.subscribe`, which is
/// `[[[method, session], ...], extranonce1, extranonce2_size]`. The
/// subscription list in front is ignored: it names the notifications the
/// pool will send, and every pool sends the same two.
pub fn subscription_from_reply(result: &Value) -> Result<Subscription> {
    let parts = result.as_array().ok_or_else(|| {
        Error::Protocol("subscribe answered with something other than a list".into())
    })?;
    let extranonce1 = parts
        .get(1)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Protocol("subscribe reply has no extranonce1".into()))
        .and_then(unhex)?;
    let extranonce2_size = parts
        .get(2)
        .and_then(Value::as_u64)
        .ok_or_else(|| Error::Protocol("subscribe reply has no extranonce2_size".into()))?;
    // Zero would leave a miner no nonce space beyond the header's, and more
    // than the coinbase's scriptSig can hold is a pool that has lost count.
    if extranonce2_size == 0 || extranonce2_size > 32 {
        return Err(Error::Protocol(format!(
            "subscribe reply offers an extranonce2 of {extranonce2_size} bytes"
        )));
    }
    Ok(Subscription {
        extranonce1,
        extranonce2_size: extranonce2_size as usize,
    })
}

/// Flattens a Stratum v1 error to text. `null` is success and gives `None`.
fn error_text(error: &Value) -> Option<String> {
    match error {
        Value::Null => None,
        Value::String(text) => Some(text.clone()),
        Value::Array(parts) => {
            let code = parts.first().and_then(Value::as_u64);
            let message = parts.get(1).and_then(Value::as_str).unwrap_or("");
            Some(match code {
                Some(code) if !message.is_empty() => format!("{code}: {message}"),
                Some(code) => format!("error {code}"),
                None if !message.is_empty() => message.to_string(),
                None => error.to_json(),
            })
        }
        other => Some(other.to_json()),
    }
}

// --- requests -------------------------------------------------------------

fn request(id: u64, method: &str, params: Vec<Value>) -> String {
    let mut line = Value::Object(vec![
        ("id".into(), Value::Number(id as f64)),
        ("method".into(), Value::String(method.into())),
        ("params".into(), Value::Array(params)),
    ])
    .to_json();
    line.push('\n');
    line
}

/// `mining.subscribe`, naming this client. The name is the one thing a pool
/// operator sees of what connected, so it should say "bridge" rather than
/// pretend to be a miner.
pub fn subscribe(id: u64, agent: &str) -> String {
    request(id, "mining.subscribe", vec![Value::String(agent.into())])
}

/// `mining.authorize`. `user` is what the miner put in `user_identity`,
/// passed through untouched so the pool's accounting keys on exactly what the
/// miner typed; `password` is whatever the pool wants there, usually nothing.
pub fn authorize(id: u64, user: &str, password: &str) -> String {
    request(
        id,
        "mining.authorize",
        vec![Value::String(user.into()), Value::String(password.into())],
    )
}

/// `mining.submit`. `ntime` and `nonce` go as eight big-endian hex digits,
/// which is how every pool reads them.
pub fn submit(
    id: u64,
    worker: &str,
    job_id: &str,
    extranonce2: &[u8],
    ntime: u32,
    nonce: u32,
) -> String {
    request(
        id,
        "mining.submit",
        vec![
            Value::String(worker.into()),
            Value::String(job_id.into()),
            Value::String(hex(extranonce2)),
            Value::String(format!("{ntime:08x}")),
            Value::String(format!("{nonce:08x}")),
        ],
    )
}

// --- bytes ----------------------------------------------------------------

/// Reverses the bytes within each of the eight 32-bit words, which is the
/// difference between a `mining.notify` previous hash and a header's. Its own
/// inverse.
pub fn swap_words(mut hash: [u8; 32]) -> [u8; 32] {
    for word in hash.chunks_exact_mut(4) {
        word.reverse();
    }
    hash
}

pub fn hex(bytes: &[u8]) -> String {
    avian_sv2::wire::hex(bytes)
}

pub fn unhex(text: &str) -> Result<Vec<u8>> {
    if text.len() % 2 != 0 {
        return Err(Error::Payload(format!(
            "{} hex digits is an odd number",
            text.len()
        )));
    }
    (0..text.len())
        .step_by(2)
        .map(|at| {
            u8::from_str_radix(&text[at..at + 2], 16)
                .map_err(|_| Error::Payload(format!("{:?} is not hex", &text[at..at + 2])))
        })
        .collect()
}

pub fn unhex32(text: &str) -> Result<[u8; 32]> {
    let bytes = unhex(text)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        Error::Payload(format!("{} bytes where 32 were expected", bytes.len()))
    })
}

fn u32_from_hex(text: &str) -> Result<u32> {
    if text.len() != 8 {
        return Err(Error::Payload(format!("{text:?} is not eight hex digits")));
    }
    u32::from_str_radix(text, 16).map_err(|_| Error::Payload(format!("{text:?} is not hex")))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A notify as a real pool sends one, with a recognisable prevhash: the
    // words count up so the swap is visible by eye.
    const NOTIFY: &str = r#"{"id":null,"method":"mining.notify","params":[
        "1a2b",
        "0302010007060504" "0b0a09080f0e0d0c" "1312111017161514" "1b1a19181f1e1d1c",
        "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff",
        "ffffffff0100f2052a01000000",
        ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        "20000000", "1d00ffff", "6543210f", true]}"#;

    fn notify_line() -> String {
        // The hash is written in four pieces above for readability; JSON has
        // no string concatenation, so join them here.
        NOTIFY.replace("\" \"", "")
    }

    #[test]
    fn a_notify_decodes_to_a_job_in_this_trees_byte_order() {
        let incoming = parse_incoming(&notify_line()).expect("a notify should parse");
        let Incoming::Notify(notify) = incoming else {
            panic!("expected a notify, got {incoming:?}");
        };
        assert_eq!(notify.job_id, "1a2b");
        // The swap: wire `03020100 07060504 ...` becomes `00010203 04050607 ...`.
        let mut expected = [0u8; 32];
        for (i, byte) in expected.iter_mut().enumerate() {
            *byte = i as u8;
        }
        assert_eq!(
            notify.prev_hash, expected,
            "prevhash words were not swapped"
        );
        assert_eq!(notify.coinb1.len(), 41);
        assert_eq!(notify.coinb2, unhex("ffffffff0100f2052a01000000").unwrap());
        assert_eq!(notify.merkle_branch, vec![[0xaa; 32]]);
        assert_eq!(notify.version, 0x2000_0000);
        assert_eq!(notify.nbits, 0x1d00_ffff);
        assert_eq!(notify.ntime, 0x6543_210f);
        assert!(notify.clean_jobs);
    }

    #[test]
    fn swapping_words_is_its_own_inverse() {
        let mut hash = [0u8; 32];
        for (i, byte) in hash.iter_mut().enumerate() {
            *byte = (i * 7 + 3) as u8;
        }
        assert_eq!(swap_words(swap_words(hash)), hash);
        assert_ne!(swap_words(hash), hash, "the swap should do something");
    }

    #[test]
    fn a_subscribe_reply_becomes_a_subscription() {
        let reply = parse_incoming(
            r#"{"id":1,"result":[[["mining.set_difficulty","d"],["mining.notify","n"]],"deadbeef",4],"error":null}"#,
        )
        .expect("a reply should parse");
        let Incoming::Reply { id, result, error } = reply else {
            panic!("expected a reply, got {reply:?}");
        };
        assert_eq!(id, 1);
        assert_eq!(error, None, "null is success");
        let subscription = subscription_from_reply(&result).expect("a subscription");
        assert_eq!(subscription.extranonce1, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(subscription.extranonce2_size, 4);
    }

    #[test]
    fn an_error_array_is_flattened_to_text() {
        let reply = parse_incoming(r#"{"id":7,"result":null,"error":[21,"Job not found",null]}"#)
            .expect("an error reply should parse");
        let Incoming::Reply { error, .. } = reply else {
            panic!("expected a reply");
        };
        assert_eq!(error.as_deref(), Some("21: Job not found"));
    }

    #[test]
    fn the_other_notifications_are_sorted_by_name() {
        let difficulty =
            parse_incoming(r#"{"id":null,"method":"mining.set_difficulty","params":[512]}"#)
                .unwrap();
        assert_eq!(difficulty, Incoming::SetDifficulty(512.0));

        let extranonce =
            parse_incoming(r#"{"id":null,"method":"mining.set_extranonce","params":["0102",6]}"#)
                .unwrap();
        assert_eq!(
            extranonce,
            Incoming::SetExtranonce(Subscription {
                extranonce1: vec![1, 2],
                extranonce2_size: 6
            })
        );

        let reconnect = parse_incoming(
            r#"{"id":null,"method":"client.reconnect","params":["pool.example",3333]}"#,
        )
        .unwrap();
        assert_eq!(
            reconnect,
            Incoming::Reconnect {
                host: "pool.example".into(),
                port: 3333
            }
        );

        // Named rather than dropped, and not an error.
        let ping = parse_incoming(r#"{"id":null,"method":"mining.ping","params":[]}"#).unwrap();
        assert_eq!(
            ping,
            Incoming::Unhandled {
                method: "mining.ping".into()
            }
        );
    }

    #[test]
    fn a_submit_renders_the_way_pools_read_it() {
        let line = submit(
            9,
            "RAddr.rig1",
            "1a2b",
            &[0, 0, 0, 1],
            0x6543_210f,
            0xdead_beef,
        );
        assert_eq!(
            line,
            "{\"id\":9,\"method\":\"mining.submit\",\"params\":[\"RAddr.rig1\",\"1a2b\",\
             \"00000001\",\"6543210f\",\"deadbeef\"]}\n"
        );
        assert!(line.ends_with('\n'), "a Stratum line is newline-terminated");
    }

    #[test]
    fn a_worker_name_is_passed_through_untouched() {
        // The pool keys its accounting on this string, so it has to arrive as
        // typed, quotes and all.
        let line = authorize(2, "RAddr.rig\"1\"", "x");
        let value = json::parse(line.trim_end()).expect("the request is valid JSON");
        let params = value.get("params").and_then(Value::as_array).unwrap();
        assert_eq!(params[0].as_str(), Some("RAddr.rig\"1\""));
    }

    #[test]
    fn a_notify_missing_a_field_is_refused_rather_than_guessed_at() {
        let short = r#"{"id":null,"method":"mining.notify","params":["1","2","3"]}"#;
        assert!(parse_incoming(short).is_err());

        let bad_hash = notify_line().replace("0302010007060504", "zz02010007060504");
        assert!(parse_incoming(&bad_hash).is_err());
    }

    #[test]
    fn a_line_that_is_not_stratum_is_a_protocol_error_and_not_unhandled() {
        assert!(parse_incoming(r#"{"hello":"world"}"#).is_err());
        assert!(parse_incoming(r#"[1,2,3]"#).is_err());
    }

    #[test]
    fn an_unusable_extranonce2_size_is_refused() {
        for size in ["0", "33"] {
            let reply = json::parse(&format!(r#"[[],"00",{size}]"#)).unwrap();
            assert!(
                subscription_from_reply(&reply).is_err(),
                "extranonce2_size {size} should be refused"
            );
        }
    }
}
