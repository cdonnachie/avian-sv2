//! A read-only snapshot of what the pool is doing, and a small HTTP server
//! that hands it out as JSON.
//!
//! Deliberately not a web page. The pool emits JSON and nothing else; a
//! separate service renders it. That boundary is what keeps the protocol code
//! free of presentation, and it means the stats port can stay unpublished
//! while only the renderer faces anyone.
//!
//! Deliberately not a web framework either. This answers `GET /stats` with a
//! few hundred bytes of JSON. Pulling in an async runtime for that would add
//! more dependency surface to a reference implementation than the feature is
//! worth, so it is a thread per request over `std::net`, with a hand-written
//! encoder. The whole HTTP surface is: `GET`, two paths, no bodies read, no
//! state changed. Anything else gets a short refusal.
//!
//! What it will not tell you:
//!
//! - **Full payout addresses.** A prefix is enough for someone to recognise
//!   their own channel and not enough to publish where everyone is paid.
//! - **Blocks the node accepted, at the moment it accepts them.**
//!   `SubmitSolution` has no reply, so the pool is never told. It can still
//!   prove acceptance after the fact, because the next `SetNewPrevHash`
//!   carries the new tip and the pool knows the hash it submitted: that is
//!   `blocks_confirmed`. `blocks_submitted` is the weaker number, and both
//!   are reported because the gap between them is real.

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use avian_sv2::avian::PowType;
use avian_sv2::error::{Error, Result};

use crate::server::AlgoContext;

/// How much of a payout address the endpoint will show.
const ADDRESS_PREFIX: usize = 8;

/// Everything the endpoint reports, gathered in one pass.
pub struct Snapshot {
    pub uptime: Duration,
    /// The pool's authority public key, base58, as a miner would paste it.
    ///
    /// Reported rather than left to the operator to copy out of a log,
    /// because a miner that does not pin this gets an encrypted connection
    /// that authenticates nobody. Taken from the running key, so it cannot
    /// drift from the one in use: publishing a stale authority key is worse
    /// than publishing none, since a miner would pin to something that either
    /// fails or belongs to whoever holds it now.
    pub authority_public_key: String,
    /// There is no persistence, so every count below starts at this process's
    /// start. The endpoint says so rather than leaving it to be assumed.
    pub algorithms: Vec<AlgoSnapshot>,
}

pub struct AlgoSnapshot {
    pub pow: PowType,
    pub upstream_connected: bool,
    pub blocks_submitted: u32,
    /// Blocks whose hash was later seen as the chain tip. The only count the
    /// pool can prove, and now it can: SubmitSolution has no reply, but the
    /// next SetNewPrevHash carries the new tip and a match is proof the block
    /// connected.
    pub blocks_confirmed: u32,
    pub prev_hash: Option<[u8; 32]>,
    pub channels: Vec<ChannelSnapshot>,
}

pub struct ChannelSnapshot {
    pub id: u32,
    pub extended: bool,
    pub worker: String,
    pub payout_prefix: String,
    pub accepted: u32,
    pub rejected: u32,
    pub blocks_submitted: u32,
    pub current_job_id: Option<u32>,
    pub connected_for: Duration,
    /// Hashes per second, inferred from accepted shares and the share target.
    pub estimated_hashrate: f64,
    pub share_target_hex: String,
}

/// A hash is at or under a target with probability (target + 1) / 2^256, so
/// each accepted share stands for 2^256 / (target + 1) hashes on average.
///
/// Derived from the target rather than from a difficulty-1 constant on
/// purpose: a "difficulty" needs a per-algorithm reference target to mean
/// anything, and getting that wrong would put a plausible but wrong number on
/// the page. This needs no constant and is the same arithmetic for both
/// algorithms.
///
/// `target` is uint256's internal little-endian order, as everywhere else.
pub fn hashes_per_share(target: &[u8; 32]) -> f64 {
    let mut value = 0.0f64;
    for byte in target.iter().rev() {
        value = value * 256.0 + f64::from(*byte);
    }
    // 2^256, which is comfortably inside f64's range.
    let span = 2.0f64.powi(256);
    if value <= 0.0 {
        return span;
    }
    span / (value + 1.0)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// A block hash is printed reversed, so a snapshot shows it the way an
/// explorer and `getblockhash` would rather than in internal order.
fn hex_reversed(bytes: &[u8; 32]) -> String {
    let mut flipped = *bytes;
    flipped.reverse();
    hex(&flipped)
}

impl Snapshot {
    pub fn gather(
        started_at: Instant,
        algos: &[Arc<AlgoContext>],
        authority_public_key: String,
    ) -> Self {
        let now = Instant::now();
        let algorithms = algos
            .iter()
            .map(|algo| {
                let channels = algo
                    .channels()
                    .iter()
                    .map(|channel| {
                        let (rejected, _) = channel.refusals();
                        let accepted = channel.accepted();
                        let connected_for = now.saturating_duration_since(channel.opened_at);
                        let seconds = connected_for.as_secs_f64();
                        let estimated_hashrate = if seconds > 0.0 {
                            f64::from(accepted) * hashes_per_share(&channel.share_target) / seconds
                        } else {
                            0.0
                        };
                        let payout_prefix = channel
                            .payout_address
                            .chars()
                            .take(ADDRESS_PREFIX)
                            .collect();
                        ChannelSnapshot {
                            id: channel.id,
                            extended: channel.kind.is_extended(),
                            worker: channel.worker.clone(),
                            payout_prefix,
                            accepted,
                            rejected,
                            blocks_submitted: channel.blocks(),
                            current_job_id: channel.current_job_id(),
                            connected_for,
                            estimated_hashrate,
                            share_target_hex: hex(&channel.share_target),
                        }
                    })
                    .collect();
                AlgoSnapshot {
                    pow: algo.pow,
                    upstream_connected: algo.submitter().is_connected(),
                    blocks_submitted: algo.blocks(),
                    blocks_confirmed: algo.confirmed(),
                    prev_hash: algo.prev_hash(),
                    channels,
                }
            })
            .collect();
        Snapshot {
            uptime: now.saturating_duration_since(started_at),
            authority_public_key,
            algorithms,
        }
    }

    /// Hand-rolled, because the only strings that reach it are a worker label
    /// and a payout prefix and both are escaped below. Everything else is a
    /// number or a bool.
    pub fn to_json(&self) -> String {
        let mut out = String::with_capacity(1024);
        out.push_str("{\n");
        out.push_str(&format!(
            "  \"uptime_seconds\": {},\n",
            self.uptime.as_secs()
        ));
        // Said rather than implied: a restart resets every number here.
        out.push_str(
            "  \"counters_since\": \"pool start, there is no persistence\",\n  \
             \"vardiff\": false,\n",
        );
        // base58 has no quote, backslash or control character in its
        // alphabet, so this needs no escaping the way a worker label does.
        out.push_str(&format!(
            "  \"authority_public_key\": \"{}\",\n",
            self.authority_public_key
        ));
        out.push_str("  \"miners\": ");
        let miners: usize = self.algorithms.iter().map(|algo| algo.channels.len()).sum();
        out.push_str(&format!("{miners},\n"));
        out.push_str("  \"algorithms\": [\n");
        for (i, algo) in self.algorithms.iter().enumerate() {
            out.push_str("    {\n");
            out.push_str(&format!("      \"algorithm\": \"{}\",\n", algo.pow));
            out.push_str(&format!(
                "      \"upstream_connected\": {},\n",
                algo.upstream_connected
            ));
            // Not "blocks found": SubmitSolution has no reply, so the pool
            // cannot know what the node did with it.
            out.push_str(&format!(
                "      \"blocks_submitted\": {},\n",
                algo.blocks_submitted
            ));
            // Provable, unlike blocks_submitted: this hash was seen as the tip.
            out.push_str(&format!(
                "      \"blocks_confirmed\": {},\n",
                algo.blocks_confirmed
            ));
            match &algo.prev_hash {
                Some(hash) => out.push_str(&format!(
                    "      \"mining_on\": \"{}\",\n",
                    hex_reversed(hash)
                )),
                None => out.push_str("      \"mining_on\": null,\n"),
            }
            out.push_str("      \"channels\": [\n");
            for (j, channel) in algo.channels.iter().enumerate() {
                out.push_str("        {\n");
                out.push_str(&format!("          \"id\": {},\n", channel.id));
                out.push_str(&format!("          \"extended\": {},\n", channel.extended));
                out.push_str(&format!(
                    "          \"worker\": \"{}\",\n",
                    escape(&channel.worker)
                ));
                out.push_str(&format!(
                    "          \"payout_prefix\": \"{}\",\n",
                    escape(&channel.payout_prefix)
                ));
                out.push_str(&format!("          \"accepted\": {},\n", channel.accepted));
                out.push_str(&format!("          \"rejected\": {},\n", channel.rejected));
                out.push_str(&format!(
                    "          \"blocks_submitted\": {},\n",
                    channel.blocks_submitted
                ));
                match channel.current_job_id {
                    Some(id) => out.push_str(&format!("          \"current_job_id\": {id},\n")),
                    None => out.push_str("          \"current_job_id\": null,\n"),
                }
                out.push_str(&format!(
                    "          \"connected_seconds\": {},\n",
                    channel.connected_for.as_secs()
                ));
                out.push_str(&format!(
                    "          \"estimated_hashrate\": {:.1},\n",
                    channel.estimated_hashrate
                ));
                out.push_str(&format!(
                    "          \"share_target\": \"{}\"\n",
                    channel.share_target_hex
                ));
                out.push_str("        }");
                out.push_str(if j + 1 == algo.channels.len() {
                    "\n"
                } else {
                    ",\n"
                });
            }
            out.push_str("      ]\n    }");
            out.push_str(if i + 1 == self.algorithms.len() {
                "\n"
            } else {
                ",\n"
            });
        }
        out.push_str("  ]\n}\n");
        out
    }
}

/// A worker label comes from a miner, so it is not trusted to be clean JSON.
/// Control characters go out as escapes and the rest of ASCII goes through;
/// anything else is dropped rather than guessed at.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c if c.is_ascii() => out.push(c),
            _ => {}
        }
    }
    out
}

pub struct StatsHandle {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl StatsHandle {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for StatsHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Unblock the accept so the thread notices.
        let _ = TcpStream::connect(self.addr);
    }
}

/// Serves the snapshot on `bind` until the handle is dropped.
///
/// `source` is called per request rather than cached, because a stats page
/// that lags the pool is worse than one that costs a mutex.
pub fn serve<F>(bind: SocketAddr, source: F) -> Result<StatsHandle>
where
    F: Fn() -> Snapshot + Send + Sync + 'static,
{
    let listener = TcpListener::bind(bind).map_err(Error::Io)?;
    let addr = listener.local_addr().map_err(Error::Io)?;
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let source = Arc::new(source);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if thread_stop.load(Ordering::SeqCst) {
                return;
            }
            let Ok(stream) = stream else { continue };
            let source = source.clone();
            // A thread per request. The expected load is one renderer polling
            // every few seconds.
            std::thread::spawn(move || {
                let _ = handle(stream, source.as_ref());
            });
        }
    });
    Ok(StatsHandle { addr, stop })
}

fn handle<F>(mut stream: TcpStream, source: &F) -> std::io::Result<()>
where
    F: Fn() -> Snapshot,
{
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request = String::new();
    if reader.read_line(&mut request)? == 0 {
        return Ok(());
    }
    // The request line is all that is needed. Headers are drained so the
    // client sees a clean response rather than a reset, and a body is never
    // read: nothing here accepts input.
    let mut header = String::new();
    loop {
        header.clear();
        if reader.read_line(&mut header)? == 0 || header.trim().is_empty() {
            break;
        }
        if header.len() > 8192 {
            break;
        }
    }

    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    if method != "GET" {
        // Read-only means read-only, and says so.
        return respond(
            &mut stream,
            "405 Method Not Allowed",
            "text/plain",
            "GET only\n",
        );
    }
    match path {
        "/" | "/stats" | "/stats.json" => {
            let body = source().to_json();
            respond(&mut stream, "200 OK", "application/json", &body)
        }
        "/healthz" => respond(&mut stream, "200 OK", "text/plain", "ok\n"),
        _ => respond(&mut stream, "404 Not Found", "text/plain", "not found\n"),
    }
}

fn respond(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    // no-store because the numbers change constantly and a cached stats page
    // is a misleading one.
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_share_at_the_easiest_target_is_worth_one_hash() {
        // An all-ones target is met by every hash, so a share stands for one.
        let target = [0xff; 32];
        let per = hashes_per_share(&target);
        assert!(
            (per - 1.0).abs() < 0.001,
            "expected about one hash per share, got {per}"
        );
    }

    #[test]
    fn halving_the_target_doubles_the_work_a_share_represents() {
        let mut easy = [0u8; 32];
        easy[31] = 0x80;
        let mut hard = [0u8; 32];
        hard[31] = 0x40;
        let ratio = hashes_per_share(&hard) / hashes_per_share(&easy);
        assert!(
            (ratio - 2.0).abs() < 0.001,
            "halving the target should double the hashes per share, got {ratio}"
        );
    }

    #[test]
    fn a_zero_target_does_not_divide_by_zero() {
        // Not reachable from a real job, but a stats endpoint that panics
        // takes the pool's thread with it.
        assert!(hashes_per_share(&[0u8; 32]).is_finite());
    }

    #[test]
    fn a_worker_label_cannot_break_the_json() {
        let nasty = "rig\"1\\\n\u{1}\u{263a}";
        let escaped = escape(nasty);
        assert!(!escaped.contains('\n'), "a raw newline survived: {escaped}");
        assert!(escaped.contains("\\\""), "the quote was not escaped");
        assert!(escaped.contains("\\\\"), "the backslash was not escaped");
        assert!(
            escaped.contains("\\u0001"),
            "the control byte was not escaped"
        );
        assert!(!escaped.contains('\u{263a}'), "a non-ASCII char survived");
    }

    #[test]
    fn an_empty_pool_still_renders_valid_json() {
        let snapshot = Snapshot {
            uptime: Duration::from_secs(42),
            authority_public_key: "9cZsf3kvbayTC4M2bamzCoHkmcSneX68fb7Yc3JEfwtEsk2cXDA".into(),
            algorithms: vec![],
        };
        let json = snapshot.to_json();
        assert!(json.contains("\"uptime_seconds\": 42"));
        assert!(json.contains("\"miners\": 0"));
        assert!(json.contains("\"algorithms\": [\n  ]"), "{json}");
        assert!(json.contains("\"vardiff\": false"));
    }
}
