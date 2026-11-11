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
//! - **What the node made of a submitted block, as it decides.** The node
//!   does answer a `SubmitSolution`, through Avian's extension, but it
//!   answers the thread holding the upstream session and says only that
//!   validation took the block. Becoming the tip is the later and stronger
//!   fact, and is proved after it happens, because the next `SetNewPrevHash`
//!   carries the new tip and the pool knows the hash it submitted: that is
//!   `blocks_confirmed`. `blocks_submitted` is the weaker number, and both
//!   are reported because the gap between them is real.
//! - **Which of the gap lost a race.** The hashes in the gap are listed as
//!   `unconfirmed`, and the pool stops there: a block that lost a race, one
//!   whose tip announcement is still on its way, and one the node refused
//!   all look the same from here, the refusal being logged and not kept.
//!   A service beside the node can finish the job with `getblock` on
//!   each hash: `confirmations` of -1 is a block that lost its race, one or
//!   more is a block on the chain, and error -5 is a hash the node is not
//!   holding, which is one that never reached it or one it refused. That
//!   turns submitted minus confirmed into a resolved number without the pool
//!   holding anything more, or writing anything at all.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use avian_sv2::avian::PowType;
use avian_sv2::error::{Error, Result};

use crate::server::AlgoContext;

/// How much of a payout address the endpoint will show.
const ADDRESS_PREFIX: usize = 8;

/// How many accepted shares an estimated hashrate rests on before this
/// endpoint is willing to call it settled.
///
/// Share arrivals are Poisson, so a rate inferred from `n` of them carries a
/// relative standard error of 1/sqrt(n): twenty-five shares is twenty
/// percent, a hundred is ten. Twenty-five is the point where the number stops
/// moving enough to be read as a measurement when it is an estimate, and at
/// the cadence the pool aims for it is minutes rather than an hour.
///
/// This is not vardiff convergence, which is what the same idea means in
/// SRI's monitoring API. There is no vardiff here, and `vardiff` in the
/// output says so; this is only about how much the estimate is built on.
const SETTLED_SHARES: u32 = 25;

/// Whether an estimate built on this many accepted shares is worth reading as
/// a measurement. See `SETTLED_SHARES`.
fn estimate_is_stable(accepted: u32) -> bool {
    accepted >= SETTLED_SHARES
}

/// The operator's side of the coinbase, as configured.
///
/// Published so the page that renders the endpoint can say what the pool
/// charges, and can show a miner how to donate only when an offer would be
/// paid rather than logged. Both numbers come from the configuration the
/// coinbase is built from, which is the point: a second copy in the
/// renderer's own environment would be free to disagree with the one in use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OperatorFee {
    /// Hundredths of a percent taken from every block; zero when nothing is.
    pub basis_points: u32,
    /// Whether there is an address to pay to. With a zero fee this is the
    /// donations-only setup, where nothing is taken and an offer is paid.
    /// Without one an offer is logged and the miner keeps the lot, so a page
    /// that invites offers when this is false invites something the pool
    /// cannot honour.
    pub has_address: bool,
}

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
    /// What the operator takes, and whether a donation goes anywhere.
    pub operator_fee: OperatorFee,
    /// The tag this pool stamps into every coinbase it builds.
    ///
    /// Published for the reason given against the authority key above, and it
    /// is the same reason: taken from the configuration the coinbase is built
    /// from, so it cannot drift from the one in use. Nothing is given away by
    /// saying it, because it is written into every block this pool finds on a
    /// public chain and anyone reading that chain already has it.
    ///
    /// What it buys is that a service walking the chain for this pool's
    /// blocks can be told the string instead of being configured with its own
    /// copy. A second copy is free to disagree with this one, and when it
    /// does the walk matches nothing and the only symptom is a pool that
    /// appears never to have found a block.
    pub coinbase_tag: String,
    /// There is no persistence, so every count below starts at this process's
    /// start. The endpoint says so rather than leaving it to be assumed.
    pub algorithms: Vec<AlgoSnapshot>,
}

pub struct AlgoSnapshot {
    pub pow: PowType,
    pub upstream_connected: bool,
    pub blocks_submitted: u32,
    /// Blocks whose hash was later seen as the chain tip. The only count the
    /// pool can prove: the node's reply to a SubmitSolution says validation
    /// took the block, while the next SetNewPrevHash carries the new tip, and
    /// a match with it is proof the block connected.
    pub blocks_confirmed: u32,
    /// Submitted and not yet seen as the tip, oldest first. Bounded by the
    /// pool to the last sixteen, so this is a worklist for whatever resolves
    /// them against the node, not a history.
    pub unconfirmed: Vec<[u8; 32]>,
    /// Blocks this algorithm made lately with the worker that made each,
    /// oldest first, whatever became of them. Not a second copy of the two
    /// counts above and not a substitute for `unconfirmed`: those say how
    /// many and which are still open, and this says whose.
    pub found: Vec<FoundSnapshot>,
    pub prev_hash: Option<[u8; 32]>,
    /// The network target in force, which is the scale a channel's best share
    /// is read against.
    pub network_target: Option<[u8; 32]>,
    pub channels: Vec<ChannelSnapshot>,
}

/// One block, with the only two facts about it that the chain cannot
/// supply. Everything else a reader wants, the height, the depth, the
/// timestamp, the algorithm, is in the block itself.
pub struct FoundSnapshot {
    pub hash: [u8; 32],
    pub worker: String,
    /// The same prefix rule as a channel's, from the same constant, because
    /// it is the same address seen from a different direction and two
    /// answers of different lengths would only invite the question of which
    /// one is the real address. On a channel paying a descriptor this is the
    /// extended key's prefix, the thing that stays the same across blocks.
    pub payout_prefix: String,
    /// The address this block's coinbase actually pays, to the same prefix
    /// rule. The same as `payout_prefix` for a channel paying an address;
    /// a different, fresh one for every block from a descriptor.
    pub paid_prefix: String,
}

pub struct ChannelSnapshot {
    pub id: u32,
    pub extended: bool,
    pub worker: String,
    /// What identifies the miner: the address, or on a channel that pays a
    /// descriptor the extended key, cut to the same prefix.
    pub payout_prefix: String,
    /// True when the channel pays a fresh address per block. Then
    /// `payout_next` is the one its next block would pay, in full, since it
    /// is a one-use address that reveals nothing about any other, and
    /// `payout_index` its position under the descriptor. Both empty on a
    /// channel paying an address.
    pub payout_derived: bool,
    pub payout_next: String,
    pub payout_index: u32,
    /// What the worker said it is running, from `SetupConnection`. Empty
    /// when it said nothing, which is every miner built before the pool
    /// started asking and is not the same as an unknown version.
    ///
    /// A claim and not a finding. See `server::PeerIdentity`.
    pub vendor: String,
    pub firmware: String,
    pub accepted: u32,
    /// Submissions the pool counted against the channel: wrong, or too many.
    pub rejected: u32,
    /// Submissions against a job the channel did not hold. Refused, but not
    /// counted against the channel: a miner submitting against the only job
    /// it has done nothing wrong, and the pool reissues work instead. Shown
    /// separately so a miner that was a job behind can see that, rather than
    /// a rejected count of zero beside a refusal it watched happen.
    pub desync: u32,
    /// What the worker offered with a `donate/` prefix, in basis points;
    /// zero when it offered nothing.
    pub donation_bp: u32,
    /// Whether that offer goes anywhere. False when there is no fee script
    /// to pay it to, which the pool logs at open and the page should show:
    /// "offered 2.00%, nowhere to put it" is not "donating 2.00%".
    pub donation_paid: bool,
    pub blocks_submitted: u32,
    pub current_job_id: Option<u32>,
    pub connected_for: Duration,
    /// Hashes per second, inferred from accepted shares and the share target.
    pub estimated_hashrate: f64,
    /// Whether `estimated_hashrate` rests on enough shares to be read as
    /// more than an opening guess. See `SETTLED_SHARES`.
    pub estimate_stable: bool,
    /// The share cadence this channel's target was sized for, which is what
    /// the observed rate should be compared against.
    pub expected_shares_per_minute: f64,
    pub share_target_hex: String,
    /// The lowest hash this channel has produced, in internal order.
    ///
    /// The closest this worker has come to a block, which on a solo pool is
    /// the number a miner is actually asking about. Reported as a hash and
    /// not as a difficulty for the reason `hashes_per_share` gives: a
    /// difficulty needs a reference target to mean anything, and a wrong one
    /// is worse here than none.
    pub best_share: Option<[u8; 32]>,
    /// Every refusal this channel has been sent, by code.
    pub refusals: BTreeMap<&'static str, u32>,
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
        operator_fee: OperatorFee,
        coinbase_tag: String,
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
                        let share_target = channel.share_target();
                        let connected_for = now.saturating_duration_since(channel.opened_at);
                        let seconds = connected_for.as_secs_f64();
                        let estimated_hashrate = if seconds > 0.0 {
                            f64::from(accepted) * hashes_per_share(&share_target) / seconds
                        } else {
                            0.0
                        };
                        let payout_prefix =
                            channel.payout_key().chars().take(ADDRESS_PREFIX).collect();
                        let next = channel.next_payout();
                        ChannelSnapshot {
                            id: channel.id,
                            extended: channel.kind.is_extended(),
                            worker: channel.worker.clone(),
                            payout_prefix,
                            payout_derived: channel.derivation.is_some(),
                            payout_next: next.as_ref().map(|(a, _)| a.clone()).unwrap_or_default(),
                            payout_index: next.map(|(_, i)| i).unwrap_or(0),
                            vendor: channel.peer.vendor.clone(),
                            firmware: channel.peer.firmware.clone(),
                            accepted,
                            rejected,
                            desync: channel.desync(),
                            donation_bp: channel.donation_basis_points,
                            donation_paid: channel.donation_paid(),
                            blocks_submitted: channel.blocks(),
                            current_job_id: channel.current_job_id(),
                            connected_for,
                            estimated_hashrate,
                            estimate_stable: estimate_is_stable(accepted),
                            expected_shares_per_minute: channel.shares_per_minute(),
                            share_target_hex: hex(&share_target),
                            best_share: channel.best_share(),
                            refusals: channel.refusals_by_code(),
                        }
                    })
                    .collect();
                AlgoSnapshot {
                    pow: algo.pow,
                    upstream_connected: algo.submitter().is_connected(),
                    blocks_submitted: algo.blocks(),
                    blocks_confirmed: algo.confirmed(),
                    unconfirmed: algo.unconfirmed(),
                    found: algo
                        .found()
                        .into_iter()
                        .map(|block| FoundSnapshot {
                            hash: block.hash,
                            worker: block.worker,
                            payout_prefix: block
                                .payout_address
                                .chars()
                                .take(ADDRESS_PREFIX)
                                .collect(),
                            paid_prefix: block.paid.chars().take(ADDRESS_PREFIX).collect(),
                        })
                        .collect(),
                    prev_hash: algo.prev_hash(),
                    network_target: algo.network_target(),
                    channels,
                }
            })
            .collect();
        Snapshot {
            uptime: now.saturating_duration_since(started_at),
            authority_public_key,
            operator_fee,
            coinbase_tag,
            algorithms,
        }
    }

    /// Hand-rolled, because the only strings that reach it are a worker
    /// label, a payout prefix and what the worker said it is running, all of
    /// which are escaped below. Everything else is a number or a bool.
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
        // From the configuration the coinbase is built from, so a renderer
        // can state the fee, and can show how to donate only when an offer
        // has somewhere to go.
        out.push_str(&format!(
            "  \"operator_fee_bp\": {},\n",
            self.operator_fee.basis_points
        ));
        out.push_str(&format!(
            "  \"donations_accepted\": {},\n",
            self.operator_fee.has_address
        ));
        // Escaped like a worker label rather than written out like the key
        // above, because this one is a string an operator typed: the pool
        // accepts any tag that fits a coinbase, and a quote in it would
        // otherwise end the field early and hand the reader broken JSON.
        out.push_str(&format!(
            "  \"coinbase_tag\": \"{}\",\n",
            escape(&self.coinbase_tag)
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
            // Not "blocks found": this counts what went up to the node, and
            // what became of it is blocks_confirmed below.
            out.push_str(&format!(
                "      \"blocks_submitted\": {},\n",
                algo.blocks_submitted
            ));
            // Provable, unlike blocks_submitted: this hash was seen as the tip.
            out.push_str(&format!(
                "      \"blocks_confirmed\": {},\n",
                algo.blocks_confirmed
            ));
            // The gap between the two, as hashes, for a resolver with a node
            // to ask. Display order, so each pastes straight into getblock.
            let unconfirmed: Vec<String> = algo
                .unconfirmed
                .iter()
                .map(|hash| format!("\"{}\"", hex_reversed(hash)))
                .collect();
            out.push_str(&format!(
                "      \"unconfirmed\": [{}],\n",
                unconfirmed.join(", ")
            ));
            // Who found what, for the same reader. Display order again, so a
            // hash here and a hash in the list above are the same string and
            // can be matched without either end reversing anything.
            if algo.found.is_empty() {
                out.push_str("      \"found\": [],\n");
            } else {
                out.push_str("      \"found\": [\n");
                for (j, block) in algo.found.iter().enumerate() {
                    out.push_str(&format!(
                        "        {{\"hash\": \"{}\", \"worker\": \"{}\", \
                         \"payout_prefix\": \"{}\", \"paid_prefix\": \"{}\"}}",
                        hex_reversed(&block.hash),
                        escape(&block.worker),
                        escape(&block.payout_prefix),
                        escape(&block.paid_prefix)
                    ));
                    out.push_str(if j + 1 == algo.found.len() {
                        "\n"
                    } else {
                        ",\n"
                    });
                }
                out.push_str("      ],\n");
            }
            match &algo.prev_hash {
                Some(hash) => out.push_str(&format!(
                    "      \"mining_on\": \"{}\",\n",
                    hex_reversed(hash)
                )),
                None => out.push_str("      \"mining_on\": null,\n"),
            }
            // Internal order, as share_target is, since both are targets and
            // neither is a block hash.
            match &algo.network_target {
                Some(target) => {
                    out.push_str(&format!("      \"network_target\": \"{}\",\n", hex(target)));
                    // The hashes a block costs at that target, which is what
                    // makes best_share_hashes below mean something: the two
                    // divide into "how much of a block this worker has
                    // already done in one share".
                    out.push_str(&format!(
                        "      \"hashes_per_block\": {:.0},\n",
                        hashes_per_share(target)
                    ));
                }
                None => out.push_str(
                    "      \"network_target\": null,\n      \
                     \"hashes_per_block\": null,\n",
                ),
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
                // The next address in full, on a descriptor channel only. A
                // one-use address says nothing about the others, and the
                // miner wants to recognise it when the block lands.
                out.push_str(&format!(
                    "          \"payout_derived\": {},\n",
                    channel.payout_derived
                ));
                out.push_str(&format!(
                    "          \"payout_next\": \"{}\",\n",
                    escape(&channel.payout_next)
                ));
                out.push_str(&format!(
                    "          \"payout_index\": {},\n",
                    channel.payout_index
                ));
                // Two fields rather than one joined string, because joining
                // them is a display decision and this is not the place for
                // one. Empty is "said nothing", which a reader must not
                // print as a version it does not have.
                out.push_str(&format!(
                    "          \"vendor\": \"{}\",\n",
                    escape(&channel.vendor)
                ));
                out.push_str(&format!(
                    "          \"firmware\": \"{}\",\n",
                    escape(&channel.firmware)
                ));
                out.push_str(&format!("          \"accepted\": {},\n", channel.accepted));
                out.push_str(&format!("          \"rejected\": {},\n", channel.rejected));
                out.push_str(&format!("          \"desync\": {},\n", channel.desync));
                out.push_str(&format!(
                    "          \"donation_bp\": {},\n",
                    channel.donation_bp
                ));
                out.push_str(&format!(
                    "          \"donation_paid\": {},\n",
                    channel.donation_paid
                ));
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
                // Beside the estimate rather than folded into it: a rate from
                // four shares and a rate from four hundred are both numbers,
                // and only one of them is a measurement.
                out.push_str(&format!(
                    "          \"estimate_stable\": {},\n",
                    channel.estimate_stable
                ));
                // What the target was sized for. The observed rate is
                // accepted over connected_seconds, which a renderer can work
                // out for itself; what it cannot work out is what cadence the
                // pool was aiming at when it chose the target.
                out.push_str(&format!(
                    "          \"expected_shares_per_minute\": {:.3},\n",
                    channel.expected_shares_per_minute
                ));
                out.push_str(&format!(
                    "          \"share_target\": \"{}\",\n",
                    channel.share_target_hex
                ));
                // Display order, as a block hash is, so it pastes into an
                // explorer and reads the way the miner's own log printed it.
                match &channel.best_share {
                    Some(hash) => {
                        out.push_str(&format!(
                            "          \"best_share\": \"{}\",\n",
                            hex_reversed(hash)
                        ));
                        // The hashes that share stands for, which is the
                        // comparable quantity: set against hashes_per_share
                        // of the network target, it says how much of a block
                        // this worker has already done in one go.
                        out.push_str(&format!(
                            "          \"best_share_hashes\": {:.0},\n",
                            hashes_per_share(hash)
                        ));
                    }
                    None => out.push_str(
                        "          \"best_share\": null,\n          \
                         \"best_share_hashes\": null,\n",
                    ),
                }
                // Every refusal by code, which sums to more than "rejected"
                // because invalid-job-id is refused without being counted
                // against the channel. The keys are Refusal::code(), which is
                // kebab-case ASCII and needs none of the escaping a worker
                // label does.
                let refusals: Vec<String> = channel
                    .refusals
                    .iter()
                    .map(|(code, count)| format!("\"{code}\": {count}"))
                    .collect();
                out.push_str(&format!(
                    "          \"rejected_by_reason\": {{{}}}\n",
                    refusals.join(", ")
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

/// What `/healthz` answers.
///
/// JSON with the pool's own clock on it rather than the word "ok". A status
/// on its own cannot tell a live answer from one something kept, and a
/// watcher comparing this with its own clock is the cheapest way to notice a
/// container whose time has drifted, which otherwise stays invisible until
/// two services disagree about how old something is.
fn health_body() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0);
    format!("{{\"status\": \"ok\", \"timestamp\": {seconds}}}\n")
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
        "/healthz" => respond(&mut stream, "200 OK", "application/json", &health_body()),
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
    fn unconfirmed_hashes_are_listed_in_display_order() {
        let mut internal = [0u8; 32];
        internal[0] = 0xab;
        internal[31] = 0x01;
        let snapshot = Snapshot {
            uptime: Duration::from_secs(1),
            authority_public_key: String::new(),
            operator_fee: OperatorFee::default(),
            coinbase_tag: String::new(),
            algorithms: vec![AlgoSnapshot {
                pow: PowType::X16rt,
                upstream_connected: true,
                blocks_submitted: 2,
                blocks_confirmed: 1,
                unconfirmed: vec![internal],
                found: Vec::new(),
                prev_hash: None,
                network_target: None,
                channels: Vec::new(),
            }],
        };
        let json = snapshot.to_json();
        // Reversed, the way getblock wants it: the 0x01 byte leads.
        let shown = format!("01{}ab", "00".repeat(30));
        assert!(
            json.contains(&format!("\"unconfirmed\": [\"{shown}\"],")),
            "{json}"
        );
    }

    #[test]
    fn no_unconfirmed_blocks_is_an_empty_list_and_not_an_absent_key() {
        let snapshot = Snapshot {
            uptime: Duration::from_secs(1),
            authority_public_key: String::new(),
            operator_fee: OperatorFee::default(),
            coinbase_tag: String::new(),
            algorithms: vec![AlgoSnapshot {
                pow: PowType::MinotaurX,
                upstream_connected: false,
                blocks_submitted: 0,
                blocks_confirmed: 0,
                unconfirmed: Vec::new(),
                found: Vec::new(),
                prev_hash: None,
                network_target: None,
                channels: Vec::new(),
            }],
        };
        assert!(snapshot.to_json().contains("\"unconfirmed\": [],"));
    }

    /// One algorithm whose only interesting feature is the blocks it found.
    fn with_found(found: Vec<FoundSnapshot>) -> Snapshot {
        Snapshot {
            uptime: Duration::from_secs(1),
            authority_public_key: String::new(),
            operator_fee: OperatorFee::default(),
            coinbase_tag: String::new(),
            algorithms: vec![AlgoSnapshot {
                pow: PowType::X16rt,
                upstream_connected: true,
                blocks_submitted: 1,
                blocks_confirmed: 1,
                unconfirmed: Vec::new(),
                found,
                prev_hash: None,
                network_target: None,
                channels: Vec::new(),
            }],
        }
    }

    #[test]
    fn a_found_block_says_whose_it_was() {
        let mut internal = [0u8; 32];
        internal[0] = 0xab;
        internal[31] = 0x01;
        let json = with_found(vec![FoundSnapshot {
            hash: internal,
            worker: "rig-a".into(),
            payout_prefix: "RXp2d4ab".into(),
            paid_prefix: "RXp2d4ab".into(),
        }])
        .to_json();
        // Display order, the way the unconfirmed list above spells a hash, so
        // the two can be matched without either end reversing one.
        let shown = format!("01{}ab", "00".repeat(30));
        assert!(
            json.contains(&format!(
                "{{\"hash\": \"{shown}\", \"worker\": \"rig-a\", \
                 \"payout_prefix\": \"RXp2d4ab\", \"paid_prefix\": \"RXp2d4ab\"}}"
            )),
            "{json}"
        );
    }

    #[test]
    fn no_blocks_found_is_an_empty_list_and_not_an_absent_key() {
        // The same distinction the unconfirmed list makes: a pool that has
        // found nothing and a pool too old to say are different facts, and
        // an absent key cannot tell them apart.
        assert!(with_found(Vec::new()).to_json().contains("\"found\": [],"));
    }

    #[test]
    fn a_worker_label_on_a_found_block_cannot_break_the_json() {
        // The same untrusted text as a channel's label, kept for longer and
        // so outliving the connection it arrived on.
        let json = with_found(vec![FoundSnapshot {
            hash: [0u8; 32],
            worker: "rig\"a\nb".into(),
            payout_prefix: "RXp2d4ab".into(),
            paid_prefix: "RXp2d4ab".into(),
        }])
        .to_json();
        assert!(json.contains("\"worker\": \"rig\\\"a\\nb\""), "{json}");
    }

    /// One channel with nothing interesting about it, for a test to change
    /// the single field it is about.
    fn channel() -> ChannelSnapshot {
        ChannelSnapshot {
            id: 1,
            extended: true,
            worker: "rig".into(),
            payout_prefix: "avn1qmyq".into(),
            payout_derived: false,
            payout_next: String::new(),
            payout_index: 0,
            vendor: String::new(),
            firmware: String::new(),
            accepted: 0,
            rejected: 0,
            desync: 0,
            donation_bp: 0,
            donation_paid: false,
            blocks_submitted: 0,
            current_job_id: None,
            connected_for: Duration::from_secs(60),
            estimated_hashrate: 0.0,
            estimate_stable: false,
            expected_shares_per_minute: 4.0,
            share_target_hex: hex(&[0xff; 32]),
            best_share: None,
            refusals: BTreeMap::new(),
        }
    }

    /// One algorithm holding whatever channels a test hands it.
    fn algo(channels: Vec<ChannelSnapshot>) -> Snapshot {
        Snapshot {
            uptime: Duration::from_secs(1),
            authority_public_key: String::new(),
            operator_fee: OperatorFee::default(),
            coinbase_tag: String::new(),
            algorithms: vec![AlgoSnapshot {
                pow: PowType::X16rt,
                upstream_connected: true,
                blocks_submitted: 0,
                blocks_confirmed: 0,
                unconfirmed: Vec::new(),
                found: Vec::new(),
                prev_hash: None,
                network_target: None,
                channels,
            }],
        }
    }

    #[test]
    fn an_estimate_is_called_stable_only_once_it_rests_on_enough_shares() {
        assert!(!estimate_is_stable(0));
        assert!(!estimate_is_stable(SETTLED_SHARES - 1));
        assert!(estimate_is_stable(SETTLED_SHARES));
        // The flag is about the sample, so it cannot come back off once the
        // shares are in.
        assert!(estimate_is_stable(u32::MAX));
    }

    #[test]
    fn a_best_share_is_shown_in_display_order_with_the_work_it_stands_for() {
        let mut internal = [0u8; 32];
        internal[0] = 0xcd;
        internal[31] = 0x02;
        let mut one = channel();
        one.best_share = Some(internal);
        let json = algo(vec![one]).to_json();
        // Reversed, as a block hash is printed, so it pastes into an explorer.
        let shown = format!("02{}cd", "00".repeat(30));
        assert!(
            json.contains(&format!("\"best_share\": \"{shown}\",")),
            "{json}"
        );
        // The same arithmetic a share target gets, because the question is
        // the same one: how many hashes does a value this low stand for.
        let expected = format!("{:.0}", hashes_per_share(&internal));
        assert!(
            json.contains(&format!("\"best_share_hashes\": {expected},")),
            "{json}"
        );
    }

    #[test]
    fn a_channel_with_no_accepted_share_reports_a_null_best_share() {
        // Null rather than absent, and null rather than zero: a channel that
        // has found nothing has no best share, and zero would read as a hash
        // of zero, which would be the best one possible.
        let json = algo(vec![channel()]).to_json();
        assert!(json.contains("\"best_share\": null,"), "{json}");
        assert!(json.contains("\"best_share_hashes\": null,"), "{json}");
    }

    #[test]
    fn refusal_codes_are_an_object_and_may_sum_past_rejected() {
        let mut one = channel();
        one.rejected = 2;
        one.desync = 3;
        one.refusals.insert("stale-share", 2);
        one.refusals.insert("invalid-job-id", 3);
        let json = one_channel_json(one);
        // BTreeMap order, so the same state renders the same JSON twice.
        assert!(
            json.contains("\"rejected_by_reason\": {\"invalid-job-id\": 3, \"stale-share\": 2}"),
            "{json}"
        );
        // The breakdown sums to five against a rejected count of two, which
        // is the point: an unknown job id is refused and not held against the
        // channel, so it appears here and not there.
        assert!(json.contains("\"rejected\": 2,"), "{json}");
        assert!(json.contains("\"desync\": 3,"), "{json}");
    }

    #[test]
    fn no_refusals_is_an_empty_object_and_not_an_absent_key() {
        let json = one_channel_json(channel());
        assert!(json.contains("\"rejected_by_reason\": {}"), "{json}");
    }

    #[test]
    fn what_a_block_costs_is_published_beside_the_target_it_comes_from() {
        let mut snapshot = algo(Vec::new());
        // Half of the easiest target, so a block is worth two hashes.
        let mut target = [0xffu8; 32];
        target[31] = 0x7f;
        snapshot.algorithms[0].network_target = Some(target);
        let json = snapshot.to_json();
        assert!(
            json.contains(&format!("\"network_target\": \"{}\",", hex(&target))),
            "{json}"
        );
        let expected = format!("{:.0}", hashes_per_share(&target));
        assert!(
            json.contains(&format!("\"hashes_per_block\": {expected},")),
            "{json}"
        );
    }

    #[test]
    fn no_template_yet_leaves_the_network_target_null_rather_than_absent() {
        // A renderer dividing a best share by this needs to tell "no
        // template" from "a block costs nothing".
        let json = algo(Vec::new()).to_json();
        assert!(json.contains("\"network_target\": null,"), "{json}");
        assert!(json.contains("\"hashes_per_block\": null,"), "{json}");
    }

    #[test]
    fn the_cadence_a_target_was_sized_for_is_published() {
        let mut one = channel();
        one.expected_shares_per_minute = 4.5;
        one.accepted = 30;
        one.estimate_stable = true;
        let json = one_channel_json(one);
        assert!(
            json.contains("\"expected_shares_per_minute\": 4.500,"),
            "{json}"
        );
        assert!(json.contains("\"estimate_stable\": true,"), "{json}");
    }

    /// The JSON of a pool serving one algorithm with this one channel on it.
    fn one_channel_json(channel: ChannelSnapshot) -> String {
        algo(vec![channel]).to_json()
    }

    #[test]
    fn health_answers_json_with_a_clock_on_it() {
        let body = health_body();
        assert!(body.contains("\"status\": \"ok\""), "{body}");
        // The clock, not a constant: anything later than the day this was
        // written means a real one was read.
        let stamp: u64 = body
            .split("\"timestamp\": ")
            .nth(1)
            .and_then(|rest| rest.trim_end().trim_end_matches('}').parse().ok())
            .unwrap_or(0);
        assert!(stamp > 1_762_000_000, "{body}");
    }

    #[test]
    fn a_descriptor_channel_says_where_its_next_block_goes() {
        let mut one = channel();
        one.payout_prefix = "xpub6BzV".into();
        one.payout_derived = true;
        one.payout_next = "avn1qmyqedhpwefp8qgpdd4enxe043nxe8kulvmavrx".into();
        one.payout_index = 2;
        let json = one_channel_json(one);
        assert!(json.contains("\"payout_prefix\": \"xpub6BzV\","), "{json}");
        assert!(json.contains("\"payout_derived\": true,"), "{json}");
        // The whole address, not a prefix: it is used once and names no
        // other, and the miner wants to recognise it when the block lands.
        assert!(
            json.contains("\"payout_next\": \"avn1qmyqedhpwefp8qgpdd4enxe043nxe8kulvmavrx\","),
            "{json}"
        );
        assert!(json.contains("\"payout_index\": 2,"), "{json}");
    }

    #[test]
    fn an_address_channel_has_the_fields_too_and_they_say_nothing() {
        // Present and empty, so a page can read them without checking the
        // pool's version first, and false means an address rather than an
        // unknown.
        let json = one_channel_json(channel());
        assert!(json.contains("\"payout_derived\": false,"), "{json}");
        assert!(json.contains("\"payout_next\": \"\","), "{json}");
        assert!(json.contains("\"payout_index\": 0,"), "{json}");
    }

    #[test]
    fn what_the_worker_said_it_is_running_is_published() {
        let mut one = channel();
        one.vendor = "avian-miner".into();
        one.firmware = "avian-miner-1.2.0-x64W".into();
        let json = one_channel_json(one);
        assert!(json.contains("\"vendor\": \"avian-miner\","), "{json}");
        assert!(
            json.contains("\"firmware\": \"avian-miner-1.2.0-x64W\","),
            "{json}"
        );
    }

    #[test]
    fn a_worker_that_said_nothing_is_published_as_having_said_nothing() {
        // Empty and not absent, and not a placeholder either. Every miner
        // built before the pool started asking sends empty fields, and a
        // page that printed "unknown" for them would be inventing a fact
        // about a perfectly ordinary worker.
        let json = one_channel_json(channel());
        assert!(json.contains("\"vendor\": \"\","), "{json}");
        assert!(json.contains("\"firmware\": \"\","), "{json}");
    }

    #[test]
    fn a_version_string_cannot_break_the_json_either() {
        // The same untrusted text as a worker label, from the same place and
        // through the same escape. Asserted separately because it reaches
        // the JSON through its own format! and a new field is exactly where
        // an unescaped one gets written.
        let mut one = channel();
        one.firmware = "1.0\" , \"accepted\": 999999".into();
        let json = one_channel_json(one);
        assert!(
            json.contains("\"firmware\": \"1.0\\\" , \\\"accepted\\\": 999999\","),
            "{json}"
        );
        assert!(json.contains("\"accepted\": 0,"), "{json}");
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
            operator_fee: OperatorFee::default(),
            coinbase_tag: String::new(),
            algorithms: vec![],
        };
        let json = snapshot.to_json();
        assert!(json.contains("\"uptime_seconds\": 42"));
        assert!(json.contains("\"miners\": 0"));
        assert!(json.contains("\"algorithms\": [\n  ]"), "{json}");
        assert!(json.contains("\"vardiff\": false"));
    }

    #[test]
    fn the_coinbase_tag_is_published_so_nothing_has_to_be_told_it_twice() {
        let snapshot = Snapshot {
            uptime: Duration::from_secs(1),
            authority_public_key: String::new(),
            operator_fee: OperatorFee::default(),
            coinbase_tag: "/avian-sv2/yyz/".into(),
            algorithms: vec![],
        };
        assert!(
            snapshot
                .to_json()
                .contains("\"coinbase_tag\": \"/avian-sv2/yyz/\","),
            "{}",
            snapshot.to_json()
        );
    }

    #[test]
    fn an_empty_tag_is_reported_as_empty_and_not_left_out() {
        // The distinction this pool has already been bitten by. A tag that is
        // not there matches nothing when a chain is walked for it, and an
        // endpoint that simply omitted the field would leave a reader unable
        // to tell that from an older pool that never published one.
        let snapshot = Snapshot {
            uptime: Duration::from_secs(1),
            authority_public_key: String::new(),
            operator_fee: OperatorFee::default(),
            coinbase_tag: String::new(),
            algorithms: vec![],
        };
        assert!(
            snapshot.to_json().contains("\"coinbase_tag\": \"\","),
            "{}",
            snapshot.to_json()
        );
    }

    #[test]
    fn a_tag_an_operator_typed_cannot_break_the_json() {
        // Unlike the authority key beside it, this is a string somebody
        // chose, and the pool takes any tag that fits in a coinbase.
        let snapshot = Snapshot {
            uptime: Duration::from_secs(1),
            authority_public_key: String::new(),
            operator_fee: OperatorFee::default(),
            coinbase_tag: "/a\"b\\c/".into(),
            algorithms: vec![],
        };
        let json = snapshot.to_json();
        assert!(
            json.contains("\"coinbase_tag\": \"/a\\\"b\\\\c/\","),
            "{json}"
        );
    }

    #[test]
    fn the_fee_and_whether_a_donation_is_paid_are_stated() {
        let mut snapshot = Snapshot {
            uptime: Duration::from_secs(1),
            authority_public_key: String::new(),
            coinbase_tag: String::new(),
            operator_fee: OperatorFee {
                basis_points: 25,
                has_address: true,
            },
            algorithms: vec![],
        };
        let json = snapshot.to_json();
        assert!(json.contains("\"operator_fee_bp\": 25,"), "{json}");
        assert!(json.contains("\"donations_accepted\": true,"), "{json}");

        // The donations-only setup: nothing taken, and an offer still paid.
        snapshot.operator_fee.basis_points = 0;
        let json = snapshot.to_json();
        assert!(json.contains("\"operator_fee_bp\": 0,"), "{json}");
        assert!(json.contains("\"donations_accepted\": true,"), "{json}");

        // No address at all: an offer goes nowhere, and the page must not
        // invite one.
        snapshot.operator_fee = OperatorFee::default();
        let json = snapshot.to_json();
        assert!(json.contains("\"donations_accepted\": false,"), "{json}");
    }
}
