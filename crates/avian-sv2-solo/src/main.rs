//! The Avian Stratum v2 solo pool.
//!
//! Upstream it is a Template Distribution client, one connection per
//! algorithm, because one connection carries one `nBits` and `target` stream.
//! Downstream it is a Mining Protocol server, one standard channel per worker.
//!
//! **Solo.** A worker's own address goes in the coinbase and consensus pays it
//! directly, so the pool never holds anyone's earnings. The address comes from
//! `user_identity` at channel open, and an address that does not parse refuses
//! the channel rather than falling back to anything.
//!
//! No accounting, no vardiff, no Stratum v1. The one thing kept across
//! restarts is which address a descriptor pays next, in `--payout-state`,
//! for a worker that asked for a fresh address per block.

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use avian_mining::pool::{self, PoolConfig};
use avian_mining::ratelimit::RateLimitConfig;
use avian_mining::server::ServerConfig;
use avian_mining::share::{AvianHasher, PowHasher};
use avian_mining::stats::{self, Snapshot};
use avian_sv2::address::{self, Address, Network};
use avian_sv2::avian::TimeConstraints;
use avian_sv2::logln;
use avian_sv2::wire::{hex, hex_rev};
use avian_sv2::Backoff;
use avian_tdp::coinbase::MAX_COINBASE_TAG;
use avian_tdp::tdp::PrevHash;
use avian_tdp::{authority, chain_subdir, default_port, PowType, Work};
use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

struct Options {
    node: SocketAddr,
    mining_bind: SocketAddr,
    /// Read-only JSON, for a renderer to poll. `None` leaves it off, which is
    /// the default: a port nobody asked for should not exist.
    stats_bind: Option<SocketAddr>,
    network: Network,
    algorithms: Vec<PowType>,
    node_authority: Option<XOnlyPublicKey>,
    pool_authority_key: PathBuf,
    fee_script: Vec<u8>,
    fee_basis_points: u32,
    coinbase_tag: Vec<u8>,
    shares_per_minute: f64,
    min_hash_rate: f64,
    max_hash_rate: f64,
    rate_limit: RateLimitConfig,
    verbose: bool,
    duration: Option<Duration>,
    coinbase_size: u32,
    coinbase_sigops: u16,
    /// Passed through to ServerConfig. Loopback-only is the library's default
    /// and stays so; a container has to ask.
    allow_public_bind: bool,
    /// Where the next derivation index per descriptor lives. None keeps it in
    /// memory, and the pool says so in its log.
    payout_state: Option<PathBuf>,
}

const DEFAULT_TAG: &str = "/avian-sv2/";

const USAGE: &str = "\
avian-sv2-solo: an Avian Stratum v2 solo pool

A worker puts its own payout address in user_identity when it opens a channel,
as `address` or `address.workername`, and the coinbase pays it directly. An
address that does not parse, or belongs to another network, refuses the
channel. There is no fallback address, by design.

A worker may give a descriptor in place of the address, `wpkh(xpub.../0/*)` or
`pkh(xpub.../0/*)`, as its wallet's `listdescriptors` prints one, and each
block it finds then pays a fresh address derived from the key: the index after
the last block's, kept in --payout-state. A key origin and a #checksum are
accepted; a hardened step or a bare xpub with no range are refused.

A worker may also leave some of its own reward to the pool, by connecting as
`donate/<percent>/address.workername`. The percentage takes up to two decimal
places, so `donate/2/`, `donate/0.5/` and `donate/12.34/` all work, and it
adds to any operator fee. Without the prefix a worker keeps everything, which
is the default and the point: nobody is charged anything they did not type.
A malformed percentage refuses the channel rather than being read as zero.

Upstream, to the node:
  --datadir <path>       the node's datadir, to read sv2_authority_key from
  --chain <name>         regtest (default), main, test, testnet4, signet
  --connect <host:port>  default: 127.0.0.1 and the chain's Sv2 port
  --authority <hex>      the node's authority x-only public key
  --insecure-tofu        connect without verifying the node's certificate
  --coinbase-size <n>    coinbase_output_max_additional_size, default 1000
  --coinbase-sigops <n>  coinbase_output_max_additional_sigops, default 10

Downstream, to miners:
  --mining-bind <addr>   where to serve the Mining Protocol
                         (default 127.0.0.1:34254, loopback only)
  --payout-state <file>  where to keep the next address index for each
                         descriptor a worker pays through (see below).
                         Without it the indices restart at 0 on every start
  --pool-key <file>      the pool's authority private key, generated on first
                         run (default: ./avian-pool-authority-key)
  --coinbase-tag <text>  goes in the coinbase scriptSig
                         (default: /avian-sv2/, at most 87 bytes)
  --operator-fee <addr>  take a fee to this address, and the address
                         donations are paid to; omit for neither
  --operator-fee-bp <n>  the fee in hundredths of a percent (100 = 1%).
                         Leave at zero to charge nothing and still accept
                         donations, which is the 100%-to-the-miner setup
  --shares-per-minute    how often each worker should find a share
                         (default 4.5). Each channel's target is worked out
                         from this and the hash rate the worker declared when
                         it opened, so a CPU and a GPU aim at the same
                         cadence. Set once per channel and never adjusted:
                         there is no vardiff
  --min-hash-rate <n>    the slowest worker to believe, in hashes a second
                         (default 1000). A worker that declares less is
                         treated as this fast, because the protocol default
                         is 1 H/s and taking that at face value would hand
                         out a target of a few dozen hashes a share
  --max-hash-rate <n>    and the fastest (default 1e12). Above this a worker
                         would be handed a target nothing it owns can meet

Submission limits, per channel:
  --share-rate-tolerance <n>   multiple of the expected rate, default 8
  --max-invalid-shares <n>     invalid submissions before the channel is
                               dropped, default 50

  --stats-bind <addr>    serve read-only JSON here; off by default. JSON
                         only, never HTML: a renderer is a separate service.
                         Do not publish this port.
  --allow-public-bind    permit --mining-bind and --stats-bind on addresses
                         that are not loopback. Needed inside a container,
                         where the listener has to be on the container's
                         network for a published port to reach it.
  --algo <name>          x16rt or minotaurx; repeatable, default: both
  --duration <seconds>   stop after this long; default: run until killed
  --verbose              print every template in full

Every flag above that takes a single value can also be given as an
environment variable, named for the flag: --coinbase-tag is
AVIAN_SV2_COINBASE_TAG, --shares-per-minute is AVIAN_SV2_SHARES_PER_MINUTE.
A flag wins over the variable, the variable wins over the default, and a
variable set to nothing at all is the same as not setting it.

That is for a deployment where the flags live in a file something overwrites,
which is what a systemd unit is: a unit has no defaulting of its own, so the
flags are written out in it, and the ones that differ between two sites of
the same pool then have nowhere to live. An environment file is the thing
that survives a deploy. The repeatable and the on-off flags have no variable:
neither is worth varying per site, and both would need a convention invented
for them. The pool prints what it ended up with when it starts.
";

fn main() {
    let options = match parse_args() {
        Ok(Some(options)) => options,
        Ok(None) => return,
        Err(message) => {
            eprintln!("{message}\n\n{USAGE}");
            std::process::exit(2);
        }
    };

    if let Err(message) = run(options) {
        eprintln!("{message}");
        std::process::exit(1);
    }
}

fn run(options: Options) -> Result<(), String> {
    let authority = load_or_create_pool_key(&options.pool_authority_key)
        .map_err(|e| format!("pool authority key: {e}"))?;
    let (pool_pubkey, _) = authority.x_only_public_key();

    let hasher: Arc<dyn PowHasher> = Arc::new(AvianHasher);
    logln!("[pool] proof of work: {}", hasher.describe());
    if hasher.hash(PowType::X16rt, &[0u8; 80]).is_none() {
        return Err(
            "the proof-of-work hashers are not available, so no share could be validated. \
             Rebuild with AVIAN_SRC pointing at the Avian Core src directory."
                .into(),
        );
    }

    logln!(
        "[pool] solo on {}: a worker's own address is paid, from user_identity at channel open",
        options.network
    );
    // Three setups, said out loud, because the one in the middle used to be
    // refused and an operator who expects that should see it start.
    match (options.fee_script.is_empty(), options.fee_basis_points) {
        (true, _) => logln!(
            "[pool] no operator fee and no donation address: a donate/ prefix is \
             logged and the miner keeps everything"
        ),
        (false, 0) => {
            logln!("[pool] no operator fee; a donate/ prefix pays the --operator-fee address")
        }
        (false, bp) => logln!(
            "[pool] operator fee {}.{:02}%; a donate/ prefix adds to it",
            bp / 100,
            bp % 100
        ),
    }

    let verbose = options.verbose;
    let observer: pool::WorkObserver =
        Arc::new(move |pow, work: &Work| print_round(pow, work, verbose));

    let handle = pool::spawn(
        PoolConfig {
            node: options.node,
            node_authority: options.node_authority,
            algorithms: options.algorithms.clone(),
            server: ServerConfig {
                bind: options.mining_bind,
                allow_public_bind: options.allow_public_bind,
                authority,
                cert_validity: avian_sv2::transport::DEFAULT_CERT_VALIDITY_SECS,
                network: options.network,
                payout_state: options.payout_state.clone(),
                fee_script: options.fee_script.clone(),
                fee_basis_points: options.fee_basis_points,
                coinbase_tag: options.coinbase_tag.clone(),
                shares_per_minute: options.shares_per_minute,
                min_hash_rate: options.min_hash_rate,
                max_hash_rate: options.max_hash_rate,
                // No flag: on a real chain the cadence above is
                // the thing to set.
                share_target_override: None,
                rate_limit: options.rate_limit,
            },
            coinbase_size: options.coinbase_size,
            coinbase_sigops: options.coinbase_sigops,
            duration: options.duration,
            upstream_backoff: Backoff::default(),
        },
        hasher,
        Some(observer),
    )
    .map_err(|e| e.to_string())?;

    logln!(
        "[pool] serving the Mining Protocol on {} for {} algorithm(s)",
        handle.mining_addr(),
        options.algorithms.len()
    );

    // What this pool is configured as, said out loud once a run.
    //
    // Each of these can now come from a flag or from the environment, and
    // between a unit, a drop-in and an environment file there is no single
    // file to read to find out which one won. A line costs nothing and
    // settles it.
    //
    // The tag is why the line exists. A wrong or empty one is silent: the
    // pool goes on finding and submitting blocks exactly as before, and the
    // only symptom is that whatever walks the chain for them comes up empty,
    // which is a long way from the cause and was a morning to track down.
    // Quoted, so that a trailing space or an empty string is visible as
    // itself rather than as the end of the line.
    logln!(
        "[pool] chain {}, node {}, coinbase tag {:?}, {} shares/minute",
        options.network.name(),
        options.node,
        String::from_utf8_lossy(&options.coinbase_tag),
        options.shares_per_minute
    );

    // Held for as long as the pool runs; dropping it stops the listener.
    let _stats = match options.stats_bind {
        Some(bind) => {
            let algos: Vec<_> = handle.algos().to_vec();
            let started_at = handle.started_at();
            let published_key = address::encode_authority_key(&pool_pubkey);
            let operator_fee = handle.operator_fee();
            // From the running pool rather than from `options`, so that what
            // the endpoint publishes is the string the coinbase is built
            // from. The two are the same value today; taking it from the
            // handle is what keeps them the same value.
            let coinbase_tag = handle.coinbase_tag().to_string();
            let handle = stats::serve(bind, move || {
                Snapshot::gather(
                    started_at,
                    &algos,
                    published_key.clone(),
                    operator_fee,
                    coinbase_tag.clone(),
                )
            })
            .map_err(|e| format!("--stats-bind {bind}: {e}"))?;
            logln!(
                "[pool] read-only stats JSON on {} at /stats. Do not publish this port.",
                handle.addr()
            );
            Some(handle)
        }
        None => None,
    };
    // Both forms, labelled. A miner's configuration takes this as one opaque
    // string the user pastes in, and the two stacks present x-only keys
    // differently: SRI and the miners built on it use base58check, while the
    // node's own tooling and this project's logs have used hex. An operator
    // who publishes the wrong one has a pool nobody can connect to, and the
    // symptom is a handshake that never completes, so print both rather than
    // guess.
    logln!(
        "[pool] authority public key, base58 (Stratum v2 miner configuration):\n    {}",
        address::encode_authority_key(&pool_pubkey)
    );
    logln!(
        "[pool] authority public key, hex (32-byte x-only):\n    {}",
        hex(&pool_pubkey.serialize())
    );

    handle.join();
    Ok(())
}

fn print_round(pow: PowType, work: &Work, verbose: bool) {
    logln!(
        "[{pow}] template {}: {}",
        work.template.template_id,
        if work.tip_changed {
            "the tip moved"
        } else {
            "in-place refresh on the same tip"
        }
    );
    if verbose {
        eprintln!("{}", work.template);
        if let Some(prev) = &work.prev_hash {
            eprintln!("{prev}");
        }
        eprintln!("{}", work.constraints);
    } else if let Some(prev) = &work.prev_hash {
        logln!(
            "[{pow}]   tip {} ntime {}..{}{}",
            hex_rev(&prev.prev_hash),
            work.constraints.ntime_min,
            work.constraints.ntime_max,
            agreement(prev, &work.constraints)
        );
    }
}

/// doc/sv2.md guarantees `AvianTimeConstraints.ntime_min` equals the
/// `ntime_start` in the `SetNewPrevHash` for the same template, so a pool can
/// narrow from it. Worth reporting when it does not hold.
fn agreement(prev: &PrevHash, constraints: &TimeConstraints) -> &'static str {
    if prev.ntime_start == constraints.ntime_min {
        ""
    } else {
        "  MISMATCH: ntime_min does not equal SetNewPrevHash.ntime_start"
    }
}

/// Reads the pool's authority private key, creating it on first run.
///
/// Mode 0600, like the node's own key files. The public half is what a miner
/// pins to know it is talking to this pool.
fn load_or_create_pool_key(path: &Path) -> Result<Keypair, String> {
    let secp = Secp256k1::new();
    if path.exists() {
        let raw = std::fs::read(path).map_err(|e| e.to_string())?;
        if raw.len() != 32 {
            return Err(format!(
                "{} is {} bytes, expected a 32-byte raw private key",
                path.display(),
                raw.len()
            ));
        }
        let secret = SecretKey::from_slice(&raw).map_err(|e| e.to_string())?;
        return Ok(Keypair::from_secret_key(&secp, &secret));
    }

    let (secret, _) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
    std::fs::write(path, secret.secret_bytes()).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    logln!("[pool] generated a new authority key in {}", path.display());
    Ok(Keypair::from_secret_key(&secp, &secret))
}

/// The script the operator fee and any donation are paid to, from the two
/// flags that describe it.
///
/// An address with a zero fee is allowed, and is the setup the help text
/// calls 100% to the miner: nothing is taken from anyone, and a worker that
/// connects with a `donate/` prefix has somewhere to leave what it offered.
/// It used to be refused as an unused address, from before donations gave
/// the address a second job. A fee with no address is still refused, since
/// there is nowhere to pay it.
fn fee_script(
    address: Option<&str>,
    basis_points: u32,
    network: Network,
) -> Result<Vec<u8>, String> {
    if basis_points > 10_000 {
        return Err("--operator-fee-bp cannot exceed 10000, which is the whole coinbase".into());
    }
    match address {
        Some(text) => Address::decode(text, network)
            .map(|address| address.script_pubkey())
            .map_err(|e| format!("--operator-fee {text:?}: {e}")),
        None if basis_points > 0 => {
            Err("--operator-fee-bp was given with no --operator-fee address to pay it to".into())
        }
        None => Ok(Vec::new()),
    }
}

/// The environment variable that stands in for a flag: `--coinbase-tag` is
/// `AVIAN_SV2_COINBASE_TAG`.
///
/// A rule and not a table, because a table is a second list of flag names to
/// keep in step with the first, and a flag somebody forgot to add to it would
/// read as an environment that said nothing rather than as a mistake.
///
/// Prefixed, and the prefix is the point rather than tidiness. `CHAIN` is a
/// word a shell is entitled to have exported in it, and a pool that read it
/// bare would take a stray export as an instruction to mine another network.
/// That exact failure has happened here once already, from a flag left on
/// testnet while the node synced mainnet, and it is not worth opening a
/// second road to it.
fn env_name(flag: &str) -> String {
    format!(
        "AVIAN_SV2_{}",
        flag.trim_start_matches('-')
            .replace('-', "_")
            .to_uppercase()
    )
}

/// What the environment says a flag's value is, or nothing at all.
///
/// Blank is nothing, because an environment file spells an unset value `KEY=`
/// and an operator who writes that means leave it alone. An empty
/// `--coinbase-tag=` is a different statement and is still taken from a flag,
/// where somebody typed it on purpose.
fn env_value(flag: &str) -> Option<String> {
    match std::env::var(env_name(flag)) {
        Ok(text) if !text.trim().is_empty() => Some(text),
        _ => None,
    }
}

/// A number from the environment, with the variable named in the complaint.
///
/// Named, because the flag is not where its reader will look: a pool whose
/// cadence came out of an environment file and whose error said
/// `--shares-per-minute` would send somebody to a unit with no such flag in
/// it, to look for a typo that is in another file entirely.
fn env_number<T: std::str::FromStr>(flag: &str) -> Result<Option<T>, String> {
    match env_value(flag) {
        None => Ok(None),
        Some(text) => text
            .parse()
            .map(Some)
            .map_err(|_| format!("{} wants a number, not {text:?}", env_name(flag))),
    }
}

fn parse_args() -> Result<Option<Options>, String> {
    // Seeded from the environment before a single argument is read, so that
    // an argument simply overwrites one of these and the order of precedence
    // needs no bookkeeping to enforce: flag, then environment, then the
    // default written here.
    //
    // This is here for a deployment that runs the same unit file at more than
    // one site. A systemd unit has no ${VAR:-default} in it, so every flag is
    // written out in the unit, and the values that have to differ per site
    // were therefore inside the one file a deploy script overwrites on every
    // run. An environment file is the part of such a deployment that survives
    // a deploy, and this is what lets the per-site values live in one.
    //
    // Only the flags that take a single value. A repeatable flag would need a
    // separator invented for it and the boolean flags would need a spelling
    // of truth agreed, and neither is a value anybody needs to vary per site;
    // both would be a new way to be surprised for no one's benefit.
    let mut datadir: Option<PathBuf> = env_value("--datadir").map(PathBuf::from);
    let mut chain = env_value("--chain").unwrap_or_else(|| "regtest".to_string());
    let mut connect: Option<String> = env_value("--connect");
    let mut authority_hex: Option<String> = env_value("--authority");
    let mut insecure = false;
    let mut algorithms: Vec<PowType> = Vec::new();
    let mut mining_bind =
        env_value("--mining-bind").unwrap_or_else(|| "127.0.0.1:34254".to_string());
    let mut stats_bind: Option<String> = env_value("--stats-bind");
    let mut payout_state: Option<PathBuf> = env_value("--payout-state").map(PathBuf::from);
    let mut allow_public_bind = false;
    let mut pool_key = env_value("--pool-key")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("avian-pool-authority-key"));
    let mut fee_address: Option<String> = env_value("--operator-fee");
    let mut fee_basis_points: u32 = env_number("--operator-fee-bp")?.unwrap_or(0);
    let mut coinbase_tag = env_value("--coinbase-tag").unwrap_or_else(|| DEFAULT_TAG.to_string());
    // Four and a half a minute: often enough that a dashboard shows
    // something within a minute of a worker connecting, rare enough that the
    // pool spends a hash per share without noticing.
    let mut shares_per_minute: f64 = env_number("--shares-per-minute")?.unwrap_or(4.5);
    let mut min_hash_rate: f64 = env_number("--min-hash-rate")?.unwrap_or(1000.0);
    let mut max_hash_rate: f64 = env_number("--max-hash-rate")?.unwrap_or(1e12);
    let mut rate_limit = RateLimitConfig::default();
    if let Some(value) = env_number("--share-rate-tolerance")? {
        rate_limit.tolerance = value;
    }
    if let Some(value) = env_number("--max-invalid-shares")? {
        rate_limit.max_invalid = value;
    }
    let mut verbose = false;
    let mut duration = env_number::<u64>("--duration")?.map(Duration::from_secs);
    let mut coinbase_size: u32 = env_number("--coinbase-size")?.unwrap_or(1000);
    let mut coinbase_sigops: u16 = env_number("--coinbase-sigops")?.unwrap_or(10);

    let mut args = std::env::args().skip(1);
    while let Some(whole) = args.next() {
        // --option=value as well as --option value. Both forms are what anyone
        // expects, and a compose file or a systemd unit nearly always writes
        // the first. Rejecting it produced a usage dump and a restart loop,
        // which is a poor way to learn about a spelling.
        let (arg, inline) = match whole.split_once('=') {
            Some((name, rest)) if name.starts_with("--") => {
                (name.to_string(), Some(rest.to_string()))
            }
            _ => (whole, None),
        };
        macro_rules! value {
            () => {
                match inline.clone() {
                    Some(value) => value,
                    None => args.next().ok_or_else(|| format!("{arg} needs a value"))?,
                }
            };
        }
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(None);
            }
            "--datadir" => datadir = Some(PathBuf::from(value!())),
            "--chain" => chain = value!(),
            "--connect" => connect = Some(value!()),
            "--authority" => authority_hex = Some(value!()),
            "--insecure-tofu" => insecure = true,
            "--mining-bind" => mining_bind = value!(),
            "--stats-bind" => stats_bind = Some(value!()),
            "--allow-public-bind" => allow_public_bind = true,
            "--pool-key" => pool_key = PathBuf::from(value!()),
            "--payout-state" => payout_state = Some(PathBuf::from(value!())),
            "--coinbase-tag" => coinbase_tag = value!(),
            "--operator-fee" => fee_address = Some(value!()),
            "--operator-fee-bp" => {
                fee_basis_points = value!()
                    .parse()
                    .map_err(|_| "--operator-fee-bp wants a number")?
            }
            "--shares-per-minute" => {
                shares_per_minute = value!()
                    .parse()
                    .map_err(|_| "--shares-per-minute wants a number")?
            }
            "--min-hash-rate" => {
                min_hash_rate = value!()
                    .parse()
                    .map_err(|_| "--min-hash-rate wants a number")?
            }
            "--max-hash-rate" => {
                max_hash_rate = value!()
                    .parse()
                    .map_err(|_| "--max-hash-rate wants a number")?
            }
            "--share-rate-tolerance" => {
                rate_limit.tolerance = value!()
                    .parse()
                    .map_err(|_| "--share-rate-tolerance wants a number")?
            }
            "--max-invalid-shares" => {
                rate_limit.max_invalid = value!()
                    .parse()
                    .map_err(|_| "--max-invalid-shares wants a number")?
            }
            "--verbose" => verbose = true,
            "--algo" => {
                let name = value!();
                algorithms.push(
                    PowType::parse(&name).ok_or_else(|| format!("unknown algorithm {name}"))?,
                );
            }
            "--duration" => {
                let seconds: u64 = value!()
                    .parse()
                    .map_err(|_| "--duration wants a number of seconds")?;
                duration = Some(Duration::from_secs(seconds));
            }
            "--coinbase-size" => {
                coinbase_size = value!()
                    .parse()
                    .map_err(|_| "--coinbase-size wants a number")?
            }
            "--coinbase-sigops" => {
                coinbase_sigops = value!()
                    .parse()
                    .map_err(|_| "--coinbase-sigops wants a number")?
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }

    if algorithms.is_empty() {
        algorithms = vec![PowType::X16rt, PowType::MinotaurX];
    }
    let network = Network::parse(&chain).ok_or_else(|| format!("unknown chain {chain}"))?;

    // Refused here rather than when the node rejects a block, which is the
    // first time it can say anything about a tag it cannot fit.
    let coinbase_tag = coinbase_tag.into_bytes();
    if coinbase_tag.len() > MAX_COINBASE_TAG {
        return Err(format!(
            "--coinbase-tag is {} bytes and the most that always fits is {MAX_COINBASE_TAG}",
            coinbase_tag.len()
        ));
    }

    let fee_script = fee_script(fee_address.as_deref(), fee_basis_points, network)?;

    let target = connect.unwrap_or_else(|| format!("127.0.0.1:{}", default_port(&chain)));
    let node = resolve(&target)?;
    let mining_bind = resolve(&mining_bind)?;

    let stats_bind = match &stats_bind {
        Some(text) => Some(resolve(text)?),
        None => None,
    };

    // Connecting out stays loopback-only with no override. The node is
    // reached over the container network in a deployment, which is loopback
    // from nobody's point of view, so this is relaxed by the same flag.
    if !node.ip().is_loopback() && !allow_public_bind {
        return Err(format!(
            "refusing to connect to {node}: loopback only without --allow-public-bind"
        ));
    }
    if !mining_bind.ip().is_loopback() && !allow_public_bind {
        return Err(format!(
            "refusing to bind {mining_bind}: loopback only without --allow-public-bind"
        ));
    }
    if let Some(stats) = stats_bind {
        if !stats.ip().is_loopback() && !allow_public_bind {
            return Err(format!(
                "refusing to bind {stats}: loopback only without --allow-public-bind"
            ));
        }
    }
    if allow_public_bind {
        // Worth a line in the log. Inside a container this is correct and
        // necessary; on a host it means the mining port is reachable from the
        // network, which is a decision rather than an accident.
        logln!(
            "[pool] --allow-public-bind: listeners may be on non-loopback \
             addresses. Publish the mining port only, never the node's \
             Stratum v2 port or this pool's stats port."
        );
    }

    // Verification is the default. Trust on first use has to be asked for.
    let node_authority = match (&authority_hex, &datadir) {
        (Some(hex), _) => Some(authority::from_hex(hex).map_err(|e| format!("--authority: {e}"))?),
        (None, Some(dir)) => {
            let path = authority::default_key_path(dir, chain_subdir(&chain));
            Some(
                authority::from_private_key_file(&path)
                    .map_err(|e| format!("reading {}: {e}", path.display()))?,
            )
        }
        (None, None) if insecure => None,
        (None, None) => {
            return Err(
                "no authority key for the node: pass --datadir or --authority, or \
                 --insecure-tofu to connect without verifying its certificate"
                    .to_string(),
            )
        }
    };

    // Fail with a clear message rather than part way through a handshake.
    TcpStream::connect_timeout(&node, Duration::from_secs(5))
        .map_err(|e| format!("nothing is listening on {node}: {e}"))?;

    Ok(Some(Options {
        node,
        mining_bind,
        stats_bind,
        network,
        algorithms,
        node_authority,
        pool_authority_key: pool_key,
        fee_script,
        fee_basis_points,
        coinbase_tag,
        shares_per_minute,
        min_hash_rate,
        max_hash_rate,
        rate_limit,
        verbose,
        duration,
        coinbase_size,
        coinbase_sigops,
        allow_public_bind,
        payout_state,
    }))
}

fn resolve(target: &str) -> Result<SocketAddr, String> {
    target
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {target}: {e}"))?
        .next()
        .ok_or_else(|| format!("{target} resolved to nothing"))
}

#[cfg(test)]
mod env_tests {
    use super::*;

    #[test]
    fn a_variable_is_named_for_its_flag_by_a_rule() {
        assert_eq!(env_name("--coinbase-tag"), "AVIAN_SV2_COINBASE_TAG");
        assert_eq!(
            env_name("--shares-per-minute"),
            "AVIAN_SV2_SHARES_PER_MINUTE"
        );
        assert_eq!(env_name("--chain"), "AVIAN_SV2_CHAIN");
    }

    #[test]
    fn and_the_prefix_is_there_so_a_bare_word_cannot_reach_it() {
        // The whole reason for the prefix: CHAIN is a word a shell may have
        // exported for its own purposes, and reading it bare would let an
        // unrelated export point this pool at another network.
        assert_ne!(env_name("--chain"), "CHAIN");
    }

    // One test for everything that touches the process environment, because
    // the environment is global and the test harness is threaded: two tests
    // setting the same variable would race, and the failure would look like
    // the feature rather than like the test.
    #[test]
    fn the_environment_fills_in_what_no_flag_said() {
        let tag = env_name("--coinbase-tag");
        let cadence = env_name("--shares-per-minute");

        std::env::set_var(&tag, "/avian-sv2/par/");
        assert_eq!(
            env_value("--coinbase-tag").as_deref(),
            Some("/avian-sv2/par/")
        );

        // Blank is an environment file saying nothing, which is how an
        // operator spells "leave this alone" in a KEY= line.
        std::env::set_var(&tag, "   ");
        assert_eq!(env_value("--coinbase-tag"), None);
        std::env::remove_var(&tag);
        assert_eq!(env_value("--coinbase-tag"), None);

        std::env::set_var(&cadence, "6.0");
        assert_eq!(env_number::<f64>("--shares-per-minute").unwrap(), Some(6.0));

        // And the complaint names the variable, not the flag, because the
        // flag is not the file its reader will go and open.
        std::env::set_var(&cadence, "often");
        let err = env_number::<f64>("--shares-per-minute").unwrap_err();
        assert!(err.contains("AVIAN_SV2_SHARES_PER_MINUTE"), "{err}");
        assert!(err.contains("often"), "{err}");
        std::env::remove_var(&cadence);
    }
}

#[cfg(test)]
mod fee_tests {
    use super::*;

    const ADDRESS: &str = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn";

    #[test]
    fn an_address_with_no_fee_is_the_donations_only_setup() {
        let script = fee_script(Some(ADDRESS), 0, Network::Regtest)
            .expect("charging nothing and still accepting donations is allowed");
        assert!(
            !script.is_empty(),
            "the donation address still has a script to pay"
        );
    }

    #[test]
    fn a_fee_with_no_address_is_refused() {
        let err = fee_script(None, 25, Network::Regtest).unwrap_err();
        assert!(err.contains("no --operator-fee address"), "{err}");
    }

    #[test]
    fn neither_is_neither() {
        assert!(fee_script(None, 0, Network::Regtest).unwrap().is_empty());
    }

    #[test]
    fn more_than_the_whole_coinbase_is_refused() {
        let err = fee_script(Some(ADDRESS), 10_001, Network::Regtest).unwrap_err();
        assert!(err.contains("10000"), "{err}");
    }

    #[test]
    fn a_bad_address_is_refused_with_the_flag_named() {
        let err = fee_script(Some("not-an-address"), 0, Network::Regtest).unwrap_err();
        assert!(err.starts_with("--operator-fee"), "{err}");
    }
}
