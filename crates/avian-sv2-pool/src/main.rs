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
//! No accounting, no payout ledger, no persistence, no vardiff, no web or
//! stats services, no Stratum v1.

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
}

const DEFAULT_TAG: &str = "/avian-sv2/";

const USAGE: &str = "\
avian-sv2-pool: an Avian Stratum v2 solo pool

A worker puts its own payout address in user_identity when it opens a channel,
as `address` or `address.workername`, and the coinbase pays it directly. An
address that does not parse, or belongs to another network, refuses the
channel. There is no fallback address, by design.

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
    println!("[pool] proof of work: {}", hasher.describe());
    if hasher.hash(PowType::X16rt, &[0u8; 80]).is_none() {
        return Err(
            "the proof-of-work hashers are not available, so no share could be validated. \
             Rebuild with AVIAN_SRC pointing at the Avian Core src directory."
                .into(),
        );
    }

    println!(
        "[pool] solo on {}: a worker's own address is paid, from user_identity at channel open",
        options.network
    );
    if options.fee_basis_points > 0 {
        println!(
            "[pool] operator fee {}.{:02}%",
            options.fee_basis_points / 100,
            options.fee_basis_points % 100
        );
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

    println!(
        "[pool] serving the Mining Protocol on {} for {} algorithm(s)",
        handle.mining_addr(),
        options.algorithms.len()
    );

    // Held for as long as the pool runs; dropping it stops the listener.
    let _stats = match options.stats_bind {
        Some(bind) => {
            let algos: Vec<_> = handle.algos().to_vec();
            let started_at = handle.started_at();
            let published_key = address::encode_authority_key(&pool_pubkey);
            let handle = stats::serve(bind, move || {
                Snapshot::gather(started_at, &algos, published_key.clone())
            })
                .map_err(|e| format!("--stats-bind {bind}: {e}"))?;
            println!(
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
    println!(
        "[pool] authority public key, base58 (Stratum v2 miner configuration):\n    {}",
        address::encode_authority_key(&pool_pubkey)
    );
    println!(
        "[pool] authority public key, hex (32-byte x-only):\n    {}",
        hex(&pool_pubkey.serialize())
    );

    handle.join();
    Ok(())
}

fn print_round(pow: PowType, work: &Work, verbose: bool) {
    println!(
        "[{pow}] template {} — {}",
        work.template.template_id,
        if work.tip_changed {
            "the tip moved"
        } else {
            "in-place refresh on the same tip"
        }
    );
    if verbose {
        println!("{}", work.template);
        if let Some(prev) = &work.prev_hash {
            println!("{prev}");
        }
        println!("{}", work.constraints);
    } else if let Some(prev) = &work.prev_hash {
        println!(
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
    println!("[pool] generated a new authority key in {}", path.display());
    Ok(Keypair::from_secret_key(&secp, &secret))
}

fn parse_args() -> Result<Option<Options>, String> {
    let mut datadir: Option<PathBuf> = None;
    let mut chain = "regtest".to_string();
    let mut connect: Option<String> = None;
    let mut authority_hex: Option<String> = None;
    let mut insecure = false;
    let mut algorithms: Vec<PowType> = Vec::new();
    let mut mining_bind = "127.0.0.1:34254".to_string();
    let mut stats_bind: Option<String> = None;
    let mut allow_public_bind = false;
    let mut pool_key = PathBuf::from("avian-pool-authority-key");
    let mut fee_address: Option<String> = None;
    let mut fee_basis_points = 0u32;
    let mut coinbase_tag = DEFAULT_TAG.to_string();
    // Four and a half a minute: often enough that a dashboard shows
    // something within a minute of a worker connecting, rare enough that the
    // pool spends a hash per share without noticing.
    let mut shares_per_minute = 4.5f64;
    let mut min_hash_rate = 1000.0f64;
    let mut max_hash_rate = 1e12f64;
    let mut rate_limit = RateLimitConfig::default();
    let mut verbose = false;
    let mut duration = None;
    let mut coinbase_size = 1000u32;
    let mut coinbase_sigops = 10u16;

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

    // Refused here rather than when the node silently rejects the block: the
    // Template Distribution Protocol has no SubmitSolution.Error.
    let coinbase_tag = coinbase_tag.into_bytes();
    if coinbase_tag.len() > MAX_COINBASE_TAG {
        return Err(format!(
            "--coinbase-tag is {} bytes and the most that always fits is {MAX_COINBASE_TAG}",
            coinbase_tag.len()
        ));
    }

    let fee_script = match &fee_address {
        Some(text) => {
            let address = Address::decode(text, network)
                .map_err(|e| format!("--operator-fee {text:?}: {e}"))?;
            if fee_basis_points == 0 {
                return Err(
                    "--operator-fee was given with no --operator-fee-bp, so the fee would be \
                     zero and the address unused"
                        .into(),
                );
            }
            address.script_pubkey()
        }
        None => {
            if fee_basis_points > 0 {
                return Err(
                    "--operator-fee-bp was given with no --operator-fee address to pay it to"
                        .into(),
                );
            }
            Vec::new()
        }
    };
    if fee_basis_points > 10_000 {
        return Err("--operator-fee-bp cannot exceed 10000, which is the whole coinbase".into());
    }

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
        eprintln!(
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
    }))
}

fn resolve(target: &str) -> Result<SocketAddr, String> {
    target
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {target}: {e}"))?
        .next()
        .ok_or_else(|| format!("{target} resolved to nothing"))
}
