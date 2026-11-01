//! The Avian Stratum v2 bridge.
//!
//! Upstream it is a Stratum v1 client, one connection per miner, to a pool
//! the operator already runs. Downstream it is the same Mining Protocol
//! server the solo pool presents. It holds nothing and credits nobody; see
//! the library's docs and doc/design.md for what that buys and what it
//! cannot.

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use avian_mining::ratelimit::RateLimitConfig;
use avian_mining::share::PowHasher;
use avian_sv1::difficulty;
use avian_sv2::address;
use avian_sv2::wire::hex;
use avian_sv2_bridge::server::{Bridge, BridgeConfig};
use avian_tdp::PowType;
use secp256k1::{Keypair, Secp256k1, SecretKey};

struct Options {
    upstreams: Vec<(PowType, SocketAddr)>,
    chain: String,
    password: String,
    ntime_roll: u32,
    first_work_timeout: Duration,
    upstream_idle_timeout: Option<Duration>,
    mining_bind: SocketAddr,
    pool_authority_key: PathBuf,
    allow_public_bind: bool,
    min_hash_rate: f64,
    max_hash_rate: f64,
    rate_limit: RateLimitConfig,
    duration: Option<Duration>,
}

const USAGE: &str = "\
avian-sv2-bridge: a Stratum v2 front for an Avian Stratum v1 pool

Miners connect here exactly as they would to the solo pool. Each one gets its
own Stratum v1 connection to the pool, opened in the name it put in
user_identity, and its shares are forwarded and judged by the pool. The bridge
holds nothing, credits nothing and keeps no ledger: the pool's accounting is
untouched by it.

Upstream, to the pool:
  --upstream <algo>=<host:port>
                         the pool's Stratum v1 port for x16rt or minotaurx.
                         Repeatable; at least one. A miner can only select
                         an algorithm that has one
  --chain <name>         main (default), test or regtest: which proof-of-work
                         limit the pool's difficulty is relative to
  --password <text>      sent in mining.authorize for every worker
                         (default: x)
  --ntime-roll <seconds> how far past a job's ntime a miner may roll
                         (default 0, which pins it: the pool's own rule for
                         ntime is not published and a share refused for
                         rolling is a share wasted)
  --first-work-timeout <seconds>
                         how long to wait for the pool's first job before
                         refusing the channel (default 30)
  --upstream-idle-timeout <seconds>
                         silence from the pool treated as a dead connection
                         (default 300; 0 waits for ever)

Downstream, to miners:
  --mining-bind <addr>   where to serve the Mining Protocol
                         (default 127.0.0.1:34254, loopback only)
  --pool-key <file>      the bridge's authority private key, generated on
                         first run (default: ./avian-bridge-authority-key)
  --allow-public-bind    permit --mining-bind on an address that is not
                         loopback. Needed inside a container
  --min-hash-rate <n>    the slowest worker to believe, in hashes a second
                         (default 1000). Only the submission limiter is sized
                         from a worker's declaration here; the target is the
                         pool's
  --max-hash-rate <n>    and the fastest (default 1e12)

Submission limits, per channel:
  --share-rate-tolerance <n>   multiple of the expected rate, default 8
  --max-invalid-shares <n>     invalid submissions, by the pool's verdict or
                               this bridge's, before the channel is dropped,
                               default 50

  --duration <seconds>   stop after this long; default: run until killed
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
        .map_err(|e| format!("bridge authority key: {e}"))?;
    let (pubkey, _) = authority.x_only_public_key();

    let hasher: Arc<dyn PowHasher> = hasher();
    println!("[bridge] proof of work: {}", hasher.describe());
    if hasher.hash(PowType::X16rt, &[0u8; 80]).is_none() {
        println!(
            "[bridge] shares are checked for everything but the hash here; the pool judges the \
             hash"
        );
    }

    let algorithms: Vec<String> = options
        .upstreams
        .iter()
        .map(|(pow, addr)| format!("{pow} at {addr}"))
        .collect();
    println!(
        "[bridge] in front of {} on {}: {}",
        if algorithms.len() == 1 {
            "one pool"
        } else {
            "pools"
        },
        options.chain,
        algorithms.join(", ")
    );

    let bridge = Arc::new(
        Bridge::new(
            BridgeConfig {
                bind: options.mining_bind,
                authority,
                cert_validity: avian_sv2::transport::DEFAULT_CERT_VALIDITY_SECS,
                allow_public_bind: options.allow_public_bind,
                upstreams: options.upstreams,
                pow_limit: difficulty::pow_limit(&options.chain),
                password: options.password,
                upstream_idle_timeout: options.upstream_idle_timeout,
                first_work_timeout: options.first_work_timeout,
                ntime_roll: options.ntime_roll,
                min_hash_rate: options.min_hash_rate,
                max_hash_rate: options.max_hash_rate,
                rate_limit: options.rate_limit,
            },
            hasher,
        )
        .map_err(|e| e.to_string())?,
    );
    let handle = bridge.listen().map_err(|e| e.to_string())?;
    println!("[bridge] serving the Mining Protocol on {}", handle.addr());
    // Both forms, for the solo pool's reason: the two miner stacks present
    // x-only keys differently, and an operator who publishes the wrong one
    // has a bridge nobody can connect to.
    println!(
        "[bridge] authority public key, base58 (Stratum v2 miner configuration):\n    {}",
        address::encode_authority_key(&pubkey)
    );
    println!(
        "[bridge] authority public key, hex (32-byte x-only):\n    {}",
        hex(&pubkey.serialize())
    );

    match options.duration {
        Some(duration) => std::thread::sleep(duration),
        None => loop {
            std::thread::park();
        },
    }
    drop(handle);
    Ok(())
}

#[cfg(feature = "pow")]
fn hasher() -> Arc<dyn PowHasher> {
    Arc::new(avian_mining::share::AvianHasher)
}

/// Without the feature the bridge checks a share's metadata and leaves the
/// hash to the pool, which is the design: no Avian sources, no C++ toolchain.
#[cfg(not(feature = "pow"))]
fn hasher() -> Arc<dyn PowHasher> {
    Arc::new(avian_mining::share::MetadataOnlyHasher)
}

/// Reads the bridge's authority private key, creating it on first run. The
/// same file format and permissions as the solo pool's, so a key can move
/// between the two.
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
    println!(
        "[bridge] generated a new authority key in {}",
        path.display()
    );
    Ok(Keypair::from_secret_key(&secp, &secret))
}

fn parse_args() -> Result<Option<Options>, String> {
    let mut upstreams: Vec<(PowType, SocketAddr)> = Vec::new();
    let mut chain = "main".to_string();
    let mut password = "x".to_string();
    let mut ntime_roll = 0u32;
    let mut first_work_timeout = Duration::from_secs(30);
    let mut upstream_idle_timeout = Some(Duration::from_secs(300));
    let mut mining_bind = "127.0.0.1:34254".to_string();
    let mut pool_key = PathBuf::from("avian-bridge-authority-key");
    let mut allow_public_bind = false;
    let mut min_hash_rate = 1000.0f64;
    let mut max_hash_rate = 1e12f64;
    let mut rate_limit = RateLimitConfig::default();
    let mut duration = None;

    let mut args = std::env::args().skip(1);
    while let Some(whole) = args.next() {
        // --option=value as well as --option value, as the solo pool takes.
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
        macro_rules! number {
            ($type:ty) => {
                value!()
                    .parse::<$type>()
                    .map_err(|_| format!("{arg} wants a number"))?
            };
        }
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(None);
            }
            "--upstream" => {
                // `--upstream=x16rt=host:port` splits at the first `=` above,
                // leaving `x16rt=host:port` as the value, which is what the
                // two-argument form gives too.
                let spec = value!();
                let (name, target) = spec
                    .split_once('=')
                    .ok_or_else(|| format!("--upstream wants <algo>=<host:port>, not {spec:?}"))?;
                let pow =
                    PowType::parse(name).ok_or_else(|| format!("unknown algorithm {name}"))?;
                let addr = resolve(target)?;
                if upstreams.iter().any(|(given, _)| *given == pow) {
                    return Err(format!("--upstream was given twice for {pow}"));
                }
                upstreams.push((pow, addr));
            }
            "--chain" => chain = value!(),
            "--password" => password = value!(),
            "--ntime-roll" => ntime_roll = number!(u32),
            "--first-work-timeout" => first_work_timeout = Duration::from_secs(number!(u64)),
            "--upstream-idle-timeout" => {
                let seconds = number!(u64);
                upstream_idle_timeout = (seconds > 0).then(|| Duration::from_secs(seconds));
            }
            "--mining-bind" => mining_bind = value!(),
            "--pool-key" => pool_key = PathBuf::from(value!()),
            "--allow-public-bind" => allow_public_bind = true,
            "--min-hash-rate" => min_hash_rate = number!(f64),
            "--max-hash-rate" => max_hash_rate = number!(f64),
            "--share-rate-tolerance" => rate_limit.tolerance = number!(f64),
            "--max-invalid-shares" => rate_limit.max_invalid = number!(u32),
            "--duration" => duration = Some(Duration::from_secs(number!(u64))),
            other => return Err(format!("unknown argument {other}")),
        }
    }

    if upstreams.is_empty() {
        return Err("at least one --upstream <algo>=<host:port> is needed".into());
    }
    match chain.as_str() {
        "main" | "mainnet" | "test" | "testnet" | "testnet4" | "signet" | "regtest" => {}
        other => return Err(format!("unknown chain {other}")),
    }

    let mining_bind = resolve(&mining_bind)?;
    if !mining_bind.ip().is_loopback() && !allow_public_bind {
        return Err(format!(
            "refusing to bind {mining_bind}: loopback only without --allow-public-bind"
        ));
    }
    if allow_public_bind {
        eprintln!(
            "[bridge] --allow-public-bind: the mining port may be on a non-loopback address. \
             Publish that port and nothing else."
        );
    }
    // Connecting out is not restricted: the pool is somewhere else by
    // definition, which is the difference from the solo pool's node.

    Ok(Some(Options {
        upstreams,
        chain,
        password,
        ntime_roll,
        first_work_timeout,
        upstream_idle_timeout,
        mining_bind,
        pool_authority_key: pool_key,
        allow_public_bind,
        min_hash_rate,
        max_hash_rate,
        rate_limit,
        duration,
    }))
}

fn resolve(target: &str) -> Result<SocketAddr, String> {
    target
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {target}: {e}"))?
        .next()
        .ok_or_else(|| format!("{target} resolved to nothing"))
}
