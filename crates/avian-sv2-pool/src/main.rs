//! The Avian Stratum v2 pool.
//!
//! Upstream it is a Template Distribution client, one connection per
//! algorithm, because one connection carries one `nBits` and `target` stream.
//! Downstream it is a Mining Protocol server, one standard channel per worker.
//! The two meet in an `AlgoContext` per algorithm: the thread that received a
//! template pushes a job onto every channel mining that algorithm, and the
//! thread reading from a worker answers its submissions and sends a winning
//! one back up as a `SubmitSolution`.
//!
//! No payouts, no share accounting beyond what validation needs, no vardiff,
//! no extended channels, no job declaration, no Stratum v1.

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use avian_mining::server::{AlgoContext, Server, ServerConfig};
use avian_mining::share::{AvianHasher, PowHasher};
use avian_tdp::avian::TimeConstraints;
use avian_tdp::tdp::PrevHash;
use avian_tdp::wire::{hex, hex_rev};
use avian_tdp::{authority, chain_subdir, default_port, PowType, SessionConfig, TdpSession, Work};
use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

struct Options {
    node: SocketAddr,
    mining_bind: SocketAddr,
    algorithms: Vec<PowType>,
    node_authority: Option<XOnlyPublicKey>,
    pool_authority_key: PathBuf,
    payout_script: Vec<u8>,
    share_target_shift: u32,
    verbose: bool,
    duration: Option<Duration>,
    coinbase_size: u32,
    coinbase_sigops: u16,
}

const USAGE: &str = "\
avian-sv2-pool: an Avian Stratum v2 pool

Upstream, to the node:
  --datadir <path>       the node's datadir, to read sv2_authority_key from
  --chain <name>         regtest (default), main, test, testnet4, signet
  --connect <host:port>  default: 127.0.0.1 and the chain's Sv2 port
  --authority <hex>      the node's authority x-only public key
  --insecure-tofu        connect without verifying the node's certificate
  --coinbase-size <n>    coinbase_output_max_additional_size, default 1000
  --coinbase-sigops <n>  coinbase_output_max_additional_sigops, default 10

Downstream, to workers:
  --mining-bind <addr>   where to serve the Mining Protocol
                         (default 127.0.0.1:34254, loopback only)
  --pool-key <file>      the pool's authority private key, generated on first
                         run (default: ./avian-pool-authority-key)
  --payout-script <hex>  scriptPubKey the pool pays itself (default 51, OP_TRUE)
  --share-target-shift   halvings below the network target for the share
                         target; 0 (default) makes them the same

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
    if !avian_pow::AVAILABLE {
        return Err(
            "the proof-of-work hashers are not available, so no share could be validated. \
             Rebuild with AVIAN_SRC pointing at the Avian Core src directory."
                .into(),
        );
    }

    // One Template Distribution session per algorithm, opened before the
    // listener so a worker never arrives to find no target to set.
    let mut algos = Vec::new();
    let mut sessions = Vec::new();
    for pow in &options.algorithms {
        let mut config = SessionConfig::new(options.node, *pow);
        config.authority = options.node_authority;
        config.coinbase_output_max_additional_size = options.coinbase_size;
        config.coinbase_output_max_additional_sigops = options.coinbase_sigops;

        let session = TdpSession::open(&config).map_err(|e| format!("{pow}: {e}"))?;
        println!(
            "[pool] {pow}: session open, extension 0x4001 accepted, version_rolling_mask \
             0x{:08x}, node certificate {}",
            session.version_rolling_mask(),
            if session.identity().verified {
                "verified"
            } else {
                "accepted on first use"
            }
        );
        let algo = Arc::new(AlgoContext::new(*pow, session.submitter()));
        algos.push(algo.clone());
        sessions.push((session, algo));
    }

    let server = Arc::new(Server::new(
        ServerConfig {
            bind: options.mining_bind,
            authority,
            cert_validity: avian_tdp::transport::DEFAULT_CERT_VALIDITY_SECS,
            payout_script: options.payout_script.clone(),
            share_target_shift: options.share_target_shift,
        },
        algos,
        hasher,
    ));

    // The first round of work has to be in hand before a worker can be told a
    // target, so pull one per algorithm before the listener opens.
    for (session, algo) in &mut sessions {
        let work = session.next_work().map_err(|e| e.to_string())?;
        report(&options, algo.pow, &work);
        for (id, e) in algo.publish(work) {
            eprintln!("[pool] channel {id}: {e}");
        }
    }

    let handle = server
        .clone()
        .listen()
        .map_err(|e| format!("mining listener: {e}"))?;
    println!(
        "[pool] serving the Mining Protocol on {} for {} algorithm(s)",
        handle.addr(),
        options.algorithms.len()
    );
    println!(
        "[pool] pool authority public key {}",
        hex(&pool_pubkey.serialize())
    );

    let deadline = options.duration.map(|d| std::time::Instant::now() + d);
    let mut threads = Vec::new();
    for (mut session, algo) in sessions {
        let verbose = options.verbose;
        threads.push(std::thread::spawn(move || {
            loop {
                if let Some(deadline) = deadline {
                    let left = deadline.saturating_duration_since(std::time::Instant::now());
                    if left.is_zero() {
                        return;
                    }
                    if session.set_read_timeout(Some(left)).is_err() {
                        return;
                    }
                }
                let work = match session.next_work() {
                    Ok(work) => work,
                    Err(e) => {
                        // Past the deadline any failure is the deadline, since
                        // the read timeout is what fired.
                        if deadline.is_some_and(|d| std::time::Instant::now() >= d) {
                            return;
                        }
                        eprintln!("[pool] {}: {e}", algo.pow);
                        return;
                    }
                };
                print_round(algo.pow, &work, verbose);
                for (id, e) in algo.publish(work) {
                    eprintln!("[pool] {} channel {id}: {e}", algo.pow);
                }
            }
        }));
    }
    for thread in threads {
        let _ = thread.join();
    }
    Ok(())
}

fn report(options: &Options, pow: PowType, work: &Work) {
    print_round(pow, work, options.verbose);
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
/// Mode 0600, like the node's own key files. The public half is what a worker
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

fn unhex(text: &str) -> Result<Vec<u8>, String> {
    if text.len() % 2 != 0 {
        return Err("hex needs an even number of characters".into());
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).map_err(|_| "not hex".to_string()))
        .collect()
}

fn parse_args() -> Result<Option<Options>, String> {
    let mut datadir: Option<PathBuf> = None;
    let mut chain = "regtest".to_string();
    let mut connect: Option<String> = None;
    let mut authority_hex: Option<String> = None;
    let mut insecure = false;
    let mut algorithms: Vec<PowType> = Vec::new();
    let mut mining_bind = "127.0.0.1:34254".to_string();
    let mut pool_key = PathBuf::from("avian-pool-authority-key");
    let mut payout_script = vec![0x51u8]; // OP_TRUE
    let mut share_target_shift = 0u32;
    let mut verbose = false;
    let mut duration = None;
    let mut coinbase_size = 1000u32;
    let mut coinbase_sigops = 10u16;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        macro_rules! value {
            () => {
                args.next().ok_or_else(|| format!("{arg} needs a value"))?
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
            "--pool-key" => pool_key = PathBuf::from(value!()),
            "--payout-script" => payout_script = unhex(&value!())?,
            "--share-target-shift" => {
                share_target_shift = value!()
                    .parse()
                    .map_err(|_| "--share-target-shift wants a number")?
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
    if payout_script.is_empty() {
        return Err("--payout-script cannot be empty".into());
    }

    let target = connect.unwrap_or_else(|| format!("127.0.0.1:{}", default_port(&chain)));
    let node = resolve(&target)?;
    let mining_bind = resolve(&mining_bind)?;

    if !node.ip().is_loopback() {
        return Err(format!("refusing to connect to {node}: loopback only"));
    }
    if !mining_bind.ip().is_loopback() {
        return Err(format!("refusing to bind {mining_bind}: loopback only"));
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
        algorithms,
        node_authority,
        pool_authority_key: pool_key,
        payout_script,
        share_target_shift,
        verbose,
        duration,
        coinbase_size,
        coinbase_sigops,
    }))
}

fn resolve(target: &str) -> Result<SocketAddr, String> {
    target
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {target}: {e}"))?
        .next()
        .ok_or_else(|| format!("{target} resolved to nothing"))
}
