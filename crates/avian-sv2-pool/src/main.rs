//! Stage 2 of the Avian Stratum v2 pool: the Template Distribution client.
//!
//! Opens one Template Distribution connection per algorithm, because one
//! connection carries one `nBits` and `target` stream, and prints every round
//! of work that arrives on each.
//!
//! No Mining Protocol, no channels, no shares, no payouts. Each algorithm's
//! state lives in its own [`AlgoContext`], which is the seam a Stage 3 Mining
//! Protocol server attaches to.

use std::io::Write;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use avian_tdp::avian::TimeConstraints;
use avian_tdp::tdp::PrevHash;
use avian_tdp::wire::hex_rev;
use avian_tdp::{authority, chain_subdir, default_port, PowType, SessionConfig, TdpSession, Work};
use secp256k1::XOnlyPublicKey;

struct Options {
    addr: SocketAddr,
    algorithms: Vec<PowType>,
    authority: Option<XOnlyPublicKey>,
    transaction_data: bool,
    /// How long to keep reading refreshed templates. `None` runs until killed.
    duration: Option<Duration>,
    coinbase_size: u32,
    coinbase_sigops: u16,
}

const USAGE: &str = "\
avian-sv2-pool: the Template Distribution half of an Avian Stratum v2 pool

  --datadir <path>       the node's datadir, to read sv2_authority_key from
  --chain <name>         regtest (default), main, test, testnet4, signet
  --connect <host:port>  default: 127.0.0.1 and the chain's Sv2 port
  --authority <hex>      the authority x-only public key, instead of a datadir
  --insecure-tofu        connect without verifying the server certificate
  --algo <name>          x16rt or minotaurx; repeatable, default: both
  --no-transaction-data  skip the RequestTransactionData round
  --duration <seconds>   stop after this long; default: run until killed
  --coinbase-size <n>    coinbase_output_max_additional_size, default 1000
  --coinbase-sigops <n>  coinbase_output_max_additional_sigops, default 10
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

    if !options.addr.ip().is_loopback() {
        eprintln!(
            "refusing to connect to {}: this client is loopback only",
            options.addr
        );
        std::process::exit(2);
    }

    if let Err(message) = run(options) {
        eprintln!("{message}");
        std::process::exit(1);
    }
}

/// Everything one algorithm needs, kept apart from everything the other needs.
///
/// Avian's two algorithms have independent difficulty, independent targets and
/// independent job streams, so nothing here is shared. Stage 3 adds the mining
/// channels for an algorithm to its own context.
struct AlgoContext {
    pow: PowType,
    session: TdpSession,
    rounds: u64,
    tip_changes: u64,
    current: Option<Work>,
}

impl AlgoContext {
    fn open(config: &SessionConfig) -> avian_tdp::Result<Self> {
        Ok(Self {
            pow: config.pow,
            session: TdpSession::open(config)?,
            rounds: 0,
            tip_changes: 0,
            current: None,
        })
    }

    fn label(&self) -> &'static str {
        self.pow.name()
    }
}

fn run(options: Options) -> Result<(), String> {
    println!(
        "connecting to {} for {} algorithm(s)",
        options.addr,
        options.algorithms.len()
    );
    if options.authority.is_none() {
        println!(
            "WARNING: trust on first use. The session is encrypted, but nothing says the peer \
             is the node you meant."
        );
    }

    // One connection per algorithm, each on its own thread, reporting into one
    // channel so the output interleaves the way the wire does.
    let (tx, rx) = mpsc::channel::<Report>();
    let deadline = options.duration.map(|d| Instant::now() + d);
    let mut handles = Vec::new();

    for pow in &options.algorithms {
        let mut config = SessionConfig::new(options.addr, *pow);
        config.authority = options.authority;
        config.coinbase_output_max_additional_size = options.coinbase_size;
        config.coinbase_output_max_additional_sigops = options.coinbase_sigops;
        let tx = tx.clone();
        let transaction_data = options.transaction_data;
        handles.push(std::thread::spawn(move || {
            pump(config, tx, transaction_data, deadline)
        }));
    }
    drop(tx);

    let mut out = std::io::stdout().lock();
    let mut failures = Vec::new();
    for report in rx {
        match report {
            Report::Line(line) => {
                let _ = writeln!(out, "{line}");
                let _ = out.flush();
            }
            Report::Failed(pow, message) => failures.push(format!("{pow}: {message}")),
        }
    }
    for handle in handles {
        let _ = handle.join();
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}

enum Report {
    Line(String),
    Failed(PowType, String),
}

fn pump(
    config: SessionConfig,
    tx: mpsc::Sender<Report>,
    transaction_data: bool,
    deadline: Option<Instant>,
) {
    let say = |line: String| {
        let _ = tx.send(Report::Line(line));
    };

    let mut context = match AlgoContext::open(&config) {
        Ok(context) => context,
        Err(e) => {
            let _ = tx.send(Report::Failed(config.pow, e.to_string()));
            return;
        }
    };

    say(format!(
        "[{}] session open: protocol {} negotiated, extension 0x4001 accepted, \
         version_rolling_mask 0x{:08x}, certificate {}",
        context.label(),
        avian_tdp::PROTOCOL_VERSION,
        context.session.version_rolling_mask(),
        if context.session.identity().verified {
            "verified against the authority key"
        } else {
            "accepted on first use"
        }
    ));

    loop {
        if let Some(deadline) = deadline {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            // Without this a session on a quiet chain would block past the
            // deadline waiting for a refresh that is not due yet.
            if context.session.set_read_timeout(Some(left)).is_err() {
                break;
            }
        }

        let work = match context.session.next_work() {
            Ok(work) => work,
            Err(e) => {
                if deadline.is_some() && is_timeout(&e) {
                    break;
                }
                let _ = tx.send(Report::Failed(context.pow, e.to_string()));
                return;
            }
        };

        context.rounds += 1;
        if work.tip_changed {
            context.tip_changes += 1;
        }
        say(render(&context, &work));

        if transaction_data && context.rounds == 1 {
            match context
                .session
                .request_transaction_data(work.template.template_id)
            {
                Ok(data) => say(indent(context.label(), &data.to_string())),
                Err(e) => say(format!("[{}] {e}", context.label())),
            }
        }
        context.current = Some(work);
    }

    say(format!(
        "[{}] closing after {} round(s), {} of them on a new tip",
        context.label(),
        context.rounds,
        context.tip_changes
    ));
}

fn render(context: &AlgoContext, work: &Work) -> String {
    let mut out = format!(
        "\n[{}] round {} — {}\n",
        context.label(),
        context.rounds,
        if work.tip_changed {
            "the tip moved"
        } else {
            "in-place refresh on the same tip"
        }
    );
    out.push_str(&indent(context.label(), &work.template.to_string()));

    match work.template.pow_type() {
        Ok(pow) if pow == context.pow => out.push_str(&format!(
            "\n[{}]   version bits 16-23 say {pow}, which is what was selected\n",
            context.label()
        )),
        Ok(pow) => out.push_str(&format!(
            "\n[{}]   MISMATCH: version bits 16-23 say {pow}, but {} was selected\n",
            context.label(),
            context.pow
        )),
        Err(e) => out.push_str(&format!("\n[{}]   {e}\n", context.label())),
    }

    if let Some(prev) = &work.prev_hash {
        out.push_str(&indent(context.label(), &prev.to_string()));
        out.push('\n');
    } else if let Some(tip) = context.session.tip() {
        out.push_str(&format!(
            "[{}]   still on tip {}\n",
            context.label(),
            hex_rev(&tip.prev_hash)
        ));
    }

    out.push_str(&indent(context.label(), &work.constraints.to_string()));
    out.push_str(&describe_window(context, work));
    out
}

/// What the ntime window means for this algorithm and chain.
fn describe_window(context: &AlgoContext, work: &Work) -> String {
    let TimeConstraints {
        ntime_min,
        ntime_max,
        ..
    } = work.constraints;
    let mut notes = Vec::new();
    if ntime_min == ntime_max {
        // Regtest and testnet allow minimum-difficulty blocks, which makes
        // nBits a function of nTime, so the node pins the window rather than
        // narrowing it.
        notes.push("pinned shut: ntime must be submitted exactly as given".to_string());
    } else {
        notes.push(format!("{} seconds of ntime room", ntime_max - ntime_min));
    }
    if context.pow == PowType::X16rt && !work.constraints.within_one_epoch() {
        notes.push(
            "WARNING: the window crosses a 128-second X16RT epoch boundary, which would change \
             the hash chain"
                .to_string(),
        );
    }
    if let Some(prev) = &work.prev_hash {
        notes.push(agreement(prev, &work.constraints));
    }
    format!("\n[{}]   {}\n", context.label(), notes.join("; "))
}

/// doc/sv2.md guarantees `ntime_min` equals the `ntime_start` of the
/// `SetNewPrevHash` for the same template, so a pool can narrow from it.
fn agreement(prev: &PrevHash, constraints: &TimeConstraints) -> String {
    if prev.ntime_start == constraints.ntime_min {
        "ntime_min agrees with SetNewPrevHash.ntime_start".to_string()
    } else {
        format!(
            "MISMATCH: SetNewPrevHash.ntime_start is {} but ntime_min is {}",
            prev.ntime_start, constraints.ntime_min
        )
    }
}

fn indent(label: &str, text: &str) -> String {
    text.lines()
        .map(|line| format!("[{label}]   {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn is_timeout(e: &avian_tdp::Error) -> bool {
    match e {
        avian_tdp::Error::Io(io) => matches!(
            io.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
        _ => false,
    }
}

fn parse_args() -> Result<Option<Options>, String> {
    let mut datadir: Option<PathBuf> = None;
    let mut chain = "regtest".to_string();
    let mut connect: Option<String> = None;
    let mut authority_hex: Option<String> = None;
    let mut insecure = false;
    let mut algorithms: Vec<PowType> = Vec::new();
    let mut transaction_data = true;
    let mut duration = None;
    let mut coinbase_size = 1000u32;
    let mut coinbase_sigops = 10u16;

    let mut args = std::env::args().skip(1).peekable();
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
            "--no-transaction-data" => transaction_data = false,
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

    let target = connect.unwrap_or_else(|| format!("127.0.0.1:{}", default_port(&chain)));
    let addr = target
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {target}: {e}"))?
        .next()
        .ok_or_else(|| format!("{target} resolved to nothing"))?;

    // Verification is the default. Trust on first use has to be asked for.
    let authority = match (&authority_hex, &datadir) {
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
                "no authority key: pass --datadir or --authority, or --insecure-tofu to connect \
                 without verifying the server certificate"
                    .to_string(),
            )
        }
    };

    // Fail with a clear message rather than part way through a handshake.
    TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|e| format!("nothing is listening on {addr}: {e}"))?;

    Ok(Some(Options {
        addr,
        algorithms,
        authority,
        transaction_data,
        duration,
        coinbase_size,
        coinbase_sigops,
    }))
}
