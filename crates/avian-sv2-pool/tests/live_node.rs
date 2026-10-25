//! Starts a regtest `aviand`, runs the client against it, and asserts that
//! templates arrive for both algorithms.
//!
//! Skipped with a message when `aviand` cannot be found, so `cargo test` still
//! passes on a machine without a build. Point `AVIAND` and `AVIAN_CLI` at the
//! binaries, or leave them and `~/avian-build/bin` is used.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use avian_tdp::{authority, chain_subdir, PowType, SessionConfig, TdpSession};

/// Not a default port, so a node left running from manual testing does not
/// get connected to by accident. Each test gets its own pair, because cargo
/// runs them in parallel in one process.
const PORT_BASE: u16 = 18450;

fn binary(var: &str, name: &str) -> Option<PathBuf> {
    if let Ok(path) = std::env::var(var) {
        let path = PathBuf::from(path);
        return path.exists().then_some(path);
    }
    let path = PathBuf::from(std::env::var("HOME").unwrap_or_default())
        .join("avian-build/bin")
        .join(name);
    path.exists().then_some(path)
}

struct Node {
    process: Child,
    datadir: PathBuf,
    cli: PathBuf,
    sv2_port: u16,
    rpc_port: u16,
}

impl Node {
    fn start(aviand: &Path, cli: &Path, tag: &str, slot: u16) -> Node {
        let sv2_port = PORT_BASE + slot * 2;
        let rpc_port = PORT_BASE + slot * 2 + 1;
        let datadir =
            std::env::temp_dir().join(format!("avian-sv2-it-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&datadir);
        std::fs::create_dir_all(&datadir).expect("cannot create the datadir");

        let process = Command::new(aviand)
            .args([
                "-regtest",
                &format!("-datadir={}", datadir.display()),
                &format!("-rpcport={rpc_port}"),
                "-rpcuser=it",
                "-rpcpassword=it",
                "-sv2",
                &format!("-sv2bind=127.0.0.1:{sv2_port}"),
                "-sv2powalgo=x16rt",
                "-sv2powalgo=minotaurx",
                // Templates refresh on this cadence when the tip has not
                // moved, which is what makes the refresh assertion quick.
                "-sv2interval=2",
                "-debug=sv2",
                "-fallbackfee=0.0001",
                // Without this the node binds the regtest P2P port and
                // refuses to start if anything else already has it, which on
                // a developer machine is usually a node started by hand.
                "-listen=0",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("cannot start aviand");

        let mut node = Node {
            process,
            datadir,
            cli: cli.to_path_buf(),
            sv2_port,
            rpc_port,
        };
        node.wait_for_rpc();
        node
    }

    fn rpc(&self, args: &[&str]) -> Result<String, String> {
        let output = Command::new(&self.cli)
            .args([
                "-regtest",
                &format!("-datadir={}", self.datadir.display()),
                &format!("-rpcport={}", self.rpc_port),
                "-rpcuser=it",
                "-rpcpassword=it",
            ])
            .args(args)
            .output()
            .map_err(|e| e.to_string())?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
        }
    }

    fn wait_for_rpc(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(90);
        while Instant::now() < deadline {
            if self.rpc(&["getblockcount"]).is_ok() {
                return;
            }
            if let Ok(Some(status)) = self.process.try_wait() {
                panic!(
                    "aviand exited with {status} before answering RPC; its log is in {}/regtest/debug.log",
                    self.datadir.display()
                );
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        panic!("aviand never answered RPC");
    }

    /// The node refuses to build templates while it considers itself in
    /// initial block download, so the chain has to be moved off genesis first.
    fn mine(&self, blocks: u32) {
        self.rpc(&["createwallet", "it"]).expect("createwallet");
        let address = self.rpc(&["getnewaddress"]).expect("getnewaddress");
        self.rpc(&["generatetoaddress", &blocks.to_string(), &address])
            .expect("generatetoaddress");
    }

    fn authority(&self) -> secp256k1::XOnlyPublicKey {
        let path = authority::default_key_path(&self.datadir, chain_subdir("regtest"));
        authority::from_private_key_file(&path).expect("authority key")
    }

    fn addr(&self) -> SocketAddr {
        format!("127.0.0.1:{}", self.sv2_port).parse().unwrap()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.rpc(&["stop"]);
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            match self.process.try_wait() {
                Ok(Some(_)) => break,
                _ if Instant::now() > deadline => {
                    let _ = self.process.kill();
                    break;
                }
                _ => std::thread::sleep(Duration::from_millis(100)),
            }
        }
        let _ = std::fs::remove_dir_all(&self.datadir);
    }
}

#[test]
fn both_algorithms_receive_templates_from_a_live_node() {
    let (Some(aviand), Some(cli)) = (binary("AVIAND", "aviand"), binary("AVIAN_CLI", "avian-cli"))
    else {
        eprintln!("skipping: aviand or avian-cli not found, set AVIAND and AVIAN_CLI");
        return;
    };

    let node = Node::start(&aviand, &cli, "both-algos", 0);
    node.mine(101);
    let tip = node.rpc(&["getbestblockhash"]).expect("getbestblockhash");

    for pow in [PowType::X16rt, PowType::MinotaurX] {
        let mut config = SessionConfig::new(node.addr(), pow);
        // Verification, not trust on first use: the key file is right there.
        config.authority = Some(node.authority());
        config.timeout = Duration::from_secs(30);

        let mut session = TdpSession::open(&config).expect("session");
        assert!(session.identity().verified);
        assert_eq!(
            session.version_rolling_mask(),
            0,
            "doc/sv2.md pins this at 0"
        );

        let work = session.next_work().expect("work");
        assert_eq!(
            work.template.pow_type().expect("pow_type"),
            pow,
            "NewTemplate.version bits 16-23 must name the algorithm that was selected"
        );
        let prev = work.prev_hash.as_ref().expect("SetNewPrevHash");
        assert_eq!(
            avian_tdp::wire::hex_rev(&prev.prev_hash),
            tip,
            "the template must be built on the current tip"
        );
        assert_eq!(work.constraints.template_id, work.template.template_id);
        assert_eq!(
            work.constraints.ntime_min, prev.ntime_start,
            "doc/sv2.md guarantees these agree"
        );
        // Regtest allows minimum-difficulty blocks, which makes nBits a
        // function of nTime, so the node pins the window rather than narrowing
        // it.
        assert_eq!(work.constraints.ntime_min, work.constraints.ntime_max);
        assert!(work.constraints.within_one_epoch());

        let data = session
            .request_transaction_data(work.template.template_id)
            .expect("RequestTransactionData");
        assert_eq!(data.template_id, work.template.template_id);

        let unknown = session.request_transaction_data(work.template.template_id + 1000);
        match unknown {
            Err(avian_tdp::Error::Refused(message)) => {
                assert!(
                    message.contains("template-id-not-found"),
                    "unexpected refusal: {message}"
                );
            }
            other => panic!("an unknown template id should be refused, got {other:?}"),
        }
    }
}

#[test]
fn a_tip_change_pushes_fresh_work() {
    let (Some(aviand), Some(cli)) = (binary("AVIAND", "aviand"), binary("AVIAN_CLI", "avian-cli"))
    else {
        eprintln!("skipping: aviand or avian-cli not found, set AVIAND and AVIAN_CLI");
        return;
    };

    let node = Node::start(&aviand, &cli, "tip-change", 1);
    node.mine(101);

    let mut config = SessionConfig::new(node.addr(), PowType::X16rt);
    config.authority = Some(node.authority());
    let mut session = TdpSession::open(&config).expect("session");

    let first = session.next_work().expect("first round");
    let address = node.rpc(&["getnewaddress"]).expect("getnewaddress");
    node.rpc(&["generatetoaddress", "1", &address])
        .expect("generatetoaddress");
    let tip = node.rpc(&["getbestblockhash"]).expect("getbestblockhash");

    // The node refreshes on an interval as well as on a tip change, so read
    // until the round that carries the new tip rather than assuming it is the
    // next one.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        assert!(Instant::now() < deadline, "no round carried the new tip");
        let work = session.next_work().expect("round");
        let prev = work.prev_hash.as_ref().expect("SetNewPrevHash");
        if avian_tdp::wire::hex_rev(&prev.prev_hash) == tip {
            assert!(work.tip_changed);
            assert_ne!(work.template.template_id, first.template.template_id);
            break;
        }
        // Until then every round is an in-place refresh on the old tip, and
        // aviand sends SetNewPrevHash on those too, which is what the
        // tip_changed flag exists to tell apart.
        assert!(!work.tip_changed);
    }
}
