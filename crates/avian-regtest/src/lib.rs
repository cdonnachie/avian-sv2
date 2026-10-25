//! Starts a regtest `aviand` for integration tests.
//!
//! Test support, not a product. It exists so the tests in more than one crate
//! can share one correct way of starting a node, because getting it wrong is
//! silent: a node still in initial block download refuses to build templates
//! and says nothing about it.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use secp256k1::XOnlyPublicKey;

/// Finds a binary from an environment variable, else `~/avian-build/bin`.
pub fn binary(var: &str, name: &str) -> Option<PathBuf> {
    if let Ok(path) = std::env::var(var) {
        let path = PathBuf::from(path);
        return path.exists().then_some(path);
    }
    let path = PathBuf::from(std::env::var("HOME").unwrap_or_default())
        .join("avian-build/bin")
        .join(name);
    path.exists().then_some(path)
}

/// `aviand` and `avian-cli`, or `None` if either is missing.
pub fn binaries() -> Option<(PathBuf, PathBuf)> {
    Some((
        binary("AVIAND", "aviand")?,
        binary("AVIAN_CLI", "avian-cli")?,
    ))
}

pub struct Node {
    process: Child,
    datadir: PathBuf,
    cli: PathBuf,
    sv2_port: u16,
    rpc_port: u16,
}

impl Node {
    /// Starts a node with Stratum v2 enabled for both algorithms.
    ///
    /// `slot` picks a port pair, because cargo runs tests in parallel inside
    /// one process. `extra` is appended to the command line.
    pub fn start(tag: &str, slot: u16, extra: &[&str]) -> Option<Node> {
        let (aviand, cli) = binaries()?;
        let sv2_port = 18500 + slot * 2;
        let rpc_port = 18500 + slot * 2 + 1;
        let datadir =
            std::env::temp_dir().join(format!("avian-sv2-it-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&datadir);
        std::fs::create_dir_all(&datadir).expect("cannot create the datadir");

        let mut args: Vec<String> = vec![
            "-regtest".into(),
            format!("-datadir={}", datadir.display()),
            format!("-rpcport={rpc_port}"),
            "-rpcuser=it".into(),
            "-rpcpassword=it".into(),
            "-sv2".into(),
            format!("-sv2bind=127.0.0.1:{sv2_port}"),
            "-sv2powalgo=x16rt".into(),
            "-sv2powalgo=minotaurx".into(),
            // Every refused solution counts, and a test that exercises the
            // rejection paths makes several.
            "-sv2maxrejects=1000".into(),
            "-debug=sv2".into(),
            "-fallbackfee=0.0001".into(),
            // Without this the node binds the regtest P2P port and refuses to
            // start if anything else already has it, which on a developer
            // machine is usually a node started by hand.
            "-listen=0".into(),
        ];
        args.extend(extra.iter().map(|a| a.to_string()));

        let process = Command::new(&aviand)
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("cannot start aviand");

        let mut node = Node {
            process,
            datadir,
            cli,
            sv2_port,
            rpc_port,
        };
        node.wait_for_rpc();
        Some(node)
    }

    pub fn rpc(&self, args: &[&str]) -> Result<String, String> {
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
                    "aviand exited with {status} before answering RPC; its log is in \
                     {}/regtest/debug.log",
                    self.datadir.display()
                );
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        panic!("aviand never answered RPC");
    }

    /// Mines past coinbase maturity, which also takes the node out of initial
    /// block download. Without this every template request is refused and
    /// nothing says so.
    pub fn mine(&self, blocks: u32) -> String {
        if self.rpc(&["getwalletinfo"]).is_err() {
            self.rpc(&["createwallet", "it"]).expect("createwallet");
        }
        let address = self.rpc(&["getnewaddress"]).expect("getnewaddress");
        self.rpc(&["generatetoaddress", &blocks.to_string(), &address])
            .expect("generatetoaddress");
        address
    }

    pub fn tip(&self) -> String {
        self.rpc(&["getbestblockhash"]).expect("getbestblockhash")
    }

    pub fn height(&self) -> u32 {
        self.rpc(&["getblockcount"])
            .expect("getblockcount")
            .parse()
            .expect("a number")
    }

    /// The `powtype` field `getblock` reports for a block.
    pub fn pow_type_of(&self, hash: &str) -> Option<String> {
        let json = self.rpc(&["getblock", hash, "1"]).ok()?;
        let at = json.find("\"powtype\"")?;
        let rest = &json[at..];
        let open = rest.find(": \"")? + 3;
        let close = rest[open..].find('"')?;
        Some(rest[open..open + close].to_string())
    }

    pub fn authority(&self) -> XOnlyPublicKey {
        let path = avian_tdp::authority::default_key_path(
            &self.datadir,
            avian_tdp::chain_subdir("regtest"),
        );
        avian_tdp::authority::from_private_key_file(&path).expect("authority key")
    }

    pub fn sv2_addr(&self) -> SocketAddr {
        format!("127.0.0.1:{}", self.sv2_port).parse().unwrap()
    }

    pub fn datadir(&self) -> &Path {
        &self.datadir
    }

    /// The node's `-debug=sv2` lines, which say why it refused something when
    /// the wire does not.
    pub fn sv2_log(&self) -> String {
        std::fs::read_to_string(self.datadir.join("regtest/debug.log"))
            .unwrap_or_default()
            .lines()
            .filter(|line| line.contains("[sv2]"))
            .collect::<Vec<_>>()
            .join("\n")
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
