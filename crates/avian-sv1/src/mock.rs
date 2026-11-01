//! A scripted Stratum v1 pool, for tests. **Test support only.**
//!
//! Public rather than `cfg(test)` because the bridge's own tests need it
//! too, and the workspace's answer to shared test support is a module or a
//! crate rather than a feature flag (`avian-regtest` is the precedent). It
//! has no place in a binary and nothing links it into one.
//!
//! It serves exactly one connection, which matches how a bridge uses a
//! client: one per channel. A test that wants two clients starts two pools.
//! It answers `mining.subscribe` with a fixed extranonce, sends a difficulty
//! and a job between that reply and the authorize reply because real pools
//! do and the client has to cope, answers `mining.authorize` and
//! `mining.submit` as scripted, and records every submission's parameters
//! for the test to inspect.

use std::io::{BufRead, BufReader, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::json::{self, Value};

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Accept,
    Reject(u64, String),
}

#[derive(Debug)]
struct Script {
    authorize: bool,
    verdict: Verdict,
    submissions: Vec<Vec<Value>>,
    /// The accepted connection, once there is one, so a test can push a
    /// notification or hang up.
    peer: Option<TcpStream>,
}

pub struct MockPool {
    addr: SocketAddr,
    script: Arc<Mutex<Script>>,
}

impl MockPool {
    pub const EXTRANONCE1: &'static str = "deadbeef";
    pub const EXTRANONCE2_SIZE: u64 = 4;
    pub const DIFFICULTY: f64 = 1024.0;
    pub const JOB_ID: &'static str = "job1";

    /// A `mining.notify` line with a recognisable shape: `prevhash` counts
    /// upward byte by byte in wire order, the coinbase halves are a regtest
    /// coinbase's, and the branch is one entry.
    pub fn notify(job_id: &str, clean: bool) -> String {
        // Every literal is on one line on purpose: a wrapped hex string
        // picks up whatever the wrap puts in it, and one stray byte in a
        // hash is a handshake failure with an unhelpful message.
        const PREV_HASH_WIRE: &str =
            "03020100070605040b0a09080f0e0d0c13121110171615141b1a19181f1e1d1c";
        const COINB1: &str =
            "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff";
        const COINB2: &str = "ffffffff0100f2052a01000000";
        const BRANCH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let params = [
            format!("\"{job_id}\""),
            format!("\"{PREV_HASH_WIRE}\""),
            format!("\"{COINB1}\""),
            format!("\"{COINB2}\""),
            format!("[\"{BRANCH}\"]"),
            "\"20000000\"".to_string(),
            "\"1d00ffff\"".to_string(),
            "\"6543210f\"".to_string(),
            clean.to_string(),
        ];
        format!(
            "{{\"id\":null,\"method\":\"mining.notify\",\"params\":[{}]}}",
            params.join(",")
        )
    }

    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
        let addr = listener.local_addr().expect("a bound address");
        let script = Arc::new(Mutex::new(Script {
            authorize: true,
            verdict: Verdict::Accept,
            submissions: Vec::new(),
            peer: None,
        }));
        let thread_script = script.clone();
        std::thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
            let mut writer = stream.try_clone().expect("a writer");
            lock(&thread_script).peer = Some(stream.try_clone().expect("a peer handle"));
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
                let Ok(request) = json::parse(line.trim_end()) else {
                    return;
                };
                let id = request.get("id").cloned().unwrap_or(Value::Null);
                let method = request.get("method").and_then(Value::as_str).unwrap_or("");
                let params = request
                    .get("params")
                    .and_then(Value::as_array)
                    .map(<[Value]>::to_vec)
                    .unwrap_or_default();
                let reply = match method {
                    "mining.subscribe" => {
                        let reply = format!(
                            r#"{{"id":{},"result":[[["mining.set_difficulty","d"],["mining.notify","n"]],"{}",{}],"error":null}}"#,
                            id.to_json(),
                            Self::EXTRANONCE1,
                            Self::EXTRANONCE2_SIZE
                        );
                        // Work before the authorize reply, as pools do.
                        let early = format!(
                            "{reply}\n{{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[{}]}}\n{}\n",
                            Self::DIFFICULTY,
                            Self::notify(Self::JOB_ID, true)
                        );
                        early
                    }
                    "mining.authorize" => {
                        let ok = lock(&thread_script).authorize;
                        format!(
                            r#"{{"id":{},"result":{ok},"error":null}}{}"#,
                            id.to_json(),
                            "\n"
                        )
                    }
                    "mining.submit" => {
                        let mut script = lock(&thread_script);
                        script.submissions.push(params);
                        match &script.verdict {
                            Verdict::Accept => {
                                format!(
                                    "{{\"id\":{},\"result\":true,\"error\":null}}\n",
                                    id.to_json()
                                )
                            }
                            Verdict::Reject(code, text) => format!(
                                "{{\"id\":{},\"result\":null,\"error\":[{code},{},null]}}\n",
                                id.to_json(),
                                Value::String(text.clone()).to_json()
                            ),
                        }
                    }
                    _ => format!(
                        "{{\"id\":{},\"result\":null,\"error\":null}}\n",
                        id.to_json()
                    ),
                };
                if writer.write_all(reply.as_bytes()).is_err() {
                    return;
                }
            }
        });
        Self { addr, script }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn set_authorize(&self, ok: bool) {
        lock(&self.script).authorize = ok;
    }

    pub fn set_verdict(&self, verdict: Verdict) {
        lock(&self.script).verdict = verdict;
    }

    /// The parameters of every `mining.submit` received so far.
    pub fn submissions(&self) -> Vec<Vec<Value>> {
        lock(&self.script).submissions.clone()
    }

    /// Pushes one raw line to the connected client, newline added.
    pub fn send(&self, line: &str) {
        let mut script = lock(&self.script);
        let peer = script
            .peer
            .as_mut()
            .expect("send needs a connected client; connect one first");
        peer.write_all(line.as_bytes())
            .expect("the client is still reading");
        peer.write_all(b"\n").expect("the client is still reading");
    }

    /// Closes the connection from the pool's side.
    pub fn hang_up(&self) {
        if let Some(peer) = lock(&self.script).peer.take() {
            let _ = peer.shutdown(Shutdown::Both);
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
