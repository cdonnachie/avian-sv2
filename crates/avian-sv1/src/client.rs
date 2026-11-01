//! One Stratum v1 connection: the handshake, a reader thread, and submissions.
//!
//! One of these per downstream Stratum v2 channel, never shared, because the
//! pool assigns `extranonce1` per connection and attributes shares by the
//! name authorized on it. Multiplexing channels onto one connection would
//! collide the extranonce space and land every share under one worker, which
//! is the operator's accounting broken by the thing meant to leave it alone.
//!
//! The handshake, `mining.subscribe` then `mining.authorize`, is done
//! synchronously inside [`Client::connect`], so a client that exists is one
//! the pool has accepted. Everything after that arrives on a reader thread
//! and is handed out as [`Event`]s: jobs, difficulty changes, the verdict on
//! each submission, and finally why the connection ended. Reconnecting is
//! the bridge's decision, with the [`avian_sv2::Backoff`] it already has;
//! this layer reports the closure and stops.
//!
//! Pools send `mining.set_difficulty` and the first `mining.notify` whenever
//! they like, often between the subscribe reply and the authorize reply.
//! Those are kept and delivered as the first events rather than lost to the
//! handshake.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use avian_sv2::error::{Error, Result};

use crate::json::Value;
use crate::message::{self, Incoming, Notify, Subscription};

/// A line longer than this is a pool that has stopped speaking Stratum, and
/// is closed on rather than buffered. A real `mining.notify` for a full block
/// is a few kilobytes.
const MAX_LINE: usize = 64 * 1024;

const SUBSCRIBE_ID: u64 = 1;
const AUTHORIZE_ID: u64 = 2;
const FIRST_SUBMIT_ID: u64 = 3;

#[derive(Debug, Clone)]
pub struct Config {
    pub addr: SocketAddr,
    /// Passed to `mining.authorize` exactly as given. The pool keys its
    /// accounting on it, so the bridge hands over what the miner typed in
    /// `user_identity` and nothing else.
    pub user: String,
    pub password: String,
    /// What `mining.subscribe` names this client as, which is the one thing a
    /// pool operator sees of what connected.
    pub agent: String,
    pub connect_timeout: Duration,
    /// How long the handshake waits for each reply.
    pub reply_timeout: Duration,
    /// How long the connection may be silent before it is treated as dead.
    /// Pools re-send work every half minute or so even on a quiet chain, so
    /// silence much longer than that is a half-open socket. `None` waits for
    /// ever, which is only right in a test.
    pub idle_timeout: Option<Duration>,
}

impl Config {
    pub fn new(addr: SocketAddr, user: impl Into<String>) -> Self {
        Self {
            addr,
            user: user.into(),
            password: "x".into(),
            agent: concat!("avian-sv2-bridge/", env!("CARGO_PKG_VERSION")).into(),
            connect_timeout: Duration::from_secs(10),
            reply_timeout: Duration::from_secs(15),
            idle_timeout: Some(Duration::from_secs(300)),
        }
    }
}

/// What the pool sent, in the order it sent it.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Job(Notify),
    Difficulty(f64),
    Extranonce(Subscription),
    /// `client.reconnect`. Whether to honour it is the bridge's call; see
    /// [`Incoming::Reconnect`].
    Reconnect {
        host: String,
        port: u16,
    },
    /// The pool's verdict on a [`Client::submit`], by the id it returned.
    Share {
        id: u64,
        accepted: bool,
        /// What the pool said when it refused, for passing on to the miner.
        error: Option<String>,
    },
    /// The reader thread has stopped and nothing more will arrive. The text
    /// says why, for the log line the bridge writes before reconnecting.
    Closed(String),
}

pub struct Client {
    addr: SocketAddr,
    stream: Mutex<TcpStream>,
    subscription: Subscription,
    next_id: AtomicU64,
    /// Submissions awaiting a verdict, so the reader can tell a reply to one
    /// from a reply to something it never sent.
    pending: Arc<Mutex<HashSet<u64>>>,
    events: Receiver<Event>,
}

impl Client {
    /// Connects, subscribes and authorizes, or says which step the pool
    /// refused. On return the pool has accepted the worker and the reader
    /// thread is delivering events.
    pub fn connect(config: &Config) -> Result<Client> {
        let stream = TcpStream::connect_timeout(&config.addr, config.connect_timeout)?;
        // A share is a race against every other miner on the pool.
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(config.reply_timeout))?;
        stream.set_write_timeout(Some(config.reply_timeout))?;

        let mut writer = stream.try_clone()?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut early = Vec::new();

        writer.write_all(message::subscribe(SUBSCRIBE_ID, &config.agent).as_bytes())?;
        let result = await_reply(&mut reader, SUBSCRIBE_ID, "subscribe", &mut early)?;
        let subscription = message::subscription_from_reply(&result)?;

        writer.write_all(
            message::authorize(AUTHORIZE_ID, &config.user, &config.password).as_bytes(),
        )?;
        let result = await_reply(&mut reader, AUTHORIZE_ID, "authorize", &mut early)?;
        if result.as_bool() != Some(true) {
            return Err(Error::Refused(format!(
                "the pool did not authorize {:?}: it answered {}",
                config.user,
                result.to_json()
            )));
        }

        stream.set_read_timeout(config.idle_timeout)?;

        let pending = Arc::new(Mutex::new(HashSet::new()));
        let (sender, events) = mpsc::channel();
        let thread_pending = pending.clone();
        std::thread::spawn(move || {
            for event in early {
                if sender.send(event).is_err() {
                    return;
                }
            }
            let reason = read_loop(&mut reader, &thread_pending, &sender);
            let _ = sender.send(Event::Closed(reason));
        });

        Ok(Client {
            addr: config.addr,
            stream: Mutex::new(stream),
            subscription,
            next_id: AtomicU64::new(FIRST_SUBMIT_ID),
            pending,
            events,
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The pool's half of the extranonce and the size of the miner's, as of
    /// the subscribe reply. A later [`Event::Extranonce`] replaces it, and
    /// the bridge has to apply that to the channel rather than expect this
    /// to change under it.
    pub fn subscription(&self) -> &Subscription {
        &self.subscription
    }

    pub fn events(&self) -> &Receiver<Event> {
        &self.events
    }

    /// Sends a `mining.submit` and returns the id its verdict will carry in
    /// [`Event::Share`]. The pool answers in its own time; waiting here would
    /// stall the miner's next share behind the pool's reply to this one.
    pub fn submit(
        &self,
        worker: &str,
        job_id: &str,
        extranonce2: &[u8],
        ntime: u32,
        nonce: u32,
    ) -> Result<u64> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let line = message::submit(id, worker, job_id, extranonce2, ntime, nonce);
        lock(&self.pending).insert(id);
        let written = lock(&self.stream).write_all(line.as_bytes());
        if let Err(error) = written {
            lock(&self.pending).remove(&id);
            return Err(error.into());
        }
        Ok(id)
    }
}

/// The address and subscription, which is what a log line about a client
/// wants. Not the socket, the pending set or the event queue.
impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("addr", &self.addr)
            .field("subscription", &self.subscription)
            .finish_non_exhaustive()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        // Unblocks the reader thread, which then reports a closure nobody is
        // listening for and exits.
        let _ = lock(&self.stream).shutdown(Shutdown::Both);
    }
}

/// A poisoned lock here means a thread panicked while holding it, and the
/// data is a socket or a set of ids that is still usable, so the lock is
/// taken anyway rather than taking the whole bridge down with the panic.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Reads until the reply to `id` arrives, keeping any notifications that
/// arrive first. Any other reply is a protocol error: the handshake sends one
/// request at a time, so there is nothing else a reply could be for.
fn await_reply(
    reader: &mut BufReader<TcpStream>,
    id: u64,
    step: &str,
    early: &mut Vec<Event>,
) -> Result<Value> {
    loop {
        let line = match read_line(reader)? {
            Some(line) => line,
            None => {
                return Err(Error::Protocol(format!(
                    "the pool closed the connection during {step}"
                )))
            }
        };
        match message::parse_incoming(&line)? {
            Incoming::Reply {
                id: got,
                result,
                error,
            } if got == id => {
                return match error {
                    Some(text) => Err(Error::Refused(format!("{step}: {text}"))),
                    None => Ok(result),
                };
            }
            Incoming::Reply { id: got, .. } => {
                return Err(Error::Protocol(format!(
                    "a reply to request {got} arrived while waiting for {step} (request {id})"
                )));
            }
            other => {
                // Both reply shapes are matched above, so this is a
                // notification and the pending set is never consulted; an
                // empty one keeps event_for to a single signature.
                if let Some(event) = event_for(other, &Mutex::new(HashSet::new())) {
                    early.push(event);
                }
            }
        }
    }
}

/// Runs until the connection ends, and says why.
fn read_loop(
    reader: &mut BufReader<TcpStream>,
    pending: &Mutex<HashSet<u64>>,
    sender: &Sender<Event>,
) -> String {
    loop {
        let line = match read_line(reader) {
            Ok(Some(line)) => line,
            Ok(None) => return "the pool closed the connection".into(),
            Err(error) => return error.to_string(),
        };
        let incoming = match message::parse_incoming(&line) {
            Ok(incoming) => incoming,
            // One unparseable line is a pool that has stopped speaking
            // Stratum, and the bridge is better off reconnecting than
            // reading on in the hope the next one makes sense.
            Err(error) => return format!("{error}, in line {line:?}"),
        };
        if let Some(event) = event_for(incoming, pending) {
            if sender.send(event).is_err() {
                return "the client was dropped".into();
            }
        }
    }
}

/// Turns an incoming message into the event a bridge acts on, or `None` for
/// one it does not: an unhandled notification, or a reply to a request this
/// client never made.
fn event_for(incoming: Incoming, pending: &Mutex<HashSet<u64>>) -> Option<Event> {
    match incoming {
        Incoming::Notify(notify) => Some(Event::Job(notify)),
        Incoming::SetDifficulty(difficulty) => Some(Event::Difficulty(difficulty)),
        Incoming::SetExtranonce(subscription) => Some(Event::Extranonce(subscription)),
        Incoming::Reconnect { host, port } => Some(Event::Reconnect { host, port }),
        Incoming::Unhandled { .. } => None,
        Incoming::Reply { id, result, error } => {
            if !lock(pending).remove(&id) {
                return None;
            }
            // A pool says yes with `true` and nothing in `error`. Some say
            // no with `false` and nothing in `error`, which is still a no.
            let accepted = error.is_none() && result.as_bool() == Some(true);
            Some(Event::Share {
                id,
                accepted,
                error,
            })
        }
    }
}

/// One line without its terminator, `None` at end of stream, and an error for
/// a line past [`MAX_LINE`] rather than an unbounded buffer.
fn read_line(reader: &mut BufReader<TcpStream>) -> Result<Option<String>> {
    let mut line = String::new();
    let mut taken = 0;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(if line.is_empty() { None } else { Some(line) });
        }
        let end = available.iter().position(|byte| *byte == b'\n');
        let chunk = match end {
            Some(at) => &available[..at],
            None => available,
        };
        taken += chunk.len();
        if taken > MAX_LINE {
            return Err(Error::Protocol(format!(
                "a line longer than {MAX_LINE} bytes"
            )));
        }
        line.push_str(
            std::str::from_utf8(chunk)
                .map_err(|_| Error::Payload("a line that is not UTF-8".into()))?,
        );
        let consumed = chunk.len() + usize::from(end.is_some());
        reader.consume(consumed);
        if end.is_some() {
            // A `\r\n` terminator is common; the `\r` is not part of the
            // JSON.
            if line.ends_with('\r') {
                line.pop();
            }
            return Ok(Some(line));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{MockPool, Verdict};

    fn config(pool: &MockPool) -> Config {
        let mut config = Config::new(pool.addr(), "RAddr.rig1");
        config.idle_timeout = Some(Duration::from_secs(5));
        config
    }

    #[test]
    fn the_handshake_yields_a_subscription_and_the_early_work() {
        let pool = MockPool::start();
        let client = Client::connect(&config(&pool)).expect("the handshake should succeed");
        assert_eq!(
            client.subscription().extranonce1,
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(client.subscription().extranonce2_size, 4);

        // The mock sends set_difficulty and a notify between the two replies,
        // the way pools do. Neither is lost to the handshake.
        let first = client.events().recv().expect("an event");
        assert_eq!(first, Event::Difficulty(MockPool::DIFFICULTY));
        let second = client.events().recv().expect("an event");
        let Event::Job(job) = second else {
            panic!("expected the first job, got {second:?}");
        };
        assert_eq!(job.job_id, MockPool::JOB_ID);
        assert!(job.clean_jobs);
    }

    #[test]
    fn a_submission_comes_back_with_the_pools_verdict() {
        let pool = MockPool::start();
        let client = Client::connect(&config(&pool)).unwrap();
        let id = client
            .submit(
                "RAddr.rig1",
                MockPool::JOB_ID,
                &[0, 0, 0, 1],
                0x6543_210f,
                0xdead_beef,
            )
            .expect("a submit should be written");
        let verdict = client
            .events()
            .iter()
            .find(|event| matches!(event, Event::Share { .. }))
            .expect("a verdict");
        assert_eq!(
            verdict,
            Event::Share {
                id,
                accepted: true,
                error: None
            }
        );
        let received = pool.submissions();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0][0].as_str(), Some("RAddr.rig1"));
        assert_eq!(received[0][2].as_str(), Some("00000001"));
    }

    #[test]
    fn a_refused_share_carries_the_pools_reason() {
        let pool = MockPool::start();
        pool.set_verdict(Verdict::Reject(23, "low difficulty share".into()));
        let client = Client::connect(&config(&pool)).unwrap();
        let id = client
            .submit("RAddr.rig1", MockPool::JOB_ID, &[0; 4], 0, 0)
            .unwrap();
        let verdict = client
            .events()
            .iter()
            .find(|event| matches!(event, Event::Share { .. }))
            .unwrap();
        assert_eq!(
            verdict,
            Event::Share {
                id,
                accepted: false,
                error: Some("23: low difficulty share".into())
            }
        );
    }

    #[test]
    fn an_authorize_refusal_fails_the_connect_and_names_the_step() {
        let pool = MockPool::start();
        pool.set_authorize(false);
        let error = Client::connect(&config(&pool)).expect_err("authorize should fail");
        assert!(
            matches!(error, Error::Refused(_)),
            "expected a refusal, got {error}"
        );
        assert!(error.to_string().contains("authorize"), "{error}");
    }

    #[test]
    fn work_pushed_later_arrives_as_events_in_order() {
        let pool = MockPool::start();
        let client = Client::connect(&config(&pool)).unwrap();
        // Drain the handshake's two.
        client.events().recv().unwrap();
        client.events().recv().unwrap();

        pool.send(r#"{"id":null,"method":"mining.set_difficulty","params":[2048]}"#);
        pool.send(&MockPool::notify("job2", false));
        assert_eq!(client.events().recv().unwrap(), Event::Difficulty(2048.0));
        let Event::Job(job) = client.events().recv().unwrap() else {
            panic!("expected a job");
        };
        assert_eq!(job.job_id, "job2");
        assert!(!job.clean_jobs);
    }

    #[test]
    fn the_pool_hanging_up_is_reported_once_and_then_nothing() {
        let pool = MockPool::start();
        let client = Client::connect(&config(&pool)).unwrap();
        client.events().recv().unwrap();
        client.events().recv().unwrap();
        pool.hang_up();
        let event = client.events().recv().expect("a closure event");
        assert!(
            matches!(event, Event::Closed(ref why) if why.contains("closed")),
            "expected a closure, got {event:?}"
        );
        assert!(
            client.events().recv().is_err(),
            "the channel should be done"
        );
    }

    #[test]
    fn a_line_that_is_not_stratum_closes_the_connection_with_the_line_in_the_reason() {
        let pool = MockPool::start();
        let client = Client::connect(&config(&pool)).unwrap();
        client.events().recv().unwrap();
        client.events().recv().unwrap();
        pool.send("this is not json");
        let event = client.events().recv().unwrap();
        let Event::Closed(reason) = event else {
            panic!("expected a closure, got {event:?}");
        };
        assert!(reason.contains("this is not json"), "{reason}");
    }
}
