//! Which address a descriptor pays next, kept across restarts.
//!
//! A miner that connects with `wpkh(xpub.../0/*)` is paid a fresh address per
//! block, and the only state that needs is a counter: the index the next
//! block goes to. It moves when a block is found, not when a job is built,
//! because a channel sees thousands of jobs per block and a wallet looks for
//! its payments along consecutive indices. Paying index 0, then 4000, then
//! 9000 would leave a wallet's gap limit staring at thousands of empty
//! addresses and giving up before the second payment.
//!
//! Keyed by the descriptor's canonical form rather than per channel, so two
//! rigs mining to one key share one sequence and never pay the same address
//! twice between them. The ledger only ever moves forward: a block found
//! against an older index than the current one still advances nothing it
//! would have to take back.
//!
//! Persistence is one small text file, rewritten whole on every advance.
//! Blocks are minutes apart at best, the file is a line per key, and a rename
//! over the old copy means a crash mid-write loses the write and nothing else.
//! Without a file the counters start at zero on every start, which pays an
//! address again and costs nobody anything but the privacy the feature was
//! for, so the pool says so in its log rather than refusing to run.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use avian_sv2::logln;

pub struct PayoutLedger {
    path: Option<PathBuf>,
    /// Canonical descriptor to the next index it pays.
    next: Mutex<BTreeMap<String, u32>>,
    /// Whether the in-memory warning has been printed, once.
    warned: AtomicBool,
}

impl std::fmt::Debug for PayoutLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.path {
            Some(path) => write!(f, "PayoutLedger({})", path.display()),
            None => f.write_str("PayoutLedger(in memory)"),
        }
    }
}

impl PayoutLedger {
    /// Counters that live as long as the process.
    pub fn in_memory() -> Self {
        Self {
            path: None,
            next: Mutex::new(BTreeMap::new()),
            warned: AtomicBool::new(false),
        }
    }

    /// Counters kept in `path`, read now if the file exists.
    ///
    /// A file that exists but cannot be read or parsed is an error, not an
    /// empty ledger: starting over from zero because of a disk fault is the
    /// one thing a persistent ledger exists to prevent.
    pub fn open(path: PathBuf) -> io::Result<Self> {
        let mut next = BTreeMap::new();
        match fs::read_to_string(&path) {
            Ok(text) => {
                for (number, line) in text.lines().enumerate() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let (index, descriptor) = line.split_once(' ').ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "{}:{}: expected '<index> <descriptor>'",
                                path.display(),
                                number + 1
                            ),
                        )
                    })?;
                    let index: u32 = index.parse().map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "{}:{}: {index:?} is not an index",
                                path.display(),
                                number + 1
                            ),
                        )
                    })?;
                    next.insert(descriptor.to_string(), index);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        Ok(Self {
            path: Some(path),
            next: Mutex::new(next),
            warned: AtomicBool::new(false),
        })
    }

    pub fn is_persistent(&self) -> bool {
        self.path.is_some()
    }

    /// The index the next block for this descriptor pays.
    pub fn next_index(&self, descriptor: &str) -> u32 {
        if !self.is_persistent() && !self.warned.swap(true, Ordering::Relaxed) {
            logln!(
                "[pool] no --payout-state file: per-block addresses start again at index 0 \
                 on every restart, so a key will be paid at the same address more than once"
            );
        }
        self.next
            .lock()
            .map(|next| next.get(descriptor).copied().unwrap_or(0))
            .unwrap_or(0)
    }

    /// A block paid `used`, so the next one pays at least `used + 1`.
    ///
    /// Returns the index now current. Never moves backwards: a block found
    /// against a job built before another channel's block moved the counter
    /// is recorded and changes nothing.
    pub fn advance(&self, descriptor: &str, used: u32) -> u32 {
        let Ok(mut next) = self.next.lock() else {
            return used.saturating_add(1);
        };
        let entry = next.entry(descriptor.to_string()).or_insert(0);
        *entry = (*entry).max(used.saturating_add(1));
        let now = *entry;
        if let Some(path) = &self.path {
            if let Err(e) = save(path, &next) {
                logln!(
                    "[pool] could not write {}: {e}; the next index for {descriptor} is {now} \
                     in memory only",
                    path.display()
                );
            }
        }
        now
    }
}

/// Writes the whole table beside the file and renames it into place.
fn save(path: &Path, next: &BTreeMap<String, u32>) -> io::Result<()> {
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    {
        let mut file = fs::File::create(&temporary)?;
        writeln!(
            file,
            "# avian-sv2-solo: the next derivation index each descriptor pays"
        )?;
        for (descriptor, index) in next {
            writeln!(file, "{index} {descriptor}")?;
        }
        file.sync_all()?;
    }
    fs::rename(&temporary, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "wpkh(tpubD6NzVbkrYhZ4X/0/*)";
    const OTHER: &str = "pkh(tpubD6NzVbkrYhZ4X/1/*)";

    fn scratch(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("avian-ledger-{}-{name}", std::process::id()));
        let _ = fs::remove_file(&path);
        path
    }

    #[test]
    fn an_unknown_key_starts_at_zero_and_a_block_moves_it_on() {
        let ledger = PayoutLedger::in_memory();
        assert_eq!(ledger.next_index(KEY), 0);
        assert_eq!(ledger.advance(KEY, 0), 1);
        assert_eq!(ledger.next_index(KEY), 1);
        // Another key is another sequence.
        assert_eq!(ledger.next_index(OTHER), 0);
    }

    #[test]
    fn the_counter_never_goes_backwards() {
        // Two rigs on one key: the second's block was built against index 3
        // after the first's block had already moved the counter to 5.
        let ledger = PayoutLedger::in_memory();
        assert_eq!(ledger.advance(KEY, 4), 5);
        assert_eq!(ledger.advance(KEY, 3), 5);
        assert_eq!(ledger.next_index(KEY), 5);
        // And a block at the current index moves it by exactly one.
        assert_eq!(ledger.advance(KEY, 5), 6);
    }

    #[test]
    fn what_was_written_is_what_is_read_back() {
        let path = scratch("roundtrip");
        {
            let ledger = PayoutLedger::open(path.clone()).unwrap();
            assert!(ledger.is_persistent());
            assert_eq!(
                ledger.next_index(KEY),
                0,
                "a file that does not exist yet is empty"
            );
            ledger.advance(KEY, 0);
            ledger.advance(KEY, 1);
            ledger.advance(OTHER, 7);
        }
        let again = PayoutLedger::open(path.clone()).unwrap();
        assert_eq!(again.next_index(KEY), 2);
        assert_eq!(again.next_index(OTHER), 8);
        let mut temporary = path.as_os_str().to_owned();
        temporary.push(".tmp");
        assert!(
            !Path::new(&temporary).exists(),
            "the temporary is renamed away"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_damaged_file_is_an_error_and_not_an_empty_ledger() {
        let path = scratch("damaged");
        fs::write(&path, "not a number wpkh(x/0/*)\n").unwrap();
        let error = PayoutLedger::open(path.clone()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let path = scratch("comments");
        fs::write(&path, "# header\n\n3 wpkh(tpubD6NzVbkrYhZ4X/0/*)\n").unwrap();
        let ledger = PayoutLedger::open(path.clone()).unwrap();
        assert_eq!(ledger.next_index(KEY), 3);
        let _ = fs::remove_file(&path);
    }
}
