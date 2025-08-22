//! Tiny in‑memory cache.
//!
//! ## Motivation
//! YARA scans are CPU‑bound and (for big files) I/O‑heavy. Re‑scanning the
//! same file 60 seconds later —even though it hasn’t changed— wastes time.
//!
//! The cheapest change detector available on every desktop FS is the tuple
//! **(mtime, size)**.  If *both* match, the file’s content is almost certainly
//! unchanged. A cryptographic hash would be stronger but aprox. 100× slower on
//! multi‑MB binaries, so we keep it simple for a first pass.
//!
//! ## Design
//! * Per‑worker instance so **no cross‑thread locking**.
//! * O(1) insertion / lookup based on `FxHashMap`.

use std::{
    collections::{VecDeque, hash_map::Entry},
    fs::Metadata,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

/// Maximum number of distinct files remembered per worker.
const MAX_ENTRIES: usize = 10_000;

/// (“last‑modified seconds since Epoch”, “length in bytes”)
type Stamp = (u64, u64);

/// A bounded Least Recently Used style cache keyed by `PathBuf`.
///
/// Tracks each file's last seen `(mtime, size)` using a hash map for fast lookup.
/// A queue stores insertion order to evict the oldest entries when capacity is exceeded.
/// This avoids re-reading and re-scanning files that haven't changed.
///
/// Internally:
/// - `map`: stores file paths and their metadata stamps.
/// - `order`: tracks insertion order for simple LRU behavior.
pub struct ScanCache {
    map: rustc_hash::FxHashMap<PathBuf, Stamp>,
    order: VecDeque<PathBuf>,
}

impl Default for ScanCache {
    fn default() -> Self {
        Self {
            map: rustc_hash::FxHashMap::default(),
            order: VecDeque::with_capacity(MAX_ENTRIES),
        }
    }
}

impl ScanCache {
    /// Return `true` if `path` is known *and* its stored stamp equals the
    /// current `(mtime, size)`.
    pub fn is_unchanged(&self, path: &Path, meta: &Metadata) -> bool {
        let stamp = Self::stamp(meta);
        self.map.get(path).copied() == Some(stamp)
    }

    /// Record or update the stamp for `path`.
    ///
    /// If the cache already contains the key we just overwrite the value
    /// (constant time).
    /// Otherwise we push the new key into `order` and evict the oldest element
    /// once we exceed `MAX_ENTRIES`.
    pub fn update(&mut self, path: &Path, meta: &Metadata) {
        let path = path.to_path_buf();
        let stamp = Self::stamp(meta);

        match self.map.entry(path.clone()) {
            Entry::Occupied(mut o) => *o.get_mut() = stamp,
            Entry::Vacant(v) => {
                v.insert(stamp);
                self.order.push_back(path);
                if self.order.len() > MAX_ENTRIES {
                    if let Some(old) = self.order.pop_front() {
                        self.map.remove(&old);
                    }
                }
            }
        }
    }

    /// Returns the `Stamp` tuple for a given metadata of a file
    ///
    /// * Nanosecond precision is overkill for our use‑case; we down‑cast to
    ///   whole seconds (`as_secs`) which is plenty to detect a rewrite.
    /// * Any error (e.g. a file on a weird FUSE FS without `mtime`) falls back
    ///   to `(0, size)` so we still compare something meaningful.
    #[inline]
    fn stamp(meta: &Metadata) -> Stamp {
        let mtime = meta
            .modified()
            .unwrap_or(SystemTime::UNIX_EPOCH)
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        (mtime, meta.len())
    }
}
