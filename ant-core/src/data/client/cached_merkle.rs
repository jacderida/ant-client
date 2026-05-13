//! On-disk cache for merkle batch payment receipts.
//!
//! Why this exists
//! ---------------
//! A merkle batch upload pays for *all* chunks in one on-chain transaction
//! up-front, then stores each chunk to its close-group. If the store phase
//! fails partway through (network flake, slow close-K, client crash), the
//! on-chain payment is gone but the proofs needed to re-attempt the store
//! are lost too — the user has to pay again from scratch.
//!
//! By persisting the [`MerkleBatchPaymentResult`] to disk **immediately after
//! the on-chain payment lands**, the next invocation can resume the upload
//! using the already-paid proofs instead of re-paying. The cache is keyed by
//! a derivation of the source file path so the same upload, re-issued for
//! the same file, transparently picks up where it left off.
//!
//! Lifecycle
//! ---------
//! * **save** — called once per upload, right after the merkle batch payment
//!   transaction confirms. Writes JSON to
//!   `<data_dir>/payments/<timestamp>_<file_hash>`.
//! * **load_for_file** — called at the top of every merkle upload. If a
//!   non-expired cached receipt exists for the file, it is returned so the
//!   upload can skip the pay phase and go straight to store.
//! * **delete_for_file** — called after a fully successful upload to remove
//!   the receipt so a future re-upload of the same path pays anew.
//! * **cleanup_outdated** — called opportunistically inside `load_for_file`
//!   to garbage-collect receipts past the 7-day expiry window.
//!
//! Filename format
//! ---------------
//! `<timestamp>_<file_hash>` where:
//! * `timestamp` is the merkle payment timestamp (seconds since epoch) used
//!   on-chain. Expiry is computed from this value so we can prune stale
//!   receipts even if their on-disk mtime has been touched.
//! * `file_hash` is the SHA-256 of the source file path string, truncated
//!   to keep filenames short. Same-name uploads from different directories
//!   collide deliberately — the user can name their file uniquely if they
//!   need parallel uploads.
//!
//! Failure-mode tolerance
//! ----------------------
//! All errors in this module are logged and swallowed in the public-facing
//! API (`try_load_for_file`, `try_save`, `try_delete_for_file`): a busted
//! cache directory must never prevent a real upload from running. The
//! tradeoff is that a corrupt cache file is silently treated as "no
//! cache", forcing the user to re-pay — but never causes data loss.

use crate::config;
use crate::data::client::merkle::MerkleBatchPaymentResult;
use crate::error::Result;
use std::fs::{self, DirEntry, File};
use std::hash::{Hash, Hasher};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// Cached merkle receipts older than this are removed from disk.
///
/// Set to match `MERKLE_PAYMENT_EXPIRATION` in `evmlib` (7 days). After
/// the payment ages out on-chain there is no point keeping the cache —
/// the proofs can no longer be verified by storers.
const PAYMENT_EXPIRATION_SECS: u64 = 7 * 24 * 60 * 60;

/// Subdirectory under the platform-appropriate data dir.
const PAYMENTS_SUBDIR: &str = "payments";

/// Returns the directory used for cached payments, creating it if needed.
fn payments_dir() -> Result<PathBuf> {
    let dir = config::data_dir()?.join(PAYMENTS_SUBDIR);
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Short non-cryptographic hash of the source file path string, used as
/// the on-disk cache key.
///
/// Filename collisions are not a correctness problem (the loaded
/// receipt is content-validated against the current encrypted chunk
/// addresses before being trusted) but they would waste a re-pay, so
/// we want low collision probability across a single user's upload
/// history. `std::hash::DefaultHasher` with 16 hex chars of output is
/// far below the collision threshold for that scale.
fn file_hash_key(file_path: &str) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    file_path.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Save the merkle batch payment receipt for a given source file path.
///
/// Idempotent: re-saving for the same `(timestamp, file_path)` overwrites
/// the previous file. Different timestamps for the same file produce
/// different filenames, which is fine — `cleanup_outdated` reaps them.
pub fn save(file_path: &str, result: &MerkleBatchPaymentResult) -> Result<PathBuf> {
    let dir = payments_dir()?;
    let ts = if result.merkle_payment_timestamp > 0 {
        result.merkle_payment_timestamp
    } else {
        // Fall back to now() if the result wasn't populated. Should not
        // happen in practice — every constructor stamps this field —
        // but defensively avoid emitting a `0_*` filename that would
        // immediately be treated as expired.
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    };
    let path = dir.join(format!("{ts}_{}", file_hash_key(file_path)));
    let handle = File::create(&path)?;
    // msgpack (rmp-serde) rather than JSON because `proofs` is keyed by
    // `[u8; 32]` which JSON cannot represent as a map key.
    rmp_serde::encode::write(&mut BufWriter::new(handle), result)
        .map_err(|e| crate::error::Error::Io(std::io::Error::other(e.to_string())))?;
    debug!(
        "Cached merkle payment receipt for {file_path:?} to {}",
        path.display()
    );
    Ok(path)
}

/// Best-effort save. Logs on failure but never returns an error.
///
/// Intended for the upload path: if we can't cache the receipt we still
/// want to attempt the chunk PUTs.
pub fn try_save(file_path: &str, result: &MerkleBatchPaymentResult) {
    if let Err(e) = save(file_path, result) {
        warn!(
            "Failed to cache merkle payment receipt for {file_path:?}: {e}. \
             Upload will proceed without resume support."
        );
    }
}

/// Load the cached merkle batch receipt for a given source file path.
///
/// Side-effect: opportunistically removes any expired receipts found in
/// the directory while scanning.
///
/// Returns `Ok(None)` if no matching non-expired receipt is found.
pub fn load_for_file(file_path: &str) -> Result<Option<(PathBuf, MerkleBatchPaymentResult)>> {
    cleanup_outdated();
    let dir = payments_dir()?;
    let key = file_hash_key(file_path);

    let read_dir = match fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(e) => {
            debug!("Could not read payments dir {}: {e}", dir.display());
            return Ok(None);
        }
    };

    for entry in read_dir.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.contains(&key) {
            continue;
        }
        if is_expired_filename(name) {
            // Found the file but it has aged out; cleanup will
            // collect it. Keep scanning in case a newer one exists.
            continue;
        }
        match read_receipt(&path) {
            Ok(receipt) => {
                info!(
                    "Found previous merkle upload attempt for {file_path}, \
                     resuming with payment cached at {}",
                    path.display()
                );
                return Ok(Some((path, receipt)));
            }
            Err(e) => {
                warn!(
                    "Cached merkle receipt at {} is unreadable ({e}). \
                     Ignoring and starting a fresh upload.",
                    path.display()
                );
            }
        }
    }
    Ok(None)
}

/// Best-effort load. Logs on failure and returns `None`.
pub fn try_load_for_file(file_path: &str) -> Option<(PathBuf, MerkleBatchPaymentResult)> {
    match load_for_file(file_path) {
        Ok(opt) => opt,
        Err(e) => {
            warn!(
                "Failed to look up cached merkle receipt for {file_path:?}: {e}. \
                 Starting a fresh upload."
            );
            None
        }
    }
}

/// Delete the cached receipt(s) matching the file path. Called on
/// successful upload completion.
pub fn delete_for_file(file_path: &str) -> Result<()> {
    let dir = payments_dir()?;
    let key = file_hash_key(file_path);
    if let Ok(read_dir) = fs::read_dir(&dir) {
        for entry in read_dir.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.contains(&key) {
                    let _ = fs::remove_file(&path);
                    debug!("Deleted cached merkle receipt {}", path.display());
                }
            }
        }
    }
    Ok(())
}

/// Best-effort delete. Logs on failure but never returns an error.
pub fn try_delete_for_file(file_path: &str) {
    if let Err(e) = delete_for_file(file_path) {
        warn!(
            "Failed to delete cached merkle receipt for {file_path:?}: {e}. \
             Will be cleaned up after expiry."
        );
    }
}

/// Garbage-collect cached receipts past the expiry window.
///
/// Logs each removal at info level so users see what we cleaned up.
/// Best-effort: any IO error is silently ignored.
pub fn cleanup_outdated() {
    let Ok(dir) = payments_dir() else {
        return;
    };
    let Ok(read_dir) = fs::read_dir(&dir) else {
        return;
    };
    for entry in read_dir.flatten() {
        if is_expired_entry(&entry) {
            let path = entry.path();
            info!(
                "Removing expired cached merkle payment file: {}",
                path.display()
            );
            let _ = fs::remove_file(path);
        }
    }
}

fn is_expired_entry(entry: &DirEntry) -> bool {
    let path = entry.path();
    if !path.is_file() {
        return false;
    }
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    is_expired_filename(name)
}

fn is_expired_filename(name: &str) -> bool {
    let ts_str = match name.split_once('_') {
        Some((ts, _)) => ts,
        None => return false,
    };
    let Ok(ts) = ts_str.parse::<u64>() else {
        return false;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now > ts.saturating_add(PAYMENT_EXPIRATION_SECS)
}

fn read_receipt(path: &Path) -> Result<MerkleBatchPaymentResult> {
    let handle = File::open(path)?;
    let receipt: MerkleBatchPaymentResult = rmp_serde::decode::from_read(BufReader::new(handle))
        .map_err(|e| crate::error::Error::Io(std::io::Error::other(e.to_string())))?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn dummy_receipt(ts: u64) -> MerkleBatchPaymentResult {
        let mut proofs: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
        proofs.insert([0u8; 32], vec![1, 2, 3]);
        MerkleBatchPaymentResult {
            proofs,
            chunk_count: 1,
            storage_cost_atto: "0".to_string(),
            gas_cost_wei: 0,
            merkle_payment_timestamp: ts,
        }
    }

    #[test]
    fn file_hash_key_is_stable() {
        let a = file_hash_key("/tmp/some/file.bin");
        let b = file_hash_key("/tmp/some/file.bin");
        assert_eq!(a, b);
        let c = file_hash_key("/tmp/some/other.bin");
        assert_ne!(a, c);
    }

    #[test]
    fn expired_filename_detected() {
        // Just past the expiry boundary.
        let stale = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(PAYMENT_EXPIRATION_SECS + 60);
        let name = format!("{stale}_abcd1234");
        assert!(is_expired_filename(&name));

        // Within the window.
        let fresh = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(60);
        let name = format!("{fresh}_abcd1234");
        assert!(!is_expired_filename(&name));
    }

    #[test]
    fn malformed_filename_is_not_expired() {
        // Defensive: garbage in payments dir must not be auto-deleted.
        assert!(!is_expired_filename("nonsense"));
        assert!(!is_expired_filename("not_a_number_abcd1234"));
    }

    #[test]
    fn roundtrip_save_load_delete() -> Result<()> {
        let file_path = format!(
            "/tmp/anselme-resumable-merkle-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let receipt = dummy_receipt(ts);
        let saved_path = save(&file_path, &receipt)?;
        assert!(saved_path.exists());

        let loaded = load_for_file(&file_path)?;
        let (loaded_path, loaded_receipt) = loaded.expect("receipt should be loadable");
        assert_eq!(loaded_path, saved_path);
        assert_eq!(loaded_receipt.chunk_count, receipt.chunk_count);
        assert_eq!(loaded_receipt.merkle_payment_timestamp, ts);

        delete_for_file(&file_path)?;
        assert!(load_for_file(&file_path)?.is_none());
        Ok(())
    }
}
