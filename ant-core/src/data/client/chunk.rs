//! Chunk storage operations.
//!
//! Chunks are immutable, content-addressed data blocks where the address
//! is the BLAKE3 hash of the content.

use crate::data::client::adaptive::{observe_op, Outcome};
use crate::data::client::classify_error;
use crate::data::client::peer_cache::record_peer_outcome;
use crate::data::client::Client;
use crate::data::error::{Error, Result};
use ant_protocol::transport::{MultiAddr, PeerId};
use ant_protocol::{
    compute_address, detect_proof_type, send_and_await_chunk_response, ChunkGetRequest,
    ChunkGetResponse, ChunkMessage, ChunkMessageBody, ChunkPutRequest, ChunkPutResponse, DataChunk,
    ProofType, XorName, CLOSE_GROUP_MAJORITY,
};
use bytes::Bytes;
use futures::stream::{FuturesUnordered, StreamExt};
use std::future::Future;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Data type identifier for chunks (used in quote requests).
const CHUNK_DATA_TYPE: u32 = 0;

/// Cold-start timeout for non-merkle chunk PUTs when the store
/// channel has no recent successful observations to derive from. Once
/// the AIMD's sliding window contains successful PUTs, the timeout
/// is derived from observed p95 latency × `latency_inflation_factor`
/// — see `adaptive_store_timeout`. Matches the prior static value so
/// the cold path is identical to historical behavior.
const COLD_START_STORE_TIMEOUT: Duration = Duration::from_secs(30);

/// Hard ceiling on the adaptive store timeout. Prevents indefinitely
/// growing timeouts on a hopelessly broken peer set. 10 minutes is
/// well past any plausible legitimate single-peer PUT — at typical
/// chunk sizes a 100 kbps uplink (~500 s for a 4 MB chunk) is the
/// outer envelope of "still trying".
const MAX_STORE_TIMEOUT: Duration = Duration::from_secs(600);

/// Pick the store-response timeout for one peer PUT.
///
/// **Merkle path** uses the configured `store_timeout_secs` directly
/// — its proof-of-payment construction has a separate latency
/// envelope and that knob is the user-facing tunable for it.
///
/// **Single-payment path** is adaptive: we derive a timeout from the
/// store channel's observed p95 latency, multiplied by
/// `latency_inflation_factor` (default 2.0). The configured
/// `store_timeout_secs` is honored as a **floor** so users can raise
/// the minimum (slow uplink) but never reduce below the floor on
/// cold start. `COLD_START_STORE_TIMEOUT` (30 s) is used when the
/// store channel has no successful samples yet, preserving the
/// historic cold-path behavior.
fn store_response_timeout_for_proof(
    proof: &[u8],
    config_store_timeout_secs: u64,
    store_limiter: &crate::data::client::adaptive::Limiter,
) -> Duration {
    match detect_proof_type(proof) {
        Some(ProofType::Merkle) => Duration::from_secs(config_store_timeout_secs),
        _ => adaptive_store_timeout(config_store_timeout_secs, store_limiter),
    }
}

fn adaptive_store_timeout(
    config_floor_secs: u64,
    store_limiter: &crate::data::client::adaptive::Limiter,
) -> Duration {
    let floor = Duration::from_secs(config_floor_secs).max(Duration::from_secs(1));
    let derived = match store_limiter.latency_p95() {
        Some(p95) => {
            let factor = store_limiter.latency_inflation_factor();
            // mul_f64 with non-finite/negative factors would panic;
            // the limiter's `sanitize` guards float fields, but be
            // explicit here too in case of future config drift.
            if factor.is_finite() && factor > 0.0 {
                p95.mul_f64(factor)
            } else {
                COLD_START_STORE_TIMEOUT
            }
        }
        None => COLD_START_STORE_TIMEOUT,
    };
    derived.max(floor).min(MAX_STORE_TIMEOUT)
}

impl Client {
    /// Store a chunk on the Autonomi network with payment.
    ///
    /// Checks if the chunk already exists before paying. If it does,
    /// returns the address immediately without incurring on-chain costs.
    /// Otherwise collects quotes, pays on-chain, then stores with proof
    /// to `CLOSE_GROUP_MAJORITY` peers.
    ///
    /// # Errors
    ///
    /// Returns an error if payment or the network operation fails.
    pub async fn chunk_put(&self, content: Bytes) -> Result<XorName> {
        let address = compute_address(&content);
        let data_size = u64::try_from(content.len())
            .map_err(|e| Error::InvalidData(format!("content size too large: {e}")))?;

        match self
            .pay_for_storage(&address, data_size, CHUNK_DATA_TYPE)
            .await
        {
            Ok((proof, peers)) => self.chunk_put_to_close_group(content, proof, &peers).await,
            Err(Error::AlreadyStored) => {
                debug!(
                    "Chunk {} already stored on network, skipping payment",
                    hex::encode(address)
                );
                Ok(address)
            }
            Err(e) => Err(e),
        }
    }

    /// Store a chunk to `CLOSE_GROUP_MAJORITY` peers from the quoted set.
    ///
    /// Maintains up to `parallelism` peer PUTs in flight at all times,
    /// where `parallelism` comes from the adaptive controller's
    /// `replication` channel and is bounded by
    /// `[1, min(peers.len(), CLOSE_GROUP_MAJORITY)]`. Each completion
    /// (success or failure) tops up the in-flight set with the next
    /// available peer until majority succeeds or peers are exhausted.
    ///
    /// On slow uplinks the controller drops `parallelism` toward 1
    /// (sequential per-peer replication) so a single chunk doesn't
    /// saturate the uplink with `MAJORITY × ~4 MB` simultaneous
    /// streams. On fast connections it stays at the ceiling
    /// (`CLOSE_GROUP_MAJORITY`) for minimum wall-clock latency.
    ///
    /// At completion, observes the chunk-level outcome on the
    /// `replication` channel and force-decreases on the saturation
    /// signature (≥ ⅔ of attempted peers timed out) — see
    /// `classify_replication_outcome`.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than `CLOSE_GROUP_MAJORITY` peers accept
    /// the chunk.
    pub(crate) async fn chunk_put_to_close_group(
        &self,
        content: Bytes,
        proof: Vec<u8>,
        peers: &[(PeerId, Vec<MultiAddr>)],
    ) -> Result<XorName> {
        let address = compute_address(&content);

        let replication_limiter = self.controller().replication.clone();
        let parallelism = replication_limiter
            .current()
            .min(peers.len())
            .clamp(1, CLOSE_GROUP_MAJORITY);

        let started = Instant::now();
        let mut peers_iter = peers.iter();
        let mut put_futures = FuturesUnordered::new();

        // Seed up to `parallelism` peers. The remainder are pulled in
        // by the top-up logic in the loop, one per completion.
        for _ in 0..parallelism {
            if let Some((peer_id, addrs)) = peers_iter.next() {
                put_futures.push(self.spawn_chunk_put(
                    content.clone(),
                    proof.clone(),
                    peer_id,
                    addrs,
                ));
            } else {
                break;
            }
        }

        let mut success_count = 0usize;
        let mut attempted = 0usize;
        let mut timeout_count = 0usize;
        let mut failures: Vec<String> = Vec::new();

        while let Some((peer_id, result)) = put_futures.next().await {
            attempted += 1;
            match &result {
                Ok(_) => {
                    success_count += 1;
                    if success_count >= CLOSE_GROUP_MAJORITY {
                        debug!(
                            "Chunk {} stored on {success_count} peers (majority reached)",
                            hex::encode(address)
                        );
                        observe_replication(
                            &replication_limiter,
                            Outcome::Success,
                            started.elapsed(),
                            attempted,
                            timeout_count,
                        );
                        return Ok(address);
                    }
                }
                Err(e) => {
                    if matches!(e, Error::Timeout(_)) {
                        timeout_count += 1;
                    }
                    warn!("Failed to store chunk on {peer_id}: {e}");
                    failures.push(format!("{peer_id}: {e}"));
                }
            }
            // Top up the in-flight set with the next peer (regardless
            // of whether the just-completed put succeeded or failed).
            // This pattern is what makes `parallelism = 1` work as
            // strict per-peer sequential replication: one slot stays
            // refilled until peers are exhausted or majority succeeds.
            if let Some((next_peer, next_addrs)) = peers_iter.next() {
                debug!(
                    "Seeding next peer {next_peer} for chunk {}",
                    hex::encode(address)
                );
                put_futures.push(self.spawn_chunk_put(
                    content.clone(),
                    proof.clone(),
                    next_peer,
                    next_addrs,
                ));
            }
        }

        // Chunk failed: classify the failure mode for the replication
        // channel. ≥ ⅔ of attempted peers timing out is the saturation
        // signature (see clip15 in PROD-LOCAL-UL-01: 11+ timeouts in
        // the same millisecond) — feed it as Outcome::Timeout AND
        // force_decrease so the next chunk runs at lower fan-out.
        observe_replication(
            &replication_limiter,
            classify_replication_outcome(attempted, timeout_count),
            started.elapsed(),
            attempted,
            timeout_count,
        );

        Err(Error::InsufficientPeers(format!(
            "Stored on {success_count} peers, need {CLOSE_GROUP_MAJORITY}. Failures: [{}]",
            failures.join("; ")
        )))
    }

    /// Spawn a chunk PUT future for a single peer.
    ///
    /// Each peer PUT is observed individually on the **store** channel
    /// of the adaptive controller. Per-peer (rather than per-chunk)
    /// granularity matters on small uploads: a 3-chunk file with
    /// majority-3 fan-out yields 9 samples per attempt, which crosses
    /// `min_window_ops` (default 8) within a single attempt, so the
    /// AIMD can react before the upload exhausts retries. Cancellation
    /// of in-flight peer futures (early return on majority) is
    /// silent — `ObserveGuard::Drop` only commits if the inner future
    /// resolves.
    fn spawn_chunk_put<'a>(
        &'a self,
        content: Bytes,
        proof: Vec<u8>,
        peer_id: &'a PeerId,
        addrs: &'a [MultiAddr],
    ) -> impl Future<Output = (PeerId, Result<XorName>)> + 'a {
        let peer_id_owned = *peer_id;
        let store_limiter = self.controller().store.clone();
        async move {
            let result = observe_op(
                &store_limiter,
                || async move {
                    self.chunk_put_with_proof(content, proof, &peer_id_owned, addrs)
                        .await
                },
                classify_error,
            )
            .await;
            (peer_id_owned, result)
        }
    }

    /// Store a chunk on the Autonomi network with a pre-built payment proof.
    ///
    /// Sends to a single peer. Callers that need replication across the
    /// close group should use `chunk_put_to_close_group` instead.
    ///
    /// # Errors
    ///
    /// Returns an error if the network operation fails.
    pub async fn chunk_put_with_proof(
        &self,
        content: Bytes,
        proof: Vec<u8>,
        target_peer: &PeerId,
        peer_addrs: &[MultiAddr],
    ) -> Result<XorName> {
        let address = compute_address(&content);
        let node = self.network().node();
        let timeout = store_response_timeout_for_proof(
            &proof,
            self.config().store_timeout_secs,
            &self.controller().store,
        );
        let timeout_secs = timeout.as_secs();

        let request_id = self.next_request_id();
        let request = ChunkPutRequest::with_payment(address, content.to_vec(), proof);
        let message = ChunkMessage {
            request_id,
            body: ChunkMessageBody::PutRequest(request),
        };
        let message_bytes = message
            .encode()
            .map_err(|e| Error::Protocol(format!("Failed to encode PUT request: {e}")))?;

        let addr_hex = hex::encode(address);

        let result = send_and_await_chunk_response(
            node,
            target_peer,
            message_bytes,
            request_id,
            timeout,
            peer_addrs,
            |body| match body {
                ChunkMessageBody::PutResponse(ChunkPutResponse::Success { address: addr }) => {
                    debug!("Chunk stored at {}", hex::encode(addr));
                    Some(Ok(addr))
                }
                ChunkMessageBody::PutResponse(ChunkPutResponse::AlreadyExists {
                    address: addr,
                }) => {
                    debug!("Chunk already exists at {}", hex::encode(addr));
                    Some(Ok(addr))
                }
                ChunkMessageBody::PutResponse(ChunkPutResponse::PaymentRequired { message }) => {
                    Some(Err(Error::Payment(format!("Payment required: {message}"))))
                }
                ChunkMessageBody::PutResponse(ChunkPutResponse::Error(e)) => Some(Err(
                    Error::Protocol(format!("Remote PUT error for {addr_hex}: {e}")),
                )),
                _ => None,
            },
            |e| Error::Network(format!("Failed to send PUT to peer: {e}")),
            || {
                Error::Timeout(format!(
                    "Timeout waiting for store response after {timeout_secs}s"
                ))
            },
        )
        .await;

        // No RTT recorded on the PUT path: the wall-clock is dominated by
        // the ~4 MB payload upload, which reflects the uploader's uplink
        // rather than the peer's responsiveness. Quote-path and GET-path
        // RTTs still feed quality scoring.
        record_peer_outcome(node, *target_peer, peer_addrs, result.is_ok(), None).await;

        result
    }

    /// Retrieve a chunk from the Autonomi network.
    ///
    /// Queries all peers in the close group for the chunk address,
    /// returning the first successful response. This handles the case
    /// where the storing peer differs from the first peer returned by
    /// DHT routing.
    ///
    /// # Errors
    ///
    /// Returns an error if the network operation fails.
    pub async fn chunk_get(&self, address: &XorName) -> Result<Option<DataChunk>> {
        // Check cache first, with integrity verification.
        if let Some(cached) = self.chunk_cache().get(address) {
            let computed = compute_address(&cached);
            if computed == *address {
                debug!("Cache hit for chunk {}", hex::encode(address));
                return Ok(Some(DataChunk::new(*address, cached)));
            }
            // Cache entry corrupted — evict and fall through to network fetch.
            debug!(
                "Cache corruption detected for {}: evicting",
                hex::encode(address)
            );
            self.chunk_cache().remove(address);
        }

        let peers = self.close_group_peers(address).await?;
        let addr_hex = hex::encode(address);

        for (peer, addrs) in &peers {
            match self.chunk_get_from_peer(address, peer, addrs).await {
                Ok(Some(chunk)) => {
                    self.chunk_cache().put(chunk.address, chunk.content.clone());
                    return Ok(Some(chunk));
                }
                Ok(None) => {
                    debug!("Chunk {addr_hex} not found on peer {peer}, trying next");
                }
                Err(Error::Timeout(_) | Error::Network(_)) => {
                    debug!("Peer {peer} unreachable for chunk {addr_hex}, trying next");
                }
                Err(e) => return Err(e),
            }
        }

        // None of the close group peers had the chunk
        Ok(None)
    }

    /// Fetch a chunk from a specific peer.
    async fn chunk_get_from_peer(
        &self,
        address: &XorName,
        peer: &PeerId,
        peer_addrs: &[MultiAddr],
    ) -> Result<Option<DataChunk>> {
        let node = self.network().node();
        let request_id = self.next_request_id();
        let request = ChunkGetRequest::new(*address);
        let message = ChunkMessage {
            request_id,
            body: ChunkMessageBody::GetRequest(request),
        };
        let message_bytes = message
            .encode()
            .map_err(|e| Error::Protocol(format!("Failed to encode GET request: {e}")))?;

        let timeout = Duration::from_secs(self.config().store_timeout_secs);
        let addr_hex = hex::encode(address);
        let timeout_secs = self.config().store_timeout_secs;

        let start = Instant::now();
        let result = send_and_await_chunk_response(
            node,
            peer,
            message_bytes,
            request_id,
            timeout,
            peer_addrs,
            |body| match body {
                ChunkMessageBody::GetResponse(ChunkGetResponse::Success {
                    address: addr,
                    content,
                }) => {
                    if addr != *address {
                        return Some(Err(Error::InvalidData(format!(
                            "Mismatched chunk address: expected {addr_hex}, got {}",
                            hex::encode(addr)
                        ))));
                    }

                    let computed = compute_address(&content);
                    if computed != addr {
                        return Some(Err(Error::InvalidData(format!(
                            "Invalid chunk content: expected hash {addr_hex}, got {}",
                            hex::encode(computed)
                        ))));
                    }

                    debug!(
                        "Retrieved chunk {} ({} bytes) from peer {peer}",
                        hex::encode(addr),
                        content.len()
                    );
                    Some(Ok(Some(DataChunk::new(addr, Bytes::from(content)))))
                }
                ChunkMessageBody::GetResponse(ChunkGetResponse::NotFound { .. }) => Some(Ok(None)),
                ChunkMessageBody::GetResponse(ChunkGetResponse::Error(e)) => Some(Err(
                    Error::Protocol(format!("Remote GET error for {addr_hex}: {e}")),
                )),
                _ => None,
            },
            |e| Error::Network(format!("Failed to send GET to peer {peer}: {e}")),
            || {
                Error::Timeout(format!(
                    "Timeout waiting for chunk {addr_hex} from {peer} after {timeout_secs}s"
                ))
            },
        )
        .await;

        let success = result.is_ok();
        let rtt_ms = success.then(|| start.elapsed().as_millis() as u64);
        record_peer_outcome(node, *peer, peer_addrs, success, rtt_ms).await;

        result
    }

    /// Check if a chunk exists on the network.
    ///
    /// # Errors
    ///
    /// Returns an error if the network operation fails.
    pub async fn chunk_exists(&self, address: &XorName) -> Result<bool> {
        self.chunk_get(address).await.map(|opt| opt.is_some())
    }
}

/// Fraction of attempted peers that must timeout for a failed
/// close-group put to be classified as bandwidth saturation rather
/// than individual peer trouble. ⅔ is conservative: one or two slow
/// peers shouldn't shrink the fan-out — but most peers timing out
/// together points squarely at the uplink.
const SATURATION_TIMEOUT_RATIO: (usize, usize) = (2, 3);

/// Classify a chunk-level close-group PUT failure for the replication
/// channel.
///
/// - **Saturation**: ≥ ⅔ of attempted peers timed out → `Timeout` (a
///   capacity signal that drives the AIMD down).
/// - **Other failure**: peers exhausted, mixed network errors, etc.
///   → `ApplicationError` (no capacity signal — the chunk failed for
///   reasons unrelated to local fan-out concurrency).
///
/// `attempted == 0` (no peers to try at all) returns
/// `ApplicationError`: not a fan-out problem, an upstream error.
fn classify_replication_outcome(attempted: usize, timeouts: usize) -> Outcome {
    if attempted == 0 {
        return Outcome::ApplicationError;
    }
    let (num, den) = SATURATION_TIMEOUT_RATIO;
    if timeouts * den >= attempted * num {
        Outcome::Timeout
    } else {
        Outcome::ApplicationError
    }
}

/// Record one chunk-level outcome on the replication channel and, on
/// the saturation signature, also force an immediate halve. Eager
/// halving bypasses the AIMD `min_window_ops` decrease gate because
/// the saturation signature is unambiguous on its own — every peer
/// in the fan-out timing out together means the uplink couldn't keep
/// up, and we already know that without needing a window of evidence.
fn observe_replication(
    limiter: &crate::data::client::adaptive::Limiter,
    outcome: Outcome,
    latency: std::time::Duration,
    attempted: usize,
    timeouts: usize,
) {
    limiter.observe(outcome, latency);
    let (num, den) = SATURATION_TIMEOUT_RATIO;
    if attempted > 0 && timeouts * den >= attempted * num {
        limiter.force_decrease();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::client::adaptive::{
        AdaptiveConfig, AdaptiveController, ChannelStart, Limiter,
    };
    use ant_protocol::{PROOF_TAG_MERKLE, PROOF_TAG_SINGLE_NODE};

    /// Arbitrary configured Merkle store timeout used by the timeout-selection tests.
    const TEST_MERKLE_TIMEOUT_SECS: u64 = 60;
    /// Sentinel byte used to represent an unknown/unrecognized proof tag.
    const UNKNOWN_PROOF_TAG: u8 = 0xff;

    /// Build an isolated store `Limiter` for testing the
    /// timeout-derivation logic without spinning up a full client.
    /// Goes through `AdaptiveController::new` so the limiter sees the
    /// production-shape window/ewma config.
    fn store_limiter_for_tests() -> Limiter {
        let controller =
            AdaptiveController::new(ChannelStart::default(), AdaptiveConfig::default());
        controller.store.clone()
    }

    #[test]
    fn single_node_proof_uses_cold_start_timeout_until_baseline_exists() {
        let limiter = store_limiter_for_tests();
        let timeout = store_response_timeout_for_proof(
            &[PROOF_TAG_SINGLE_NODE],
            10, // config floor below cold-start
            &limiter,
        );
        // No successful samples → cold-start timeout.
        assert_eq!(timeout, COLD_START_STORE_TIMEOUT);
    }

    #[test]
    fn unknown_proof_uses_cold_start_timeout_until_baseline_exists() {
        let limiter = store_limiter_for_tests();
        let timeout = store_response_timeout_for_proof(&[UNKNOWN_PROOF_TAG], 10, &limiter);
        assert_eq!(timeout, COLD_START_STORE_TIMEOUT);
    }

    #[test]
    fn merkle_proof_uses_configured_store_timeout() {
        let limiter = store_limiter_for_tests();
        let timeout = store_response_timeout_for_proof(
            &[PROOF_TAG_MERKLE],
            TEST_MERKLE_TIMEOUT_SECS,
            &limiter,
        );

        assert_eq!(timeout, Duration::from_secs(TEST_MERKLE_TIMEOUT_SECS));
    }

    /// When the store channel has accumulated successful PUT
    /// observations, the single-payment timeout grows with observed
    /// p95 × inflation factor — this is the slow-uplink rescue.
    #[test]
    fn adaptive_timeout_grows_with_observed_p95_latency() {
        let limiter = store_limiter_for_tests();
        // Feed enough successful samples for the window to populate.
        // The default config uses min_window_ops=8 / window_ops=32.
        for _ in 0..16 {
            limiter.observe(Outcome::Success, Duration::from_secs(20));
        }
        let timeout = store_response_timeout_for_proof(
            &[PROOF_TAG_SINGLE_NODE],
            10, // config floor
            &limiter,
        );
        // p95 ≈ 20 s, factor = 2.0 → ~40 s. Should be well above
        // both the floor (10 s) and the cold-start default (30 s).
        assert!(
            timeout > COLD_START_STORE_TIMEOUT,
            "expected adaptive timeout > {COLD_START_STORE_TIMEOUT:?}, got {timeout:?}",
        );
        assert!(
            timeout >= Duration::from_secs(35),
            "expected ≥35 s based on p95×2, got {timeout:?}",
        );
    }

    /// `store_timeout_secs` is honored as a floor: a user pinning a
    /// high value via `--store-timeout` always raises the minimum,
    /// even when observed p95 would suggest a lower derived timeout.
    #[test]
    fn config_store_timeout_floor_raises_minimum() {
        let limiter = store_limiter_for_tests();
        for _ in 0..16 {
            limiter.observe(Outcome::Success, Duration::from_secs(2));
        }
        let timeout = store_response_timeout_for_proof(
            &[PROOF_TAG_SINGLE_NODE],
            120, // pinned floor of 2 minutes
            &limiter,
        );
        // p95 ≈ 2 s × 2.0 = 4 s, but the config floor is 120 s.
        assert_eq!(timeout, Duration::from_secs(120));
    }

    /// The adaptive timeout is capped at `MAX_STORE_TIMEOUT` so a
    /// pathologically slow peer set cannot drive it to infinity.
    #[test]
    fn adaptive_timeout_caps_at_max_ceiling() {
        let limiter = store_limiter_for_tests();
        for _ in 0..16 {
            limiter.observe(Outcome::Success, Duration::from_secs(1000));
        }
        let timeout = store_response_timeout_for_proof(&[PROOF_TAG_SINGLE_NODE], 10, &limiter);
        assert_eq!(timeout, MAX_STORE_TIMEOUT);
    }

    /// `classify_replication_outcome` flags ≥⅔ timeouts as the
    /// saturation signature, otherwise falls through to non-capacity
    /// signal.
    #[test]
    fn saturation_classifier_recognizes_majority_timeout_as_capacity_signal() {
        // 4 attempts, 3 timeouts (75% > 66%) → Timeout
        assert_eq!(
            classify_replication_outcome(4, 3),
            Outcome::Timeout,
            "75% timeouts must classify as saturation"
        );
        // 4 attempts, 2 timeouts (50% < 66%) → ApplicationError
        assert_eq!(
            classify_replication_outcome(4, 2),
            Outcome::ApplicationError,
            "50% timeouts is not the saturation signature"
        );
        // 3 attempts, 2 timeouts (66.6% ≥ 66%) → Timeout
        assert_eq!(
            classify_replication_outcome(3, 2),
            Outcome::Timeout,
            "exactly ⅔ timeouts must trigger saturation"
        );
        // No attempts → ApplicationError (upstream error, not fan-out).
        assert_eq!(
            classify_replication_outcome(0, 0),
            Outcome::ApplicationError,
            "no attempts is not a fan-out signal"
        );
    }
}
