//! Chunk storage operations.
//!
//! Chunks are immutable, content-addressed data blocks where the address
//! is the BLAKE3 hash of the content.

use crate::data::client::batch::{finalize_batch_payment, PreparedChunk};
use crate::data::client::peer_cache::record_peer_outcome;
use crate::data::client::Client;
use crate::data::error::{Error, Result};
use ant_protocol::evm::{QuoteHash, TxHash};
use ant_protocol::transport::{MultiAddr, PeerId};
use ant_protocol::{
    compute_address, detect_proof_type, send_and_await_chunk_response, ChunkGetRequest,
    ChunkGetResponse, ChunkMessage, ChunkMessageBody, ChunkPutRequest, ChunkPutResponse, DataChunk,
    ProofType, XorName, CLOSE_GROUP_MAJORITY,
};
use bytes::Bytes;
use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::HashMap;
use std::future::Future;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Data type identifier for chunks (used in quote requests).
const CHUNK_DATA_TYPE: u32 = 0;

/// Result of one sweep over a chunk's close group.
///
/// Either we got the chunk from some peer, or every peer in the group
/// returned NotFound, timed out, or hit a transport error. The counts
/// are used to decide whether to retry: a quorum of authoritative
/// NotFound responses means the chunk really isn't there and we should
/// give up; anything else looks like reachability and is worth one
/// retry against a freshly re-walked close group.
struct CloseGroupOutcome {
    chunk: Option<DataChunk>,
    queried: usize,
    not_found: usize,
    timeout: usize,
    network_err: usize,
}

/// `true` if a majority of queried peers actively responded NotFound.
///
/// This is the signal that the chunk is genuinely absent from the close
/// group: peers that respond NotFound are reachable and authoritative
/// about what they store. Anything else (timeout, transport error) is
/// reachability noise.
fn is_authoritative_not_found(not_found: usize, quorum: usize) -> bool {
    not_found >= quorum
}

/// Store-response timeout for non-merkle chunk PUTs.
const STORE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

fn store_response_timeout_for_proof(proof: &[u8], merkle_timeout_secs: u64) -> Duration {
    match detect_proof_type(proof) {
        Some(ProofType::Merkle) => Duration::from_secs(merkle_timeout_secs),
        _ => STORE_RESPONSE_TIMEOUT,
    }
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
    /// Initially sends the PUT concurrently to the first
    /// `CLOSE_GROUP_MAJORITY` peers. If any fail, falls back to the
    /// remaining peers in the quoted set until majority is reached or
    /// all peers are exhausted.
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

        let initial_count = peers.len().min(CLOSE_GROUP_MAJORITY);
        let (initial_peers, fallback_peers) = peers.split_at(initial_count);

        let mut put_futures = FuturesUnordered::new();
        for (peer_id, addrs) in initial_peers {
            put_futures.push(self.spawn_chunk_put(content.clone(), proof.clone(), peer_id, addrs));
        }

        let mut success_count = 0usize;
        let mut failures: Vec<String> = Vec::new();
        let mut fallback_iter = fallback_peers.iter();

        while let Some((peer_id, result)) = put_futures.next().await {
            match result {
                Ok(_) => {
                    success_count += 1;
                    if success_count >= CLOSE_GROUP_MAJORITY {
                        debug!(
                            "Chunk {} stored on {success_count} peers (majority reached)",
                            hex::encode(address)
                        );
                        return Ok(address);
                    }
                }
                Err(e) => {
                    warn!("Failed to store chunk on {peer_id}: {e}");
                    failures.push(format!("{peer_id}: {e}"));

                    if let Some((fb_peer, fb_addrs)) = fallback_iter.next() {
                        debug!(
                            "Falling back to peer {fb_peer} for chunk {}",
                            hex::encode(address)
                        );
                        put_futures.push(self.spawn_chunk_put(
                            content.clone(),
                            proof.clone(),
                            fb_peer,
                            fb_addrs,
                        ));
                    }
                }
            }
        }

        Err(Error::InsufficientPeers(format!(
            "Stored on {success_count} peers, need {CLOSE_GROUP_MAJORITY}. Failures: [{}]",
            failures.join("; ")
        )))
    }

    /// Spawn a chunk PUT future for a single peer.
    fn spawn_chunk_put<'a>(
        &'a self,
        content: Bytes,
        proof: Vec<u8>,
        peer_id: &'a PeerId,
        addrs: &'a [MultiAddr],
    ) -> impl Future<Output = (PeerId, Result<XorName>)> + 'a {
        let peer_id_owned = *peer_id;
        async move {
            let result = self
                .chunk_put_with_proof(content, proof, &peer_id_owned, addrs)
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
        let timeout =
            store_response_timeout_for_proof(&proof, self.config().merkle_store_timeout_secs);
        let timeout_secs = timeout.as_secs();

        let request_id = self.next_request_id();
        // `content` is a refcounted `Bytes` shared with the sibling
        // close-group sends; pass it through directly so each peer shares
        // the same backing buffer instead of deep-copying the 4 MB payload.
        let request = ChunkPutRequest::with_payment(address, content, proof);
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

        let addr_hex = hex::encode(address);
        let quorum = self.config().close_group_size / 2 + 1;

        // First attempt against the current close-group view.
        let first = self.chunk_get_try_close_group(address).await?;
        if let Some(chunk) = first.chunk {
            self.chunk_cache().put(chunk.address, chunk.content.clone());
            return Ok(Some(chunk));
        }

        // A quorum of NotFound responses is authoritative — the chunk
        // really isn't on the close group. Don't retry; surface Ok(None).
        if is_authoritative_not_found(first.not_found, quorum) {
            info!(
                "chunk_get giving up on {addr_hex} (authoritative NotFound): \
                 queried={} not_found={} timeout={} network_err={} quorum={quorum}",
                first.queried, first.not_found, first.timeout, first.network_err
            );
            return Ok(None);
        }

        // Otherwise the failure looks like reachability (most peers timed out
        // or hit transport errors). The chunk is most likely still on the
        // network but the current close-group view either (a) caught a
        // transient transport blip or (b) converged on the wrong neighbourhood
        // because the routing table is thin. One retry against a freshly
        // re-walked close group is the cheapest defence against both.
        info!(
            "chunk_get retrying {addr_hex} after reachability failure: \
             queried={} not_found={} timeout={} network_err={}",
            first.queried, first.not_found, first.timeout, first.network_err
        );

        // Brief settle so any in-flight transport state can quiesce before
        // we re-walk the DHT. Keep this small so we don't add meaningful
        // latency to the genuinely-lost case (we already paid for one full
        // close-group sweep before getting here).
        tokio::time::sleep(Duration::from_secs(1)).await;

        // If the retry's DHT lookup itself fails, treat that as "still
        // couldn't find" rather than escalating the error — matches the
        // semantics of the first attempt when peers are unreachable.
        let retry = match self.chunk_get_try_close_group(address).await {
            Ok(o) => o,
            Err(e) => {
                info!(
                    "chunk_get retry close-group lookup failed for {addr_hex}: {e}; \
                     first(queried={} not_found={} timeout={} network_err={})",
                    first.queried, first.not_found, first.timeout, first.network_err
                );
                return Ok(None);
            }
        };
        if let Some(chunk) = retry.chunk {
            info!("chunk_get retry succeeded for {addr_hex}");
            self.chunk_cache().put(chunk.address, chunk.content.clone());
            return Ok(Some(chunk));
        }

        info!(
            "chunk_get exhausted close group after retry for {addr_hex}: \
             first(queried={} not_found={} timeout={} network_err={}) \
             retry(queried={} not_found={} timeout={} network_err={})",
            first.queried,
            first.not_found,
            first.timeout,
            first.network_err,
            retry.queried,
            retry.not_found,
            retry.timeout,
            retry.network_err,
        );
        Ok(None)
    }

    /// One sweep of the current close group: fetch the K closest peers
    /// for `address` from the DHT and ask each for the chunk in turn,
    /// returning on the first success.
    async fn chunk_get_try_close_group(
        &self,
        address: &XorName,
    ) -> Result<CloseGroupOutcome> {
        let peers = self.close_group_peers(address).await?;
        let addr_hex = hex::encode(address);
        let queried = peers.len();
        let mut not_found = 0usize;
        let mut timeout = 0usize;
        let mut network_err = 0usize;

        for (peer, addrs) in &peers {
            match self.chunk_get_from_peer(address, peer, addrs).await {
                Ok(Some(chunk)) => {
                    return Ok(CloseGroupOutcome {
                        chunk: Some(chunk),
                        queried,
                        not_found,
                        timeout,
                        network_err,
                    });
                }
                Ok(None) => {
                    not_found += 1;
                    debug!("Chunk {addr_hex} not found on peer {peer}, trying next");
                }
                Err(Error::Timeout(_)) => {
                    timeout += 1;
                    debug!("Peer {peer} timed out for chunk {addr_hex}, trying next");
                }
                Err(Error::Network(_)) => {
                    network_err += 1;
                    debug!("Peer {peer} unreachable for chunk {addr_hex}, trying next");
                }
                Err(e) => return Err(e),
            }
        }

        Ok(CloseGroupOutcome {
            chunk: None,
            queried,
            not_found,
            timeout,
            network_err,
        })
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

        let timeout = Duration::from_secs(self.config().chunk_get_timeout_secs);
        let addr_hex = hex::encode(address);
        let timeout_secs = self.config().chunk_get_timeout_secs;

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

    /// Finalize a single-chunk publish after an external signer has paid.
    ///
    /// Single-chunk analogue of [`Client::finalize_upload`]. Takes a
    /// [`PreparedChunk`] (from [`Client::prepare_chunk_payment`]) and a
    /// `quote_hash -> tx_hash` map containing receipts for every non-zero
    /// quote in the chunk's payment. Builds the `PaymentProof` and stores
    /// the chunk on `CLOSE_GROUP_MAJORITY` peers, returning its address.
    ///
    /// Wave-batch payment shape only. Single-chunk publishes don't need
    /// Merkle batching: one chunk's worth of quotes is well below the
    /// wave-batch threshold.
    ///
    /// # Errors
    ///
    /// Returns an error if the proof construction fails (e.g. missing
    /// `tx_hash` for a non-zero quote) or if fewer than
    /// `CLOSE_GROUP_MAJORITY` peers accept the chunk.
    pub async fn finalize_chunk(
        &self,
        prepared: PreparedChunk,
        tx_hash_map: &HashMap<QuoteHash, TxHash>,
    ) -> Result<XorName> {
        let mut paid = finalize_batch_payment(vec![prepared], tx_hash_map)?;
        // finalize_batch_payment returns one PaidChunk per PreparedChunk
        // input; we passed exactly one. If that invariant is ever violated
        // it's an upstream bug — fail loudly rather than silently address-0.
        let chunk = paid.pop().ok_or_else(|| {
            Error::Payment(
                "finalize_batch_payment returned no paid chunks for a single \
                 prepared chunk — internal invariant violated"
                    .into(),
            )
        })?;
        self.chunk_put_to_close_group(chunk.content, chunk.proof_bytes, &chunk.quoted_peers)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ant_protocol::{PROOF_TAG_MERKLE, PROOF_TAG_SINGLE_NODE};

    /// Arbitrary configured Merkle store timeout used by the timeout-selection tests.
    const TEST_MERKLE_TIMEOUT_SECS: u64 = 60;
    /// Sentinel byte used to represent an unknown/unrecognized proof tag.
    const UNKNOWN_PROOF_TAG: u8 = 0xff;

    #[test]
    fn authoritative_not_found_requires_quorum() {
        // Standard close-group-size 7: quorum is 4.
        let quorum = 7 / 2 + 1;
        assert_eq!(quorum, 4);

        // 4-of-7 is the threshold.
        assert!(is_authoritative_not_found(4, quorum));
        assert!(is_authoritative_not_found(7, quorum));

        // 3-of-7 is still reachability-shaped — must retry.
        assert!(!is_authoritative_not_found(3, quorum));
        // All reachability failures, zero NotFound — must retry.
        assert!(!is_authoritative_not_found(0, quorum));
    }

    #[test]
    fn single_node_proof_uses_store_response_timeout() {
        let timeout =
            store_response_timeout_for_proof(&[PROOF_TAG_SINGLE_NODE], TEST_MERKLE_TIMEOUT_SECS);

        assert_eq!(timeout, STORE_RESPONSE_TIMEOUT);
    }

    #[test]
    fn unknown_proof_uses_store_response_timeout() {
        let timeout =
            store_response_timeout_for_proof(&[UNKNOWN_PROOF_TAG], TEST_MERKLE_TIMEOUT_SECS);

        assert_eq!(timeout, STORE_RESPONSE_TIMEOUT);
    }

    #[test]
    fn merkle_proof_uses_configured_store_timeout() {
        let timeout =
            store_response_timeout_for_proof(&[PROOF_TAG_MERKLE], TEST_MERKLE_TIMEOUT_SECS);

        assert_eq!(timeout, Duration::from_secs(TEST_MERKLE_TIMEOUT_SECS));
    }

    /// Regression: the default `merkle_store_timeout_secs` must be at
    /// least the storer-side `CLOSENESS_LOOKUP_TIMEOUT` (240 s) plus
    /// padding. If either side moves and this invariant breaks, the
    /// client will give up on chunks the storer is still verifying.
    /// See `DEFAULT_MERKLE_STORE_TIMEOUT_SECS` doc comment for the
    /// derivation.
    #[test]
    fn default_merkle_store_timeout_satisfies_storer_invariant() {
        use crate::data::client::ClientConfig;
        const STORER_CLOSENESS_LOOKUP_TIMEOUT_SECS: u64 = 240;
        const MIN_PADDING_SECS: u64 = 30;
        let config = ClientConfig::default();
        assert!(
            config.merkle_store_timeout_secs
                >= STORER_CLOSENESS_LOOKUP_TIMEOUT_SECS + MIN_PADDING_SECS,
            "merkle_store_timeout_secs ({}) must be >= storer CLOSENESS_LOOKUP_TIMEOUT ({}) + padding ({})",
            config.merkle_store_timeout_secs,
            STORER_CLOSENESS_LOOKUP_TIMEOUT_SECS,
            MIN_PADDING_SECS,
        );
    }

    /// Regression: the non-merkle PUT path uses the hardcoded
    /// `STORE_RESPONSE_TIMEOUT` constant, not the per-config
    /// `merkle_store_timeout_secs`. If a future refactor accidentally
    /// routes non-merkle PUTs through the merkle field they'd inherit
    /// the 270 s value and silently regress non-merkle latency.
    /// `store_response_timeout_for_proof` with a non-merkle proof tag
    /// must return the const regardless of what merkle timeout is
    /// passed.
    #[test]
    fn non_merkle_put_ignores_merkle_timeout_value() {
        let absurd_merkle_timeout = 9_999;
        for tag in [PROOF_TAG_SINGLE_NODE, UNKNOWN_PROOF_TAG] {
            let timeout = store_response_timeout_for_proof(&[tag], absurd_merkle_timeout);
            assert_eq!(
                timeout, STORE_RESPONSE_TIMEOUT,
                "non-merkle proof tag {tag:#x} should ignore merkle timeout {absurd_merkle_timeout}",
            );
        }
    }
}
