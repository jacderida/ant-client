//! Quote and payment operations.
//!
//! Handles requesting storage quotes from network nodes and
//! managing payment for data storage.

use crate::data::client::peer_cache::record_peer_outcome;
use crate::data::client::Client;
use crate::data::error::{Error, Result};
use ant_protocol::evm::{Amount, PaymentQuote};
use ant_protocol::transport::{MultiAddr, PeerId};
use ant_protocol::{
    compute_address, send_and_await_chunk_response, ChunkMessage, ChunkMessageBody,
    ChunkQuoteRequest, ChunkQuoteResponse, CLOSE_GROUP_MAJORITY, CLOSE_GROUP_SIZE,
};
use futures::stream::{FuturesUnordered, StreamExt};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Compute XOR distance between a peer's ID bytes and a target address.
///
/// Uses the first 32 bytes of the peer ID (or fewer if shorter) XORed with
/// the target address. Returns a byte array suitable for lexicographic comparison.
fn xor_distance(peer_id: &PeerId, target: &[u8; 32]) -> [u8; 32] {
    let peer_bytes = peer_id.as_bytes();
    let mut distance = [0u8; 32];
    for (i, d) in distance.iter_mut().enumerate() {
        let pb = peer_bytes.get(i).copied().unwrap_or(0);
        *d = pb ^ target[i];
    }
    distance
}

/// Check that a quote's `pub_key` BLAKE3-hashes to the claimed `peer_id`.
///
/// The storer node enforces this via `validate_peer_bindings` in
/// `ant-node/src/payment/verifier.rs`: every quote inside a `ProofOfPayment`
/// must satisfy `BLAKE3(pub_key) == peer_id`. If even one of the
/// `CLOSE_GROUP_SIZE` quotes fails the check, the storer rejects the entire
/// proof and the chunk's payment is wasted.
///
/// This mirrors the storer-side check so we can drop bad quotes before
/// committing payment, instead of paying for a proof we know will be
/// rejected. Mismatches happen when an operator runs two co-located node
/// identities with crossed quote-signing keys.
fn quote_binding_is_valid(peer_id: &PeerId, quote: &PaymentQuote) -> bool {
    compute_address(&quote.pub_key) == *peer_id.as_bytes()
}

/// Drop quotes whose `pub_key` does not BLAKE3-hash to the peer that supplied
/// them. Logs each dropped quote at WARN.
fn drop_quotes_with_bad_bindings(
    quotes: &mut Vec<(PeerId, Vec<MultiAddr>, PaymentQuote, Amount)>,
) -> usize {
    let before = quotes.len();
    quotes.retain(|(peer_id, _, quote, _)| {
        if quote_binding_is_valid(peer_id, quote) {
            true
        } else {
            warn!(
                "Dropping quote from peer {peer_id} — quote.pub_key BLAKE3 mismatch \
                 (peer is signing quotes with another peer's key); the storer would \
                 reject this proof"
            );
            false
        }
    });
    before - quotes.len()
}

impl Client {
    /// Get storage quotes from the closest peers for a given address.
    ///
    /// Queries 2x `CLOSE_GROUP_SIZE` peers from the DHT for fault tolerance,
    /// requests quotes from all of them concurrently, and returns the
    /// `CLOSE_GROUP_SIZE` closest successful responders sorted by XOR distance.
    ///
    /// Returns `Error::AlreadyStored` early if `CLOSE_GROUP_MAJORITY` peers
    /// report the chunk is already stored.
    ///
    /// # Errors
    ///
    /// Returns an error if insufficient quotes can be collected.
    #[allow(clippy::too_many_lines)]
    pub async fn get_store_quotes(
        &self,
        address: &[u8; 32],
        data_size: u64,
        data_type: u32,
    ) -> Result<Vec<(PeerId, Vec<MultiAddr>, PaymentQuote, Amount)>> {
        let node = self.network().node();

        // Over-query for fault tolerance: ask 2x peers, keep closest successful ones.
        let over_query_count = CLOSE_GROUP_SIZE * 2;
        debug!(
            "Requesting quotes from up to {over_query_count} peers for address {} (size: {data_size})",
            hex::encode(address)
        );

        let remote_peers = self
            .network()
            .find_closest_peers(address, over_query_count)
            .await?;

        if remote_peers.len() < CLOSE_GROUP_SIZE {
            return Err(Error::InsufficientPeers(format!(
                "Found {} peers, need {CLOSE_GROUP_SIZE}",
                remote_peers.len()
            )));
        }

        let per_peer_timeout = Duration::from_secs(self.config().quote_timeout_secs);
        // Overall timeout for collecting all quotes. Must accommodate
        // connect_with_fallback cascade (direct 5s + hole-punch 15s×3 + relay 30s ≈ 80s)
        // plus the per-peer quote timeout. 120s is generous.
        let overall_timeout = Duration::from_secs(120);

        // Request quotes from all peers concurrently
        let mut quote_futures = FuturesUnordered::new();

        for (peer_id, peer_addrs) in &remote_peers {
            let request_id = self.next_request_id();
            let request = ChunkQuoteRequest {
                address: *address,
                data_size,
                data_type,
            };
            let message = ChunkMessage {
                request_id,
                body: ChunkMessageBody::QuoteRequest(request),
            };

            let message_bytes = match message.encode() {
                Ok(bytes) => bytes,
                Err(e) => {
                    warn!("Failed to encode quote request for {peer_id}: {e}");
                    continue;
                }
            };

            let peer_id_clone = *peer_id;
            let addrs_clone = peer_addrs.clone();
            let node_clone = node.clone();

            let quote_future = async move {
                let start = Instant::now();
                let result = send_and_await_chunk_response(
                    &node_clone,
                    &peer_id_clone,
                    message_bytes,
                    request_id,
                    per_peer_timeout,
                    &addrs_clone,
                    |body| match body {
                        ChunkMessageBody::QuoteResponse(ChunkQuoteResponse::Success {
                            quote,
                            already_stored,
                        }) => {
                            if already_stored {
                                debug!("Peer {peer_id_clone} already has chunk");
                                return Some(Err(Error::AlreadyStored));
                            }
                            match rmp_serde::from_slice::<PaymentQuote>(&quote) {
                                Ok(payment_quote) => {
                                    let price = payment_quote.price;
                                    debug!("Received quote from {peer_id_clone}: price = {price}");
                                    Some(Ok((payment_quote, price)))
                                }
                                Err(e) => Some(Err(Error::Serialization(format!(
                                    "Failed to deserialize quote from {peer_id_clone}: {e}"
                                )))),
                            }
                        }
                        ChunkMessageBody::QuoteResponse(ChunkQuoteResponse::Error(e)) => Some(Err(
                            Error::Protocol(format!("Quote error from {peer_id_clone}: {e}")),
                        )),
                        _ => None,
                    },
                    |e| {
                        Error::Network(format!(
                            "Failed to send quote request to {peer_id_clone}: {e}"
                        ))
                    },
                    || Error::Timeout(format!("Timeout waiting for quote from {peer_id_clone}")),
                )
                .await;

                let success = result.is_ok();
                let rtt_ms = success.then(|| start.elapsed().as_millis() as u64);
                record_peer_outcome(&node_clone, peer_id_clone, &addrs_clone, success, rtt_ms)
                    .await;

                (peer_id_clone, addrs_clone, result)
            };

            quote_futures.push(quote_future);
        }

        // Collect all responses with an overall timeout to prevent indefinite stalls.
        // Over-query means we have 2x peers, so we can tolerate failures.
        let mut quotes = Vec::with_capacity(over_query_count);
        let mut already_stored_peers: Vec<(PeerId, [u8; 32])> = Vec::new();
        let mut failures: Vec<String> = Vec::new();

        let collect_result: std::result::Result<std::result::Result<(), Error>, _> =
            tokio::time::timeout(overall_timeout, async {
                while let Some((peer_id, addrs, quote_result)) = quote_futures.next().await {
                    match quote_result {
                        Ok((quote, price)) => {
                            quotes.push((peer_id, addrs, quote, price));
                        }
                        Err(Error::AlreadyStored) => {
                            info!("Peer {peer_id} reports chunk already stored");
                            let dist = xor_distance(&peer_id, address);
                            already_stored_peers.push((peer_id, dist));
                        }
                        Err(e) => {
                            warn!("Failed to get quote from {peer_id}: {e}");
                            failures.push(format!("{peer_id}: {e}"));
                        }
                    }
                }
                Ok(())
            })
            .await;

        match collect_result {
            Err(_elapsed) => {
                warn!(
                    "Quote collection timed out after {overall_timeout:?} for address {}",
                    hex::encode(address)
                );
                // Fall through to check if we have enough quotes despite timeout.
                // The timeout fires when slow peers haven't responded yet, but we
                // may already have enough successful quotes from fast peers.
            }
            Ok(Err(e)) => return Err(e),
            Ok(Ok(())) => {}
        }

        let bad_dropped = drop_quotes_with_bad_bindings(&mut quotes);
        if bad_dropped > 0 {
            info!(
                "Dropped {bad_dropped} quotes with mismatched peer bindings for address {} \
                 ({} good quotes remain from {} responders)",
                hex::encode(address),
                quotes.len(),
                quotes.len() + bad_dropped,
            );
        }

        // Check already-stored: only count votes from the closest CLOSE_GROUP_SIZE peers.
        if !already_stored_peers.is_empty() {
            let mut all_peers_by_distance: Vec<(bool, [u8; 32])> = Vec::new();
            for (peer_id, _, _, _) in &quotes {
                all_peers_by_distance.push((false, xor_distance(peer_id, address)));
            }
            for (_, dist) in &already_stored_peers {
                all_peers_by_distance.push((true, *dist));
            }
            all_peers_by_distance.sort_by_key(|a| a.1);

            let close_group_stored = all_peers_by_distance
                .iter()
                .take(CLOSE_GROUP_SIZE)
                .filter(|(is_stored, _)| *is_stored)
                .count();

            if close_group_stored >= CLOSE_GROUP_MAJORITY {
                debug!(
                    "Chunk {} already stored ({close_group_stored}/{CLOSE_GROUP_SIZE} close-group peers confirm)",
                    hex::encode(address)
                );
                return Err(Error::AlreadyStored);
            }
        }

        let already_stored_count = already_stored_peers.len();
        let failure_count = failures.len();
        let quote_count = quotes.len();
        let total_responses = quote_count + failure_count + already_stored_count;

        if quotes.len() >= CLOSE_GROUP_SIZE {
            // Sort by XOR distance to target, keep the closest CLOSE_GROUP_SIZE.
            quotes.sort_by(|a, b| {
                let dist_a = xor_distance(&a.0, address);
                let dist_b = xor_distance(&b.0, address);
                dist_a.cmp(&dist_b)
            });
            quotes.truncate(CLOSE_GROUP_SIZE);

            info!(
                "Collected {} quotes for address {} ({total_responses} responses: {quote_count} ok, {already_stored_count} already_stored, {failure_count} failed)",
                quotes.len(),
                hex::encode(address),
            );
            return Ok(quotes);
        }

        Err(Error::InsufficientPeers(format!(
            "Got {quote_count} quotes, need {CLOSE_GROUP_SIZE} ({total_responses} responses: {already_stored_count} already_stored, {failure_count} failed). Failures: [{}]",
            failures.join("; ")
        )))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use ant_protocol::evm::RewardsAddress;
    use std::time::SystemTime;
    use xor_name::XorName;

    /// Build a `(PeerId, MultiAddrs, PaymentQuote, Amount)` tuple where the
    /// quote's `pub_key` correctly BLAKE3-hashes to the peer ID.
    fn good_quote(pub_key: Vec<u8>) -> (PeerId, Vec<MultiAddr>, PaymentQuote, Amount) {
        let peer_id_bytes = compute_address(&pub_key);
        let peer_id = PeerId::from_bytes(peer_id_bytes);
        let quote = PaymentQuote {
            content: XorName([0u8; 32]),
            timestamp: SystemTime::UNIX_EPOCH,
            price: Amount::ZERO,
            rewards_address: RewardsAddress::new([0u8; 20]),
            pub_key,
            signature: Vec::new(),
        };
        (peer_id, Vec::new(), quote, Amount::ZERO)
    }

    /// Build a tuple where the quote's `pub_key` BLAKE3-hashes to a different
    /// peer ID than the one we claim. This is the "misbehaving operator
    /// running two co-located identities with crossed quote-signing keys"
    /// shape that triggers the storer-side rejection.
    fn bad_quote(
        claimed_pub_key: Vec<u8>,
        signed_with_pub_key: Vec<u8>,
    ) -> (PeerId, Vec<MultiAddr>, PaymentQuote, Amount) {
        // Peer ID is BLAKE3 of the *claimed* identity's public key…
        let peer_id_bytes = compute_address(&claimed_pub_key);
        let peer_id = PeerId::from_bytes(peer_id_bytes);
        // …but the quote carries a *different* public key.
        let quote = PaymentQuote {
            content: XorName([0u8; 32]),
            timestamp: SystemTime::UNIX_EPOCH,
            price: Amount::ZERO,
            rewards_address: RewardsAddress::new([0u8; 20]),
            pub_key: signed_with_pub_key,
            signature: Vec::new(),
        };
        (peer_id, Vec::new(), quote, Amount::ZERO)
    }

    #[test]
    fn quote_binding_accepts_matched_pubkey() {
        let (peer_id, _, quote, _) = good_quote(b"valid pub_key bytes".to_vec());
        assert!(quote_binding_is_valid(&peer_id, &quote));
    }

    #[test]
    fn quote_binding_rejects_mismatched_pubkey() {
        let (peer_id, _, quote, _) = bad_quote(
            b"claimed identity pub_key".to_vec(),
            b"a different identity's pub_key".to_vec(),
        );
        assert!(!quote_binding_is_valid(&peer_id, &quote));
    }

    #[test]
    fn drop_quotes_with_bad_bindings_leaves_only_good_ones() {
        let mut quotes = vec![
            good_quote(b"peer-A pub_key".to_vec()),
            bad_quote(b"peer-B pub_key".to_vec(), b"peer-X pub_key".to_vec()),
            good_quote(b"peer-C pub_key".to_vec()),
            bad_quote(b"peer-D pub_key".to_vec(), b"peer-Y pub_key".to_vec()),
            good_quote(b"peer-E pub_key".to_vec()),
        ];

        let dropped = drop_quotes_with_bad_bindings(&mut quotes);

        assert_eq!(dropped, 2, "two bad-binding quotes should be dropped");
        assert_eq!(quotes.len(), 3, "three good quotes should remain");
        for (peer_id, _, quote, _) in &quotes {
            assert!(
                quote_binding_is_valid(peer_id, quote),
                "every retained quote must have a valid binding"
            );
        }
    }

    #[test]
    fn drop_quotes_with_bad_bindings_is_noop_when_all_good() {
        let mut quotes: Vec<_> = (0..5)
            .map(|i| good_quote(format!("peer-{i} pub_key").into_bytes()))
            .collect();
        let before = quotes.len();
        let dropped = drop_quotes_with_bad_bindings(&mut quotes);
        assert_eq!(dropped, 0);
        assert_eq!(quotes.len(), before);
    }

    /// Repro of the production failure from 2026-04-30 testnet runs:
    ///
    /// An external operator on `75.48.86.24` ran two co-located ant-node
    /// identities (peer `0755ecb55b…` and peer `073db92f…`) that crossed
    /// their quote-signing keys. Every chunk whose XOR-closest set
    /// happened to include peer `0755ecb5` got a payment proof with one
    /// malformed quote, and the storer's `validate_peer_bindings` rejected
    /// the entire close-group proof — burning the chunk's payment.
    ///
    /// With the over-query buffer (`2x CLOSE_GROUP_SIZE` peers) and the
    /// drop-bad-bindings filter, the misbehaving peer is now removed
    /// before payment, leaving `CLOSE_GROUP_SIZE` good quotes from the
    /// remaining over-queried peers.
    #[test]
    fn repro_2026_04_30_one_bad_peer_in_over_query_set() {
        // Simulate the over-query response: 14 peers, one of them is the
        // misbehaving operator's `0755ecb5` identity that signs with
        // `073db92f`'s key.
        let over_query_count = CLOSE_GROUP_SIZE * 2;
        let mut quotes: Vec<_> = (0..over_query_count - 1)
            .map(|i| good_quote(format!("honest-peer-{i}").into_bytes()))
            .collect();
        // Splice the bad peer somewhere in the middle.
        quotes.insert(
            over_query_count / 2,
            bad_quote(
                b"0755ecb5_claimed_identity".to_vec(),
                b"073db92f_signing_identity".to_vec(),
            ),
        );
        assert_eq!(quotes.len(), over_query_count);

        let dropped = drop_quotes_with_bad_bindings(&mut quotes);

        assert_eq!(dropped, 1);
        assert!(
            quotes.len() >= CLOSE_GROUP_SIZE,
            "after dropping the misbehaving peer we must still have \
             CLOSE_GROUP_SIZE good quotes — that's the whole point of \
             over-querying 2x"
        );
    }
}
