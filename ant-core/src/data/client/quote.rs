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
    compute_address, send_and_await_chunk_response, verify_quote_content, verify_quote_signature,
    ChunkMessage, ChunkMessageBody, ChunkQuoteRequest, ChunkQuoteResponse, CLOSE_GROUP_MAJORITY,
    CLOSE_GROUP_SIZE,
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

/// ML-DSA-65 public key length in bytes. Mirrors the same value defined as
/// `pub const ML_DSA_65_PUBLIC_KEY_SIZE` in `saorsa-pqc::pqc::types`, which
/// the storer's `peer_id_from_public_key_bytes` enforces. We keep a local
/// copy here rather than adding a direct `saorsa-pqc` dep — the constant
/// is FIPS-mandated for ML-DSA-65 and won't change unless we change variant.
///
/// TODO: switch to `saorsa_pqc::pqc::types::ML_DSA_65_PUBLIC_KEY_SIZE` once
/// `ant-protocol` re-exports it (`pqc::ops::ML_DSA_65_PUBLIC_KEY_SIZE`).
const ML_DSA_PUB_KEY_LEN: usize = 1952;

/// Check that a quote's `pub_key` is well-formed and BLAKE3-hashes to the
/// claimed `peer_id`.
///
/// The storer node enforces both constraints in `ant-node/src/payment/verifier.rs`
/// (via `peer_id_from_public_key_bytes` and `validate_peer_bindings`): every
/// quote inside a `ProofOfPayment` must (a) have a 1952-byte `pub_key` parsable
/// as ML-DSA-65 and (b) satisfy `BLAKE3(pub_key) == peer_id`. A single quote
/// failing either check causes the storer to reject the entire close-group
/// proof and burn the chunk's payment.
///
/// This is one of three storer-side checks the client now mirrors. The other
/// two — `verify_quote_content` and `verify_quote_signature` — live in
/// `classify_quote_response` so they run ahead of payment commitment.
fn quote_binding_is_valid(peer_id: &PeerId, quote: &PaymentQuote) -> bool {
    if quote.pub_key.len() != ML_DSA_PUB_KEY_LEN {
        return false;
    }
    compute_address(&quote.pub_key) == *peer_id.as_bytes()
}

/// Classification of a `ChunkQuoteResponse::Success` body for a single peer.
///
/// Mirrors all three storer-side rejection conditions from
/// `ant-node/src/payment/verifier.rs` so the client never pays on-chain
/// for a `ProofOfPayment` the network is guaranteed to reject:
///
///   1. peer-binding (`BLAKE3(pub_key) == peer_id`),
///   2. content (`quote.content == request.address`), and
///   3. ML-DSA-65 signature over `(content, timestamp, price, rewards_address)`.
///
/// Pulling the logic out of the async closure lets us unit-test the
/// primary defense (not just the post-collect defensive filter).
///
/// # Returns
///
/// - `Ok((quote, price))` — the response is honoured as a quote.
/// - `Err(Error::AlreadyStored)` — the peer claims the chunk is already
///   present AND the quote it provided passes all three storer checks.
///   Vote counts in the close-group "already stored" majority.
/// - `Err(Error::BadQuoteBinding { .. })` — peer-binding failure.
/// - `Err(Error::BadQuoteContent { .. })` — content-address mismatch.
/// - `Err(Error::BadQuoteSignature { .. })` — ML-DSA-65 signature failure.
/// - `Err(Error::Serialization(...))` — the quote bytes did not deserialize.
///
/// All bad-quote variants flow into the outer collector as failures so
/// `record_peer_outcome` correctly marks the peer as a failure in the
/// AIMD bootstrap cache.
fn classify_quote_response(
    peer_id: &PeerId,
    address: &[u8; 32],
    quote_bytes: &[u8],
    already_stored: bool,
) -> std::result::Result<(PaymentQuote, Amount), Error> {
    let payment_quote = rmp_serde::from_slice::<PaymentQuote>(quote_bytes).map_err(|e| {
        Error::Serialization(format!("Failed to deserialize quote from {peer_id}: {e}"))
    })?;

    // 1. Peer binding: BLAKE3(pub_key) must equal peer_id.
    if !quote_binding_is_valid(peer_id, &payment_quote) {
        let derived = compute_address(&payment_quote.pub_key);
        warn!(
            "Dropping response from {peer_id} — quote.pub_key BLAKE3 mismatch \
             (peer is signing quotes with another peer's key); the storer \
             would reject this proof"
        );
        return Err(Error::BadQuoteBinding {
            peer_id: peer_id.to_string(),
            detail: format!(
                "BLAKE3(pub_key)={} pub_key_len={}",
                hex::encode(derived),
                payment_quote.pub_key.len(),
            ),
        });
    }

    // 2. Content address: quote must be for the chunk we asked about.
    // The storer enforces this; a peer could otherwise replay a stale-but-
    // fresh quote for a different chunk and the storer rejects post-payment.
    if !verify_quote_content(&payment_quote, address) {
        warn!(
            "Dropping response from {peer_id} — quote.content does not match \
             requested address; the storer would reject this proof"
        );
        return Err(Error::BadQuoteContent {
            peer_id: peer_id.to_string(),
            expected: hex::encode(address),
            actual: hex::encode(payment_quote.content.0),
        });
    }

    // 3. ML-DSA-65 signature: storer verifies, so we should too. Otherwise
    // a peer with a self-consistent (peer_id, pub_key) pair but a forged or
    // empty signature would still pass the binding check, get included in
    // the proof, and the storer rejects post-payment. Cost: ~1 ms per quote,
    // far below the per-peer RTT we already paid.
    if !verify_quote_signature(&payment_quote) {
        warn!(
            "Dropping response from {peer_id} — quote signature failed \
             ML-DSA-65 verification; the storer would reject this proof"
        );
        return Err(Error::BadQuoteSignature {
            peer_id: peer_id.to_string(),
        });
    }

    if already_stored {
        debug!("Peer {peer_id} already has chunk");
        return Err(Error::AlreadyStored);
    }
    let price = payment_quote.price;
    debug!("Received quote from {peer_id}: price = {price}");
    Ok((payment_quote, price))
}

/// Map a per-peer quote-collection outcome to the AIMD-cache success flag.
///
/// `Ok(_)` and `AlreadyStored` are both *benign* outcomes — the peer is
/// reachable and well-behaved — so we record them as successes (recording
/// a smooth RTT). Every other variant (network/timeout/protocol/
/// serialization, plus the three storer-rejecting variants
/// `BadQuoteBinding` / `BadQuoteContent` / `BadQuoteSignature`) records
/// as a failure so the local AIMD bootstrap cache learns to deprioritize
/// peers that don't help us upload.
///
/// Pulled out of the per-peer closure for unit-testing.
fn quote_outcome_is_success(result: &std::result::Result<(PaymentQuote, Amount), Error>) -> bool {
    matches!(result, Ok(_) | Err(Error::AlreadyStored))
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
            let address_clone = *address;

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
                        }) => Some(classify_quote_response(
                            &peer_id_clone,
                            &address_clone,
                            &quote,
                            already_stored,
                        )),
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

                // Record the per-peer outcome for the AIMD bootstrap cache.
                // See `quote_outcome_is_success` for the full classification.
                let success = quote_outcome_is_success(&result);
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

        // Track storer-rejecting peers separately (binding, content, signature
        // failures) so we can surface their count in diagnostics — they're a
        // special class of failure (peer misconfigured or hostile, not
        // network-broken) and the user benefits from seeing them called out.
        let mut bad_quote_count = 0usize;

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
                            // Count storer-rejecting variants separately (typed
                            // — no string sniffing). Treat as normal failures
                            // for InsufficientPeers reporting otherwise.
                            if matches!(
                                &e,
                                Error::BadQuoteBinding { .. }
                                    | Error::BadQuoteContent { .. }
                                    | Error::BadQuoteSignature { .. }
                            ) {
                                bad_quote_count += 1;
                            }
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

        // Defensive double-check: the per-peer handler already filters
        // bad-binding responses into `failures`, but if any path slipped a bad
        // quote into `quotes` (e.g. a future refactor) this catches it before
        // we sort by distance and return. `bad_dropped` should be 0 in normal
        // operation; non-zero indicates an upstream regression worth investigating.
        let bad_dropped = drop_quotes_with_bad_bindings(&mut quotes);
        if bad_dropped > 0 {
            warn!(
                "Defensive filter dropped {bad_dropped} quotes with mismatched peer bindings \
                 for address {} — the per-peer handler should have caught these earlier \
                 (this indicates an upstream regression)",
                hex::encode(address),
            );
            bad_quote_count += bad_dropped;
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
                "Collected {} quotes for address {} ({total_responses} responses: \
                 {quote_count} ok, {already_stored_count} already_stored, {failure_count} failed, \
                 {bad_quote_count} would-be-rejected by storer)",
                quotes.len(),
                hex::encode(address),
            );
            return Ok(quotes);
        }

        Err(Error::InsufficientPeers(format!(
            "Got {quote_count} quotes, need {CLOSE_GROUP_SIZE} ({total_responses} responses: \
             {already_stored_count} already_stored, {failure_count} failed including \
             {bad_quote_count} that the storer would have rejected — peer-binding, \
             content, or signature mismatch). Failures: [{}]",
            failures.join("; ")
        )))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    //! Test fixtures use real ML-DSA-65 keypairs (1952-byte public keys) and
    //! produce real ML-DSA-65 signatures over `bytes_for_sig`. This avoids
    //! the "synthetic-key" honesty problem and exercises exactly the same
    //! byte paths that run in production. The "bad" quotes mirror the
    //! shapes the storer would reject:
    //!
    //!   * `bad_binding_quote_for(addr)` — `quote.pub_key` swapped for a
    //!     different keypair's pub_key (the Apr 30 production failure).
    //!   * `bad_content_quote_for(addr)` — `quote.content` is a different
    //!     XorName than the chunk address we asked for.
    //!   * `bad_signature_quote_for(addr)` — quote is signed but with a
    //!     post-hoc field tweak that invalidates the signature.

    use super::*;
    use ant_protocol::evm::RewardsAddress;
    use ant_protocol::pqc::ops::{MlDsaOperations, MlDsaPublicKey, MlDsaSecretKey};
    use ant_protocol::transport::MlDsa65;
    use std::time::SystemTime;
    use xor_name::XorName;

    /// A real ML-DSA-65 keypair plus its derived peer ID.
    struct Keypair {
        peer_id: PeerId,
        pub_key_bytes: Vec<u8>,
        secret_key_bytes: Vec<u8>,
    }

    fn gen_keypair() -> Keypair {
        let ml_dsa = MlDsa65::new();
        let (pub_key, sk) = ml_dsa.generate_keypair().expect("ML-DSA-65 keygen");
        let pub_key_bytes = pub_key.as_bytes().to_vec();
        let secret_key_bytes = sk.as_bytes().to_vec();
        let peer_id = PeerId::from_bytes(compute_address(&pub_key_bytes));
        Keypair {
            peer_id,
            pub_key_bytes,
            secret_key_bytes,
        }
    }

    /// Sign a quote's `bytes_for_sig` with the given secret key bytes.
    fn sign_quote(quote: &mut PaymentQuote, secret_key_bytes: &[u8]) {
        let ml_dsa = MlDsa65::new();
        let sk = MlDsaSecretKey::from_bytes(secret_key_bytes).expect("sk parse");
        let msg = quote.bytes_for_sig();
        quote.signature = ml_dsa
            .sign(&sk, &msg)
            .expect("ml-dsa sign")
            .as_bytes()
            .to_vec();
    }

    /// Build a fully-valid quote: the keypair is internally consistent, the
    /// content matches `address`, and the signature is genuine. The storer
    /// must accept this; the classifier must accept this.
    fn good_quote_for(address: &[u8; 32]) -> (PeerId, Vec<MultiAddr>, PaymentQuote, Amount) {
        let kp = gen_keypair();
        let mut quote = PaymentQuote {
            content: XorName(*address),
            timestamp: SystemTime::now(),
            price: Amount::from(42u64),
            rewards_address: RewardsAddress::new([1u8; 20]),
            pub_key: kp.pub_key_bytes,
            signature: Vec::new(),
        };
        sign_quote(&mut quote, &kp.secret_key_bytes);
        (kp.peer_id, Vec::new(), quote, Amount::ZERO)
    }

    /// Build a quote where `quote.pub_key` belongs to a DIFFERENT keypair
    /// than the peer_id derives from (the Apr 30 production-failure shape).
    /// Signature is over the served pub_key's secret so it would pass the
    /// signature check in isolation — the binding check is what catches it.
    fn bad_binding_quote_for(address: &[u8; 32]) -> (PeerId, Vec<MultiAddr>, PaymentQuote, Amount) {
        let claimed = gen_keypair();
        let signing = gen_keypair();
        assert_ne!(claimed.pub_key_bytes, signing.pub_key_bytes);
        assert_ne!(claimed.peer_id.as_bytes(), signing.peer_id.as_bytes());
        let mut quote = PaymentQuote {
            content: XorName(*address),
            timestamp: SystemTime::now(),
            price: Amount::from(42u64),
            rewards_address: RewardsAddress::new([1u8; 20]),
            pub_key: signing.pub_key_bytes.clone(),
            signature: Vec::new(),
        };
        // Sign with the served pub_key's secret so the signature is valid
        // over the served pub_key. The defect is the binding mismatch
        // between served pub_key and claimed peer_id, not the signature.
        sign_quote(&mut quote, &signing.secret_key_bytes);
        (claimed.peer_id, Vec::new(), quote, Amount::ZERO)
    }

    /// Build a quote whose `content` is a DIFFERENT XorName than `address`.
    /// The peer is honest (binding + signature both valid) but is replaying
    /// a quote it issued for a different chunk. The storer enforces
    /// `verify_quote_content`, so we filter this too.
    fn bad_content_quote_for(
        _address: &[u8; 32],
    ) -> (PeerId, Vec<MultiAddr>, PaymentQuote, Amount) {
        let kp = gen_keypair();
        // Use a content address that is definitely NOT what the caller asked for.
        let wrong_content = [0xAAu8; 32];
        let mut quote = PaymentQuote {
            content: XorName(wrong_content),
            timestamp: SystemTime::now(),
            price: Amount::from(42u64),
            rewards_address: RewardsAddress::new([1u8; 20]),
            pub_key: kp.pub_key_bytes,
            signature: Vec::new(),
        };
        sign_quote(&mut quote, &kp.secret_key_bytes);
        (kp.peer_id, Vec::new(), quote, Amount::ZERO)
    }

    /// Build a quote with a valid binding but an invalid signature: we sign
    /// the original message, then tweak the price after signing so the
    /// signature no longer covers the new payload. The storer enforces
    /// `verify_quote_signature`, so we filter this too.
    fn bad_signature_quote_for(
        address: &[u8; 32],
    ) -> (PeerId, Vec<MultiAddr>, PaymentQuote, Amount) {
        let kp = gen_keypair();
        let mut quote = PaymentQuote {
            content: XorName(*address),
            timestamp: SystemTime::now(),
            price: Amount::from(42u64),
            rewards_address: RewardsAddress::new([1u8; 20]),
            pub_key: kp.pub_key_bytes,
            signature: Vec::new(),
        };
        sign_quote(&mut quote, &kp.secret_key_bytes);
        // Tamper: change the price after signing so the signature no longer
        // matches `bytes_for_sig`.
        quote.price = Amount::from(99_999u64);
        (kp.peer_id, Vec::new(), quote, Amount::ZERO)
    }

    /// Independent re-implementation of ALL THREE storer-side spec checks
    /// (`ant-node/src/payment/verifier.rs`):
    ///
    ///   1. `peer_id_from_public_key_bytes` — pub_key parses as ML-DSA-65,
    ///   2. `validate_peer_bindings` — `BLAKE3(pub_key) == peer_id`,
    ///   3. `verify_quote_content` — `quote.content == address`,
    ///   4. `verify_quote_signature` — ML-DSA-65 sig over `bytes_for_sig`.
    ///
    /// Re-derived from spec, NOT delegating to `quote_binding_is_valid` or
    /// `classify_quote_response`, so cross-checks are not "function ==
    /// itself".
    fn storer_would_accept(peer_id: &PeerId, address: &[u8; 32], quote: &PaymentQuote) -> bool {
        // 1+2: pub_key is ML-DSA-65 length and BLAKE3-binds to peer_id.
        if MlDsaPublicKey::from_bytes(&quote.pub_key).is_err() {
            return false;
        }
        if compute_address(&quote.pub_key) != *peer_id.as_bytes() {
            return false;
        }
        // 3: content matches the requested chunk address.
        if quote.content.0 != *address {
            return false;
        }
        // 4: signature verifies. (We delegate to the upstream helper here —
        // it's the spec that the storer also calls, so equality is the right
        // notion of "would the storer accept this".)
        if !verify_quote_signature(quote) {
            return false;
        }
        true
    }

    /// Default test address used by the legacy filter tests. Most filter-
    /// only tests don't care which content address the quotes carry, so a
    /// fixed value is fine.
    const TEST_ADDR: [u8; 32] = [7u8; 32];

    // ============================================================
    // Tests for `quote_binding_is_valid` (the predicate)
    // ============================================================

    #[test]
    fn binding_accepts_real_self_consistent_keypair() {
        let (peer_id, _, quote, _) = good_quote_for(&TEST_ADDR);
        // Property under test: the predicate accepts a quote whose pub_key
        // genuinely belongs to the claimed peer.
        assert!(quote_binding_is_valid(&peer_id, &quote));
        // Cross-check against the independent full storer-spec implementation.
        assert!(storer_would_accept(&peer_id, &TEST_ADDR, &quote));
    }

    #[test]
    fn binding_rejects_real_crossed_keypair() {
        let (peer_id, _, quote, _) = bad_binding_quote_for(&TEST_ADDR);
        assert!(!quote_binding_is_valid(&peer_id, &quote));
        assert!(!storer_would_accept(&peer_id, &TEST_ADDR, &quote));
    }

    #[test]
    fn binding_rejects_oversize_pubkey() {
        // A pub_key longer than ML-DSA-65 (1952 bytes) must be rejected
        // even if BLAKE3 happens to agree, because the storer rejects on
        // length first via `peer_id_from_public_key_bytes`.
        let oversized = vec![0u8; ML_DSA_PUB_KEY_LEN + 1];
        let peer_id = PeerId::from_bytes(compute_address(&oversized));
        let quote = PaymentQuote {
            content: XorName([0u8; 32]),
            timestamp: SystemTime::UNIX_EPOCH,
            price: Amount::ZERO,
            rewards_address: RewardsAddress::new([0u8; 20]),
            pub_key: oversized,
            signature: Vec::new(),
        };
        // BLAKE3(pub_key) DOES equal the peer_id we constructed, so the
        // bare hash check would pass — but the length guard must reject.
        assert_eq!(compute_address(&quote.pub_key), *peer_id.as_bytes());
        assert!(
            !quote_binding_is_valid(&peer_id, &quote),
            "predicate must reject oversize pub_key even when BLAKE3 happens to match"
        );
        assert!(!storer_would_accept(&peer_id, &TEST_ADDR, &quote));
    }

    #[test]
    fn binding_rejects_undersize_pubkey() {
        let undersized = vec![0u8; ML_DSA_PUB_KEY_LEN - 1];
        let peer_id = PeerId::from_bytes(compute_address(&undersized));
        let quote = PaymentQuote {
            content: XorName([0u8; 32]),
            timestamp: SystemTime::UNIX_EPOCH,
            price: Amount::ZERO,
            rewards_address: RewardsAddress::new([0u8; 20]),
            pub_key: undersized,
            signature: Vec::new(),
        };
        assert!(!quote_binding_is_valid(&peer_id, &quote));
        assert!(!storer_would_accept(&peer_id, &TEST_ADDR, &quote));
    }

    // ============================================================
    // Tests for the filter (`drop_quotes_with_bad_bindings`)
    // ============================================================

    #[test]
    fn filter_drops_only_bad_bindings_and_leaves_storer_acceptable_quotes() {
        let mut quotes = vec![
            good_quote_for(&TEST_ADDR),
            bad_binding_quote_for(&TEST_ADDR),
            good_quote_for(&TEST_ADDR),
            bad_binding_quote_for(&TEST_ADDR),
            good_quote_for(&TEST_ADDR),
        ];

        let dropped = drop_quotes_with_bad_bindings(&mut quotes);

        assert_eq!(dropped, 2, "two crossed-key quotes must be dropped");
        assert_eq!(quotes.len(), 3, "three real-key quotes must remain");

        // Cross-checked invariant: every retained quote would be accepted by
        // a storer running the full spec. The defensive filter only checks
        // the binding, so this asserts the binding-only filter is correct
        // for binding-only failures (other failure modes are filtered by
        // the per-peer classifier upstream).
        for (peer_id, _, quote, _) in &quotes {
            assert!(
                storer_would_accept(peer_id, &TEST_ADDR, quote),
                "every retained quote must satisfy the full storer-side spec"
            );
        }
    }

    #[test]
    fn filter_is_noop_when_all_quotes_are_storer_acceptable() {
        let mut quotes: Vec<_> = (0..5).map(|_| good_quote_for(&TEST_ADDR)).collect();
        let before = quotes.len();
        let dropped = drop_quotes_with_bad_bindings(&mut quotes);
        assert_eq!(dropped, 0);
        assert_eq!(quotes.len(), before);
        for (peer_id, _, quote, _) in &quotes {
            assert!(storer_would_accept(peer_id, &TEST_ADDR, quote));
        }
    }

    #[test]
    fn filter_drops_all_when_every_responder_is_bad() {
        // The "all hostile" case: every over-queried peer returned a bad
        // binding. The patch should leave us with zero quotes (not panic,
        // not skip the filter, not return malformed quotes). The caller in
        // get_store_quotes then surfaces InsufficientPeers.
        let mut quotes: Vec<_> = (0..CLOSE_GROUP_SIZE * 2)
            .map(|_| bad_binding_quote_for(&TEST_ADDR))
            .collect();
        let dropped = drop_quotes_with_bad_bindings(&mut quotes);
        assert_eq!(dropped, CLOSE_GROUP_SIZE * 2);
        assert!(quotes.is_empty());
    }

    #[test]
    fn filter_preserves_quote_payload_byte_for_byte() {
        // After filtering, the retained quotes must be untouched — pub_key,
        // signature, content, timestamp, price, rewards_address. The patch
        // is a filter, not a transformation; this test catches any future
        // regression that mutates a retained quote.
        let (peer_id, addrs, original_quote, amount) = good_quote_for(&TEST_ADDR);
        let mut quotes = vec![(peer_id, addrs.clone(), original_quote.clone(), amount)];
        let _ = drop_quotes_with_bad_bindings(&mut quotes);

        let (kept_peer, kept_addrs, kept_quote, kept_amount) =
            quotes.pop().expect("the good quote must survive filtering");
        assert_eq!(kept_peer.as_bytes(), peer_id.as_bytes());
        assert_eq!(kept_addrs.len(), addrs.len());
        assert_eq!(kept_amount, amount);
        assert_eq!(kept_quote.pub_key, original_quote.pub_key);
        assert_eq!(kept_quote.signature, original_quote.signature);
        assert_eq!(kept_quote.content.0, original_quote.content.0);
        assert_eq!(kept_quote.timestamp, original_quote.timestamp);
        assert_eq!(kept_quote.price, original_quote.price);
        assert_eq!(kept_quote.rewards_address, original_quote.rewards_address);
    }

    // ============================================================
    // The Apr 30 production-failure repro
    // ============================================================

    /// Repro of the production failure from 2026-04-30 testnet runs.
    ///
    /// An external operator on `75.48.86.24` ran two co-located ant-node
    /// identities (peer `0755ecb55b…` and peer `073db92f…`) that crossed
    /// their quote-signing keys. Every chunk whose XOR-closest set happened
    /// to include peer `0755ecb5` got a payment proof with one malformed
    /// quote, and the storer's `validate_peer_bindings` rejected the
    /// entire close-group proof — burning the chunk's payment.
    ///
    /// This test is the strongest proof the patch fixes that failure shape:
    ///
    /// 1. We assemble `2x CLOSE_GROUP_SIZE` real ML-DSA-65 quotes — the same
    ///    over-query buffer the production code uses (line 93 of this file).
    /// 2. One of them is a *crossed-key* quote — the production failure shape.
    /// 3. We run an independent `storer_would_accept` check (re-derived from
    ///    the storer spec, not from `quote_binding_is_valid`) over the
    ///    pre-filter set; we confirm the bad peer is rejected, proving the
    ///    storer **would** burn the chunk's payment if we proceeded unfiltered.
    /// 4. We run `drop_quotes_with_bad_bindings`.
    /// 5. We re-run `storer_would_accept` over the post-filter set; we confirm
    ///    EVERY remaining quote would be accepted, proving the patched
    ///    `ProofOfPayment` will not trigger the `validate_peer_bindings`
    ///    rejection that caused the Apr 30 outage.
    /// 6. We confirm the post-filter set has at least `CLOSE_GROUP_SIZE`
    ///    quotes — the over-query buffer (2x) is sufficient.
    #[test]
    fn repro_apr_30_storer_would_have_rejected_pre_filter_and_accepts_post_filter() {
        let over_query_count = CLOSE_GROUP_SIZE * 2;
        let mut quotes: Vec<_> = (0..over_query_count - 1)
            .map(|_| good_quote_for(&TEST_ADDR))
            .collect();
        // Splice the crossed-key quote in the middle (mirrors the random
        // position the bad peer takes in the DHT-returned closest set).
        quotes.insert(over_query_count / 2, bad_binding_quote_for(&TEST_ADDR));
        assert_eq!(quotes.len(), over_query_count);

        // Step 1: prove the storer would reject the pre-filter set.
        let storer_would_reject_count = quotes
            .iter()
            .filter(|(p, _, q, _)| !storer_would_accept(p, &TEST_ADDR, q))
            .count();
        assert_eq!(
            storer_would_reject_count, 1,
            "exactly one quote (the crossed-key one) must be rejected by the storer spec"
        );

        // Step 2: run the patched filter.
        let dropped = drop_quotes_with_bad_bindings(&mut quotes);
        assert_eq!(dropped, 1, "exactly the crossed-key quote must be filtered");

        // Step 3: prove the storer would accept every survivor under the FULL spec.
        for (peer_id, _, quote, _) in &quotes {
            assert!(
                storer_would_accept(peer_id, &TEST_ADDR, quote),
                "every post-filter quote must be accepted by the storer spec — \
                 this is what the patch guarantees: no more burned payments"
            );
        }

        // Step 4: prove the over-query buffer is sufficient to refill.
        assert!(
            quotes.len() >= CLOSE_GROUP_SIZE,
            "after filtering, at least CLOSE_GROUP_SIZE good quotes must remain \
             so we can build a non-rejected ProofOfPayment"
        );
    }

    /// When more than the over-query buffer of peers misbehave, the filter
    /// must NOT silently produce a short proof. The downstream caller in
    /// `get_store_quotes` must see fewer than `CLOSE_GROUP_SIZE` survivors
    /// and return `InsufficientPeers`.
    #[test]
    fn filter_leaves_short_set_when_too_many_bad_peers() {
        // Buffer is 2x; if more than half are bad, there's no way to refill.
        let bad_count = CLOSE_GROUP_SIZE + 1;
        let good_count = CLOSE_GROUP_SIZE - 1;
        let mut quotes: Vec<_> = std::iter::repeat_with(|| bad_binding_quote_for(&TEST_ADDR))
            .take(bad_count)
            .chain(std::iter::repeat_with(|| good_quote_for(&TEST_ADDR)).take(good_count))
            .collect();

        let dropped = drop_quotes_with_bad_bindings(&mut quotes);
        assert_eq!(dropped, bad_count);
        assert!(
            quotes.len() < CLOSE_GROUP_SIZE,
            "this is the precondition for InsufficientPeers downstream"
        );
        // Sanity: every survivor is storer-acceptable under the full spec.
        for (peer_id, _, quote, _) in &quotes {
            assert!(storer_would_accept(peer_id, &TEST_ADDR, quote));
        }
    }

    // ============================================================
    // Tests for the per-peer response classifier (the PRIMARY defense).
    //
    // These tests exercise the production code path that runs inside
    // get_store_quotes' per-peer async closure. The defensive
    // `drop_quotes_with_bad_bindings` is a second line of defence —
    // these tests make sure the FIRST line is what actually catches
    // misbehaving peers in production. Without these, a regression
    // that removes the per-peer check could be masked by the post-
    // collect filter and pass the rest of the suite.
    // ============================================================

    /// Helper: serialize a `PaymentQuote` to bytes the way the wire layer
    /// does (rmp_serde / msgpack), to feed into `classify_quote_response`.
    fn serialize_quote(quote: &PaymentQuote) -> Vec<u8> {
        rmp_serde::to_vec(quote).expect("serialize quote")
    }

    #[test]
    fn classifier_accepts_real_self_consistent_quote() {
        let (peer_id, _, quote, _) = good_quote_for(&TEST_ADDR);
        let bytes = serialize_quote(&quote);
        let result = classify_quote_response(&peer_id, &TEST_ADDR, &bytes, false);
        match result {
            Ok((q, price)) => {
                assert_eq!(q.pub_key, quote.pub_key);
                assert_eq!(price, quote.price);
            }
            Err(e) => panic!("expected Ok, got {e}"),
        }
    }

    #[test]
    fn classifier_rejects_crossed_keypair_with_typed_error() {
        let (peer_id, _, quote, _) = bad_binding_quote_for(&TEST_ADDR);
        let bytes = serialize_quote(&quote);
        let result = classify_quote_response(&peer_id, &TEST_ADDR, &bytes, false);
        match result {
            Err(Error::BadQuoteBinding {
                peer_id: pid,
                detail,
            }) => {
                assert_eq!(pid, peer_id.to_string());
                assert!(
                    detail.contains("BLAKE3(pub_key)="),
                    "diagnostic detail must include the derived peer id: {detail}"
                );
            }
            other => panic!("expected BadQuoteBinding for crossed-key quote, got {other:?}"),
        }
    }

    /// CRITICAL: a misbehaving peer that votes `already_stored=true` must
    /// NOT be allowed to influence the close-group "already stored"
    /// majority decision. The bind-check runs before the AlreadyStored
    /// short-circuit, so a crossed-key peer voting "already stored" is
    /// classified as `BadQuoteBinding`, not `AlreadyStored`.
    ///
    /// This locks in a specific reviewer concern from round 1:
    ///   "A peer with a crossed/garbage signing key could simply respond
    ///   already_stored=true and its vote enters already_stored_peers
    ///   unfiltered."
    #[test]
    fn classifier_rejects_already_stored_vote_from_bad_binding_peer() {
        let (peer_id, _, quote, _) = bad_binding_quote_for(&TEST_ADDR);
        let bytes = serialize_quote(&quote);
        // The peer claims already_stored=true, but its quote has a crossed key.
        let result = classify_quote_response(&peer_id, &TEST_ADDR, &bytes, true);
        assert!(
            matches!(result, Err(Error::BadQuoteBinding { .. })),
            "crossed-key peer must be classified BadQuoteBinding even when \
             voting already_stored=true; got {result:?}"
        );
    }

    /// An honest peer's `already_stored=true` vote IS honoured (after
    /// passing the bind-check). This is the contrast to the test above.
    #[test]
    fn classifier_honours_already_stored_vote_from_good_binding_peer() {
        let (peer_id, _, quote, _) = good_quote_for(&TEST_ADDR);
        let bytes = serialize_quote(&quote);
        let result = classify_quote_response(&peer_id, &TEST_ADDR, &bytes, true);
        assert!(
            matches!(result, Err(Error::AlreadyStored)),
            "honest peer's already_stored vote must be honoured; got {result:?}"
        );
    }

    #[test]
    fn classifier_returns_serialization_error_on_bad_bytes() {
        let (peer_id, _, _, _) = good_quote_for(&TEST_ADDR);
        let garbage = b"this is not a valid msgpack PaymentQuote".to_vec();
        let result = classify_quote_response(&peer_id, &TEST_ADDR, &garbage, false);
        assert!(
            matches!(result, Err(Error::Serialization(_))),
            "garbage bytes must produce a Serialization error; got {result:?}"
        );
    }

    /// The classifier rejects a quote whose `content` does not match the
    /// requested chunk address. Mirrors the storer's `verify_quote_content`.
    #[test]
    fn classifier_rejects_quote_with_wrong_content_address() {
        let (peer_id, _, quote, _) = bad_content_quote_for(&TEST_ADDR);
        let bytes = serialize_quote(&quote);
        let result = classify_quote_response(&peer_id, &TEST_ADDR, &bytes, false);
        match result {
            Err(Error::BadQuoteContent {
                peer_id: pid,
                expected,
                actual,
            }) => {
                assert_eq!(pid, peer_id.to_string());
                assert_eq!(expected, hex::encode(TEST_ADDR));
                assert_ne!(actual, expected, "actual must differ from expected");
            }
            other => panic!("expected BadQuoteContent for content-mismatched quote, got {other:?}"),
        }
    }

    /// The classifier rejects a quote whose ML-DSA-65 signature does not
    /// verify. Mirrors the storer's `verify_quote_signature`.
    #[test]
    fn classifier_rejects_quote_with_invalid_signature() {
        let (peer_id, _, quote, _) = bad_signature_quote_for(&TEST_ADDR);
        let bytes = serialize_quote(&quote);
        let result = classify_quote_response(&peer_id, &TEST_ADDR, &bytes, false);
        match result {
            Err(Error::BadQuoteSignature { peer_id: pid }) => {
                assert_eq!(pid, peer_id.to_string());
            }
            other => {
                panic!("expected BadQuoteSignature for tampered-after-sign quote, got {other:?}")
            }
        }
    }

    /// The classifier rejects a content-mismatched quote even when the peer
    /// votes `already_stored=true` (mirrors the same defense as the
    /// crossed-key already-stored test, but for content mismatch).
    #[test]
    fn classifier_rejects_already_stored_vote_from_wrong_content_peer() {
        let (peer_id, _, quote, _) = bad_content_quote_for(&TEST_ADDR);
        let bytes = serialize_quote(&quote);
        let result = classify_quote_response(&peer_id, &TEST_ADDR, &bytes, true);
        assert!(
            matches!(result, Err(Error::BadQuoteContent { .. })),
            "wrong-content peer must NOT be allowed to cast an AlreadyStored vote"
        );
    }

    // ============================================================
    // AIMD attribution: every error variant is classified correctly
    // for `record_peer_outcome` so misbehaving peers are deprioritized
    // and reachable-but-already-storing peers stay reputable.
    // ============================================================

    #[test]
    fn aimd_success_for_ok_result() {
        let (_, _, quote, _) = good_quote_for(&TEST_ADDR);
        let result: std::result::Result<(PaymentQuote, Amount), Error> =
            Ok((quote.clone(), quote.price));
        assert!(quote_outcome_is_success(&result));
    }

    #[test]
    fn aimd_success_for_already_stored() {
        let result: std::result::Result<(PaymentQuote, Amount), Error> = Err(Error::AlreadyStored);
        assert!(
            quote_outcome_is_success(&result),
            "an honest peer reporting already_stored is a benign outcome — \
             the peer is reachable and well-behaved, so the AIMD cache must \
             keep them at high reputation"
        );
    }

    #[test]
    fn aimd_failure_for_bad_quote_binding() {
        let result: std::result::Result<(PaymentQuote, Amount), Error> =
            Err(Error::BadQuoteBinding {
                peer_id: "abc123".to_string(),
                detail: "test".to_string(),
            });
        assert!(
            !quote_outcome_is_success(&result),
            "BadQuoteBinding peers must be marked as failures so the AIMD \
             bootstrap cache learns to stop asking them on every upload"
        );
    }

    #[test]
    fn aimd_failure_for_bad_quote_signature() {
        let result: std::result::Result<(PaymentQuote, Amount), Error> =
            Err(Error::BadQuoteSignature {
                peer_id: "abc123".to_string(),
            });
        assert!(!quote_outcome_is_success(&result));
    }

    #[test]
    fn aimd_failure_for_bad_quote_content() {
        let result: std::result::Result<(PaymentQuote, Amount), Error> =
            Err(Error::BadQuoteContent {
                peer_id: "abc123".to_string(),
                expected: "00".to_string(),
                actual: "ff".to_string(),
            });
        assert!(!quote_outcome_is_success(&result));
    }

    #[test]
    fn aimd_failure_for_network_and_timeout_and_protocol_and_serialization() {
        for err in [
            Error::Network("net".to_string()),
            Error::Timeout("to".to_string()),
            Error::Protocol("proto".to_string()),
            Error::Serialization("ser".to_string()),
        ] {
            let result: std::result::Result<(PaymentQuote, Amount), Error> = Err(err);
            assert!(
                !quote_outcome_is_success(&result),
                "network-class errors must be classified as failures: {result:?}"
            );
        }
    }

    /// Independent attestation: round-trip a "would be rejected by storer"
    /// quote through the classifier and confirm the classifier's verdict
    /// matches the storer's spec verdict across ALL three failure modes.
    /// If they ever disagree, either the classifier is letting through a
    /// quote the storer will reject (money-loss regression), or it's
    /// filtering a quote the storer would have accepted (availability
    /// regression). Both are bugs.
    #[test]
    fn classifier_verdict_matches_storer_spec_for_mixed_failure_modes() {
        // 8 honest + 3 crossed-key + 3 wrong-content + 3 invalid-signature.
        let mut responders: Vec<(PeerId, PaymentQuote)> = (0..8)
            .map(|_| {
                let (p, _, q, _) = good_quote_for(&TEST_ADDR);
                (p, q)
            })
            .collect();
        for _ in 0..3 {
            let (p, _, q, _) = bad_binding_quote_for(&TEST_ADDR);
            responders.push((p, q));
        }
        for _ in 0..3 {
            let (p, _, q, _) = bad_content_quote_for(&TEST_ADDR);
            responders.push((p, q));
        }
        for _ in 0..3 {
            let (p, _, q, _) = bad_signature_quote_for(&TEST_ADDR);
            responders.push((p, q));
        }

        for (peer_id, quote) in &responders {
            let bytes = serialize_quote(quote);
            let storer_verdict = storer_would_accept(peer_id, &TEST_ADDR, quote);
            let classifier_verdict =
                classify_quote_response(peer_id, &TEST_ADDR, &bytes, false).is_ok();
            assert_eq!(
                classifier_verdict, storer_verdict,
                "classifier and storer-spec must agree on every responder \
                 (peer_id={}, storer={storer_verdict}, classifier={classifier_verdict})",
                peer_id
            );
        }
    }
}
