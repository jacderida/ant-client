//! Persistent client bootstrap peer cache.
//!
//! Client peer IDs are ephemeral, so this cache is not keyed by distance from
//! the local client. It remembers authenticated node peers that we have already
//! connected to, and stores only their DHT `Direct`-tagged dial addresses.

use crate::config;
use ant_protocol::transport::{IPDiversityConfig, MultiAddr, P2PNode, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

pub const CLIENT_PEER_CACHE_MAX_PEERS: usize = 50;

const CLIENT_PEER_CACHE_SCHEMA_VERSION: u32 = 1;
const CLIENT_PEER_CACHE_FILE_NAME: &str = "client_peer_cache.json";
const CLIENT_PEER_CACHE_TEMP_SUFFIX: &str = "tmp";
const DEFAULT_MAX_PER_EXACT_IP: usize = 2;
const SUBNET_LIMIT_K_DIVISOR: usize = 4;
const IPV4_SUBNET_PREFIX_OCTETS: usize = 3;
const IPV6_SUBNET_PREFIX_SEGMENTS: usize = 3;
const BITS_PER_BYTE: u8 = 8;
const PEER_ID_SECTOR_BITS: u8 = 4;
const PEER_ID_SECTOR_COUNT: usize = 1 << PEER_ID_SECTOR_BITS;

// saorsa-core's AddressType enum is visible through the P2P node API but is not
// re-exported by ant-protocol. `AddressType::Direct.priority()` is 1 there.
const DIRECT_ADDRESS_TYPE_PRIORITY: u8 = 1;

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ClientPeerCacheFile {
    schema_version: u32,
    peers: Vec<CachedPeer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CachedPeer {
    peer_id: PeerId,
    direct_addresses: Vec<MultiAddr>,
    first_connected_epoch_secs: u64,
    last_connected_epoch_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SubnetKey {
    V4([u8; IPV4_SUBNET_PREFIX_OCTETS]),
    V6([u16; IPV6_SUBNET_PREFIX_SEGMENTS]),
}

struct DiversityTracker {
    exact_ip_counts: HashMap<IpAddr, usize>,
    subnet_counts: HashMap<SubnetKey, usize>,
    max_per_ip: usize,
    max_per_subnet: usize,
}

/// Build the on-disk cache path for the client peer cache.
#[must_use]
pub fn cache_path() -> Option<PathBuf> {
    match config::data_dir() {
        Ok(data_dir) => Some(data_dir.join(CLIENT_PEER_CACHE_FILE_NAME)),
        Err(err) => {
            warn!("client peer cache disabled: failed to resolve data dir: {err}");
            None
        }
    }
}

/// Load cache addresses to try before configured bootstrap peers.
///
/// Returns at most one direct address per cached peer. saorsa-core stops client
/// bootstrap after the client bootstrap target is reached, so every usable
/// cached peer is ordered before the configured fallback peers without forcing
/// all cached peers to be dialed on a healthy warm start.
#[must_use]
pub fn cached_bootstrap_peers(cache_path: &Path, k_value: usize) -> Vec<MultiAddr> {
    let Some(mut cache) = ClientPeerCacheFile::load_existing(cache_path) else {
        return Vec::new();
    };
    let loaded_peer_count = cache.peers.len();
    let loaded_direct_address_count = cache.direct_address_count();
    let diversity_config = cache_diversity_config();
    let normalized = cache.normalize(&diversity_config, k_value);
    if normalized {
        cache.save(cache_path);
    }
    let bootstrap_addresses = cache.bootstrap_addresses(CLIENT_PEER_CACHE_MAX_PEERS);
    info!(
        path = %cache_path.display(),
        cached_peers = loaded_peer_count,
        direct_addresses = loaded_direct_address_count,
        usable_cached_peers = cache.peers.len(),
        bootstrap_candidates = bootstrap_addresses.len(),
        "client peer bootstrap cache file found and loaded; cached peers available",
    );
    bootstrap_addresses
}

/// Select startup bootstrap peers.
///
/// Cached peers are ordered first and configured bootstrap peers are appended
/// behind them. saorsa-core stops client bootstrap after the client bootstrap
/// target is reached, so configured peers are only reached when the cached
/// candidates do not produce enough successful connections.
#[must_use]
pub fn select_bootstrap_peers(
    cached: impl IntoIterator<Item = MultiAddr>,
    configured: impl IntoIterator<Item = MultiAddr>,
) -> Vec<MultiAddr> {
    dedupe_bootstrap_peers(cached.into_iter().chain(configured))
}

fn dedupe_bootstrap_peers(addrs: impl IntoIterator<Item = MultiAddr>) -> Vec<MultiAddr> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();

    for addr in addrs {
        if seen.insert(bootstrap_address_key(&addr)) {
            deduped.push(addr);
        }
    }

    deduped
}

/// Persist connected routing-table peers that also have Direct-tagged DHT
/// addresses.
///
/// The successful dial may have used any address type. The cache admission
/// condition is stricter: the peer must currently be connected and its routing
/// table record must contain at least one Direct-tagged, dialable address.
pub async fn promote_connected_direct_peers(node: &P2PNode, cache_path: &Path, k_value: usize) {
    let connected_peers = node
        .connected_peers()
        .await
        .into_iter()
        .collect::<HashSet<_>>();
    if connected_peers.is_empty() {
        return;
    }

    let routing_table_peers = node.dht().routing_table_peers().await;
    let mut cache = ClientPeerCacheFile::load(cache_path);
    let diversity_config = cache_diversity_config();
    let now = now_epoch_secs();
    let mut changed = false;

    for dht_node in routing_table_peers {
        if !connected_peers.contains(&dht_node.peer_id) {
            continue;
        }

        let direct_addresses = dht_node
            .typed_addresses()
            .into_iter()
            .filter_map(|(addr, ty)| {
                if ty.priority() == DIRECT_ADDRESS_TYPE_PRIORITY
                    && addr.dialable_socket_addr().is_some()
                {
                    Some(addr.with_peer_id(dht_node.peer_id))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        changed |= cache.upsert_connected_peer(
            dht_node.peer_id,
            direct_addresses,
            now,
            &diversity_config,
            k_value,
        );
    }

    if changed {
        cache.save(cache_path);
    }
}

/// The cache applies the default k-bucket IP diversity policy rather than the
/// client's permissive routing-table setting. This keeps the persisted
/// bootstrap surface from collapsing onto one IP or subnet.
#[must_use]
fn cache_diversity_config() -> IPDiversityConfig {
    IPDiversityConfig::default()
}

impl ClientPeerCacheFile {
    fn empty() -> Self {
        Self {
            schema_version: CLIENT_PEER_CACHE_SCHEMA_VERSION,
            peers: Vec::new(),
        }
    }

    fn load(path: &Path) -> Self {
        Self::load_existing(path).unwrap_or_else(Self::empty)
    }

    fn load_existing(path: &Path) -> Option<Self> {
        let Ok(data) = std::fs::read_to_string(path) else {
            return None;
        };

        match serde_json::from_str::<Self>(&data) {
            Ok(cache) if cache.schema_version == CLIENT_PEER_CACHE_SCHEMA_VERSION => Some(cache),
            Ok(cache) => {
                debug!(
                    path = %path.display(),
                    schema_version = cache.schema_version,
                    "ignoring client peer cache with unsupported schema version",
                );
                None
            }
            Err(err) => {
                warn!(
                    path = %path.display(),
                    "ignoring unreadable client peer cache: {err}",
                );
                None
            }
        }
    }

    fn direct_address_count(&self) -> usize {
        self.peers
            .iter()
            .map(|peer| peer.direct_addresses.len())
            .sum()
    }

    fn save(&self, path: &Path) {
        if let Some(parent) = path.parent() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                warn!(
                    path = %path.display(),
                    "failed to create client peer cache directory: {err}",
                );
                return;
            }
        }

        let data = match serde_json::to_vec_pretty(self) {
            Ok(data) => data,
            Err(err) => {
                warn!("failed to serialize client peer cache: {err}");
                return;
            }
        };

        let temp_path = temp_path_for(path);
        if let Err(err) = std::fs::write(&temp_path, data) {
            warn!(
                path = %temp_path.display(),
                "failed to write client peer cache temp file: {err}",
            );
            return;
        }

        #[cfg(windows)]
        if path.exists() {
            if let Err(err) = std::fs::remove_file(path) {
                warn!(
                    path = %path.display(),
                    "failed to replace existing client peer cache: {err}",
                );
                let _ = std::fs::remove_file(&temp_path);
                return;
            }
        }

        if let Err(err) = std::fs::rename(&temp_path, path) {
            warn!(
                from = %temp_path.display(),
                to = %path.display(),
                "failed to commit client peer cache: {err}",
            );
            let _ = std::fs::remove_file(temp_path);
        }
    }

    fn upsert_connected_peer(
        &mut self,
        peer_id: PeerId,
        direct_addresses: Vec<MultiAddr>,
        now: u64,
        diversity_config: &IPDiversityConfig,
        k_value: usize,
    ) -> bool {
        let direct_addresses = sanitize_direct_addresses(peer_id, direct_addresses);
        if direct_addresses.is_empty() {
            return false;
        }

        let before = self.peers.clone();
        if let Some(existing) = self.peers.iter_mut().find(|peer| peer.peer_id == peer_id) {
            existing.direct_addresses = direct_addresses;
            existing.last_connected_epoch_secs = now;
        } else {
            self.peers.push(CachedPeer {
                peer_id,
                direct_addresses,
                first_connected_epoch_secs: now,
                last_connected_epoch_secs: now,
            });
        }

        self.normalize(diversity_config, k_value);
        self.peers != before
    }

    fn normalize(&mut self, diversity_config: &IPDiversityConfig, k_value: usize) -> bool {
        let before = self.peers.clone();
        self.peers.retain(|peer| !peer.direct_addresses.is_empty());
        self.peers.sort_by(|left, right| {
            right
                .last_connected_epoch_secs
                .cmp(&left.last_connected_epoch_secs)
                .then_with(|| left.peer_id.to_hex().cmp(&right.peer_id.to_hex()))
        });

        let mut tracker = DiversityTracker::new(diversity_config, k_value);
        let mut seen_peers = HashSet::new();
        let mut normalized = Vec::with_capacity(CLIENT_PEER_CACHE_MAX_PEERS);

        for peer in self.peers.drain(..) {
            if normalized.len() >= CLIENT_PEER_CACHE_MAX_PEERS {
                break;
            }
            if !seen_peers.insert(peer.peer_id) {
                continue;
            }
            if tracker.admit_peer(&peer) {
                normalized.push(peer);
            }
        }

        self.peers = normalized;
        self.peers != before
    }

    fn bootstrap_addresses(&self, limit: usize) -> Vec<MultiAddr> {
        let mut sectors = (0..PEER_ID_SECTOR_COUNT)
            .map(|_| Vec::new())
            .collect::<Vec<Vec<&CachedPeer>>>();

        for peer in &self.peers {
            sectors[peer_id_sector(peer.peer_id)].push(peer);
        }

        let mut positions = [0usize; PEER_ID_SECTOR_COUNT];
        let mut addresses = Vec::with_capacity(self.peers.len().min(limit));

        loop {
            let mut added_this_round = false;
            for sector in 0..PEER_ID_SECTOR_COUNT {
                let position = positions[sector];
                let Some(peer) = sectors[sector].get(position) else {
                    continue;
                };
                if let Some(addr) = peer.direct_addresses.first() {
                    addresses.push(addr.clone());
                    added_this_round = true;
                    positions[sector] += 1;
                }
                if addresses.len() >= limit {
                    return addresses;
                }
            }
            if !added_this_round {
                return addresses;
            }
        }
    }
}

impl DiversityTracker {
    fn new(config: &IPDiversityConfig, k_value: usize) -> Self {
        Self {
            exact_ip_counts: HashMap::new(),
            subnet_counts: HashMap::new(),
            max_per_ip: config.max_per_ip.unwrap_or(DEFAULT_MAX_PER_EXACT_IP),
            max_per_subnet: config
                .max_per_subnet
                .unwrap_or_else(|| default_subnet_limit(k_value)),
        }
    }

    fn admit_peer(&mut self, peer: &CachedPeer) -> bool {
        let ip_set = peer
            .direct_addresses
            .iter()
            .filter_map(|addr| {
                addr.dialable_socket_addr()
                    .map(|socket| canonical_ip(socket.ip()))
            })
            .collect::<HashSet<_>>();

        if ip_set.is_empty() {
            return false;
        }

        let subnet_set = ip_set
            .iter()
            .map(|ip| subnet_key(*ip))
            .collect::<HashSet<_>>();

        for ip in &ip_set {
            if self.exact_ip_counts.get(ip).copied().unwrap_or_default() >= self.max_per_ip {
                return false;
            }
        }

        for subnet in &subnet_set {
            if self.subnet_counts.get(subnet).copied().unwrap_or_default() >= self.max_per_subnet {
                return false;
            }
        }

        for ip in ip_set {
            *self.exact_ip_counts.entry(ip).or_default() += 1;
        }
        for subnet in subnet_set {
            *self.subnet_counts.entry(subnet).or_default() += 1;
        }

        true
    }
}

fn sanitize_direct_addresses(peer_id: PeerId, direct_addresses: Vec<MultiAddr>) -> Vec<MultiAddr> {
    let mut seen = HashSet::new();
    let mut sanitized = Vec::new();

    for addr in direct_addresses {
        if addr.dialable_socket_addr().is_none() {
            continue;
        }
        let addr = addr.with_peer_id(peer_id);
        if seen.insert(addr.to_string()) {
            sanitized.push(addr);
        }
    }

    sanitized
}

fn bootstrap_address_key(addr: &MultiAddr) -> String {
    addr.dialable_socket_addr()
        .map(|socket| socket.to_string())
        .unwrap_or_else(|| addr.to_string())
}

fn default_subnet_limit(k_value: usize) -> usize {
    std::cmp::max(k_value / SUBNET_LIMIT_K_DIVISOR, 1)
}

fn subnet_key(ip: IpAddr) -> SubnetKey {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            SubnetKey::V4([octets[0], octets[1], octets[IPV4_SUBNET_PREFIX_OCTETS - 1]])
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            SubnetKey::V6([
                segments[0],
                segments[1],
                segments[IPV6_SUBNET_PREFIX_SEGMENTS - 1],
            ])
        }
    }
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(ip) => IpAddr::V4(ip),
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
    }
}

fn peer_id_sector(peer_id: PeerId) -> usize {
    let sector_shift = BITS_PER_BYTE - PEER_ID_SECTOR_BITS;
    usize::from(peer_id.as_bytes()[0] >> sector_shift)
}

fn temp_path_for(path: &Path) -> PathBuf {
    let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let process_id = std::process::id();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(CLIENT_PEER_CACHE_FILE_NAME);
    path.with_file_name(format!(
        ".{file_name}.{process_id}.{counter}.{CLIENT_PEER_CACHE_TEMP_SUFFIX}"
    ))
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    const TEST_PEER_ID_LEN: usize = 32;
    const TEST_K_VALUE: usize = 20;
    const FIRST_PORT: u16 = 10_000;
    const TEST_NOW: u64 = 1_000_000;
    const EXACT_IP_ATTEMPTS: u8 = 3;
    const SUBNET_ATTEMPTS: u8 = 6;
    const PEER_COUNT_OVER_CACHE_LIMIT: usize = CLIENT_PEER_CACHE_MAX_PEERS + 10;
    const BOOTSTRAP_ROUND_ROBIN_TEST_LIMIT: usize = 6;

    fn peer_id(byte: u8) -> PeerId {
        let mut bytes = [0u8; TEST_PEER_ID_LEN];
        bytes[0] = byte;
        PeerId::from_bytes(bytes)
    }

    fn direct_addr(ip: IpAddr, port: u16) -> MultiAddr {
        MultiAddr::quic(SocketAddr::new(ip, port))
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6(first_segment: u16, host: u16) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(first_segment, 0, 0, 0, 0, 0, 0, host))
    }

    #[test]
    fn cache_keeps_most_recent_peers_when_full() {
        let mut cache = ClientPeerCacheFile::empty();
        let diversity = IPDiversityConfig::permissive();

        for idx in 0..PEER_COUNT_OVER_CACHE_LIMIT {
            let peer = peer_id(idx as u8);
            let addr = direct_addr(
                v4(1, 0, idx as u8, 1),
                FIRST_PORT + u16::try_from(idx).unwrap(),
            );
            cache.upsert_connected_peer(
                peer,
                vec![addr],
                TEST_NOW + u64::try_from(idx).unwrap(),
                &diversity,
                TEST_K_VALUE,
            );
        }

        assert_eq!(cache.peers.len(), CLIENT_PEER_CACHE_MAX_PEERS);
        assert!(cache.peers.iter().any(|peer| peer.peer_id == peer_id(59)));
        assert!(!cache.peers.iter().any(|peer| peer.peer_id == peer_id(0)));
    }

    #[test]
    fn cache_applies_exact_ip_limit() {
        let mut cache = ClientPeerCacheFile::empty();
        let diversity = IPDiversityConfig::default();

        for idx in 0..EXACT_IP_ATTEMPTS {
            cache.upsert_connected_peer(
                peer_id(idx),
                vec![direct_addr(v4(203, 0, 113, 1), FIRST_PORT + u16::from(idx))],
                TEST_NOW + u64::from(idx),
                &diversity,
                TEST_K_VALUE,
            );
        }

        assert_eq!(cache.peers.len(), DEFAULT_MAX_PER_EXACT_IP);
        assert!(cache.peers.iter().any(|peer| peer.peer_id == peer_id(2)));
        assert!(cache.peers.iter().any(|peer| peer.peer_id == peer_id(1)));
        assert!(!cache.peers.iter().any(|peer| peer.peer_id == peer_id(0)));
    }

    #[test]
    fn cache_applies_subnet_limit() {
        let mut cache = ClientPeerCacheFile::empty();
        let diversity = IPDiversityConfig::default();

        for idx in 0..SUBNET_ATTEMPTS {
            cache.upsert_connected_peer(
                peer_id(idx),
                vec![direct_addr(
                    v4(198, 51, 100, idx),
                    FIRST_PORT + u16::from(idx),
                )],
                TEST_NOW + u64::from(idx),
                &diversity,
                TEST_K_VALUE,
            );
        }

        assert_eq!(cache.peers.len(), default_subnet_limit(TEST_K_VALUE));
        assert!(cache.peers.iter().any(|peer| peer.peer_id == peer_id(5)));
        assert!(!cache.peers.iter().any(|peer| peer.peer_id == peer_id(0)));
    }

    #[test]
    fn cache_rejects_peers_without_dialable_direct_addresses() {
        let mut cache = ClientPeerCacheFile::empty();
        let diversity = IPDiversityConfig::permissive();

        let changed =
            cache.upsert_connected_peer(peer_id(1), Vec::new(), TEST_NOW, &diversity, TEST_K_VALUE);

        assert!(!changed);
        assert!(cache.peers.is_empty());
    }

    #[test]
    fn cached_bootstrap_addresses_round_robin_peer_id_sectors() {
        let mut cache = ClientPeerCacheFile::empty();
        let diversity = IPDiversityConfig::permissive();

        cache.upsert_connected_peer(
            peer_id(0x01),
            vec![direct_addr(v4(1, 0, 0, 1), FIRST_PORT)],
            TEST_NOW,
            &diversity,
            TEST_K_VALUE,
        );
        cache.upsert_connected_peer(
            peer_id(0x02),
            vec![direct_addr(v4(1, 0, 0, 2), FIRST_PORT + 1)],
            TEST_NOW + 1,
            &diversity,
            TEST_K_VALUE,
        );
        cache.upsert_connected_peer(
            peer_id(0xf0),
            vec![direct_addr(v6(0x2001, 1), FIRST_PORT + 2)],
            TEST_NOW + 2,
            &diversity,
            TEST_K_VALUE,
        );

        let addresses = cache.bootstrap_addresses(BOOTSTRAP_ROUND_ROBIN_TEST_LIMIT);

        assert_eq!(addresses.len(), 3);
        assert_eq!(
            addresses[0].dialable_socket_addr().unwrap().ip(),
            v4(1, 0, 0, 2)
        );
        assert_eq!(
            addresses[1].dialable_socket_addr().unwrap().ip(),
            v6(0x2001, 1)
        );
        assert_eq!(
            addresses[2].dialable_socket_addr().unwrap().ip(),
            v4(1, 0, 0, 1)
        );
    }

    #[test]
    fn cached_addresses_are_stored_with_peer_id_suffix() {
        let mut cache = ClientPeerCacheFile::empty();
        let diversity = IPDiversityConfig::permissive();

        cache.upsert_connected_peer(
            peer_id(1),
            vec![direct_addr(v4(203, 0, 113, 10), FIRST_PORT)],
            TEST_NOW,
            &diversity,
            TEST_K_VALUE,
        );

        let addr = cache.peers[0].direct_addresses[0].clone();
        assert_eq!(addr.peer_id(), Some(&peer_id(1)));
    }

    #[test]
    fn select_bootstrap_peers_orders_configured_after_cached_fallback() {
        let first_cached = MultiAddr::quic(SocketAddr::new(v4(203, 0, 113, 20), FIRST_PORT))
            .with_peer_id(peer_id(1));
        let second_cached = MultiAddr::quic(SocketAddr::new(v4(203, 0, 113, 21), FIRST_PORT))
            .with_peer_id(peer_id(2));
        let configured = MultiAddr::quic(SocketAddr::new(v4(203, 0, 113, 22), FIRST_PORT));

        let selected = select_bootstrap_peers(
            vec![first_cached.clone(), second_cached.clone()],
            vec![configured.clone()],
        );

        assert_eq!(selected, vec![first_cached, second_cached, configured]);
    }

    #[test]
    fn select_bootstrap_peers_uses_configured_when_cache_empty() {
        let configured = MultiAddr::quic(SocketAddr::new(v4(203, 0, 113, 21), FIRST_PORT));

        let selected = select_bootstrap_peers(Vec::new(), vec![configured.clone()]);

        assert_eq!(selected, vec![configured]);
    }

    #[test]
    fn cached_bootstrap_peers_include_all_usable_cached_peers() {
        let mut cache = ClientPeerCacheFile::empty();
        let diversity = IPDiversityConfig::permissive();

        for idx in 0..BOOTSTRAP_ROUND_ROBIN_TEST_LIMIT + 1 {
            cache.upsert_connected_peer(
                peer_id(idx as u8),
                vec![direct_addr(
                    v4(1, 0, idx as u8, 1),
                    FIRST_PORT + u16::try_from(idx).unwrap(),
                )],
                TEST_NOW + u64::try_from(idx).unwrap(),
                &diversity,
                TEST_K_VALUE,
            );
        }

        let addresses = cache.bootstrap_addresses(CLIENT_PEER_CACHE_MAX_PEERS);

        assert_eq!(addresses.len(), BOOTSTRAP_ROUND_ROBIN_TEST_LIMIT + 1);
    }
}
