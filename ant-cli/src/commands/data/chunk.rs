use std::io::{Read as _, Write as _};
use std::path::PathBuf;

use bytes::Bytes;
use clap::Subcommand;
use tracing::info;

use ant_core::data::client::chunk::ChunkPeerGetResult;
use ant_core::data::{Client, Error as DataError, MAX_CHUNK_SIZE};

/// Chunk subcommands.
#[derive(Subcommand, Debug)]
pub enum ChunkAction {
    /// Store a single chunk. Reads from FILE or stdin.
    Put {
        /// Input file (reads from stdin if omitted).
        file: Option<PathBuf>,
    },
    /// Retrieve a single chunk. Writes to FILE or stdout.
    Get {
        /// Hex-encoded chunk address (64 hex chars).
        address: String,
        /// Output file (writes to stdout if omitted).
        #[arg(long, short)]
        output: Option<PathBuf>,
        /// Try every close-group peer and print ranked per-peer results.
        ///
        /// In this diagnostic mode chunk bytes are only written when
        /// -o/--output is supplied.
        #[arg(long, alias = "try-all-peers")]
        all_peers: bool,
    },
}

impl ChunkAction {
    pub async fn execute(self, client: &Client) -> anyhow::Result<()> {
        match self {
            ChunkAction::Put { file } => {
                let content = read_input(file.as_deref())?;
                info!("Storing single chunk ({} bytes)", content.len());

                let address = client
                    .chunk_put(Bytes::from(content))
                    .await
                    .map_err(|e| anyhow::anyhow!("Chunk put failed: {e}"))?;

                let hex_addr = hex::encode(address);
                info!("Chunk stored at {hex_addr}");
                println!("{hex_addr}");
            }
            ChunkAction::Get {
                address,
                output,
                all_peers,
            } => {
                let addr = parse_address(&address)?;
                info!("Retrieving chunk {address}");

                if all_peers {
                    return get_chunk_from_all_peers(client, &addr, &address, output).await;
                }

                let result = client
                    .chunk_get(&addr)
                    .await
                    .map_err(|e| anyhow::anyhow!("Chunk get failed: {e}"))?;

                match result {
                    Some(chunk) => {
                        if let Some(path) = output {
                            std::fs::write(&path, &chunk.content)?;
                            info!("Chunk saved to {}", path.display());
                        } else {
                            std::io::stdout().write_all(&chunk.content)?;
                        }
                    }
                    None => {
                        anyhow::bail!("Chunk not found for address {address}");
                    }
                }
            }
        }
        Ok(())
    }
}

/// Length of an `XorName` address in bytes.
const XORNAME_BYTE_LEN: usize = 32;
/// Base used for decimal rendering.
const DECIMAL_RADIX: u16 = 10;
/// Base represented by one byte.
const BYTE_RADIX: u16 = u8::MAX as u16 + 1;
/// ASCII value for the decimal zero digit.
const ASCII_ZERO: u8 = b'0';

#[derive(Default)]
struct PeerGetSummary {
    found: usize,
    not_found: usize,
    timeout: usize,
    network_error: usize,
    error: usize,
}

fn read_input(file: Option<&std::path::Path>) -> anyhow::Result<Vec<u8>> {
    if let Some(path) = file {
        let meta = std::fs::metadata(path)?;
        if meta.len() > MAX_CHUNK_SIZE as u64 {
            anyhow::bail!(
                "Input file exceeds MAX_CHUNK_SIZE ({MAX_CHUNK_SIZE} bytes): {} bytes",
                meta.len()
            );
        }
        return Ok(std::fs::read(path)?);
    }
    let limit = (MAX_CHUNK_SIZE + 1) as u64;
    let mut buf = Vec::new();
    std::io::stdin().take(limit).read_to_end(&mut buf)?;
    if buf.len() > MAX_CHUNK_SIZE {
        anyhow::bail!("Stdin input exceeds MAX_CHUNK_SIZE ({MAX_CHUNK_SIZE} bytes)");
    }
    Ok(buf)
}

async fn get_chunk_from_all_peers(
    client: &Client,
    addr: &[u8; XORNAME_BYTE_LEN],
    address: &str,
    output: Option<PathBuf>,
) -> anyhow::Result<()> {
    let results = client
        .chunk_get_from_close_group(addr)
        .await
        .map_err(|e| anyhow::anyhow!("Chunk get failed: {e}"))?;

    let summary = print_peer_get_results(address, &results);

    let chunk = results
        .iter()
        .find_map(|result| match &result.chunk_result {
            Ok(Some(chunk)) => Some(chunk),
            Ok(None) | Err(_) => None,
        });

    let Some(chunk) = chunk else {
        anyhow::bail!("Chunk not found for address {address}");
    };

    if let Some(path) = output {
        std::fs::write(&path, &chunk.content)?;
        info!("Chunk saved to {}", path.display());
        println!("Saved closest successful chunk to {}", path.display());
    } else {
        println!(
            "Chunk found on {} peer(s); content not written in --all-peers mode",
            summary.found
        );
    }

    Ok(())
}

fn print_peer_get_results(address: &str, results: &[ChunkPeerGetResult]) -> PeerGetSummary {
    let mut summary = PeerGetSummary::default();

    println!("Close group GET results for {address}:");
    for (index, result) in results.iter().enumerate() {
        let rank = index + 1;
        let distance = xor_distance_decimal(&result.xor_distance);
        let status = peer_get_status(result, &mut summary);
        println!(
            "{rank}. peer={} distance={distance} addrs={} result={status}",
            result.peer_id,
            result.peer_addrs.len()
        );
    }
    println!(
        "Summary: found={} not_found={} timeout={} network_error={} error={}",
        summary.found, summary.not_found, summary.timeout, summary.network_error, summary.error
    );

    summary
}

fn peer_get_status(result: &ChunkPeerGetResult, summary: &mut PeerGetSummary) -> String {
    match &result.chunk_result {
        Ok(Some(chunk)) => {
            summary.found += 1;
            format!("found bytes={}", chunk.content.len())
        }
        Ok(None) => {
            summary.not_found += 1;
            "not_found".to_string()
        }
        Err(DataError::Timeout(e)) => {
            summary.timeout += 1;
            format!("timeout message={e}")
        }
        Err(DataError::Network(e)) => {
            summary.network_error += 1;
            format!("network_error message={e}")
        }
        Err(e) => {
            summary.error += 1;
            format!("error message={e}")
        }
    }
}

fn xor_distance_decimal(distance: &[u8; XORNAME_BYTE_LEN]) -> String {
    let mut digits = vec![0u8];

    for byte in distance {
        let mut carry = u16::from(*byte);
        for digit in &mut digits {
            let value = u16::from(*digit) * BYTE_RADIX + carry;
            *digit = (value % DECIMAL_RADIX) as u8;
            carry = value / DECIMAL_RADIX;
        }

        while carry > 0 {
            digits.push((carry % DECIMAL_RADIX) as u8);
            carry /= DECIMAL_RADIX;
        }
    }

    digits
        .iter()
        .rev()
        .map(|digit| char::from(ASCII_ZERO + *digit))
        .collect()
}

pub fn parse_address(address: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(address)?;
    if bytes.len() != XORNAME_BYTE_LEN {
        anyhow::bail!(
            "Invalid address length: expected {XORNAME_BYTE_LEN} bytes, got {}",
            bytes.len()
        );
    }
    let mut out = [0u8; XORNAME_BYTE_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_distance_decimal_formats_zero() {
        assert_eq!(xor_distance_decimal(&[0; XORNAME_BYTE_LEN]), "0");
    }

    #[test]
    fn xor_distance_decimal_formats_single_byte() {
        let mut distance = [0; XORNAME_BYTE_LEN];
        distance[XORNAME_BYTE_LEN - 1] = 42;

        assert_eq!(xor_distance_decimal(&distance), "42");
    }

    #[test]
    fn xor_distance_decimal_formats_multi_byte() {
        let mut distance = [0; XORNAME_BYTE_LEN];
        distance[XORNAME_BYTE_LEN - 2] = 1;

        assert_eq!(xor_distance_decimal(&distance), "256");
    }
}
