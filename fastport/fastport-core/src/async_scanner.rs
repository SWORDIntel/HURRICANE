//! Async port scanner with Tokio runtime and SIMD acceleration
//!
//! This module provides high-performance asynchronous port scanning
//! with automatic SIMD optimization selection (AVX2/AVX512/Scalar).

use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use std::sync::Arc;
use parking_lot::RwLock;
use crossbeam::queue::SegQueue;

use crate::simd_scanner::*;
use crate::ScanStats;

/// Scan result for a single port
#[derive(Debug, Clone)]
pub struct PortScanResult {
    pub port: u16,
    pub is_open: bool,
    pub response_time_ms: u64,
    pub banner: Option<String>,
}

/// Async scan multiple ports on a target
pub async fn async_scan_ports(
    target: &str,
    ports: &[u16],
    timeout_ms: u64,
) -> anyhow::Result<Vec<PortScanResult>> {
    let stats = Arc::new(RwLock::new(ScanStats::default()));
    let results_queue = Arc::new(SegQueue::new());

    // Create concurrent scan tasks
    let mut tasks = Vec::with_capacity(ports.len());

    for &port in ports {
        let target = target.to_string();
        let stats_clone = stats.clone();
        let results_clone = results_queue.clone();

        let task = tokio::spawn(async move {
            let start = std::time::Instant::now();
            let addr = format!("{}:{}", target, port);

            match timeout(
                Duration::from_millis(timeout_ms),
                TcpStream::connect(&addr),
            )
            .await
            {
                Ok(Ok(stream)) => {
                    // Port is open
                    stats_clone.write().ports_open += 1;
                    stats_clone.write().packets_received += 1;

                    let response_time = start.elapsed().as_millis() as u64;

                    // Try to grab banner
                    let banner = grab_banner(stream).await;

                    results_clone.push(PortScanResult {
                        port,
                        is_open: true,
                        response_time_ms: response_time,
                        banner,
                    });
                }
                Ok(Err(_)) | Err(_) => {
                    // Port is closed or filtered
                    stats_clone.write().ports_closed += 1;
                }
            }

            stats_clone.write().packets_sent += 1;
        });

        tasks.push(task);
    }

    // Wait for all tasks
    for task in tasks {
        let _ = task.await;
    }

    // Collect results
    let mut results = Vec::new();
    while let Some(result) = results_queue.pop() {
        results.push(result);
    }

    // Sort by port number
    results.sort_by_key(|r| r.port);

    Ok(results)
}

/// Grab banner from open port
async fn grab_banner(mut stream: TcpStream) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buffer = vec![0u8; 1024];

    // Try to read banner (some services send immediately)
    match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => {
            return Some(String::from_utf8_lossy(&buffer[..n]).to_string());
        }
        _ => {}
    }

    // Try sending probe for HTTP
    if let Ok(_) = stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await {
        match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                return Some(String::from_utf8_lossy(&buffer[..n]).to_string());
            }
            _ => {}
        }
    }

    None
}

/// High-performance batch scanner using SIMD for result processing
pub async fn async_scan_batch_simd(
    target: &str,
    start_port: u16,
    end_port: u16,
    concurrency: usize,
    timeout_ms: u64,
) -> anyhow::Result<Vec<u16>> {
    let port_count = (end_port - start_port + 1) as usize;
    let mut ports = Vec::with_capacity(port_count);
    let mut responses = vec![0u8; port_count];

    // Generate port list
    for port in start_port..=end_port {
        ports.push(port);
    }

    // Scan in batches with controlled concurrency
    let batch_size = concurrency;
    for (batch_idx, port_batch) in ports.chunks(batch_size).enumerate() {
        let mut tasks = Vec::with_capacity(port_batch.len());

        for (idx, &port) in port_batch.iter().enumerate() {
            let target = target.to_string();
            let global_idx = batch_idx * batch_size + idx;

            let task = tokio::spawn(async move {
                let addr = format!("{}:{}", target, port);
                match timeout(
                    Duration::from_millis(timeout_ms),
                    TcpStream::connect(&addr),
                )
                .await
                {
                    Ok(Ok(_)) => (global_idx, 1u8),
                    _ => (global_idx, 0u8),
                }
            });

            tasks.push(task);
        }

        // Collect batch results
        for task in tasks {
            if let Ok((idx, status)) = task.await {
                responses[idx] = status;
            }
        }
    }

    // Use SIMD to extract open ports from responses
    let open_ports = simd_check_ports_open(&ports, &responses);

    Ok(open_ports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scan_localhost() {
        // Scan some common ports on localhost
        let results = async_scan_ports("127.0.0.1", &[22, 80, 443], 1000)
            .await
            .unwrap();

        // Should complete without panic
        assert!(results.len() <= 3);
    }

    #[tokio::test]
    async fn test_batch_scan() {
        let open_ports = async_scan_batch_simd("127.0.0.1", 1, 1000, 100, 500)
            .await
            .unwrap();

        // Should complete
        assert!(open_ports.len() < 1000);
    }
}
