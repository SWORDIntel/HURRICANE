//! FastPort Core - High-Performance Async Port Scanner
//!
//! Rust-based scanner core with runtime AVX-512/AVX2 SIMD detection
//! and P-core thread pinning for maximum performance.
//!
//! Enhanced with robust AVX2 fallback for systems where AVX-512 is unavailable.

use pyo3::prelude::*;
use std::sync::Arc;
use tokio::runtime::Runtime;
use parking_lot::RwLock;

mod async_scanner;
mod packet_processor;
mod simd_scanner;
mod thread_pinning;

pub use async_scanner::*;
pub use packet_processor::*;
pub use simd_scanner::*;
pub use thread_pinning::*;

/// Scanner statistics shared across threads
#[derive(Debug, Default, Clone)]
pub struct ScanStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub ports_open: u32,
    pub ports_closed: u32,
    pub ports_filtered: u32,
    pub scan_duration_ms: u64,
}

/// Global scanner instance with thread-safe statistics
pub struct FastPortScanner {
    runtime: Arc<Runtime>,
    stats: Arc<RwLock<ScanStats>>,
    worker_count: usize,
}

impl FastPortScanner {
    /// Create new scanner with P-core pinning
    pub fn new(worker_count: Option<usize>) -> anyhow::Result<Self> {
        let pcore_count = get_pcore_count();
        let workers = worker_count.unwrap_or(pcore_count);

        // Create multi-threaded runtime with P-core affinity
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(workers)
            .thread_name("fastport-worker")
            .enable_all()
            .on_thread_start(move || {
                // Pin to P-cores on startup
                if let Err(e) = pin_to_pcore() {
                    eprintln!("Warning: Failed to pin thread to P-core: {}", e);
                }
            })
            .build()?;

        Ok(Self {
            runtime: Arc::new(runtime),
            stats: Arc::new(RwLock::new(ScanStats::default())),
            worker_count: workers,
        })
    }

    /// Get SIMD variant being used
    pub fn simd_variant(&self) -> &'static str {
        get_simd_variant()
    }

    /// Get worker count
    pub fn worker_count(&self) -> usize {
        self.worker_count
    }

    /// Get current statistics
    pub fn get_stats(&self) -> ScanStats {
        self.stats.read().clone()
    }
}

/// Python module initialization
#[pymodule]
fn fastport_core(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyFastPortScanner>()?;
    m.add_function(wrap_pyfunction!(get_cpu_features, m)?)?;
    m.add_function(wrap_pyfunction!(benchmark_simd, m)?)?;
    Ok(())
}

/// Python wrapper for FastPortScanner
#[pyclass(name = "FastPortScanner")]
struct PyFastPortScanner {
    inner: Arc<FastPortScanner>,
}

#[pymethods]
impl PyFastPortScanner {
    #[new]
    fn new(worker_count: Option<usize>) -> PyResult<Self> {
        let scanner = FastPortScanner::new(worker_count)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(Self {
            inner: Arc::new(scanner),
        })
    }

    /// Async scan method callable from Python - returns count of open ports
    fn scan(&self, target: String, ports: Vec<u16>, timeout_ms: u64) -> PyResult<usize> {
        let results = self.inner.runtime.block_on(async {
            async_scan_ports(&target, &ports, timeout_ms).await
        })
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;

        Ok(results.len())
    }

    fn get_simd_variant(&self) -> &'static str {
        self.inner.simd_variant()
    }

    fn get_worker_count(&self) -> usize {
        self.inner.worker_count()
    }

    fn get_stats(&self) -> PyResult<String> {
        let stats = self.inner.get_stats();
        Ok(format!(
            "Packets: {}/{}, Ports: {} open, {} closed, Duration: {}ms",
            stats.packets_received,
            stats.packets_sent,
            stats.ports_open,
            stats.ports_closed,
            stats.scan_duration_ms
        ))
    }
}

/// Get CPU features detected at runtime
#[pyfunction]
fn get_cpu_features() -> PyResult<String> {
    let variant = get_simd_variant();
    let pcores = get_pcore_count();

    // Runtime detection results
    let runtime_avx512 = cfg!(target_arch = "x86_64") &&
        std::arch::is_x86_feature_detected!("avx512f") &&
        std::arch::is_x86_feature_detected!("avx512bw");
    let runtime_avx2 = cfg!(target_arch = "x86_64") &&
        std::arch::is_x86_feature_detected!("avx2");

    Ok(format!(
        "Active SIMD: {}\n\
         P-cores: {}\n\
         Runtime Detection:\n\
         - AVX-512: {} (compiled: {})\n\
         - AVX2: {} (compiled: {})\n\
         Note: Preferring AVX2 for compatibility",
        variant,
        pcores,
        if runtime_avx512 { "detected" } else { "not available" },
        if simd_scanner::AVX512_ENABLED { "yes" } else { "no" },
        if runtime_avx2 { "detected" } else { "not available" },
        if simd_scanner::AVX2_ENABLED { "yes" } else { "no" }
    ))
}

/// Benchmark SIMD performance
#[pyfunction]
fn benchmark_simd() -> PyResult<String> {
    let iterations = 1_000_000;
    let start = std::time::Instant::now();

    // Benchmark packet processing with SIMD
    for _ in 0..iterations {
        let _ = simd_process_packet(&[0u8; 64]);
    }

    let duration = start.elapsed();
    let ops_per_sec = (iterations as f64 / duration.as_secs_f64()) / 1_000_000.0;

    Ok(format!(
        "SIMD Variant: {}\nProcessed {} packets in {:?}\nThroughput: {:.2}M packets/sec",
        get_simd_variant(),
        iterations,
        duration,
        ops_per_sec
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let scanner = FastPortScanner::new(None).unwrap();
        assert!(scanner.worker_count() > 0);
        assert!(!scanner.simd_variant().is_empty());
    }

    #[test]
    fn test_cpu_features() {
        let features = get_cpu_features().unwrap();
        assert!(features.contains("SIMD"));
    }
}
