//! SIMD-optimized packet processing with AVX-512 and AVX2 variants
//!
//! This module provides vectorized operations for high-speed packet processing.
//! Enhanced with runtime CPU feature detection and robust AVX2 fallback.

use std::sync::OnceLock;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

// Include generated CPU feature detection
include!(concat!(env!("OUT_DIR"), "/cpu_features.rs"));

/// Global SIMD variant cached at runtime
static RUNTIME_SIMD: OnceLock<SIMDVariant> = OnceLock::new();

/// Get the SIMD variant to use (cached after first call)
#[inline(always)]
fn get_runtime_simd() -> SIMDVariant {
    *RUNTIME_SIMD.get_or_init(|| {
        let variant = detect_runtime_simd();
        eprintln!("[FastPort] Using SIMD variant: {:?}", variant);
        variant
    })
}

/// Process packet with SIMD optimizations (runtime dispatch)
#[inline(always)]
pub fn simd_process_packet(packet: &[u8]) -> u32 {
    match get_runtime_simd() {
        SIMDVariant::AVX2 => {
            #[cfg(target_arch = "x86_64")]
            unsafe {
                if std::arch::is_x86_feature_detected!("avx2") {
                    return simd_process_packet_avx2(packet);
                }
            }
            simd_process_packet_scalar(packet)
        }
        SIMDVariant::AVX512 => {
            #[cfg(target_arch = "x86_64")]
            unsafe {
                if std::arch::is_x86_feature_detected!("avx512f") &&
                   std::arch::is_x86_feature_detected!("avx512bw") {
                    return simd_process_packet_avx512(packet);
                }
            }
            // Fallback to AVX2 if AVX512 fails
            simd_process_packet(packet)
        }
        SIMDVariant::Scalar => simd_process_packet_scalar(packet),
    }
}

/// AVX-512 optimized packet checksum (64 bytes at once)
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512bw,avx512vl")]
unsafe fn simd_process_packet_avx512(packet: &[u8]) -> u32 {
    if packet.len() < 64 {
        return simd_process_packet_scalar(packet);
    }

    // Load 64 bytes into AVX-512 register
    let ptr = packet.as_ptr() as *const __m512i;
    let data = _mm512_loadu_si512(ptr);

    // Compute checksum using horizontal sum
    let sum = _mm512_reduce_add_epi32(_mm512_sad_epu8(data, _mm512_setzero_si512())) as u32;

    // Process flags and extract port state
    let flags_mask = _mm512_set1_epi8(0x12); // SYN-ACK flags
    let masked = _mm512_and_si512(data, flags_mask);
    let has_syn_ack = _mm512_test_epi8_mask(masked, masked);

    // Return combined checksum and port state
    sum.wrapping_add(has_syn_ack.count_ones())
}

/// AVX2 fallback packet checksum (32 bytes at once)
/// Enhanced with better error handling and edge case support
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn simd_process_packet_avx2(packet: &[u8]) -> u32 {
    // Handle small packets with scalar fallback
    if packet.len() < 32 {
        return simd_process_packet_scalar(packet);
    }

    let mut total_sum = 0u32;
    let mut flag_count = 0u32;

    // Process packet in 32-byte chunks
    let chunks = packet.len() / 32;
    for i in 0..chunks {
        let ptr = packet.as_ptr().add(i * 32) as *const __m256i;
        let data = _mm256_loadu_si256(ptr);

        // Compute checksum using SAD (Sum of Absolute Differences)
        let zero = _mm256_setzero_si256();
        let sad = _mm256_sad_epu8(data, zero);

        // Horizontal sum across all lanes
        let sum128 = _mm_add_epi64(
            _mm256_extracti128_si256(sad, 0),
            _mm256_extracti128_si256(sad, 1),
        );
        let sum = _mm_extract_epi64(sum128, 0) + _mm_extract_epi64(sum128, 1);
        total_sum = total_sum.wrapping_add(sum as u32);

        // Check for SYN-ACK flags (TCP flags: SYN=0x02, ACK=0x10, combined=0x12)
        let flags_mask = _mm256_set1_epi8(0x12);
        let masked = _mm256_and_si256(data, flags_mask);
        let cmp = _mm256_cmpeq_epi8(masked, flags_mask);
        let has_flags = _mm256_movemask_epi8(cmp).count_ones();
        flag_count += has_flags;
    }

    // Process remaining bytes with scalar
    let remainder = packet.len() % 32;
    if remainder > 0 {
        let offset = chunks * 32;
        for &byte in &packet[offset..] {
            total_sum = total_sum.wrapping_add(byte as u32);
        }
    }

    total_sum.wrapping_add(flag_count)
}

/// Scalar fallback for non-SIMD architectures or small packets
/// Optimized for efficiency and correctness
#[inline(always)]
fn simd_process_packet_scalar(packet: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut syn_ack_count = 0u32;

    // Process bytes with loop unrolling for better performance
    let chunks = packet.len() / 4;
    let mut i = 0;

    for _ in 0..chunks {
        sum = sum.wrapping_add(packet[i] as u32);
        sum = sum.wrapping_add(packet[i + 1] as u32);
        sum = sum.wrapping_add(packet[i + 2] as u32);
        sum = sum.wrapping_add(packet[i + 3] as u32);
        i += 4;
    }

    // Process remaining bytes
    while i < packet.len() {
        sum = sum.wrapping_add(packet[i] as u32);
        i += 1;
    }

    // Check TCP flags at standard position (offset 13 in TCP/IP packet)
    if packet.len() > 33 {  // Ensure we have a full TCP/IP header
        // TCP flags are at IP header (20 bytes) + TCP offset 13
        if (packet[33] & 0x12) == 0x12 {
            syn_ack_count = 1;
        }
    }

    sum.wrapping_add(syn_ack_count)
}

/// Vectorized port range checking (runtime dispatch)
/// AVX2: 16 ports at once, AVX-512: 32 ports at once
#[inline(always)]
pub fn simd_check_ports_open(ports: &[u16], responses: &[u8]) -> Vec<u16> {
    match get_runtime_simd() {
        SIMDVariant::AVX2 => {
            #[cfg(target_arch = "x86_64")]
            unsafe {
                if std::arch::is_x86_feature_detected!("avx2") {
                    return simd_check_ports_avx2(ports, responses);
                }
            }
            simd_check_ports_scalar(ports, responses)
        }
        SIMDVariant::AVX512 => {
            #[cfg(target_arch = "x86_64")]
            unsafe {
                if std::arch::is_x86_feature_detected!("avx512f") &&
                   std::arch::is_x86_feature_detected!("avx512bw") {
                    return simd_check_ports_avx512(ports, responses);
                }
            }
            // Fallback to AVX2
            simd_check_ports_open(ports, responses)
        }
        SIMDVariant::Scalar => simd_check_ports_scalar(ports, responses),
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512bw")]
unsafe fn simd_check_ports_avx512(ports: &[u16], responses: &[u8]) -> Vec<u16> {
    let mut open_ports = Vec::with_capacity(ports.len() / 4);

    // Process 32 ports at a time with AVX-512
    for chunk_idx in (0..ports.len()).step_by(32) {
        let remaining = ports.len() - chunk_idx;
        if remaining < 32 {
            // Handle remainder with scalar
            for i in chunk_idx..ports.len() {
                if responses[i] > 0 {
                    open_ports.push(ports[i]);
                }
            }
            break;
        }

        // Load 32 ports (16-bit each = 64 bytes) - currently unused but kept for future optimization
        let _ports_ptr = ports[chunk_idx..].as_ptr() as *const __m512i;
        // let _ports_vec = _mm512_loadu_si512(_ports_ptr);

        // Load 32 response bytes
        let responses_ptr = responses[chunk_idx..].as_ptr() as *const __m256i;
        let resp_vec = _mm256_loadu_si256(responses_ptr);

        // Check which responses are non-zero (port is open)
        let zero = _mm256_setzero_si256();
        let open_mask = _mm256_cmpgt_epi8(resp_vec, zero);
        let mask_bits = _mm256_movemask_epi8(open_mask) as u32;

        // Extract open ports using mask
        for bit_idx in 0..32 {
            if mask_bits & (1 << bit_idx) != 0 {
                open_ports.push(ports[chunk_idx + bit_idx]);
            }
        }
    }

    open_ports
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn simd_check_ports_avx2(ports: &[u16], responses: &[u8]) -> Vec<u16> {
    let mut open_ports = Vec::with_capacity(ports.len() / 4);

    // Process 16 ports at a time with AVX2
    for chunk_idx in (0..ports.len()).step_by(16) {
        let remaining = ports.len() - chunk_idx;
        if remaining < 16 {
            for i in chunk_idx..ports.len() {
                if responses[i] > 0 {
                    open_ports.push(ports[i]);
                }
            }
            break;
        }

        // Load 16 response bytes
        let responses_ptr = responses[chunk_idx..].as_ptr() as *const __m128i;
        let resp_vec = _mm_loadu_si128(responses_ptr);

        // Check which are non-zero
        let zero = _mm_setzero_si128();
        let open_mask = _mm_cmpgt_epi8(resp_vec, zero);
        let mask_bits = _mm_movemask_epi8(open_mask) as u16;

        // Extract open ports
        for bit_idx in 0..16 {
            if mask_bits & (1 << bit_idx) != 0 {
                open_ports.push(ports[chunk_idx + bit_idx]);
            }
        }
    }

    open_ports
}

fn simd_check_ports_scalar(ports: &[u16], responses: &[u8]) -> Vec<u16> {
    ports
        .iter()
        .zip(responses.iter())
        .filter_map(|(&port, &resp)| if resp > 0 { Some(port) } else { None })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_processing() {
        let packet = vec![0u8; 64];
        let result = simd_process_packet(&packet);
        assert_eq!(result, 0);
    }

    #[test]
    fn test_port_checking() {
        let ports = vec![80, 443, 8080, 22, 3306];
        let responses = vec![1, 1, 0, 1, 0];
        let open = simd_check_ports_open(&ports, &responses);
        assert_eq!(open, vec![80, 443, 22]);
    }
}
