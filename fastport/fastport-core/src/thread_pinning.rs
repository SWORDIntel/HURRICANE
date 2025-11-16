//! Thread pinning to P-cores for maximum performance on hybrid architectures

use std::io;

#[cfg(target_os = "linux")]
use std::mem;

/// Pin current thread to a P-core
pub fn pin_to_pcore() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use libc::{cpu_set_t, sched_setaffinity, CPU_SET, CPU_ZERO};

        unsafe {
            let mut cpu_set: cpu_set_t = mem::zeroed();
            CPU_ZERO(&mut cpu_set);

            // Get total CPU count
            let cpu_count = num_cpus::get();
            let pcore_count = cpu_count / 2; // Assume first half are P-cores

            // Get current thread ID
            let tid = libc::pthread_self() as usize;

            // Pin to a P-core based on thread ID
            let target_core = (tid % pcore_count) as i32;
            CPU_SET(target_core as usize, &mut cpu_set);

            let result = sched_setaffinity(0, mem::size_of::<cpu_set_t>(), &cpu_set);

            if result != 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        // macOS doesn't support direct affinity, use thread_policy
        use libc::{mach_port_t, thread_affinity_policy, thread_policy_set};
        use libc::{THREAD_AFFINITY_POLICY, THREAD_AFFINITY_POLICY_COUNT};

        unsafe {
            let thread_port = libc::pthread_mach_thread_np(libc::pthread_self());
            let mut policy = thread_affinity_policy { affinity_tag: 1 };

            let result = thread_policy_set(
                thread_port,
                THREAD_AFFINITY_POLICY,
                &mut policy as *mut _ as *mut _,
                THREAD_AFFINITY_POLICY_COUNT,
            );

            if result != 0 {
                return Err(io::Error::from_raw_os_error(result));
            }
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    {
        // Windows affinity via SetThreadAffinityMask
        use winapi::um::processthreadsapi::{GetCurrentThread, SetThreadAffinityMask};

        unsafe {
            let cpu_count = num_cpus::get();
            let pcore_count = cpu_count / 2;

            // Create affinity mask for P-cores (first half)
            let mut affinity_mask: usize = 0;
            for i in 0..pcore_count {
                affinity_mask |= 1 << i;
            }

            let result = SetThreadAffinityMask(GetCurrentThread(), affinity_mask);
            if result == 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        // Unsupported OS - no-op
        Ok(())
    }
}

/// Get CPU topology information
pub fn get_cpu_topology() -> CpuTopology {
    let total_cpus = num_cpus::get();

    // Heuristic: on hybrid architectures, assume P-cores are first half
    // More sophisticated detection would parse /proc/cpuinfo or CPUID
    let p_cores = if is_hybrid_architecture() {
        total_cpus / 2
    } else {
        total_cpus
    };

    CpuTopology {
        total_cpus,
        p_cores,
        e_cores: total_cpus - p_cores,
    }
}

/// CPU topology information
#[derive(Debug, Clone)]
pub struct CpuTopology {
    pub total_cpus: usize,
    pub p_cores: usize,
    pub e_cores: usize,
}

/// Detect if running on hybrid architecture (P+E cores)
fn is_hybrid_architecture() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        // Check CPUID for hybrid topology
        if let Some(_cpuid) = raw_cpuid::CpuId::new().get_feature_info() {
            // Hybrid bit in CPUID.07H:EDX[bit 15]
            // For now, use AVX512 as a proxy for modern hybrid architectures
            return std::arch::is_x86_feature_detected!("avx512f");
        }
    }

    // Conservative fallback: assume modern CPUs with many cores might be hybrid
    num_cpus::get() >= 12
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_topology() {
        let topology = get_cpu_topology();
        assert!(topology.total_cpus > 0);
        assert!(topology.p_cores > 0);
    }

    #[test]
    fn test_pin_to_pcore() {
        // Should not panic even if it fails
        let _ = pin_to_pcore();
    }
}
