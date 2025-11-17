use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("cpu_features.rs");
    let mut f = File::create(&dest_path).unwrap();

    // Detect target CPU features at compile time
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let target_features = env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();

    writeln!(f, "// Auto-generated CPU feature detection with runtime fallback").unwrap();
    writeln!(f, "// Target architecture: {}", target_arch).unwrap();
    writeln!(f, "").unwrap();

    if target_arch == "x86_64" {
        // Check for compile-time features
        let compile_avx512 = cfg!(feature = "avx512") || target_features.contains("avx512f");
        let compile_avx2 = cfg!(feature = "avx2") || target_features.contains("avx2") || compile_avx512;

        writeln!(f, "pub const COMPILE_AVX512_ENABLED: bool = {};", compile_avx512).unwrap();
        writeln!(f, "pub const COMPILE_AVX2_ENABLED: bool = {};", compile_avx2).unwrap();
        writeln!(f, "").unwrap();

        // Generate runtime detection functions
        writeln!(f, "/// Runtime CPU feature detection with fallback").unwrap();
        writeln!(f, "#[inline]").unwrap();
        writeln!(f, "pub fn detect_runtime_simd() -> SIMDVariant {{").unwrap();
        writeln!(f, "    #[cfg(target_arch = \"x86_64\")]").unwrap();
        writeln!(f, "    {{").unwrap();
        writeln!(f, "        // Try AVX2 first (more compatible)").unwrap();
        writeln!(f, "        if std::arch::is_x86_feature_detected!(\"avx2\") {{").unwrap();
        writeln!(f, "            // Check if AVX512 is available AND compiled in").unwrap();
        writeln!(f, "            if COMPILE_AVX512_ENABLED &&").unwrap();
        writeln!(f, "               std::arch::is_x86_feature_detected!(\"avx512f\") &&").unwrap();
        writeln!(f, "               std::arch::is_x86_feature_detected!(\"avx512bw\") {{").unwrap();
        writeln!(f, "                // AVX512 detected, but prefer AVX2 for stability").unwrap();
        writeln!(f, "                eprintln!(\"[SIMD] AVX-512 detected but using AVX2 for compatibility\");").unwrap();
        writeln!(f, "                return SIMDVariant::AVX2;").unwrap();
        writeln!(f, "            }}").unwrap();
        writeln!(f, "            return SIMDVariant::AVX2;").unwrap();
        writeln!(f, "        }}").unwrap();
        writeln!(f, "        eprintln!(\"[SIMD] No AVX2 support, falling back to scalar\");").unwrap();
        writeln!(f, "        SIMDVariant::Scalar").unwrap();
        writeln!(f, "    }}").unwrap();
        writeln!(f, "    #[cfg(not(target_arch = \"x86_64\"))]").unwrap();
        writeln!(f, "    {{").unwrap();
        writeln!(f, "        SIMDVariant::Scalar").unwrap();
        writeln!(f, "    }}").unwrap();
        writeln!(f, "}}").unwrap();
        writeln!(f, "").unwrap();

        // Add SIMD variant enum
        writeln!(f, "#[derive(Debug, Clone, Copy, PartialEq, Eq)]").unwrap();
        writeln!(f, "pub enum SIMDVariant {{").unwrap();
        writeln!(f, "    AVX512,").unwrap();
        writeln!(f, "    AVX2,").unwrap();
        writeln!(f, "    Scalar,").unwrap();
        writeln!(f, "}}").unwrap();
        writeln!(f, "").unwrap();

        writeln!(f, "impl SIMDVariant {{").unwrap();
        writeln!(f, "    pub fn as_str(&self) -> &'static str {{").unwrap();
        writeln!(f, "        match self {{").unwrap();
        writeln!(f, "            SIMDVariant::AVX512 => \"AVX-512\",").unwrap();
        writeln!(f, "            SIMDVariant::AVX2 => \"AVX2\",").unwrap();
        writeln!(f, "            SIMDVariant::Scalar => \"Scalar\",").unwrap();
        writeln!(f, "        }}").unwrap();
        writeln!(f, "    }}").unwrap();
        writeln!(f, "}}").unwrap();
        writeln!(f, "").unwrap();

        // Backward compatibility
        writeln!(f, "pub const AVX512_ENABLED: bool = {};", compile_avx512).unwrap();
        writeln!(f, "pub const AVX2_ENABLED: bool = {};", compile_avx2).unwrap();
        writeln!(f, "").unwrap();

        writeln!(f, "#[inline]").unwrap();
        writeln!(f, "pub fn get_simd_variant() -> &'static str {{").unwrap();
        writeln!(f, "    detect_runtime_simd().as_str()").unwrap();
        writeln!(f, "}}").unwrap();
        writeln!(f, "").unwrap();

        // Build messages
        if compile_avx512 {
            println!("cargo:warning=AVX-512 compiled but will prefer AVX2 at runtime for stability");
        } else if compile_avx2 {
            println!("cargo:warning=AVX2 mode enabled - Optimal performance and compatibility");
        } else {
            println!("cargo:warning=Building without SIMD support. Performance will be reduced.");
            println!("cargo:warning=To enable AVX2: RUSTFLAGS='-C target-cpu=native' cargo build --release --features avx2");
        }

    } else if target_arch == "aarch64" {
        writeln!(f, "pub const NEON_ENABLED: bool = true;").unwrap();
        writeln!(f, "pub const COMPILE_AVX512_ENABLED: bool = false;").unwrap();
        writeln!(f, "pub const COMPILE_AVX2_ENABLED: bool = false;").unwrap();
        writeln!(f, "").unwrap();
        writeln!(f, "#[derive(Debug, Clone, Copy, PartialEq, Eq)]").unwrap();
        writeln!(f, "pub enum SIMDVariant {{ NEON, Scalar }}").unwrap();
        writeln!(f, "impl SIMDVariant {{ pub fn as_str(&self) -> &'static str {{ \"NEON\" }} }}").unwrap();
        writeln!(f, "#[inline]").unwrap();
        writeln!(f, "pub fn detect_runtime_simd() -> SIMDVariant {{ SIMDVariant::NEON }}").unwrap();
        writeln!(f, "#[inline]").unwrap();
        writeln!(f, "pub fn get_simd_variant() -> &'static str {{ \"NEON\" }}").unwrap();
    } else {
        writeln!(f, "pub const AVX512_ENABLED: bool = false;").unwrap();
        writeln!(f, "pub const AVX2_ENABLED: bool = false;").unwrap();
        writeln!(f, "pub const COMPILE_AVX512_ENABLED: bool = false;").unwrap();
        writeln!(f, "pub const COMPILE_AVX2_ENABLED: bool = false;").unwrap();
        writeln!(f, "").unwrap();
        writeln!(f, "#[derive(Debug, Clone, Copy, PartialEq, Eq)]").unwrap();
        writeln!(f, "pub enum SIMDVariant {{ Scalar }}").unwrap();
        writeln!(f, "impl SIMDVariant {{ pub fn as_str(&self) -> &'static str {{ \"Scalar\" }} }}").unwrap();
        writeln!(f, "#[inline]").unwrap();
        writeln!(f, "pub fn detect_runtime_simd() -> SIMDVariant {{ SIMDVariant::Scalar }}").unwrap();
        writeln!(f, "#[inline]").unwrap();
        writeln!(f, "pub fn get_simd_variant() -> &'static str {{ \"scalar\" }}").unwrap();
    }

    // Generate P-core detection code
    writeln!(f, "").unwrap();
    writeln!(f, "/// Get number of performance cores for pinning").unwrap();
    writeln!(f, "#[inline]").unwrap();
    writeln!(f, "pub fn get_pcore_count() -> usize {{").unwrap();
    writeln!(f, "    // On hybrid architectures, assume first 50% are P-cores").unwrap();
    writeln!(f, "    let total = num_cpus::get();").unwrap();
    writeln!(f, "    std::cmp::max(total / 2, 1)").unwrap();
    writeln!(f, "}}").unwrap();
}
