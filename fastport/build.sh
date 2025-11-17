#!/bin/bash
# FastPort Automated Build Script
# Builds Rust core and Python package for distribution

set -e  # Exit on error

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  FastPort Automated Builder"
echo "  Building high-performance port scanner with AVX-512"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check for required tools
echo "🔍 Checking dependencies..."

if ! command -v rustc &> /dev/null; then
    echo "❌ Rust not found. Installing..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

RUST_VERSION=$(rustc --version | awk '{print $2}')
echo "✅ Rust $RUST_VERSION found"

if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3.8 or newer."
    exit 1
fi

PYTHON_VERSION=$(python3 --version)
echo "✅ $PYTHON_VERSION found"

if ! python3 -c "import maturin" 2>/dev/null; then
    echo "📦 Installing maturin..."
    pip3 install maturin
fi

echo "✅ maturin found"
echo ""

# Detect CPU features
echo "🖥  Detecting CPU features..."

HAS_AVX512=false
HAS_AVX2=false

if command -v lscpu &> /dev/null; then
    if lscpu | grep -q avx512; then
        HAS_AVX512=true
        echo "✅ AVX-512 detected"
    elif lscpu | grep -q avx2; then
        HAS_AVX2=true
        echo "✅ AVX2 detected (AVX-512 not available)"
    else
        echo "⚠️  No AVX support detected"
    fi
elif [[ -f /proc/cpuinfo ]]; then
    if grep -q avx512 /proc/cpuinfo; then
        HAS_AVX512=true
        echo "✅ AVX-512 detected"
    elif grep -q avx2 /proc/cpuinfo; then
        HAS_AVX2=true
        echo "✅ AVX2 detected (AVX-512 not available)"
    fi
elif command -v sysctl &> /dev/null; then
    # macOS
    if sysctl -a | grep -q "hw.optional.avx512"; then
        HAS_AVX512=true
        echo "✅ AVX-512 detected"
    elif sysctl -a | grep -q "hw.optional.avx2_0: 1"; then
        HAS_AVX2=true
        echo "✅ AVX2 detected"
    fi
fi

echo ""

# Build configuration
BUILD_MODE="release"
BUILD_FEATURES=""

if [ "$1" == "--dev" ]; then
    BUILD_MODE="dev"
    echo "🔧 Building in development mode (faster compile, slower runtime)"
else
    echo "🚀 Building in release mode (slower compile, faster runtime)"
fi

if [ "$HAS_AVX512" = true ]; then
    BUILD_FEATURES="avx512"
    RUSTFLAGS="-C target-cpu=native -C target-feature=+avx512f,+avx512bw,+avx512dq,+avx512vl"
    echo "⚡ Building with AVX-512 optimization"
elif [ "$HAS_AVX2" = true ]; then
    BUILD_FEATURES="avx2"
    RUSTFLAGS="-C target-cpu=native -C target-feature=+avx2,+fma"
    echo "⚡ Building with AVX2 optimization"
else
    RUSTFLAGS="-C target-cpu=native"
    echo "⚠️  Building without SIMD optimization (performance will be reduced)"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Building Rust Core"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

cd fastport-core

if [ "$BUILD_MODE" == "release" ]; then
    export RUSTFLAGS
    if [ -n "$BUILD_FEATURES" ]; then
        maturin develop --release --features "$BUILD_FEATURES"
    else
        maturin develop --release
    fi
else
    maturin develop
fi

cd ..

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Installing Python Package"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

pip3 install -e .

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Verifying Installation"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

python3 -c "
import fastport_core
scanner = fastport_core.FastPortScanner(workers=None)
print('✅ Rust core loaded successfully')
print(f'⚡ SIMD Variant: {scanner.get_simd_variant()}')
print(f'🧵 Workers: {scanner.get_worker_count()}')
print('')
print('CPU Features:')
print(fastport_core.get_cpu_features())
print('')
print('Performance Benchmark:')
print(fastport_core.benchmark_simd())
"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✅ Build Complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Available commands:"
echo "  fastport         - Command-line port scanner"
echo "  fastport-tui     - Basic interactive TUI"
echo "  fastport-pro     - Professional TUI with real-time stats"
echo "  fastport-gui     - Graphical interface (requires PyQt6)"
echo "  fastport-cve     - CVE vulnerability scanner"
echo "  fastport-cve-tui - Interactive CVE scanner"
echo ""
echo "Try it out:"
echo "  fastport-pro scanme.nmap.org -p 22,80,443"
echo ""
