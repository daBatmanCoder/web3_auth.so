#!/bin/bash

# Kamailio Web3 Auth Module Build Script

set -e  # Exit on any error

echo "🚀 Kamailio Web3 Auth Module Builder"
echo "===================================="

# Check if we're on a system with Kamailio dev headers
check_local_build() {
    if command -v pkg-config >/dev/null 2>&1; then
        if pkg-config --exists kamailio 2>/dev/null; then
            echo "✅ Kamailio development headers found locally"
            return 0
        fi
    fi
    
    # Check for headers in common locations
    for path in /usr/include/kamailio /usr/local/include/kamailio /opt/kamailio/include; do
        if [ -f "$path/sr_module.h" ]; then
            echo "✅ Kamailio headers found at $path"
            export KAMAILIO_INCLUDE="$path"
            return 0
        fi
    done
    
    return 1
}

# Build locally
build_local() {
    echo "🔨 Building locally..."
    
    # Use the fixed version with system headers
    cp web3_auth_fixed.c web3_auth.c
    
    # Update Makefile if needed
    if [ -n "$KAMAILIO_INCLUDE" ]; then
        sed -i.bak "s|KAMAILIO_PATH.*|KAMAILIO_INCLUDE = $KAMAILIO_INCLUDE|" Makefile
    fi
    
    # Build
    make clean 2>/dev/null || true
    make
    
    echo "✅ Module built successfully: web3_auth.so"
}

# Build with Docker
build_docker() {
    echo "🐳 Building with Docker..."
    
    if ! command -v docker >/dev/null 2>&1; then
        echo "❌ Docker not found. Please install Docker or build on a Linux system with Kamailio dev headers."
        exit 1
    fi
    
    # Build Docker image
    echo "📦 Building Docker image..."
    docker build -t kamailio-web3-builder .
    
    # Run container to build module
    echo "🔨 Building module in container..."
    docker run --rm -v "$(pwd)":/output kamailio-web3-builder
    
    # Check if module was created
    if [ -f "web3_auth.so" ]; then
        echo "✅ Module built successfully with Docker: web3_auth.so"
    else
        echo "❌ Docker build failed"
        exit 1
    fi
}

# Main build logic
main() {
    echo "🔍 Checking build environment..."
    
    case "${1:-auto}" in
        "local")
            if check_local_build; then
                build_local
            else
                echo "❌ Kamailio development headers not found locally"
                echo "💡 Try: $0 docker"
                exit 1
            fi
            ;;
        "docker")
            build_docker
            ;;
        "auto"|*)
            if check_local_build; then
                echo "🎯 Using local build"
                build_local
            else
                echo "🎯 Falling back to Docker build"
                build_docker
            fi
            ;;
    esac
    
    # Final checks
    if [ -f "web3_auth.so" ]; then
        echo ""
        echo "🎉 Build completed successfully!"
        echo "📁 Module file: web3_auth.so"
        echo "📏 File size: $(ls -lh web3_auth.so | awk '{print $5}')"
        echo ""
        echo "📋 Next steps:"
        echo "1. Copy web3_auth.so to your Kamailio modules directory"
        echo "2. Add 'loadmodule \"web3_auth.so\"' to kamailio.cfg"
        echo "3. Configure module parameters"
        echo "4. Use web3_auth_check() in your routes"
        echo ""
        echo "💡 See README.md for detailed deployment instructions"
    else
        echo "❌ Build failed - web3_auth.so not found"
        exit 1
    fi
}

# Show help
show_help() {
    cat << EOF
Kamailio Web3 Auth Module Build Script

Usage: $0 [option]

Options:
  auto    - Auto-detect best build method (default)
  local   - Force local build (requires Kamailio dev headers)
  docker  - Force Docker build (requires Docker)
  help    - Show this help

Examples:
  $0              # Auto-detect and build
  $0 local        # Build locally
  $0 docker       # Build with Docker
  $0 help         # Show help

EOF
}

# Handle command line arguments
case "${1:-auto}" in
    "help"|"-h"|"--help")
        show_help
        ;;
    *)
        main "$1"
        ;;
esac 