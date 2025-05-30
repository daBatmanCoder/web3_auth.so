# Kamailio Web3 Auth Module - Deployment Guide

## Option 1: Build on Target Server (Recommended)

### Step 1: Copy Files to Server
```bash
# From your Mac, copy the module directory to your Linux server
scp -r kamailio-web3-auth/ user@your-server:/tmp/
```

### Step 2: Install Dependencies on Server
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install kamailio-dev libcurl4-openssl-dev build-essential

# CentOS/RHEL/Rocky
sudo yum install kamailio-devel libcurl-devel gcc make
# or for newer versions:
sudo dnf install kamailio-devel libcurl-devel gcc make
```

### Step 3: Fix Include Paths
Create a fixed version of web3_auth.c with proper system paths:

```bash
cd /tmp/kamailio-web3-auth
```

Then edit web3_auth.c to use system headers instead of relative paths.

### Step 4: Build Module
```bash
# Build the module
make

# Install to Kamailio modules directory
sudo make install

# Or manually copy if make install doesn't work
sudo cp web3_auth.so /usr/lib/x86_64-linux-gnu/kamailio/modules/
# (path may vary: /usr/local/lib/kamailio/modules/ or /usr/lib64/kamailio/modules/)
```

### Step 5: Find Your Module Directory
```bash
# Find where Kamailio modules are installed
find /usr -name "*.so" -path "*/kamailio/modules*" | head -5

# Or check Kamailio config
kamailio -f /etc/kamailio/kamailio.cfg -c | grep "module_path"
```

## Option 2: Build with Docker (Alternative)

If you want to build on your Mac for Linux deployment:

### Step 1: Create Docker Build Environment
```bash
# Create Dockerfile for building
cat > Dockerfile << 'EOF'
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    kamailio-dev \
    libcurl4-openssl-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
RUN make

CMD ["cp", "web3_auth.so", "/output/"]
EOF
```

### Step 2: Build with Docker
```bash
# Build the module using Docker
docker build -t kamailio-web3-builder .
docker run --rm -v $(pwd):/output kamailio-web3-builder

# This creates web3_auth.so in your current directory
```

## Option 3: Manual Header Path Configuration

If you know your Kamailio installation paths, update the Makefile:

```make
# Find Kamailio headers location
KAMAILIO_INCLUDE = /usr/include/kamailio
# or /usr/local/include/kamailio
# or /opt/kamailio/include

# Update include flags
INCLUDES = -I$(KAMAILIO_INCLUDE)
```

## Troubleshooting Common Issues

### Issue 1: "kamailio/sr_module.h not found"
```bash
# Find where Kamailio headers are installed
find /usr -name "sr_module.h" 2>/dev/null

# Update KAMAILIO_PATH in Makefile to the found path
```

### Issue 2: "Cannot find kamailio-dev package"
```bash
# Add Kamailio repository first
sudo apt-get install software-properties-common
sudo add-apt-repository ppa:kamailio/kamailio
sudo apt-get update
sudo apt-get install kamailio-dev
```

### Issue 3: "libcurl not found"
```bash
# Install curl development headers
sudo apt-get install libcurl4-openssl-dev

# Or for older systems
sudo apt-get install libcurl3-dev
```

### Issue 4: Module loads but functions not found
```bash
# Check module exports
nm -D web3_auth.so | grep web3_auth_check

# Verify module loads correctly
kamailio -f kamailio.cfg -c
```

## Testing the Installation

### Step 1: Test Module Loading
```bash
# Test configuration without starting
kamailio -f /etc/kamailio/kamailio.cfg -c

# Should show no errors about web3_auth module
```

### Step 2: Test with Debug
```bash
# Add to kamailio.cfg for testing
debug=4
log_stderror=yes

# Start Kamailio in foreground
sudo kamailio -f /etc/kamailio/kamailio.cfg -D -E
```

### Step 3: Check Logs
```bash
# Monitor Kamailio logs
tail -f /var/log/kamailio.log | grep -i web3

# Should see initialization messages:
# "Web3 Auth module initializing..."
# "Web3 Auth module initialized successfully"
```

## Production Deployment Checklist

- [ ] Dependencies installed (kamailio-dev, libcurl-dev)
- [ ] Module compiled successfully (web3_auth.so created)
- [ ] Module copied to correct Kamailio modules directory
- [ ] Kamailio configuration updated with module load and parameters
- [ ] Configuration syntax checked (`kamailio -c`)
- [ ] Test restart of Kamailio service
- [ ] Monitor logs for any errors
- [ ] Test authentication with SIP client

## Quick Commands Summary

```bash
# On your Mac - copy files
scp -r kamailio-web3-auth/ user@server:/tmp/

# On server - install and build
sudo apt-get install kamailio-dev libcurl4-openssl-dev build-essential
cd /tmp/kamailio-web3-auth
make
sudo cp web3_auth.so /usr/lib/x86_64-linux-gnu/kamailio/modules/
sudo systemctl restart kamailio
``` 