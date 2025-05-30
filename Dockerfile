FROM ubuntu:20.04

# Avoid interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    software-properties-common \
    wget \
    gnupg2 \
    && rm -rf /var/lib/apt/lists/*

# Add Kamailio repository
RUN wget -O- https://packages.kamailio.org/kamailio54_key.asc | apt-key add - \
    && echo "deb http://packages.kamailio.org/ubuntu focal main" > /etc/apt/sources.list.d/kamailio.list

# Install Kamailio development packages and build tools
RUN apt-get update && apt-get install -y \
    kamailio-dev \
    libcurl4-openssl-dev \
    build-essential \
    gcc \
    make \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy source files
COPY web3_auth_fixed.c web3_auth.c
COPY Makefile .

# Update Makefile for system headers
RUN sed -i 's|KAMAILIO_PATH.*|KAMAILIO_INCLUDE = /usr/include/kamailio|' Makefile

# Build the module
RUN make

# Create output directory
RUN mkdir -p /output

# Copy the built module to output
CMD ["cp", "web3_auth.so", "/output/"] 