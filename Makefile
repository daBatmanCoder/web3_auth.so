# Web3 Authentication Module Makefile

# Module name
MODULE_NAME = web3_auth

# Source files
SOURCES = web3_auth.c

# Include directories (adjust path based on your Kamailio installation)
KAMAILIO_PATH ?= /usr/src/kamailio
KAMAILIO_INCLUDE = $(KAMAILIO_PATH)

# Compiler and flags
CC = gcc
CFLAGS = -fPIC -Wall -Wextra -O2 -g
INCLUDES = -I$(KAMAILIO_INCLUDE)
LIBS = -lcurl

# Module shared library
MODULE_SO = $(MODULE_NAME).so

# Default target
all: $(MODULE_SO)

# Build the shared library
$(MODULE_SO): $(SOURCES)
	$(CC) $(CFLAGS) $(INCLUDES) -shared -o $@ $< $(LIBS)

# Clean target
clean:
	rm -f $(MODULE_SO) *.o

# Install target (adjust path based on your Kamailio modules directory)
KAMAILIO_MODULES_DIR ?= /usr/lib/x86_64-linux-gnu/kamailio/modules
install: $(MODULE_SO)
	sudo cp $(MODULE_SO) $(KAMAILIO_MODULES_DIR)/

# Test compilation without linking
test:
	$(CC) $(CFLAGS) $(INCLUDES) -c $(SOURCES) -o web3_auth.o

# Show help
help:
	@echo "Available targets:"
	@echo "  all      - Build the module (default)"
	@echo "  clean    - Remove built files"
	@echo "  install  - Install module to Kamailio modules directory"
	@echo "  test     - Test compilation only"
	@echo "  help     - Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  KAMAILIO_PATH        - Path to Kamailio source (default: /usr/src/kamailio)"
	@echo "  KAMAILIO_MODULES_DIR - Kamailio modules directory (default: /usr/lib/x86_64-linux-gnu/kamailio/modules)"

.PHONY: all clean install test help 