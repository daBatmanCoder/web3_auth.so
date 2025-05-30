# Web3 Authentication Module for Kamailio

This Kamailio module provides blockchain-based SIP authentication using the Oasis Sapphire testnet. It verifies SIP digest authentication against smart contract stored credentials.

## Features

- **Blockchain Authentication**: Verifies SIP users against smart contract credentials
- **Full Keccak-256 Implementation**: Native computation of Ethereum function selectors
- **Dynamic ABI Encoding**: Handles string parameters with proper padding
- **Configurable RPC**: Supports custom blockchain RPC endpoints
- **Thread-Safe**: Uses proper memory management for concurrent calls

## Prerequisites

- Kamailio development headers
- libcurl development libraries
- GCC compiler
- Make

### Installing Dependencies

#### Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install kamailio-dev libcurl4-openssl-dev build-essential
```

#### CentOS/RHEL:
```bash
sudo yum install kamailio-devel libcurl-devel gcc make
```

## Building the Module

1. **Clone or copy the module files**:
   ```bash
   mkdir kamailio-web3-auth
   cd kamailio-web3-auth
   # Copy web3_auth.c and Makefile here
   ```

2. **Adjust Kamailio paths** (if needed):
   Edit the `Makefile` and set the correct paths:
   ```make
   KAMAILIO_PATH = /path/to/kamailio/source
   KAMAILIO_MODULES_DIR = /path/to/kamailio/modules
   ```

3. **Build the module**:
   ```bash
   make
   ```

4. **Test compilation** (optional):
   ```bash
   make test
   ```

5. **Install the module**:
   ```bash
   make install
   ```

## Configuration

### Module Parameters

Add these parameters to your `kamailio.cfg`:

```
# Load the web3_auth module
loadmodule "web3_auth.so"

# Module parameters
modparam("web3_auth", "rpc_url", "https://testnet.sapphire.oasis.dev")
modparam("web3_auth", "contract_address", "0x1b55e67Ce5118559672Bf9EC0564AE3A46C41000")
```

### Module Functions

#### web3_auth_check()

Verifies SIP digest authentication against blockchain contract.

**Returns**:
- `1`: Authentication successful
- `-1`: Authentication failed

**Usage Example**:

```
route[AUTH] {
    # Check for Authorization header
    if(!is_present_hf("Authorization")) {
        auth_challenge("$fd", "0");
        exit;
    }
    
    # Perform blockchain authentication
    if(web3_auth_check()) {
        xlog("L_INFO", "Blockchain authentication successful for user $fU\n");
        # Continue with call processing
        return;
    } else {
        xlog("L_INFO", "Blockchain authentication failed for user $fU\n");
        sl_send_reply("403", "Forbidden");
        exit;
    }
}
```

## Complete Kamailio Configuration Example

```
#!KAMAILIO

# Basic settings
debug=3
log_stderror=no
log_facility=LOG_LOCAL0
fork=yes
children=4

# Load modules
loadmodule "tm.so"
loadmodule "sl.so"
loadmodule "rr.so"
loadmodule "pv.so"
loadmodule "maxfwd.so"
loadmodule "textops.so"
loadmodule "siputils.so"
loadmodule "xlog.so"
loadmodule "sanity.so"
loadmodule "auth.so"
loadmodule "web3_auth.so"

# Module parameters
modparam("web3_auth", "rpc_url", "https://testnet.sapphire.oasis.dev")
modparam("web3_auth", "contract_address", "0x1b55e67Ce5118559672Bf9EC0564AE3A46C41000")

# Main request routing
request_route {
    # Initial sanity checks
    if (!mf_process_maxfwd_header("10")) {
        sl_send_reply("483", "Too Many Hops");
        exit;
    }
    
    if (!sanity_check()) {
        xlog("Malformed SIP request from $si:$sp\n");
        exit;
    }

    # Handle REGISTER requests
    if (is_method("REGISTER")) {
        route(AUTH);
        route(REGISTRAR);
    }
    
    # Handle other requests...
}

# Authentication route
route[AUTH] {
    if(!is_present_hf("Authorization")) {
        auth_challenge("sip.example.com", "0");
        exit;
    }
    
    # Perform blockchain authentication
    if(web3_auth_check()) {
        xlog("L_INFO", "Web3 authentication successful for $fU@$fd\n");
        return;
    } else {
        xlog("L_INFO", "Web3 authentication failed for $fU@$fd\n");
        sl_send_reply("403", "Forbidden - Invalid blockchain credentials");
        exit;
    }
}

# Registration handling
route[REGISTRAR] {
    if (!save("location")) {
        sl_reply_error();
    }
}
```

## Smart Contract Interface

The module calls the following smart contract function:

```solidity
function getDigestHash(
    string username,
    string realm, 
    string method,
    string uri,
    string nonce
) public view returns (bytes32)
```

### Expected Contract Behavior

- **Success**: Returns a 32-byte hash matching the SIP digest response
- **User Not Found**: Reverts with "User not found" message
- **Other Errors**: Revert with appropriate error message

## Testing

### Test with Sample Data

You can test the module with a SIP client or using `kamctl`:

```bash
# Register a user (replace with your test data)
kamctl add test_user sip.example.com password

# Test with SIP client
# The client should send proper Authorization header with digest authentication
```

### Debug Logging

Enable debug logging in `kamailio.cfg`:

```
debug=4
log_stderror=yes
```

Check logs for authentication flow:
```bash
tail -f /var/log/kamailio.log | grep web3_auth
```

## Troubleshooting

### Common Issues

1. **Module won't load**: Check that libcurl is properly installed and the module path is correct
2. **Compilation errors**: Verify Kamailio development headers are installed
3. **RPC timeouts**: Check network connectivity to blockchain RPC endpoint
4. **Authentication always fails**: Verify contract address and function signature

### Error Messages

- `"Failed to extract authentication components"`: Malformed Authorization header
- `"User not found in blockchain contract"`: Username doesn't exist in smart contract
- `"curl_easy_perform() failed"`: Network error connecting to blockchain RPC
- `"Error encoding call data"`: Memory allocation error

## Development

### Code Structure

- `web3_auth.c`: Main module implementation
- `Makefile`: Build configuration
- `README.md`: Documentation

### Key Functions

- `web3_auth_check()`: Main authentication function called from Kamailio
- `extract_auth_components()`: Parses SIP Authorization header
- `verify_blockchain_auth()`: Handles blockchain RPC call
- `encode_digest_hash_call()`: ABI encoding for smart contract call
- `keccak256()`: Native Keccak-256 implementation

## License

This module is provided as-is for educational and development purposes. Use in production environments should include proper testing and security review.

## Support

For issues and questions:
- Check Kamailio logs for error messages
- Verify blockchain connectivity
- Test with known good credentials
- Review smart contract state and function signatures 