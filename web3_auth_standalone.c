/*
 * Standalone Web3 Authentication Module
 * 
 * This is a standalone version of the Kamailio web3 auth module
 * that can be compiled as a shared library (.so) without Kamailio headers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

// Define our own basic types for standalone compilation
#define LM_INFO(fmt, ...) printf("[INFO] " fmt, ##__VA_ARGS__)
#define LM_ERR(fmt, ...) printf("[ERROR] " fmt, ##__VA_ARGS__)
#define LM_DBG(fmt, ...) printf("[DEBUG] " fmt, ##__VA_ARGS__)

// Module configuration
#define DEFAULT_RPC_URL "https://testnet.sapphire.oasis.dev"
#define DEFAULT_CONTRACT_ADDRESS "0x1b55e67Ce5118559672Bf9EC0564AE3A46C41000"
#define MAX_AUTH_HEADER_SIZE 2048
#define MAX_FIELD_SIZE 256

// Global configuration
static char *rpc_url = DEFAULT_RPC_URL;
static char *contract_address = DEFAULT_CONTRACT_ADDRESS;

// Keccak-256 implementation
#define KECCAK_ROUNDS 24

static const uint64_t keccak_round_constants[KECCAK_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int rho_offsets[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const int pi_offsets[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

// Structure to hold SIP digest auth components
typedef struct {
    char username[MAX_FIELD_SIZE];
    char realm[MAX_FIELD_SIZE];
    char uri[MAX_FIELD_SIZE];
    char nonce[MAX_FIELD_SIZE];
    char response[MAX_FIELD_SIZE];
    char method[MAX_FIELD_SIZE];
} sip_auth_t;

// Rotate left function
static inline uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

// Keccak permutation
static void keccak_f1600(uint64_t state[25]) {
    for (int round = 0; round < KECCAK_ROUNDS; round++) {
        // Theta step
        uint64_t C[5];
        for (int i = 0; i < 5; i++) {
            C[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
        }
        
        for (int i = 0; i < 5; i++) {
            uint64_t D = C[(i + 4) % 5] ^ rotl64(C[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) {
                state[j + i] ^= D;
            }
        }
        
        // Rho and Pi steps
        uint64_t current = state[1];
        for (int i = 0; i < 24; i++) {
            int j = pi_offsets[i];
            uint64_t temp = state[j];
            state[j] = rotl64(current, rho_offsets[i]);
            current = temp;
        }
        
        // Chi step
        for (int j = 0; j < 25; j += 5) {
            uint64_t t[5];
            for (int i = 0; i < 5; i++) {
                t[i] = state[j + i];
            }
            for (int i = 0; i < 5; i++) {
                state[j + i] = t[i] ^ ((~t[(i + 1) % 5]) & t[(i + 2) % 5]);
            }
        }
        
        // Iota step
        state[0] ^= keccak_round_constants[round];
    }
}

// Keccak-256 hash function
void keccak256(const uint8_t *input, size_t input_len, uint8_t output[32]) {
    uint64_t state[25] = {0};
    uint8_t *state_bytes = (uint8_t *)state;
    
    // Absorb phase
    size_t rate = 136; // (1600 - 256) / 8 for Keccak-256
    size_t offset = 0;
    
    while (input_len >= rate) {
        for (size_t i = 0; i < rate; i++) {
            state_bytes[i] ^= input[offset + i];
        }
        keccak_f1600(state);
        offset += rate;
        input_len -= rate;
    }
    
    // Final block with remaining input
    for (size_t i = 0; i < input_len; i++) {
        state_bytes[i] ^= input[offset + i];
    }
    
    // Padding
    state_bytes[input_len] ^= 0x01;
    state_bytes[rate - 1] ^= 0x80;
    
    // Final permutation
    keccak_f1600(state);
    
    // Extract output
    memcpy(output, state_bytes, 32);
}

// Calculate function selector from function signature
char* get_function_selector(const char* function_signature) {
    uint8_t hash[32];
    keccak256((const uint8_t*)function_signature, strlen(function_signature), hash);
    
    // Take first 4 bytes and convert to hex string
    char* selector = malloc(11); // "0x" + 8 hex chars + null terminator
    if (!selector) return NULL;
    
    snprintf(selector, 11, "0x%02x%02x%02x%02x", 
             hash[0], hash[1], hash[2], hash[3]);
    
    return selector;
}

// Helper function to pad string to 32-byte boundaries
char* pad_string_data(const char* str, size_t* padded_length) {
    size_t len = strlen(str);
    size_t padded_len = ((len + 31) / 32) * 32; // Round up to nearest 32 bytes
    
    // If empty string, still need at least 32 bytes
    if (padded_len == 0) padded_len = 32;
    
    char* padded = malloc(padded_len * 2 + 1); // *2 for hex, +1 for null terminator
    
    if (!padded) return NULL;
    
    // Initialize with zeros
    memset(padded, '0', padded_len * 2);
    padded[padded_len * 2] = '\0';
    
    // Convert string to hex
    for (size_t i = 0; i < len; i++) {
        sprintf(padded + i * 2, "%02x", (unsigned char)str[i]);
    }
    
    *padded_length = padded_len;
    return padded;
}

// Encode call data for getDigestHash(string,string,string,string,string)
char* encode_digest_hash_call(const char* str1, const char* str2, const char* str3, const char* str4, const char* str5) {
    char* selector = get_function_selector("getDigestHash(string,string,string,string,string)");
    if (!selector) return NULL;
    
    // Calculate lengths and padding for all 5 strings
    size_t len1 = strlen(str1), len2 = strlen(str2), len3 = strlen(str3), len4 = strlen(str4), len5 = strlen(str5);
    size_t padded_len1, padded_len2, padded_len3, padded_len4, padded_len5;
    
    char* padded_str1 = pad_string_data(str1, &padded_len1);
    char* padded_str2 = pad_string_data(str2, &padded_len2);
    char* padded_str3 = pad_string_data(str3, &padded_len3);
    char* padded_str4 = pad_string_data(str4, &padded_len4);
    char* padded_str5 = pad_string_data(str5, &padded_len5);
    
    if (!padded_str1 || !padded_str2 || !padded_str3 || !padded_str4 || !padded_str5) {
        if (selector) free(selector);
        if (padded_str1) free(padded_str1); 
        if (padded_str2) free(padded_str2); 
        if (padded_str3) free(padded_str3); 
        if (padded_str4) free(padded_str4); 
        if (padded_str5) free(padded_str5);
        return NULL;
    }
    
    // Calculate offsets for 5 strings
    size_t offset1 = 0xA0;
    size_t offset2 = offset1 + 32 + padded_len1;
    size_t offset3 = offset2 + 32 + padded_len2;
    size_t offset4 = offset3 + 32 + padded_len3;
    size_t offset5 = offset4 + 32 + padded_len4;
    
    // Calculate total size needed
    size_t total_size = 8 + (64 * 5) + (64 * 5) + strlen(padded_str1) + strlen(padded_str2) + 
                       strlen(padded_str3) + strlen(padded_str4) + strlen(padded_str5) + 1;
    char* call_data = malloc(total_size);
    
    if (!call_data) {
        free(selector);
        free(padded_str1); free(padded_str2); free(padded_str3); 
        free(padded_str4); free(padded_str5);
        return NULL;
    }
    
    snprintf(call_data, total_size,
        "%s"                              // function selector
        "%064lx"                          // offset to string 1
        "%064lx"                          // offset to string 2
        "%064lx"                          // offset to string 3
        "%064lx"                          // offset to string 4
        "%064lx"                          // offset to string 5
        "%064lx%s"                        // length + data for string 1
        "%064lx%s"                        // length + data for string 2
        "%064lx%s"                        // length + data for string 3
        "%064lx%s"                        // length + data for string 4
        "%064lx%s",                       // length + data for string 5
        selector + 2,                     // remove "0x" prefix
        offset1, offset2, offset3, offset4, offset5,
        len1, padded_str1,
        len2, padded_str2,
        len3, padded_str3,
        len4, padded_str4,
        len5, padded_str5);
    
    free(selector);
    free(padded_str1); free(padded_str2); free(padded_str3); 
    free(padded_str4); free(padded_str5);
    
    return call_data;
}

// Test function for the authentication system
int test_web3_auth() {
    LM_INFO("Testing Web3 Authentication Module\n");
    
    // Test Keccak-256
    const char* test_input = "getDigestHash(string,string,string,string,string)";
    uint8_t hash[32];
    keccak256((const uint8_t*)test_input, strlen(test_input), hash);
    
    printf("Function signature: %s\n", test_input);
    printf("Keccak-256 hash: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
    
    // Test function selector
    char* selector = get_function_selector(test_input);
    if (selector) {
        printf("Function selector: %s\n", selector);
        free(selector);
    }
    
    // Test ABI encoding
    char* encoded = encode_digest_hash_call("testuser", "testrealm", "REGISTER", "/", "testnonce");
    if (encoded) {
        printf("Encoded call data (first 100 chars): %.100s...\n", encoded);
        free(encoded);
    }
    
    LM_INFO("Web3 Auth module test completed\n");
    return 1;
}

// Main module initialization function
int web3_auth_init() {
    LM_INFO("Web3 Auth standalone module initializing...\n");
    LM_INFO("RPC URL: %s\n", rpc_url);
    LM_INFO("Contract Address: %s\n", contract_address);
    
    // Run test
    test_web3_auth();
    
    LM_INFO("Web3 Auth standalone module initialized successfully\n");
    return 0;
}

// Module info function (for dynamic loading)
const char* module_info() {
    return "web3_auth standalone module v1.0 - Blockchain SIP authentication";
}

// Export symbol for dynamic loading
__attribute__((constructor))
void module_load() {
    printf("Web3 Auth Module Loaded!\n");
    web3_auth_init();
} 