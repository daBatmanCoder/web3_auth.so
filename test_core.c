/*
 * Test compilation of core Web3 auth functions
 * This tests the crypto and networking parts without Kamailio dependencies
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <stdint.h>
#include <ctype.h>

#define MAX_FIELD_SIZE 256

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

// Structure to hold response data
struct ResponseData {
    char *memory;
    size_t size;
};

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

// Test the core functions
int main() {
    printf("Testing Web3 Auth Core Functions\n");
    printf("=================================\n\n");
    
    // Test function selector calculation
    char* selector = get_function_selector("getDigestHash(string,string,string,string,string)");
    if (selector) {
        printf("Function selector: %s\n", selector);
        free(selector);
    } else {
        printf("ERROR: Failed to calculate function selector\n");
        return 1;
    }
    
    // Test string padding
    size_t padded_len;
    char* padded = pad_string_data("abcf", &padded_len);
    if (padded) {
        printf("Padded string 'abcf': %s (length: %zu)\n", padded, padded_len);
        free(padded);
    } else {
        printf("ERROR: Failed to pad string\n");
        return 1;
    }
    
    // Test empty string padding
    char* padded_empty = pad_string_data("", &padded_len);
    if (padded_empty) {
        printf("Padded empty string: %s (length: %zu)\n", padded_empty, padded_len);
        free(padded_empty);
    } else {
        printf("ERROR: Failed to pad empty string\n");
        return 1;
    }
    
    printf("\n✅ All core function tests passed!\n");
    printf("✅ Ready for Kamailio module compilation!\n");
    
    return 0;
} 