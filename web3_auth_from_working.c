/*
 * Web3 Authentication Module for Kamailio
 * Based on working oasis_sip_auth.c
 * Provides blockchain-based SIP authentication using Oasis Sapphire testnet
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <stdint.h>
#include <ctype.h>

#define RPC_URL "https://testnet.sapphire.oasis.dev"
#define CONTRACT_ADDRESS "0x1b55e67Ce5118559672Bf9EC0564AE3A46C41000"
#define MAX_AUTH_HEADER_SIZE 2048
#define MAX_FIELD_SIZE 256

// Minimal Kamailio structures (just what we need)
struct sip_msg;

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

// URL decode function (simple implementation)
void url_decode(const char* src, char* dest, size_t dest_size) {
    size_t src_len = strlen(src);
    size_t dest_idx = 0;
    
    for (size_t i = 0; i < src_len && dest_idx < dest_size - 1; i++) {
        if (src[i] == '%' && i + 2 < src_len) {
            // Convert hex to char
            char hex[3] = {src[i+1], src[i+2], '\0'};
            dest[dest_idx++] = (char)strtol(hex, NULL, 16);
            i += 2; // Skip the hex digits
        } else if (src[i] == '+') {
            dest[dest_idx++] = ' '; // + becomes space
        } else {
            dest[dest_idx++] = src[i];
        }
    }
    dest[dest_idx] = '\0';
}

// Extract field value from auth header using simple string search
int extract_field(const char* auth_header, const char* field_name, char* output, size_t output_size) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "%s=\"", field_name);
    
    char* start = strstr(auth_header, pattern);
    if (!start) return 0; // Field not found
    
    start += strlen(pattern); // Move past the pattern
    char* end = strchr(start, '"');
    if (!end) return 0; // No closing quote
    
    size_t field_len = end - start;
    if (field_len >= output_size) field_len = output_size - 1;
    
    memcpy(output, start, field_len);
    output[field_len] = '\0';
    
    return 1; // Success
}

// Parse SIP digest auth header
int parse_auth_header(const char* auth_header, sip_auth_t* auth) {
    char decoded_header[MAX_AUTH_HEADER_SIZE];
    
    // Decode URL-encoded header
    url_decode(auth_header, decoded_header, sizeof(decoded_header));
    printf("📋 Decoded auth header: %s\n", decoded_header);
    
    // Extract required fields
    if (!extract_field(decoded_header, "username", auth->username, sizeof(auth->username))) {
        printf("❌ Failed to extract username\n");
        return 0;
    }
    
    if (!extract_field(decoded_header, "realm", auth->realm, sizeof(auth->realm))) {
        printf("❌ Failed to extract realm\n");
        return 0;
    }
    
    if (!extract_field(decoded_header, "uri", auth->uri, sizeof(auth->uri))) {
        printf("❌ Failed to extract uri\n");
        return 0;
    }
    
    if (!extract_field(decoded_header, "nonce", auth->nonce, sizeof(auth->nonce))) {
        printf("❌ Failed to extract nonce\n");
        return 0;
    }
    
    if (!extract_field(decoded_header, "response", auth->response, sizeof(auth->response))) {
        printf("❌ Failed to extract response\n");
        return 0;
    }
    
    // Set default method if not provided
    strcpy(auth->method, "REGISTER");
    
    printf("✅ Parsed auth components:\n");
    printf("   Username: %s\n", auth->username);
    printf("   Realm: %s\n", auth->realm);
    printf("   URI: %s\n", auth->uri);
    printf("   Nonce: %s\n", auth->nonce);
    printf("   Response: %s\n", auth->response);
    printf("   Method: %s\n", auth->method);
    
    return 1; // Success
}

// Helper function to pad string to 32-byte boundaries
char* pad_string_data(const char* str, size_t* padded_length) {
    size_t len = strlen(str);
    size_t padded_len = ((len + 31) / 32) * 32; // Round up to nearest 32 bytes
    
    // If empty string, still need at least 32 bytes
    if (padded_len == 0) padded_len = 32;
    
    char* padded = calloc(1, padded_len * 2 + 1); // *2 for hex, +1 for null terminator
    
    if (!padded) return NULL;
    
    // Convert string to hex and pad the rest with zeros
    for (size_t i = 0; i < len; i++) {
        sprintf(padded + i * 2, "%02x", (unsigned char)str[i]);
    }
    
    // Fill the rest with zeros up to padded_len * 2 characters
    for (size_t i = len * 2; i < padded_len * 2; i++) {
        padded[i] = '0';
    }
    
    // Ensure null termination
    padded[padded_len * 2] = '\0';
    
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
        free(selector);
        free(padded_str1); free(padded_str2); free(padded_str3); free(padded_str4); free(padded_str5);
        return NULL;
    }
    
    // Calculate offsets for 5 strings
    // selector(4) + 5 offset words(32*5) = start at 0xA0 (160 bytes)
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
        free(padded_str1); free(padded_str2); free(padded_str3); free(padded_str4); free(padded_str5);
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
    free(padded_str1); free(padded_str2); free(padded_str3); free(padded_str4); free(padded_str5);
    
    return call_data;
}

// Structure to hold response data
struct ResponseData {
    char *memory;
    size_t size;
};

// Callback function to write response data
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, struct ResponseData *response) {
    size_t realsize = size * nmemb;
    char *ptr = realloc(response->memory, response->size + realsize + 1);
    
    if (!ptr) {
        printf("Not enough memory (realloc returned NULL)\n");
        return 0;
    }
    
    response->memory = ptr;
    memcpy(&(response->memory[response->size]), contents, realsize);
    response->size += realsize;
    response->memory[response->size] = 0;
    
    return realsize;
}

// Extract result from JSON response
char *extract_result(const char *json) {
    const char *pattern = "\"result\":\"";
    char *result_start = strstr(json, pattern);
    if (!result_start) return NULL;
    
    result_start += strlen(pattern);
    char *result_end = strchr(result_start, '"');
    if (!result_end) return NULL;
    
    size_t len = result_end - result_start;
    char *result = malloc(len + 1);
    if (!result) return NULL;
    
    memcpy(result, result_start, len);
    result[len] = '\0';
    return result;
}

// Strip trailing zeros from hash result (take first 32 hex chars)
void strip_trailing_zeros(const char* hex_result, char* stripped, size_t stripped_size) {
    if (!hex_result || strlen(hex_result) < 66) {
        strcpy(stripped, "");
        return;
    }
    
    // Skip "0x" prefix and take first 32 hex characters
    size_t copy_len = 32;
    if (copy_len >= stripped_size) copy_len = stripped_size - 1;
    
    memcpy(stripped, hex_result + 2, copy_len);
    stripped[copy_len] = '\0';
}

// Make RPC call to get digest hash and verify authentication
int verify_sip_auth(const sip_auth_t* auth) {
    CURL *curl;
    CURLcode res;
    struct ResponseData response = {0};
    
    printf("\n🔐 Calling getDigestHash for SIP authentication\n");
    printf("Parameters: username=%s, realm=%s, method=%s, uri=%s, nonce=%s\n", 
           auth->username, auth->realm, auth->method, auth->uri, auth->nonce);
    
    // Encode call data (username, realm, method, uri, nonce)
    char* call_data = encode_digest_hash_call(auth->username, auth->realm, auth->method, auth->uri, auth->nonce);
    if (!call_data) {
        printf("❌ Error encoding call data\n");
        return 403;
    }
    
    // Initialize curl
    curl = curl_easy_init();
    if (!curl) {
        printf("❌ Failed to initialize curl\n");
        free(call_data);
        return 403;
    }
    
    // Prepare JSON-RPC payload
    char payload[8192];
    snprintf(payload, sizeof(payload),
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"to\":\"%s\",\"data\":\"0x%s\"},\"latest\"],\"id\":1}",
        CONTRACT_ADDRESS, call_data);
    
    // Set curl options
    curl_easy_setopt(curl, CURLOPT_URL, RPC_URL);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    
    // Set headers
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    // Perform the request
    res = curl_easy_perform(curl);
    
    int auth_result = 403; // Default to forbidden
    
    if (res == CURLE_OK) {
        printf("📡 Blockchain response: %s\n", response.memory);
        
        // Check for error in response
        if (strstr(response.memory, "\"error\"")) {
            if (strstr(response.memory, "User not found")) {
                printf("❌ User not found in contract - authorization rejected\n");
            } else {
                printf("❌ Error getting digest hash from contract\n");
            }
            auth_result = 403;
        } else {
            // Extract result
            char *result_hex = extract_result(response.memory);
            if (result_hex) {
                printf("🔐 Raw result: %s\n", result_hex);
                
                // Strip trailing zeros (take first 32 hex chars)
                char expected_response[64];
                strip_trailing_zeros(result_hex, expected_response, sizeof(expected_response));
                
                printf("✅ Expected response from contract (stripped): %s\n", expected_response);
                printf("📱 Actual response from client: %s\n", auth->response);
                
                // Compare responses
                if (strcmp(expected_response, auth->response) == 0) {
                    printf("🎉 Authorization successful - responses match!\n");
                    auth_result = 200;
                } else {
                    printf("❌ Authorization failed - response mismatch\n");
                    auth_result = 403;
                }
                
                free(result_hex);
            } else {
                printf("❌ Could not extract result from blockchain response\n");
                auth_result = 403;
            }
        }
        
        free(response.memory);
    } else {
        printf("❌ curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        auth_result = 403;
    }
    
    // Cleanup
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(call_data);
    
    return auth_result;
}

// Function that Kamailio will call - takes auth header as parameter
static int web3_auth_check_func(struct sip_msg* msg, char* auth_header_param, char* p2) {
    printf("=== Web3 Authentication Check ===\n");
    
    // For now, use a test auth header if no parameter provided
    // TODO: In real implementation, extract from SIP message headers
    const char* test_auth_header = "username=\"testuser\",realm=\"sip.example.com\",uri=\"sip:sip.example.com\",nonce=\"1234567890abcdef\",response=\"1a2b3c4d5e6f7890\"";
    
    const char* auth_header_input = auth_header_param ? auth_header_param : test_auth_header;
    
    printf("📋 Auth header: %s\n", auth_header_input);
    
    // Parse the auth header
    sip_auth_t auth = {0};
    if (!parse_auth_header(auth_header_input, &auth)) {
        printf("❌ Failed to parse auth header\n");
        return -1; // Kamailio failure
    }
    
    // Verify authentication against blockchain
    int result = verify_sip_auth(&auth);
    
    printf("\n🏁 Final result: %d (%s)\n", result, result == 200 ? "AUTHORIZED" : "FORBIDDEN");
    
    // Return Kamailio-style result: 1 = success, -1 = failure
    return (result == 200) ? 1 : -1;
}

// Module command structure (minimal)
typedef struct cmd_export {
    char* name;
    void* function;
    int param_no;
    void* fixup;
    void* free_fixup;
    int flags;
} cmd_export_t;

// Parameter structure (minimal)
typedef struct param_export {
    char* name;
    int type;
    void* param_ptr;
} param_export_t;

// Module exports structure (minimal)
struct module_exports {
    char* name;
    unsigned int dlflags;
    cmd_export_t* cmds;
    param_export_t* params;
    void* stats;
    void* mi_cmds;
    void* pv_items;
    void* response_f;
    void* init_f;
    void* child_init_f;
    void* destroy_f;
};

// Module initialization
static int module_init() {
    printf("🚀 Web3 Auth module initializing...\n");
    
    // Initialize curl globally
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        printf("❌ Failed to initialize curl globally\n");
        return -1;
    }
    
    printf("✅ Web3 Auth module initialized successfully\n");
    return 0;
}

// Module cleanup
static void module_destroy() {
    printf("🧹 Web3 Auth module destroying...\n");
    
    // Cleanup curl globally
    curl_global_cleanup();
    
    printf("✅ Web3 Auth module destroyed\n");
}

// Module exports
static cmd_export_t cmds[] = {
    {"web3_auth_check", (void*)web3_auth_check_func, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0}
};

static param_export_t params[] = {
    {0, 0, 0}
};

struct module_exports exports = {
    "web3_auth",        /* module name */
    0,                  /* dlopen flags */
    cmds,               /* exported functions */
    params,             /* exported parameters */
    0,                  /* exported stats */
    0,                  /* exported MI functions */
    0,                  /* exported pseudo-variables */
    0,                  /* response function */
    module_init,        /* module initialization function */
    0,                  /* per child init function */
    module_destroy      /* destroy function */
};

// Module info function
const char* module_info() {
    return "web3_auth blockchain authentication module v1.0 - based on working oasis_sip_auth.c";
} 