/*
 * Web3 Authentication Module for Kamailio
 * 
 * This module provides blockchain-based SIP authentication using Oasis Sapphire testnet.
 * It verifies SIP digest authentication against smart contract stored credentials.
 * 
 * Fixed version with system header paths
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <stdint.h>
#include <ctype.h>

// Use system-installed Kamailio headers
#include <kamailio/sr_module.h>
#include <kamailio/dprint.h>
#include <kamailio/mod_fix.h>
#include <kamailio/parser/parse_param.h>
#include <kamailio/parser/digest/digest.h>
#include <kamailio/parser/parse_uri.h>

MODULE_VERSION

// Module configuration
#define DEFAULT_RPC_URL "https://testnet.sapphire.oasis.dev"
#define DEFAULT_CONTRACT_ADDRESS "0x1b55e67Ce5118559672Bf9EC0564AE3A46C41000"
#define MAX_AUTH_HEADER_SIZE 2048
#define MAX_FIELD_SIZE 256

// Module parameters
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

// Structure to hold response data
struct ResponseData {
    char *memory;
    size_t size;
};

// Function prototypes
static int mod_init(void);
static void mod_destroy(void);
static int web3_auth_check(struct sip_msg* msg, char* p1, char* p2);

// Module exports
static cmd_export_t cmds[] = {
    {"web3_auth_check", (cmd_function)web3_auth_check, 0, 0, 0, REQUEST_ROUTE},
    {0, 0, 0, 0, 0, 0}
};

static param_export_t params[] = {
    {"rpc_url", PARAM_STRING, &rpc_url},
    {"contract_address", PARAM_STRING, &contract_address},
    {0, 0, 0}
};

struct module_exports exports = {
    "web3_auth",        /* module name */
    DEFAULT_DLFLAGS,    /* dlopen flags */
    cmds,               /* exported functions */
    params,             /* exported parameters */
    0,                  /* RPC methods */
    0,                  /* exported pseudo-variables */
    0,                  /* response function */
    mod_init,           /* module initialization function */
    0,                  /* per child init function */
    mod_destroy         /* destroy function */
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
    char* selector = pkg_malloc(11); // "0x" + 8 hex chars + null terminator
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
    
    char* padded = pkg_malloc(padded_len * 2 + 1); // *2 for hex, +1 for null terminator
    
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
        if (selector) pkg_free(selector);
        if (padded_str1) pkg_free(padded_str1); 
        if (padded_str2) pkg_free(padded_str2); 
        if (padded_str3) pkg_free(padded_str3); 
        if (padded_str4) pkg_free(padded_str4); 
        if (padded_str5) pkg_free(padded_str5);
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
    char* call_data = pkg_malloc(total_size);
    
    if (!call_data) {
        pkg_free(selector);
        pkg_free(padded_str1); pkg_free(padded_str2); pkg_free(padded_str3); 
        pkg_free(padded_str4); pkg_free(padded_str5);
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
    
    pkg_free(selector);
    pkg_free(padded_str1); pkg_free(padded_str2); pkg_free(padded_str3); 
    pkg_free(padded_str4); pkg_free(padded_str5);
    
    return call_data;
}

// Callback function to write response data
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, struct ResponseData *response) {
    size_t realsize = size * nmemb;
    char *ptr = pkg_realloc(response->memory, response->size + realsize + 1);
    
    if (!ptr) {
        LM_ERR("Not enough memory (realloc returned NULL)\n");
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
    char *result = pkg_malloc(len + 1);
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

// Extract auth components from Authorization header
int extract_auth_components(struct sip_msg* msg, sip_auth_t* auth) {
    struct hdr_field* hf;
    auth_body_t* cred;
    
    // Parse all headers
    if (parse_headers(msg, HDR_EOH_F, 0) < 0) {
        LM_ERR("Failed to parse headers\n");
        return -1;
    }
    
    // Find Authorization header
    for (hf = msg->headers; hf; hf = hf->next) {
        if (hf->type == HDR_AUTHORIZATION_T) {
            break;
        }
    }
    
    if (!hf) {
        LM_ERR("No Authorization header found\n");
        return -1;
    }
    
    // Parse digest credentials
    if (parse_credentials(hf) < 0) {
        LM_ERR("Failed to parse authorization header\n");
        return -1;
    }
    
    cred = (auth_body_t*)hf->parsed;
    if (!cred) {
        LM_ERR("No credentials in authorization header\n");
        return -1;
    }
    
    // Extract username
    if (cred->digest.username.s && cred->digest.username.len < MAX_FIELD_SIZE) {
        memcpy(auth->username, cred->digest.username.s, cred->digest.username.len);
        auth->username[cred->digest.username.len] = '\0';
    } else {
        LM_ERR("Invalid or missing username\n");
        return -1;
    }
    
    // Extract realm
    if (cred->digest.realm.s && cred->digest.realm.len < MAX_FIELD_SIZE) {
        memcpy(auth->realm, cred->digest.realm.s, cred->digest.realm.len);
        auth->realm[cred->digest.realm.len] = '\0';
    } else {
        LM_ERR("Invalid or missing realm\n");
        return -1;
    }
    
    // Extract URI
    if (cred->digest.uri.s && cred->digest.uri.len < MAX_FIELD_SIZE) {
        memcpy(auth->uri, cred->digest.uri.s, cred->digest.uri.len);
        auth->uri[cred->digest.uri.len] = '\0';
    } else {
        LM_ERR("Invalid or missing URI\n");
        return -1;
    }
    
    // Extract nonce
    if (cred->digest.nonce.s && cred->digest.nonce.len < MAX_FIELD_SIZE) {
        memcpy(auth->nonce, cred->digest.nonce.s, cred->digest.nonce.len);
        auth->nonce[cred->digest.nonce.len] = '\0';
    } else {
        LM_ERR("Invalid or missing nonce\n");
        return -1;
    }
    
    // Extract response
    if (cred->digest.response.s && cred->digest.response.len < MAX_FIELD_SIZE) {
        memcpy(auth->response, cred->digest.response.s, cred->digest.response.len);
        auth->response[cred->digest.response.len] = '\0';
    } else {
        LM_ERR("Invalid or missing response\n");
        return -1;
    }
    
    // Get method from SIP message
    if (msg->first_line.u.request.method.len < MAX_FIELD_SIZE) {
        memcpy(auth->method, msg->first_line.u.request.method.s, msg->first_line.u.request.method.len);
        auth->method[msg->first_line.u.request.method.len] = '\0';
    } else {
        strcpy(auth->method, "REGISTER"); // Default
    }
    
    LM_INFO("Extracted auth components: user=%s, realm=%s, method=%s\n", 
            auth->username, auth->realm, auth->method);
    
    return 0;
}

// Verify authentication against blockchain
int verify_blockchain_auth(const sip_auth_t* auth) {
    CURL *curl;
    CURLcode res;
    struct ResponseData response = {0};
    int auth_result = -1; // Default to error
    
    LM_INFO("Calling blockchain for user %s\n", auth->username);
    
    // Encode call data (username, realm, method, uri, nonce)
    char* call_data = encode_digest_hash_call(auth->username, auth->realm, auth->method, auth->uri, auth->nonce);
    if (!call_data) {
        LM_ERR("Error encoding call data\n");
        return -1;
    }
    
    // Initialize curl
    curl = curl_easy_init();
    if (!curl) {
        LM_ERR("Failed to initialize curl\n");
        pkg_free(call_data);
        return -1;
    }
    
    // Prepare JSON-RPC payload
    char *payload = pkg_malloc(8192);
    if (!payload) {
        LM_ERR("Failed to allocate payload memory\n");
        curl_easy_cleanup(curl);
        pkg_free(call_data);
        return -1;
    }
    
    snprintf(payload, 8192,
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"to\":\"%s\",\"data\":\"0x%s\"},\"latest\"],\"id\":1}",
        contract_address, call_data);
    
    // Set curl options
    curl_easy_setopt(curl, CURLOPT_URL, rpc_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L); // 10 second timeout
    
    // Set headers
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    // Perform the request
    res = curl_easy_perform(curl);
    
    if (res == CURLE_OK) {
        LM_DBG("Blockchain response: %s\n", response.memory);
        
        // Check for error in response
        if (strstr(response.memory, "\"error\"")) {
            if (strstr(response.memory, "User not found")) {
                LM_INFO("User %s not found in blockchain contract\n", auth->username);
            } else {
                LM_ERR("Error from blockchain contract\n");
            }
            auth_result = -1;
        } else {
            // Extract result
            char *result_hex = extract_result(response.memory);
            if (result_hex) {
                // Strip trailing zeros (take first 32 hex chars)
                char expected_response[64];
                strip_trailing_zeros(result_hex, expected_response, sizeof(expected_response));
                
                LM_INFO("Expected response: %s, Actual response: %s\n", 
                        expected_response, auth->response);
                
                // Compare responses
                if (strcmp(expected_response, auth->response) == 0) {
                    LM_INFO("Blockchain authentication successful for user %s\n", auth->username);
                    auth_result = 1; // Success
                } else {
                    LM_INFO("Blockchain authentication failed for user %s - response mismatch\n", auth->username);
                    auth_result = -1;
                }
                
                pkg_free(result_hex);
            } else {
                LM_ERR("Could not extract result from blockchain response\n");
                auth_result = -1;
            }
        }
        
        if (response.memory) pkg_free(response.memory);
    } else {
        LM_ERR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        auth_result = -1;
    }
    
    // Cleanup
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    pkg_free(call_data);
    pkg_free(payload);
    
    return auth_result;
}

// Main function called from Kamailio config
static int web3_auth_check(struct sip_msg* msg, char* p1, char* p2) {
    sip_auth_t auth = {0};
    int result;
    
    LM_INFO("Web3 authentication check started\n");
    
    // Extract authentication components from SIP message
    if (extract_auth_components(msg, &auth) < 0) {
        LM_ERR("Failed to extract authentication components\n");
        return -1;
    }
    
    // Verify against blockchain
    result = verify_blockchain_auth(&auth);
    
    if (result == 1) {
        LM_INFO("Web3 authentication successful for user %s\n", auth.username);
        return 1; // Success
    } else {
        LM_INFO("Web3 authentication failed for user %s\n", auth.username);
        return -1; // Failure
    }
}

// Module initialization
static int mod_init(void) {
    LM_INFO("Web3 Auth module initializing...\n");
    LM_INFO("RPC URL: %s\n", rpc_url);
    LM_INFO("Contract Address: %s\n", contract_address);
    
    // Initialize curl globally
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        LM_ERR("Failed to initialize curl globally\n");
        return -1;
    }
    
    LM_INFO("Web3 Auth module initialized successfully\n");
    return 0;
}

// Module cleanup
static void mod_destroy(void) {
    LM_INFO("Web3 Auth module destroying...\n");
    
    // Cleanup curl globally
    curl_global_cleanup();
    
    LM_INFO("Web3 Auth module destroyed\n");
} 