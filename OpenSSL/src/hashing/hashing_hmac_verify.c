#include <openssl/crypto.h>
#include "utils.h"
#include "hashing/hashing_utils.h"

/**
 * @brief Verifies that a message's HMAC-SHA256 matches the expected digest.
 *
 * @param[in] key Pointer to the HMAC key
 * @param[in] key_len Length of the HMAC key
 * @param[in] message Pointer to the message to verify
 * @param[in] message_len Length of the message
 * @param[in] expected_digest Pointer to the expected HMAC digest
 * @param[in] expected_digest_len Length of the expected digest
 *
 * @return 0 if the computed HMAC matches the expected digest, 1 otherwise
 *
 * Notes:
 *  - Errors are handled internally via hashing_handle_md_errors().
 */
int hashing_hmac_sha256_verify(const unsigned char *key, const size_t key_len,
                               const unsigned char *message, size_t message_len,
                               const unsigned char *expected_digest, const size_t expected_digest_len) {

    if (!key || !message || !expected_digest) {
        fprintf(stderr, "[ERROR] Null pointer passed to hashing_hmac_sha256_verify.\n");
        return EXIT_FAILURE;
    }

    printf("[INFO] Starting HMAC-SHA256 verification...\n");

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        hashing_handle_md_errors("[ERROR] Creating EVP_MD_CTX", NULL);
    printf("[STEP 1] Digest context created.\n");

    EVP_PKEY *pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, (int)key_len);
    if (!pkey) {
        EVP_MD_CTX_free(ctx);
        hashing_handle_md_errors("[ERROR] Creating HMAC key", NULL);
    }
    printf("[STEP 2] HMAC key created.\n");

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(ctx);
        hashing_handle_md_errors("[ERROR] Initializing DigestSignInit", NULL);
    }
    printf("[STEP 3] DigestSign initialized with SHA-256.\n");

    if (EVP_DigestSignUpdate(ctx, message, message_len) != 1) {
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(ctx);
        hashing_handle_md_errors("[ERROR] DigestSignUpdate failed", NULL);
    }
    printf("[STEP 4] Message fed into HMAC context.\n");

    unsigned char computed_digest[EVP_MD_size(EVP_sha256())];
    size_t computed_digest_len = EVP_MD_size(EVP_sha256());
    if (EVP_DigestSignFinal(ctx, computed_digest, &computed_digest_len) != 1) {
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(ctx);
        hashing_handle_md_errors("[ERROR] DigestSignFinal failed", NULL);
    }
    printf("[STEP 5] Computed HMAC-SHA256 (length: %zu bytes).\n", computed_digest_len);

    const int valid = (computed_digest_len == expected_digest_len) &&
                      (CRYPTO_memcmp(computed_digest, expected_digest, computed_digest_len) == 0);
    printf("[STEP 6] HMAC verification %s.\n", valid ? "SUCCESS" : "FAILED");

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(ctx);
    printf("[INFO] HMAC-SHA256 verification completed.\n\n");

    return valid ? EXIT_SUCCESS : EXIT_FAILURE;
}