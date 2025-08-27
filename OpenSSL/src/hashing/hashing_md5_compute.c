#include <openssl/evp.h>
#include "hashing/hashing_utils.h"

/**
 * @brief Computes MD5 hash for a message buffer.
 *
 * @param[in] message Pointer to the input data
 * @param[in] message_len Length of the input data
 * @param[out] out_digest Pointer to store allocated digest buffer (caller must free with OPENSSL_free)
 * @param[out] out_digest_len Pointer to store length of the computed digest
 *
 * @return 0 on success, aborts on error
 *
 * Notes:
 *  - Errors are handled internally via hashing_handle_md_errors().
 */
int hashing_md5_compute(const unsigned char *message, size_t message_len,
                        unsigned char **out_digest, unsigned int *out_digest_len) {

    if (!message || !out_digest || !out_digest_len) {
        fprintf(stderr, "[ERROR] Null pointer passed to hashing_md5_compute.\n");
        return EXIT_FAILURE;
    }

    printf("[INFO] Starting MD5 hash computation...\n");

    // Step 1: Create digest context
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
        hashing_handle_md_errors("[ERROR] Creating digest context", NULL);
    printf("[STEP 1] Digest context created.\n");

    // Step 2: Initialize MD5 digest
    const EVP_MD *hash_function = EVP_md5();
    if (EVP_DigestInit_ex(md_ctx, hash_function, NULL) != 1) {
        EVP_MD_CTX_free(md_ctx);
        hashing_handle_md_errors("[ERROR] Initializing digest context", md_ctx);
    }
    printf("[STEP 2] Digest initialized with MD5.\n");

    // Step 3: Feed message into digest
    if (EVP_DigestUpdate(md_ctx, message, message_len) != 1) {
        EVP_MD_CTX_free(md_ctx);
        hashing_handle_md_errors("[ERROR] Updating digest context", md_ctx);
    }
    printf("[STEP 3] Message data fed into digest.\n");

    // Step 4: Allocate buffer for digest
    unsigned int digest_len = EVP_MD_size(hash_function);
    unsigned char *digest = OPENSSL_malloc(digest_len);
    if (!digest) {
        EVP_MD_CTX_free(md_ctx);
        hashing_handle_md_errors("[ERROR] Allocating memory for digest", md_ctx);
    }
    printf("[STEP 4] Memory allocated for MD5 digest (length: %u bytes).\n", digest_len);

    // Step 5: Finalize digest
    if (EVP_DigestFinal_ex(md_ctx, digest, &digest_len) != 1) {
        OPENSSL_free(digest);
        EVP_MD_CTX_free(md_ctx);
        hashing_handle_md_errors("[ERROR] Finalizing digest", md_ctx);
    }
    printf("[STEP 5] MD5 digest computed successfully.\n");

    // Step 6: Clean up and output
    EVP_MD_CTX_free(md_ctx);
    *out_digest = digest;
    *out_digest_len = digest_len;

    printf("[INFO] MD5 computation complete.\n\n");
    return EXIT_SUCCESS;
}