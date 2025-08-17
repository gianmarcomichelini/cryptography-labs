#include <openssl/evp.h>
#include "hashing/hashing_utils.h"
// Computes MD5 hash for the given message buffer.
// Parameters:
// - message: pointer to the input data
// - message_len: length of the input data
// - out_digest: pointer to store allocated digest buffer (caller must free)
// - out_digest_len: pointer to store the length of the digest
// Returns EXIT_SUCCESS on success, otherwise handles errors internally.
int hashing_md5_compute(const unsigned char *message, size_t message_len, unsigned char **out_digest, unsigned int *out_digest_len) {
    int rc;
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
        hashing_handle_md_errors("ERROR: creation of digest context", NULL);

    const EVP_MD *hash_function = EVP_md5();
    rc = EVP_DigestInit_ex(md_ctx, hash_function, NULL);
    if (rc != 1) {
        EVP_MD_CTX_free(md_ctx);
        hashing_handle_md_errors("ERROR: initializing the digest context", md_ctx);
    }

    rc = EVP_DigestUpdate(md_ctx, message, message_len);
    if (rc != 1) {
        EVP_MD_CTX_free(md_ctx);
        hashing_handle_md_errors("ERROR: updating the digest context", md_ctx);
    }

    unsigned int digest_len = EVP_MD_size(hash_function);
    unsigned char *digest = OPENSSL_malloc(digest_len);
    if (!digest) {
        EVP_MD_CTX_free(md_ctx);
        hashing_handle_md_errors("ERROR: Allocating memory for the digest", md_ctx);
    }

    rc = EVP_DigestFinal_ex(md_ctx, digest, &digest_len);
    if (rc != 1) {
        OPENSSL_free(digest);
        EVP_MD_CTX_free(md_ctx);
        hashing_handle_md_errors("ERROR: Storing the context output in the digest", md_ctx);
    }

    EVP_MD_CTX_free(md_ctx);

    *out_digest = digest;
    *out_digest_len = digest_len;

    return EXIT_SUCCESS;
}