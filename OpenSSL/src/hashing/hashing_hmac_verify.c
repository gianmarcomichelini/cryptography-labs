#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/crypto.h>  // for CRYPTO_memcmp
#include "utils.h"
#include "hashing/hashing_utils.h"


// Verify HMAC-SHA256 of message matches expected digest using given key
// Returns 1 if valid, 0 otherwise


int hashing_hmac_sha256_verify(const unsigned char *key, const size_t key_len,
                       const unsigned char *message, size_t message_len,
                       const unsigned char *expected_digest, const size_t expected_digest_len) {

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        hashing_handle_md_errors("ERROR: creating EVP_MD_CTX", NULL);

    EVP_PKEY *pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, (int) key_len);
    if (!pkey) {
        EVP_MD_CTX_free(ctx);
        hashing_handle_md_errors("ERROR: creating EVP_PKEY HMAC key", NULL);
    }

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(ctx);
        hashing_handle_md_errors("ERROR: initializing DigestSignInit", NULL);
    }

    if (EVP_DigestSignUpdate(ctx, message, message_len) != 1) {
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(ctx);
        hashing_handle_md_errors("ERROR: updating DigestSign", NULL);
    }

    unsigned char computed_digest[EVP_MD_size(EVP_sha256())];
    size_t computed_digest_len = EVP_MD_size(EVP_sha256());
    if (EVP_DigestSignFinal(ctx, computed_digest, &computed_digest_len) != 1) {
        OPENSSL_free(computed_digest);
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(ctx);
        hashing_handle_md_errors("ERROR: finalizing DigestSign", NULL);
    }

    const int valid = (computed_digest_len == expected_digest_len) &&
                (CRYPTO_memcmp(computed_digest, expected_digest, computed_digest_len) == 0);

    OPENSSL_free(computed_digest);
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(ctx);

    return valid ? 1 : 0;
}