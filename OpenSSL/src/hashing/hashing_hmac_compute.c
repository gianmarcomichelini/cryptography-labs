#include <openssl/rand.h>
#include "hashing/hashing_utils.h"


/**
 * @brief Computes the HMAC-SHA256 of a given message using the provided key.
 *
 * Uses OpenSSL's EVP interface to compute a keyed hash (HMAC) with SHA-256.
 * On failure, the function calls hashing_handle_md_errors() and handles
 * resource cleanup internally.
 *
 * @param[in]  key          Pointer to the HMAC secret key.
 * @param[in]  key_len      Length of the HMAC key in bytes.
 * @param[in]  message      Pointer to the message data to authenticate.
 * @param[in]  message_len  Length of the message in bytes.
 * @param[out] out_hmac     Pointer to a buffer pointer that will be allocated
 *                          and filled with the computed HMAC. The caller must
 *                          free this buffer using OPENSSL_free().
 * @param[out] out_hmac_len Pointer to a size_t variable where the length of the
 *                          generated HMAC will be stored.
 *
 * @return EXIT_SUCCESS on success. Errors are handled internally.
 *
 * @note The caller is responsible for freeing *out_hmac using OPENSSL_free().
 */
int hashing_hmac_sha256_compute(const unsigned char *key, const size_t key_len,
                         const unsigned char *message, const size_t message_len,
                         unsigned char **out_hmac, size_t *out_hmac_len) {
    int rc;

    EVP_PKEY *hkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key,(int) key_len);
    if (!hkey)
        hashing_handle_md_errors("ERROR: creating EVP_PKEY HMAC key", NULL);

    EVP_MD_CTX *hmac_ctx = EVP_MD_CTX_new();
    if (!hmac_ctx) {
        EVP_PKEY_free(hkey);
        hashing_handle_md_errors("ERROR: creating EVP_MD_CTX", NULL);
    }

    rc = EVP_DigestSignInit(hmac_ctx, NULL, EVP_sha256(), NULL, hkey);
    if (rc != 1) {
        EVP_MD_CTX_free(hmac_ctx);
        EVP_PKEY_free(hkey);
        hashing_handle_md_errors("ERROR: initializing DigestSignInit", hmac_ctx);
    }

    rc = EVP_DigestSignUpdate(hmac_ctx, message, message_len);
    if (rc != 1) {
        EVP_MD_CTX_free(hmac_ctx);
        EVP_PKEY_free(hkey);
        hashing_handle_md_errors("ERROR: updating DigestSign", hmac_ctx);
    }

    size_t hmac_len = 0;
    rc = EVP_DigestSignFinal(hmac_ctx, NULL, &hmac_len);
    if (rc != 1) {
        EVP_MD_CTX_free(hmac_ctx);
        EVP_PKEY_free(hkey);
        hashing_handle_md_errors("ERROR: getting HMAC length", hmac_ctx);
    }

    unsigned char *hmac_value = OPENSSL_malloc(hmac_len);
    if (!hmac_value) {
        EVP_MD_CTX_free(hmac_ctx);
        EVP_PKEY_free(hkey);
        hashing_handle_md_errors("ERROR: allocating memory for HMAC", hmac_ctx);
    }

    rc = EVP_DigestSignFinal(hmac_ctx, hmac_value, &hmac_len);
    if (rc != 1) {
        OPENSSL_free(hmac_value);
        EVP_MD_CTX_free(hmac_ctx);
        EVP_PKEY_free(hkey);
        hashing_handle_md_errors("ERROR: finalizing DigestSign", hmac_ctx);
    }

    EVP_MD_CTX_free(hmac_ctx);
    EVP_PKEY_free(hkey);

    *out_hmac = hmac_value;
    *out_hmac_len = hmac_len;

    return EXIT_SUCCESS;
}