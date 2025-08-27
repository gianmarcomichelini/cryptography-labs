#include <openssl/rand.h>
#include "hashing/hashing_utils.h"

/**
 * @brief Computes HMAC-SHA256 of a memory buffer using a key.
 *
 * @param[in]  key          Pointer to the HMAC secret key.
 * @param[in]  key_len      Length of the HMAC key in bytes.
 * @param[in]  message      Pointer to the message to authenticate.
 * @param[in]  message_len  Length of the message in bytes.
 * @param[out] out_hmac     Pointer to a buffer pointer where the computed HMAC will be stored.
 *                          The caller is responsible for freeing it using OPENSSL_free().
 * @param[out] out_hmac_len Pointer to store the length of the computed HMAC.
 *
 * @return 0 on success, 1 if any parameter is NULL.
 *
 * Notes:
 *  - Uses OpenSSL EVP interface.
 *  - Errors are handled internally via hashing_handle_md_errors().
 */
int hashing_hmac_sha256_compute(const unsigned char *key, const size_t key_len,
                                const unsigned char *message, const size_t message_len,
                                unsigned char **out_hmac, size_t *out_hmac_len) {

    if (!key || !message || !out_hmac || !out_hmac_len) {
        fprintf(stderr, "[ERROR] Null pointer passed to hashing_hmac_sha256_compute.\n");
        return 1;
    }

    EVP_PKEY *hkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, (int)key_len);
    if (!hkey)
        hashing_handle_md_errors("[ERROR] Creating EVP_PKEY HMAC key", NULL);

    EVP_MD_CTX *hmac_ctx = EVP_MD_CTX_new();
    if (!hmac_ctx) {
        EVP_PKEY_free(hkey);
        hashing_handle_md_errors("[ERROR] Creating EVP_MD_CTX", NULL);
    }

    if (EVP_DigestSignInit(hmac_ctx, NULL, EVP_sha256(), NULL, hkey) != 1 ||
        EVP_DigestSignUpdate(hmac_ctx, message, message_len) != 1) {
        EVP_MD_CTX_free(hmac_ctx);
        EVP_PKEY_free(hkey);
        hashing_handle_md_errors("[ERROR] HMAC initialization/update failed", hmac_ctx);
    }

    size_t hmac_len = 0;
    if (EVP_DigestSignFinal(hmac_ctx, NULL, &hmac_len) != 1) {
        EVP_MD_CTX_free(hmac_ctx);
        EVP_PKEY_free(hkey);
        hashing_handle_md_errors("[ERROR] Determining HMAC length failed", hmac_ctx);
    }

    unsigned char *hmac_value = OPENSSL_malloc(hmac_len);
    if (!hmac_value) {
        EVP_MD_CTX_free(hmac_ctx);
        EVP_PKEY_free(hkey);
        hashing_handle_md_errors("[ERROR] Allocating memory for HMAC failed", hmac_ctx);
    }

    if (EVP_DigestSignFinal(hmac_ctx, hmac_value, &hmac_len) != 1) {
        OPENSSL_free(hmac_value);
        EVP_MD_CTX_free(hmac_ctx);
        EVP_PKEY_free(hkey);
        hashing_handle_md_errors("[ERROR] DigestSignFinal failed", hmac_ctx);
    }

    EVP_MD_CTX_free(hmac_ctx);
    EVP_PKEY_free(hkey);

    *out_hmac = hmac_value;
    *out_hmac_len = hmac_len;

    return 0;
}

/**
 * @brief Computes HMAC-SHA256 of a file using a key.
 *
 * @param[in]  fp           Pointer to an open FILE for reading input data.
 * @param[in]  key          Pointer to the HMAC key.
 * @param[in]  key_len      Length of the HMAC key in bytes.
 * @param[out] hmac_out     Buffer to store the computed HMAC.
 * @param[out] hmac_out_len Pointer to store the length of the computed HMAC.
 *
 * @return 0 on success, 1 if any parameter is NULL.
 *
 * Notes:
 *  - Uses OpenSSL EVP interface.
 *  - Errors are handled internally via hashing_handle_md_errors().
 */
int hashing_hmac_sha256_compute_from_file(FILE *fp,
                                          const unsigned char *key, const size_t key_len,
                                          unsigned char *hmac_out, unsigned int* hmac_out_len) {
    if (!fp || !key || !hmac_out || !hmac_out_len) {
        fprintf(stderr, "[ERROR] Null pointer passed to hashing_hmac_sha256_compute_from_file.\n");
        return 1;
    }

    EVP_PKEY *hmac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, (int)key_len);
    if (!hmac_key)
        hashing_handle_md_errors("[ERROR] Creating HMAC key", NULL);

    EVP_MD_CTX *hmac_ctx = EVP_MD_CTX_new();
    if (!hmac_ctx) {
        EVP_PKEY_free(hmac_key);
        hashing_handle_md_errors("[ERROR] Creating HMAC context", NULL);
    }

    if (EVP_DigestSignInit(hmac_ctx, NULL, EVP_sha256(), NULL, hmac_key) != 1) {
        EVP_MD_CTX_free(hmac_ctx);
        EVP_PKEY_free(hmac_key);
        hashing_handle_md_errors("[ERROR] Initializing HMAC context", hmac_ctx);
    }

    size_t n_bytes;
    unsigned char buf[BUFSIZ];
    while ((n_bytes = fread(buf, 1, BUFSIZ, fp)) > 0) {
        if (EVP_DigestSignUpdate(hmac_ctx, buf, n_bytes) != 1) {
            EVP_MD_CTX_free(hmac_ctx);
            EVP_PKEY_free(hmac_key);
            hashing_handle_md_errors("[ERROR] Updating HMAC context", hmac_ctx);
        }
    }

    if (EVP_DigestSignFinal(hmac_ctx, hmac_out, (size_t*)hmac_out_len) != 1) {
        EVP_MD_CTX_free(hmac_ctx);
        EVP_PKEY_free(hmac_key);
        hashing_handle_md_errors("[ERROR] Finalizing HMAC", hmac_ctx);
    }

    EVP_MD_CTX_free(hmac_ctx);
    EVP_PKEY_free(hmac_key);

    return 0;
}