//
// Created by gim on 11/08/25.
//


#include "utils.h"
#include "hashing/hashing_utils.h"

int hashing_hmac_sha256_compute_from_file(FILE *fp,
                                          const unsigned char *key, const size_t key_len,
                                          unsigned char *hmac_out, unsigned int* hmac_out_len) {
    int rc;

    EVP_PKEY *hmac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, (int) key_len);
    if (!hmac_key) {
        hashing_handle_md_errors("ERROR: creating HMAC key", NULL);
    }

    EVP_MD_CTX *hmac_ctx = EVP_MD_CTX_new();
    if (!hmac_ctx) {
        EVP_PKEY_free(hmac_key);
        hashing_handle_md_errors("ERROR: creating context", NULL);
    }

    rc = EVP_DigestSignInit(hmac_ctx, NULL, EVP_sha256(), NULL, hmac_key);
    if (rc != 1) {
        EVP_MD_CTX_free(hmac_ctx);
        EVP_PKEY_free(hmac_key);
        hashing_handle_md_errors("ERROR: initializing context", NULL);
    }

    size_t n_bytes;
    unsigned char buf[BUFSIZ];

    while ((n_bytes = fread(buf, 1, BUFSIZ, fp)) > 0) {
        rc = EVP_DigestSignUpdate(hmac_ctx, buf, n_bytes);
        if (rc != 1) {
            EVP_MD_CTX_free(hmac_ctx);
            EVP_PKEY_free(hmac_key);
            hashing_handle_md_errors("ERROR: updating context", hmac_ctx);
        }
    }

    rc = EVP_DigestSignFinal(hmac_ctx, hmac_out, (size_t*) hmac_out_len);
    if (rc != 1) {
        EVP_MD_CTX_free(hmac_ctx);
        EVP_PKEY_free(hmac_key);
        hashing_handle_md_errors("ERROR: finalizing context", hmac_ctx);
    }

    EVP_MD_CTX_free(hmac_ctx);
    EVP_PKEY_free(hmac_key);
    return 1;
}