//
// Created by gim on 11/08/25.
//

#include <ctype.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * @brief Handles fatal errors in hashing operations.
 *
 * Prints the error message, frees the digest context if provided, and aborts.
 *
 * @param err Message describing the error.
 * @param ctx EVP_MD_CTX pointer to free (can be NULL).
 */
__attribute__((noreturn))
void hashing_handle_md_errors(const char *err, EVP_MD_CTX *ctx) {
    fprintf(stderr, "\n[ERROR] %s\n", err);
    if (ctx) {
        printf("[INFO] Freeing EVP_MD_CTX at %p\n", (void *) ctx);
        EVP_MD_CTX_free(ctx);
    }
    abort();
}

/**
 * @brief Prints basic information about a given EVP_MD_CTX context.
 *
 * Displays pointer address, digest algorithm, and digest size.
 *
 * @param ctx EVP_MD_CTX pointer (can be NULL).
 */
void hashing_print_context_info(EVP_MD_CTX *ctx) {
    printf("[INFO] Printing digest context information:\n");

    if (!ctx) {
        printf("\tContext is NULL.\n");
        return;
    }

    printf("\tContext pointer: %p\n", (void *) ctx);

    const EVP_MD *md = EVP_MD_CTX_get0_md(ctx);
    if (md) {
        printf("\tDigest algorithm: %s\n", EVP_MD_name(md));
        printf("\tDigest size: %d bytes\n\n", EVP_MD_size(md));
    } else {
        printf("\tNo digest algorithm set in this context.\n\n");
    }
}