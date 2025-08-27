#include "utils.h"
#include "bignum/bignum_utils.h"

/**
 * @brief Creates a new BIGNUM context.
 *
 * @param[out] bn Pointer to a BIGNUM pointer that will be allocated.
 *
 * @return 0 on success, 1 on failure (e.g., memory allocation failure).
 */
int bignum_create_context(BIGNUM **bn) {
    *bn = BN_new();
    if (!*bn) {
        fprintf(stderr, "[ERROR] Failed to allocate BIGNUM\n");
        handle_openssl_errors();
        return EXIT_FAILURE;
    }

    printf("[INFO] Successfully created a new BIGNUM context.\n");
    return EXIT_SUCCESS;
}

/**
 * @brief Frees a BIGNUM context and sets the pointer to NULL.
 *
 * @param[in,out] bn Pointer to a BIGNUM pointer to free.
 *
 * @return 0 on success, 1 if the pointer is NULL.
 */
int bignum_free_context(BIGNUM **bn) {
    if (!bn || !*bn) {
        fprintf(stderr, "[WARNING] BIGNUM pointer is NULL, nothing to free.\n");
        return EXIT_FAILURE;
    }

    BN_free(*bn);
    *bn = NULL;  // avoid dangling pointer
    printf("[INFO] Successfully freed BIGNUM context.\n");
    return EXIT_SUCCESS;
}

/**
 * @brief Generates a random 256-bit BIGNUM.
 *
 * @param[out] bn Pointer to a pre-allocated BIGNUM.
 *
 * @return 0 on success, 1 on failure (e.g., NULL pointer or BN_rand failure).
 *
 * @note Uses OpenSSL's BN_rand to create a cryptographically random 256-bit number.
 */
int bignum_generate_random(BIGNUM *bn) {
    if (!bn) {
        fprintf(stderr, "[ERROR] BIGNUM pointer is NULL, cannot generate random number.\n");
        return EXIT_FAILURE;
    }

    if (!BN_rand(bn, 256, 0, 0)) { // 256-bit number, top=0, bottom=0
        fprintf(stderr, "[ERROR] Failed to generate random BIGNUM.\n");
        handle_openssl_errors();
        return EXIT_FAILURE;
    }

    printf("[INFO] Successfully generated a random 256-bit BIGNUM: ");
    BN_print_fp(stdout, bn);
    printf("\n");

    return EXIT_SUCCESS;
}