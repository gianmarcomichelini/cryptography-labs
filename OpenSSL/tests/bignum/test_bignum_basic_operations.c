#include "bignum/bignum_utils.h"
#include <stdio.h>
#include <openssl/bn.h>

/**
 * @brief Test function for BIGNUM basic operations.
 *
 * Initializes sample BIGNUMs, performs basic arithmetic, modular, and logical
 * operations using bignum_basic_operations().
 *
 * @return 0 on success, 1 on failure
 */
int test_bignum_basic_operations() {
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create BN_CTX\n");
        return EXIT_FAILURE;
    }

    printf("\n\n=======\n"
           "BIGNUM basic operations\n"
           "=======\n\n");

    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *exp = BN_new();

    if (!a || !b || !m || !exp) {
        fprintf(stderr, "Failed to allocate BIGNUMs\n");
        BN_free(a); BN_free(b); BN_free(m); BN_free(exp);
        BN_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    // Initialize values
    BN_set_word(a, 42);
    BN_set_word(b, 12);
    BN_set_word(m, 17);
    BN_set_word(exp, 3);

    printf("a = "); BN_print_fp(stdout, a); printf("\n");
    printf("b = "); BN_print_fp(stdout, b); printf("\n");

    // Perform operations
    bignum_basic_operations(a, b, m, exp, ctx);

    BN_free(a); BN_free(b); BN_free(m); BN_free(exp);
    BN_CTX_free(ctx);
    return EXIT_SUCCESS;
}