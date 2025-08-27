#include "bignum/bignum_utils.h"

/**
 * @brief Test function for BIGNUM basic operations, copy, and conversions.
 *
 * Creates three BIGNUMs, generates random values, prints them, performs copy
 * and conversion demonstrations, and finally frees the contexts.
 *
 * @return 0 on success, 1 on failure
 */
int test_bignum_basics(void) {
    BIGNUM* bn1 = NULL;
    BIGNUM* bn2 = NULL;
    BIGNUM* bn3 = NULL;

    if (!bignum_create_context(&bn1) ||
        !bignum_create_context(&bn2) ||
        !bignum_create_context(&bn3)) {
        return EXIT_FAILURE;
        }

    if (!bignum_generate_random(bn1) ||
        !bignum_generate_random(bn2) ||
        !bignum_generate_random(bn3)) {
        bignum_free_context(&bn1);
        bignum_free_context(&bn2);
        bignum_free_context(&bn3);
        return EXIT_FAILURE;
        }

    printf("Bignum1 is:\n");
    BN_print_fp(stdout, bn1);
    printf("\n");

    printf("Bignum2 is:\n");
    BN_print_fp(stdout, bn2);
    printf("\n");

    printf("Bignum3 is:\n");
    BN_print_fp(stdout, bn3);
    printf("\n");

    bignum_copy(bn1, bn2, &bn3);

    bignum_conversions(bn1);

    bignum_free_context(&bn1);
    bignum_free_context(&bn2);
    bignum_free_context(&bn3);

    return EXIT_SUCCESS;
}