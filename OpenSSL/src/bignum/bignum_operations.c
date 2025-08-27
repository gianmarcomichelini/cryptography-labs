#include "bignum/bignum_utils.h"

/**
 * @brief Perform basic BIGNUM operations and print detailed explanations.
 *
 * @param[in] a    First input BIGNUM.
 * @param[in] b    Second input BIGNUM.
 * @param[in] m    Modulus for modular operations.
 * @param[in] exp  Exponent for modular exponentiation.
 * @param[in] ctx  BN_CTX context for temporary calculations.
 *
 * @note Demonstrates the following operations on BIGNUMs:
 *       - Addition, squaring, division with remainder
 *       - Modular addition and modular exponentiation
 *       - Greatest common divisor computation
 *       - Basic logical checks and comparisons
 *
 * @warning Temporary BIGNUMs are allocated within the function and freed before returning.
 */
void bignum_basic_operations(const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, const BIGNUM *exp, BN_CTX *ctx) {
    // Allocate temporary BIGNUMs
    BIGNUM *r = BN_new();      // general result
    BIGNUM *sqr = BN_new();    // square of a
    BIGNUM *dv = BN_new();     // division result
    BIGNUM *rem = BN_new();    // remainder
    BIGNUM *gcd = BN_new();    // gcd result

    if (!r || !sqr || !dv || !rem || !gcd) {
        fprintf(stderr, "[ERROR] Failed to allocate temporary BIGNUMs\n");
        BN_free(r); BN_free(sqr); BN_free(dv); BN_free(rem); BN_free(gcd);
        return;
    }

    printf("=== BIGNUM Basic Operations ===\n");

    // Addition
    BN_add(r, a, b);
    printf("Step 1: Addition (a + b) = ");
    BN_print_fp(stdout, r);
    printf("\n");

    // Squaring
    BN_sqr(sqr, a, ctx);
    printf("Step 2: Squaring (a^2) = ");
    BN_print_fp(stdout, sqr);
    printf("\n");

    // Division
    BN_div(dv, rem, a, b, ctx);
    printf("Step 3: Division (a / b) = ");
    BN_print_fp(stdout, dv);
    printf(", remainder = ");
    BN_print_fp(stdout, rem);
    printf("\n");

    // Modular addition
    BN_mod_add(r, a, b, m, ctx);
    printf("Step 4: Modular addition ((a + b) mod m) = ");
    BN_print_fp(stdout, r);
    printf("\n");

    // Modular exponentiation
    BN_mod_exp(r, a, exp, m, ctx);
    printf("Step 5: Modular exponentiation (a^exp mod m) = ");
    BN_print_fp(stdout, r);
    printf("\n");

    // GCD
    BN_gcd(gcd, a, b, ctx);
    printf("Step 6: Greatest common divisor (gcd(a, b)) = ");
    BN_print_fp(stdout, gcd);
    printf("\n");

    // Logical / comparison tests
    const int cmp = BN_cmp(a, b);
    printf("Step 7: Comparison BN_cmp(a, b) = %d (0=equal, <0=a<b, >0=a>b)\n", cmp);
    printf("Step 8: BN_is_zero(a) = %d\n", BN_is_zero(a));
    printf("Step 9: BN_is_one(a) = %d\n", BN_is_one(a));
    printf("Step 10: BN_is_word(a, 42) = %d (checks if a == 42)\n", BN_is_word(a, 42));

    printf("=== End of BIGNUM Operations ===\n\n");

    // Free temporary BIGNUMs
    BN_free(r); BN_free(sqr); BN_free(dv); BN_free(rem); BN_free(gcd);
}