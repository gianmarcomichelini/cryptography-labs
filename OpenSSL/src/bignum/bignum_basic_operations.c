#include "bignum/bignum_utils.h"

void bignum_basic_operations(BIGNUM *a, BIGNUM *b, BIGNUM *m, BIGNUM *exp, BN_CTX *ctx) {
    BIGNUM *r = BN_new();
    BIGNUM *sqr = BN_new();
    BIGNUM *dv = BN_new();
    BIGNUM *rem = BN_new();
    BIGNUM *gcd = BN_new();

    if (!r || !sqr || !dv || !rem || !gcd) {
        fprintf(stderr, "Failed to allocate temporary BIGNUMs\n");
        BN_free(r); BN_free(sqr); BN_free(dv); BN_free(rem); BN_free(gcd);
        return;
    }

    // Arithmetic operations
    BN_add(r, a, b);
    printf("a + b = "); BN_print_fp(stdout, r); printf("\n");

    BN_sqr(sqr, a, ctx);
    printf("a^2 = "); BN_print_fp(stdout, sqr); printf("\n");

    BN_div(dv, rem, a, b, ctx);
    printf("a / b = "); BN_print_fp(stdout, dv);
    printf(", remainder = "); BN_print_fp(stdout, rem); printf("\n");

    BN_mod_add(r, a, b, m, ctx);
    printf("(a + b) mod m = "); BN_print_fp(stdout, r); printf("\n");

    BN_mod_exp(r, a, exp, m, ctx);
    printf("a^exp mod m = "); BN_print_fp(stdout, r); printf("\n");

    BN_gcd(gcd, a, b, ctx);
    printf("gcd(a, b) = "); BN_print_fp(stdout, gcd); printf("\n");

    // Logical / tests
    const int cmp = BN_cmp(a, b);
    printf("BN_cmp(a, b) = %d\n", cmp);
    printf("BN_is_zero(a) = %d\n", BN_is_zero(a));
    printf("BN_is_one(a) = %d\n", BN_is_one(a));
    printf("BN_is_word(a, 42) = %d\n", BN_is_word(a, 42));

    printf("\n");


    BN_free(r); BN_free(sqr); BN_free(dv); BN_free(rem); BN_free(gcd);
}
