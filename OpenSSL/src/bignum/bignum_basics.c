#include "utils.h"
#include "bignum/bignum_utils.h"

int bignum_create_context(BIGNUM** bn) {
    *bn = BN_new();
    if (!bn)
        handle_openssl_errors();

    return 1;
}

int bignum_free_context(BIGNUM** bn) {
    BN_free(*bn);
    if (!*bn)
        handle_openssl_errors();

    return 1;
}

int bignum_generate_random(BIGNUM *bn) {

    if (!BN_rand(bn, 256, 0, 0)) {
        handle_openssl_errors();
    }

    return 1;
}
