//
// Created by gim on 17/08/25.
//

#ifndef BIGNUM_UTILS_H
#define BIGNUM_UTILS_H

#include <openssl/bn.h>

extern int bignum_create_context(BIGNUM** bn);

extern int bignum_free_context(BIGNUM** bn);

extern int bignum_generate_random(BIGNUM *bn);

extern int bignum_copy(BIGNUM *bn1, BIGNUM *bn2, BIGNUM **bn3);

extern int bignum_conversions(BIGNUM *bn1);

void bignum_basic_operations(const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, const BIGNUM *exp, BN_CTX *ctx);

#endif //BIGNUM_UTILS_H
