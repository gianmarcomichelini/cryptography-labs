#include "utils.h"
#include "bignum/bignum_utils.h"

int bignum_conversions(BIGNUM *bn1) {
    if (!bn1) {
        fprintf(stderr, "Error: bn1 is NULL\n");
        return 0;
    }

    const size_t bn1_len = (size_t) BN_num_bytes(bn1);

    printf("\n============\n"
           "CONVERSIONS of bn1: BIGNUM->binary->BIGNUM\n"
           "============\n\n");

    printf("Converting from BIGNUM to binary:\n");
    unsigned char buf[bn1_len];
    BN_bn2bin(bn1, buf);
    for (size_t i = 0; i < bn1_len; i++) {
        printf("%02X", buf[i]);
        if (i < bn1_len - 1) printf("-");   // introducing dashes
    }
    printf("\n");

    BIGNUM *bn2 = BN_new();
    if (!bn2) {
        handle_openssl_errors();
    }

    printf("Converting from binary to BIGNUM:\n");
    BN_bin2bn(buf, (int) bn1_len, bn2);
    BN_print_fp(stdout, bn2);
    printf("\n");

    if (BN_cmp(bn1,bn2)== 0)
        printf("Conversion BIGNUM->binary->BIGNUM successful\n");
    else
        fprintf(stderr, "ERROR: conversion failed\n");

    printf("\n");




    return 1;
}
