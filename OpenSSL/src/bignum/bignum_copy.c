#include "bignum/bignum_utils.h"

int bignum_copy(BIGNUM *bn1, BIGNUM *bn2, BIGNUM *bn3) {
    // ! never perform bn1 = bn2

    BN_copy(bn1, bn2); // copies from bn2 to bn1


    bn3 = BN_dup(bn2); // creates a new BIGNUM containing the value from bn2

    printf("\n============\n"
           "COPY: bn1->bn2 and bn2->bn3:\n"
           "============\n\n");

    printf("Bignum1 is:\n");
    BN_print_fp(stdout, bn1);
    printf("\n");

    printf("Bignum2 is:\n");
    BN_print_fp(stdout, bn2);
    printf("\n");

    printf("Bignum3 is:\n");
    BN_print_fp(stdout, bn3);
    printf("\n");

    return 1;
}
