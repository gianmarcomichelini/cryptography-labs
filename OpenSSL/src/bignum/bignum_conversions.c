#include "utils.h"
#include "bignum/bignum_utils.h"

/**
 * @brief Demonstrates conversions between BIGNUM and binary representation.
 *
 * @param[in] bn1  Input BIGNUM to convert.
 *
 * @return 0 on success, 1 on failure (e.g., null input or memory allocation failure).
 *
 * @note This function performs the following steps:
 *       - Converts a BIGNUM to a binary buffer using BN_bn2bin.
 *       - Prints the binary in hexadecimal format with dashes between bytes.
 *       - Reconstructs a new BIGNUM from the binary buffer using BN_bin2bn.
 *       - Compares the original and reconstructed BIGNUMs for correctness.
 */
int bignum_conversions(BIGNUM *bn1) {
    if (!bn1) {
        fprintf(stderr, "[ERROR] bn1 is NULL\n");
        return EXIT_FAILURE;
    }

    const size_t bn1_len = (size_t) BN_num_bytes(bn1);

    printf("\n============\n");
    printf("CONVERSIONS of bn1: BIGNUM -> binary -> BIGNUM\n");
    printf("============\n\n");

    // Step 1: BIGNUM -> binary
    printf("[STEP 1] Converting from BIGNUM to binary:\n");
    unsigned char buf[bn1_len];
    BN_bn2bin(bn1, buf);

    printf("Binary representation (hex, dashed):\n");
    for (size_t i = 0; i < bn1_len; i++) {
        printf("%02X", buf[i]);
        if (i < bn1_len - 1) printf("-");
    }
    printf("\n\n");

    // Step 2: binary -> BIGNUM
    printf("[STEP 2] Converting from binary back to BIGNUM:\n");
    BIGNUM *bn2 = BN_new();
    if (!bn2) {
        handle_openssl_errors();
    }
    BN_bin2bn(buf, (int) bn1_len, bn2);
    printf("Reconstructed BIGNUM: ");
    BN_print_fp(stdout, bn2);
    printf("\n\n");

    // Step 3: Verify correctness
    if (BN_cmp(bn1, bn2) == 0) {
        printf("[SUCCESS] Conversion BIGNUM -> binary -> BIGNUM is correct.\n");
    } else {
        fprintf(stderr, "[ERROR] Conversion failed: original and reconstructed BIGNUMs differ.\n");
    }

    BN_free(bn2);

    printf("\n============\nEnd of conversion demonstration\n============\n\n");

    return EXIT_SUCCESS;
}