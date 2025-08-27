#include "bignum/bignum_utils.h"

/**
 * @brief Demonstrates copying BIGNUMs using BN_copy and BN_dup.
 *
 * @param[in,out] bn1  Destination BIGNUM for BN_copy (must already be allocated).
 * @param[in]     bn2  Source BIGNUM to copy from.
 * @param[out]    bn3  Pointer to a BIGNUM pointer; will be allocated with BN_dup of bn2.
 *
 * @return 0 on success, 1 on failure (e.g., null pointer or BN_dup failure).
 *
 * @note This function prints detailed steps showing:
 *       - Copying bn2 into bn1 using BN_copy.
 *       - Duplicating bn2 into a new BIGNUM (bn3) using BN_dup.
 *       - Original bn2 remains unchanged.
 */
int bignum_copy(BIGNUM *bn1, BIGNUM *bn2, BIGNUM **bn3) {
    if (!bn1 || !bn2 || !bn3) {
        fprintf(stderr, "[ERROR] Null BIGNUM pointer provided.\n");
        return 0;
    }

    printf("\n============\n");
    printf("COPY OPERATIONS: bn1 <- bn2, bn3 = duplicate of bn2\n");
    printf("============\n\n");

    // Copy value from bn2 to bn1 (bn1 must already exist)
    BN_copy(bn1, bn2);
    printf("[STEP 1] Copied bn2 into bn1:\n");
    BN_print_fp(stdout, bn1);
    printf("\n\n");

    // Duplicate bn2 into a new BIGNUM for bn3
    *bn3 = BN_dup(bn2);
    if (!*bn3) {
        fprintf(stderr, "[ERROR] Failed to duplicate bn2 into bn3\n");
        return EXIT_FAILURE;
    }
    printf("[STEP 2] Duplicated bn2 into bn3:\n");
    BN_print_fp(stdout, *bn3);
    printf("\n\n");

    // Display original bn2
    printf("[INFO] Original bn2 remains unchanged:\n");
    BN_print_fp(stdout, bn2);
    printf("\n============\nEnd of copy demonstration\n============\n\n");

    return EXIT_SUCCESS;
}