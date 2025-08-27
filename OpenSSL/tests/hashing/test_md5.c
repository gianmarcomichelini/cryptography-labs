//
// Created by gim on 10/08/25.
//

#include "utils.h"
#include "hashing/hashing_utils.h"

/**
 * @brief Test the computation of an MD5 digest.
 *
 * Steps performed:
 *  - Define a simple message string
 *  - Compute the MD5 digest of the message
 *  - Print the resulting digest in hexadecimal format
 *
 * @return 0 if the MD5 digest is computed successfully,
 *         1 otherwise
 */
int test_digest_md5_compute(void) {
    const char message[] = "Simple message";

    unsigned char *digest = NULL;
    unsigned int digest_len = 0;

    printf("Computing MD5 hash for: \"%s\"\n", message);

    const int res = hashing_md5_compute((const unsigned char *)message, sizeof(message), &digest, &digest_len);
    if (res == EXIT_SUCCESS) {
        printf("Digest: ");
        print_hex_buffer(digest, digest_len);
        printf("\n");
    }

    OPENSSL_free(digest);

    return res;
}