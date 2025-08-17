//
// Created by gim on 10/08/25.
//

#include "utils.h"

#include "hashing/hashing_utils.h"

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
