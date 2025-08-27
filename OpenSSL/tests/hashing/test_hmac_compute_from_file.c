#include <stdlib.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "utils.h"
#include "hashing/hashing_utils.h"

/**
 * @brief Test the computation of an HMAC-SHA256 over a file.
 *
 * Steps performed:
 *  - Open the input file "../data/hmac.txt"
 *  - Use a fixed key ("deadbeefdeadbeed", 16 bytes)
 *  - Compute the HMAC-SHA256 digest
 *  - Print the resulting tag in hex format
 *
 * @return 0 on success, 1 on failure
 */
int test_hmac_sha256_compute_from_file(void) {
    FILE *fp = fopen("../data/hmac.txt", "rb");
    if (!fp) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    const unsigned char key[] = "deadbeefdeadbeed";
    const size_t key_len = 16;

    unsigned char hmac_out[EVP_MD_size(EVP_sha256())];
    unsigned int hmac_out_len = EVP_MD_size(EVP_sha256());

    if (!hashing_hmac_sha256_compute_from_file(fp, key, key_len, hmac_out, &hmac_out_len)) {
        perror("error computing hmac");
        fclose(fp);
        return EXIT_FAILURE;
    }

    fclose(fp);
    print_hex_buffer(hmac_out, hmac_out_len);

    return EXIT_SUCCESS;
}