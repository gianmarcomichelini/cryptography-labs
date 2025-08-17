#include <_stdlib.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "utils.h"
#include "hashing/hashing_utils.h"


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