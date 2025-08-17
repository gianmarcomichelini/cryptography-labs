#include <_stdlib.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "utils.h"
#include "hashing/hashing_utils.h"

#define KEY_LEN 16

int test_hmac_sha256_compute(void) {
    const unsigned char key[KEY_LEN] = "deadbeefdeadbeed";
    const size_t key_len = sizeof(key) - 1;

    const unsigned char message[] = "Simple Message";
    const size_t message_len = sizeof(message) - 1;

    unsigned char *hmac_out = NULL;
    size_t hmac_out_len = 0;

    if (hashing_hmac_sha256_compute(key, key_len, message, message_len, &hmac_out, &hmac_out_len) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    printf("HMAC digest (SHA256): ");
    print_hex_buffer(hmac_out, hmac_out_len);

    OPENSSL_free(hmac_out);

    return EXIT_SUCCESS;
}