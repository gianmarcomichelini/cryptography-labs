#include <openssl/err.h>
#include <openssl/rand.h>
#include "utils.h"

/**
 * @brief Generates a cryptographically secure random byte array.
 *
 * @param[out] buffer Pointer to a buffer where random bytes will be written
 * @param[in] len Number of random bytes to generate
 *
 * @return 0 on success, 1 on error
 *
 * Notes:
 *  - Uses OpenSSL's RAND_bytes.
 *  - Prints OpenSSL errors if generation fails.
 */
int generate_random_bytes(unsigned char *buffer, const size_t len) {
    if (!buffer) {
        fprintf(stderr, "[ERROR] Null buffer passed to generate_random_bytes.\n");
        return 1;
    }

    printf("[INFO] Generating %zu cryptographically secure random bytes...\n", len);

    const int rc = RAND_bytes(buffer, (int)len);
    if (rc != 1) {
        fprintf(stderr, "[ERROR] RAND_bytes failed.\n");

        const unsigned long err = ERR_get_error();
        if (err) {
            char err_buf[256];
            print_openssl_errors(err, err_buf);
            fprintf(stderr, "[ERROR] OpenSSL error: %s\n", err_buf);
        }

        ERR_print_errors_fp(stderr);
        return 1;
    }

    printf("[INFO] Successfully generated %zu random bytes.\n\n", len);
    return 0;
}