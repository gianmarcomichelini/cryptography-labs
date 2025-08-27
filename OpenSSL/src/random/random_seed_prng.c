#include <openssl/err.h>
#include <openssl/rand.h>
#include "utils.h"

/**
 * @brief Seeds the OpenSSL PRNG from /dev/random.
 *
 * @param[in] seed_bytes Number of bytes to read from /dev/random for seeding
 *
 * @return 1 on success, 0 on failure
 */
int seed_prng(size_t seed_bytes) {
    const int rc = RAND_load_file("/dev/random", (int)seed_bytes);
    if (rc != (int)seed_bytes) {
        const unsigned long err = ERR_get_error();
        if (err) {
            char err_buf[256];
            print_openssl_errors(err, err_buf);
            fprintf(stderr, "[ERROR] PRNG seeding failed: %s\n", err_buf);
        }
        return 0;
    }
    return 1;
}