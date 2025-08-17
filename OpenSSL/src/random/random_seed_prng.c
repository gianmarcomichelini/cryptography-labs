#include <openssl/err.h>
#include <openssl/rand.h>

#include "utils.h"

// Seeds the PRNG from /dev/random with specified bytes
// Returns EXIT_SUCCESS or EXIT_FAILURE on error
int seed_prng(size_t seed_bytes) {
    const int rc = RAND_load_file("/dev/random", (int)seed_bytes);
    if (rc != (int)seed_bytes) {
        const unsigned long err = ERR_get_error();
        if (err) {
            char err_buf[256];
            print_openssl_errors(err, err_buf);
        }
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}