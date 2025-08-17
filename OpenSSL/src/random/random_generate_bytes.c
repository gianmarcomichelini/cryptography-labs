#include <openssl/err.h>
#include <openssl/rand.h>

#include "utils.h"
// Generates a cryptographically secure random byte array of given length
// Returns EXIT_SUCCESS or EXIT_FAILURE on error
int generate_random_bytes(unsigned char *buffer, const size_t len) {
    const int rc = RAND_bytes(buffer, (int)len);
    if (rc != 1) {
        const unsigned long err = ERR_get_error();
        if (err) {
            char err_buf[256];
            print_openssl_errors(err, err_buf);
        }
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}