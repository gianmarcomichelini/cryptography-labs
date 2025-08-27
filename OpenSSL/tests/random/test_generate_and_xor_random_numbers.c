#include "random/random_utils.h"
#include "utils.h"

#define RANDOM_LEN 32

/**
 * @brief Generates two random byte arrays and derives a key via XOR.
 *
 * Steps performed:
 *  - Seeds the pseudo-random number generator (PRNG).
 *  - Generates two cryptographically strong random byte arrays of length RANDOM_LEN.
 *  - Computes their XOR, byte by byte, to produce a key.
 *  - Prints the two random arrays and the resulting key in hexadecimal format.
 *
 * @return 0 on success,
 *         1 on failure
 */
int test_xor_randoms_and_obtain_key(void) {

    if (seed_prng(RANDOM_LEN) != EXIT_SUCCESS) {
        fprintf(stderr, "Failed to seed the PRNG\n");
        return EXIT_FAILURE;
    }

    printf("Generating the random numbers...\n");

    unsigned char buffer1[RANDOM_LEN];
    unsigned char buffer2[RANDOM_LEN];
    unsigned char key[RANDOM_LEN];

    if (generate_random_bytes(buffer1, RANDOM_LEN) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    if (generate_random_bytes(buffer2, RANDOM_LEN) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    printf("rand1:           ");
    print_hex_buffer(buffer1, RANDOM_LEN);
    printf("rand2:           ");
    print_hex_buffer(buffer2, RANDOM_LEN);

    xor_buffers(buffer1, buffer2, key, RANDOM_LEN);

    printf("rand1 XOR rand2: ");
    print_hex_buffer(key, RANDOM_LEN);

    return EXIT_SUCCESS;
}