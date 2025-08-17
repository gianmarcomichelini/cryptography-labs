

#include "random/random_utils.h"
#include "utils.h"

#define RANDOM_LEN 32

// Main function demonstrating random generation, XOR, and printing
int test_xor_randoms_and_obtain_key(void) {
    printf(
        "\n==========================================\n"
        "Generate two cryptographically strong random byte arrays.\n"
        "XOR the two arrays byte-wise to produce a key.\n"
        "The key is printed as a hex string with dashes.\n"
        "==========================================\n\n"
    );

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