//
// Created by gim on 09/08/25.
//

#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>

#include "utils.h"

#define LEN 32

int create_randoms(void) {

    printf(
        "\n==========================================\n"
        "Generate two cryptographically strong random byte arrays.\n"
        "XOR the two arrays byte-wise to produce a key.\n"
        "The key is printed as a hex string with dashes.\n"
        "==========================================\n\n"
    );

    unsigned long err;
    char buf[256];
    int rc;

    printf("Seeding the PRNG...\n"
           "------------------------\n");

    // Seed the PRNG with 32 bytes from /dev/random
    rc = RAND_load_file("/dev/random", 32);
    if (rc != 32) {
        err = ERR_get_error();
        if (err) {
            print_openssl_errors(err, buf);
        }
        return EXIT_FAILURE;
    }

    printf("Generating the random numbers...\n");

    unsigned char buffer1[LEN];
    unsigned char buffer2[LEN];
    unsigned char key[LEN];

    // Fetch 32 cryptographically strong random bytes
    // put them in the buffers
    rc = RAND_bytes(buffer1, sizeof(buffer1));
    if (rc != 1) {
        err = ERR_get_error();
        if (err) {
            print_openssl_errors(err, buf);
        }
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }

    rc = RAND_bytes((unsigned char *)buffer2, sizeof(buffer2));
    if (rc != 1) {
        err = ERR_get_error();
        if (err) {
            print_openssl_errors(err, buf);
        }
        fprintf(stderr, "ERROR: RAND_bytes failed\n");
        return EXIT_FAILURE;
    }

    printf("rand1:           ");
    print_hex_buffer(buffer1, LEN);
    printf("rand2:           ");
    print_hex_buffer(buffer2, LEN);

    printf("rand1 XOR rand2: ");
    for (size_t i = 0; i < LEN; i++) {
        key[i] = buffer1[i] ^ buffer2[i];
    }
    print_hex_buffer(key, LEN);



    return EXIT_SUCCESS;
}