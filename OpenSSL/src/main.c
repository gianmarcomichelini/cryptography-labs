#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "tests/tests.h"

typedef int (*test_func_t)(void);

typedef struct {
    const char *name;
    test_func_t func;
} test_entry_t;

static test_entry_t tests[] = {
    {"xor_from_hex_strings",      test_bytewise_operations},
    {"xor_from_randoms",          test_xor_randoms_and_obtain_key},
    {"md5_digest",                test_digest_md5_compute},
    {"hmac_sha256_basic",         test_hmac_sha256_compute},
    {"hmac_sha256_verify",        test_hmac_sha256_verify},
    {"hmac_sha256_from_file",     test_hmac_sha256_compute_from_file},
    {"aes256_encrypt_message",    test_encrypt_aes256_compute},
    {"aes256_file_encrypt_decrypt",test_encrypt_aes256cbc_compute_from_file},
    {"bignum_init",               test_bignum_basics},
    {"bignum_arithmetic",         test_bignum_basic_operations},
    {"rsa_asym_encrypt_decrypt",  test_enc_asym_basics},
    {NULL, NULL}
};

/**
 * @brief Find a test by name in the registry.
 * @param name Test name as string
 * @return Pointer to test_entry_t or NULL if not found
 */
static test_entry_t* find_test_by_name(const char *name) {
    for (int i = 0; tests[i].name != NULL; i++) {
        if (strcmp(name, tests[i].name) == 0) {
            return &tests[i];
        }
    }
    return NULL;
}

int main(void) {
    char input[256];

    printf("\nAvailable labs:\n");
    for (int i = 0; tests[i].name != NULL; i++) {
        printf("  - %s\n", tests[i].name);
    }
    printf("Type 'help' to list labs again, or 'exit' to quit.\n");

    while (1) {
        printf("\nEnter a lab: ");

        if (fgets(input, sizeof(input), stdin) == NULL) {
            fprintf(stderr, "Input error\n");
            continue;
        }

        input[strcspn(input, "\n")] = '\0'; // remove newline

        if (strlen(input) == 0) {
            fprintf(stderr, "No lab name provided.\n");
            continue;
        }

        if (strcmp(input, "exit") == 0 || strcmp(input, "quit") == 0) {
            printf("Exiting...\n");
            break;
        }

        if (strcmp(input, "help") == 0) {
            printf("\nAvailable labs:\n");
            for (int i = 0; tests[i].name != NULL; i++) {
                printf("  - %s\n", tests[i].name);
            }
            continue;
        }

        test_entry_t *t = find_test_by_name(input);
        if (!t) {
            fprintf(stderr, "Unknown lab: %s\n", input);
            continue;
        }

        const int result = t->func();
        printf("Test finished with code %d\n", result);
    }

    return EXIT_SUCCESS;
}