#include <stdio.h>
#include <string.h>
#include "tests/tests.h"

typedef int (*test_func_t)(void);

typedef struct {
    const char *name;
    test_func_t func;
} test_entry_t;

static test_entry_t tests[] = {
    {"bytewise_operations", test_bytewise_operations},
    {"randoms_xor_obtaining_key", test_xor_randoms_and_obtain_key},
    {"md5_basic_operations", test_digest_md5_compute},
    {"hmac_sha256_compute", test_hmac_sha256_compute},
    {"hmac_sha256_verify", test_hmac_sha256_verify},
    {"hmac_sha256_compute_from_file", test_hmac_sha256_compute_from_file},
    {"encrypt_aes256_from_message", test_encrypt_aes256_compute},
    {"encrypt_decrypt_aes256_from_file", test_encrypt_aes256cbc_compute_from_file},
    {NULL, NULL} // terminator
};



int main(void) {
    char input[256];


    printf("\nAvailable labs:\n");
    for (int i = 0; tests[i].name != NULL; i++) {
        printf("  - %s\n", tests[i].name);
    }

    while (1) {

        printf("\nEnter a lab (full sub-challenge name): ");

        if (fgets(input, sizeof(input), stdin) == NULL) {
            fprintf(stderr, "Input error\n");
            continue;
        }

        input[strcspn(input, "\n")] = '\0';

        if (strlen(input) == 0) {
            fprintf(stderr, "No lab name provided.\n");
            continue;
        }

        int found = 0;
        for (int i = 0; tests[i].name != NULL; i++) {
            if (strcmp(input, tests[i].name) == 0) {
                const int result = tests[i].func();
                printf("Test finished with code %d\n", result);
                found = 1;
                break;
            }
        }

        if (!found) {
            fprintf(stderr, "Unknown lab: %s\n", input);
        }
    }
}