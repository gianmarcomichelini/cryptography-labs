#include <stdio.h>
#include <string.h>

#include "utils.h"

int test_bytewise_operations(void) {
    printf(
        "=============================================\n"
        "Two hex strings are given, separated by dashes.\n"
        "Remove the dashes, convert to bytes, XOR them.\n"
        "The XOR result is your key.\n"
        "=============================================\n"
    );

    printf("Given two random numbers:\n");

    const char *RAND1 =
        "ed-8a-3b-e8-17-68-38-78-f6-b1-77-3e-73-b3-f7-97-f3-00-47-76-54-ee-8d-51-0a-2f-10-79-17-f8-ea-d8-81-83-6e-0f-0c-b8-49-5a-77-ef-2d-62-b6-5e-e2-10-69-d6-cc-d6-a0-77-a2-0a-d3-f7-9f-a7-9e-a7-c9-08";

    const char *RAND2 =
        "4c-75-82-ca-02-07-bd-1d-8d-52-f0-6c-7a-d6-b7-87-83-95-06-2f-e0-f7-d4-24-f8-03-68-97-41-4c-85-29-e5-0d-b0-e4-3c-ee-74-dc-18-8a-aa-26-f0-46-94-e8-52-91-4a-43-8f-dd-ea-bb-a8-cf-51-14-79-ec-17-c2";

    printf("rnd1: %s\nrnd2: %s\n------------------------------------------------------------\n", RAND1, RAND2);

    size_t len1 = strlen(RAND1);
    size_t len2 = strlen(RAND2);

    if (len1 != len2) {
        fprintf(stderr, "ERROR: random numbers have different lengths\n");
        return EXIT_FAILURE;
    }

    char *r1 = remove_dashes(RAND1, len1);
    char *r2 = remove_dashes(RAND2, len2);

    if (!r1 || !r2) {
        fprintf(stderr, "ERROR: memory allocation failed during dash removal\n");
        free(r1);
        free(r2);
        return EXIT_FAILURE;
    }

    size_t bytes_len = strlen(r1) / 2;
    unsigned char *key = malloc(bytes_len);
    if (!key) {
        fprintf(stderr, "ERROR: memory allocation failed for key\n");
        free(r1);
        free(r2);
        return EXIT_FAILURE;
    }

    for (size_t i = 0; i < bytes_len; i++) {
        unsigned char b1 = hex_to_byte(r1[i * 2], r1[i * 2 + 1]);
        unsigned char b2 = hex_to_byte(r2[i * 2], r2[i * 2 + 1]);
        key[i] = b1 ^ b2;
    }

    printf("XOR result:\n");
    for (size_t i = 0; i < bytes_len; i++) {
        printf("%02X", key[i]);
    }
    printf("\n");

    free(r1);
    free(r2);
    free(key);

    return EXIT_SUCCESS;
}