#include <stdio.h>
#include <string.h>
#include "rand/rand.h"
#include "hashing/hashing.h"

void guess_algo(void);
void first_decryption(void);
void in_the_name_of_the_cipher(void);
void padding(void);
void guess_what(void);
void first_hmac(void);
void change_dgst(void);
void keyed_digest(void);

int main(void) {
    char input[256];

    // List of available labs
    printf("available labs:\n");
    printf("  - openssl-sym: guess-algo, firstdecryption, in-the-name-of-the-cipher, padding\n");
    printf("  - openssl-asym: guess-what\n");
    printf("  - openssl-hmac: hmac_compute, hmac_verify, firsthmac\n");
    printf("  - openssl-dgst: md5_compute, changedgst, keyed-digest\n");
    printf("  - openssl-rand: bytewise-operations, create-randoms\n");
    printf("\nenter a lab (full sub-challenge name): ");

    if (fgets(input, sizeof(input), stdin) != NULL) {
        input[strcspn(input, "\n")] = 0; // strip newline

        if (strlen(input) == 0) {
            fprintf(stderr, "no lab name provided.\n");
            return 1;
        }



        // Dispatch table
        if (strcmp(input, "guess-algo") == 0) guess_algo();
        else if (strcmp(input, "firstdecryption") == 0) first_decryption();
        else if (strcmp(input, "in-the-name-of-the-cipher") == 0) in_the_name_of_the_cipher();
        else if (strcmp(input, "padding") == 0) padding();
        else if (strcmp(input, "guess-what") == 0) guess_what();
        else if (strcmp(input, "firsthmac") == 0) first_hmac();
        else if (strcmp(input, "hmac_verify") == 0) hashing_hmac_verify();
        else if (strcmp(input, "hmac_compute") == 0) hashing_hmac_compute();
        else if (strcmp(input, "md5_compute") == 0) hashing_md5_compute();
        else if (strcmp(input, "changedgst") == 0) change_dgst();
        else if (strcmp(input, "keyed-digest") == 0) keyed_digest();
        else if (strcmp(input, "bytewise-operations") == 0) bytewise_operations();
        else if (strcmp(input, "create-randoms") == 0) create_randoms();
        else {
            fprintf(stderr, "unknown lab: %s\n", input);
            return 1;
        }

        return 0;
    } else {
        fprintf(stderr, "input error\n");
        return 1;
    }
}

// Dummy function implementations
void guess_algo(void) { printf("Running guess-algo\n"); }
void first_decryption(void) { printf("Running firstdecryption\n"); }
void in_the_name_of_the_cipher(void) { printf("Running in-the-name-of-the-cipher\n"); }
void padding(void) { printf("Running padding\n"); }
void guess_what(void) { printf("Running guess-what\n"); }
void first_hmac(void) { printf("Running firsthmac\n"); }
void change_dgst(void) { printf("Running changedgst\n"); }
void keyed_digest(void) { printf("Running keyed-digest\n"); }