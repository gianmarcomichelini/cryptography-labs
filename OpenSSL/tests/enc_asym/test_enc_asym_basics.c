#include "utils.h"
#include "enc_asym/enc_asym_utils.h"

/**
 * @brief Test function for basic asymmetric RSA operations.
 *
 * Performs:
 *  - RSA keypair generation
 *  - Saving public and private keys to files
 *  - Encrypting a plaintext message
 *  - Reading encrypted message and decrypting it
 *
 * @return 0 on success, 1 on failure
 */
int test_enc_asym_basics(void) {
    /* KEYPAIR MANAGEMENT */

    EVP_PKEY *rsa_keypair = NULL;
    const int n_bits = 2048;

    enc_asym_key_generation(&rsa_keypair, n_bits);
    if (!rsa_keypair) return EXIT_FAILURE;

    FILE *rsa_keypair_public_file = fopen("../data/key_public.pem", "w");
    if (!rsa_keypair_public_file) return EXIT_FAILURE;
    enc_asym_write_pkey_file(rsa_keypair, rsa_keypair_public_file);

    FILE *rsa_keypair_private_file = fopen("../data/key_private.pem", "w");
    if (!rsa_keypair_private_file) {
        EVP_PKEY_free(rsa_keypair);
        return EXIT_FAILURE;
    }
    enc_asym_write_private_key_file(rsa_keypair, rsa_keypair_private_file);

    /* ENCRYPTION */

    const char plaintext[] = "hi!! This is the message to encrypt with RSA";
    enc_asym_encrypt_RSA(plaintext, rsa_keypair);

    /* DECRYPTION */

    unsigned char ciphertext[BUFSIZ];
    printf("Reading the encrypted message from the file \"rsa_decrypt.bin\" and attempting decryption...\n");

    FILE *fin = fopen("../data/rsa_decrypt.bin", "r");
    if (!fin) {
        EVP_PKEY_free(rsa_keypair);
        return EXIT_FAILURE;
    }
    const size_t ciphertext_len = fread(ciphertext, 1, EVP_PKEY_size(rsa_keypair), fin);
    fclose(fin);

    if (ciphertext_len == 0) {
        EVP_PKEY_free(rsa_keypair);
        handle_openssl_errors();
        return EXIT_FAILURE;
    }

    enc_asym_decrypt_RSA(ciphertext, ciphertext_len, rsa_keypair);

    /* cleanup */
    EVP_PKEY_free(rsa_keypair);

    return EXIT_SUCCESS;
}