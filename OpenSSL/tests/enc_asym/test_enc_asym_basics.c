#include "utils.h"
#include "enc_asym/encryption_asymmetric_utils.h"

int test_enc_asym_basics(void) {
    /* KEYPAIR MANAGEMENT */

    // generate the public/private keypair
    EVP_PKEY *rsa_keypair = NULL;
    const int n_bits = 2048;

    enc_asym_key_generation(&rsa_keypair, n_bits);

    // save the public key into a file
    FILE *rsa_keypair_public_file = NULL;
    if ((rsa_keypair_public_file = fopen("../data/key_public.pem", "w")) == NULL) {
        fprintf(stderr, "Couldn't create the private key file.\n");
        abort();
    }

    enc_asym_write_pkey_file(rsa_keypair, rsa_keypair_public_file);


    // save the private key into a file (no encryption)
    FILE *rsa_keypair_private_file = NULL;
    if ((rsa_keypair_private_file = fopen("../data/key_private.pem", "w")) == NULL) {
        fprintf(stderr, "Couldn't create the private key file.\n");
        abort();
    }

    enc_asym_write_private_key_file(rsa_keypair, rsa_keypair_private_file);


    /* ENCRYPTION (using the rsa_keypair obtained from above) */

    const char plaintext[] = "hi!! This is the message to encrypt with RSA";

    enc_asym_encrypt_RSA(plaintext, rsa_keypair);


    /* DECRYPTION */

    unsigned char ciphertext[BUFSIZ];
    printf("Reading the encrypted message from the file \"rsa_decrypt.bin\" and attempting decryption...\n");

    FILE *fin = fopen("../data/rsa_decrypt.bin", "r");
    if (!fin) {
        perror("Unable to open encrypted file");
        abort();
    }
    const size_t ciphertext_len = fread(ciphertext, 1, EVP_PKEY_size(rsa_keypair), fin);
    if (ciphertext_len == 0) {
        handle_openssl_errors();
    }
    fclose(fin);


    enc_asym_decrypt_RSA(ciphertext,ciphertext_len,rsa_keypair);


    /* cleanup */
    EVP_PKEY_free(rsa_keypair);

    return 0;
}

