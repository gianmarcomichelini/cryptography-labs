#include "utils.h"
#include "enc_asym/encryption_asymmetric_utils.h"

void enc_asym_encrypt_RSA(const char plaintext[], EVP_PKEY *rsa_keypair) {

    printf("Attempting encryption...\n");

    // create the encryption context
    EVP_PKEY_CTX *enc_ctx = EVP_PKEY_CTX_new(rsa_keypair, NULL);
    if (!enc_ctx) handle_openssl_errors();

    // initialize the context
    if (EVP_PKEY_encrypt_init(enc_ctx) <= 0) {
        handle_openssl_errors();
    }

    // set the padding mechanism
    if (EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) handle_openssl_errors();

    // determine the size of the ciphertext
    size_t ciphertext_len;
    if (EVP_PKEY_encrypt(enc_ctx,NULL, &ciphertext_len, (const unsigned char *) plaintext, strlen(plaintext)) <= 0) {
        handle_openssl_errors();
    }

    // encrypt the plaintext -> obtain the ciphertext
    unsigned char ciphertext[ciphertext_len];
    if (EVP_PKEY_encrypt(enc_ctx, ciphertext, &ciphertext_len, (const unsigned char *) plaintext,
                         strlen(plaintext)) <= 0) {
        handle_openssl_errors();
    }


    FILE *f_out = fopen("../data/rsa_decrypt.bin", "w");
    if (!f_out) {
        perror("Unable to open output file for RSA encryption");
        abort();
    }
    if (fwrite(ciphertext, 1, ciphertext_len, f_out) < EVP_PKEY_size(rsa_keypair))
        handle_openssl_errors();
    fclose(f_out);

    printf("Encrypted message written to the file \"rsa_decrypt.bin\".\n");
}


void enc_asym_decrypt_RSA(const unsigned char* ciphertext, const size_t ciphertext_len, EVP_PKEY *rsa_keypair) {
    EVP_PKEY_CTX* dec_ctx = EVP_PKEY_CTX_new(rsa_keypair, NULL);
    if (!dec_ctx) handle_openssl_errors();

    if (EVP_PKEY_decrypt_init(dec_ctx) <= 0) {
        handle_openssl_errors();
    }

    if (EVP_PKEY_CTX_set_rsa_padding(dec_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        handle_openssl_errors();
    }

    size_t decrypted_msg_len;
    
    if (EVP_PKEY_decrypt(dec_ctx, NULL, &decrypted_msg_len, ciphertext, ciphertext_len) <= 0) {
        handle_openssl_errors();
    }

    unsigned char decrypted_msg[decrypted_msg_len+1];   // add 1 for the terminator of the literal

    if (EVP_PKEY_decrypt(dec_ctx, decrypted_msg, &decrypted_msg_len, ciphertext, ciphertext_len) <= 0) {
        handle_openssl_errors();
    }

    decrypted_msg[decrypted_msg_len] = '\0';
    printf("\nDecrypted Plaintext is:\n"
           "======================================================\n"
           "%s\n"
           "======================================================\n",
           (char*) decrypted_msg);
}