#include "utils.h"
#include "enc_asym/enc_asym_utils.h"

/**
 * @brief Encrypts a plaintext string using RSA and writes the ciphertext to a file.
 *
 * @param[in] plaintext  Null-terminated string to encrypt
 * @param[in] rsa_keypair EVP_PKEY containing the RSA public key
 *
 * @note The encrypted message is written to "../data/rsa_decrypt.bin".
 */
void enc_asym_encrypt_RSA(const char plaintext[], EVP_PKEY *rsa_keypair) {
    if (!plaintext || !rsa_keypair) {
        fprintf(stderr, "[ERROR] Null pointer passed to enc_asym_encrypt_RSA.\n");
        return;
    }

    printf("[INFO] Starting RSA encryption...\n");

    EVP_PKEY_CTX *enc_ctx = EVP_PKEY_CTX_new(rsa_keypair, NULL);
    if (!enc_ctx) handle_openssl_errors();
    printf("[STEP 1] Encryption context created.\n");

    if (EVP_PKEY_encrypt_init(enc_ctx) <= 0) handle_openssl_errors();
    printf("[STEP 2] Encryption context initialized.\n");

    if (EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        handle_openssl_errors();
    printf("[STEP 3] RSA OAEP padding set.\n");

    size_t ciphertext_len;
    if (EVP_PKEY_encrypt(enc_ctx, NULL, &ciphertext_len,
                         (const unsigned char *) plaintext, strlen(plaintext)) <= 0)
        handle_openssl_errors();
    printf("[STEP 4] Ciphertext length determined: %zu bytes.\n", ciphertext_len);

    unsigned char ciphertext[ciphertext_len];
    if (EVP_PKEY_encrypt(enc_ctx, ciphertext, &ciphertext_len,
                         (const unsigned char *) plaintext, strlen(plaintext)) <= 0)
        handle_openssl_errors();
    printf("[STEP 5] Encryption complete.\n");

    FILE *f_out = fopen("../data/rsa_decrypt.bin", "wb");
    if (!f_out) {
        perror("[ERROR] Unable to open output file for RSA encryption");
        abort();
    }
    if (fwrite(ciphertext, 1, ciphertext_len, f_out) < ciphertext_len)
        handle_openssl_errors();
    fclose(f_out);
    printf("[STEP 6] Encrypted message written to \"../data/rsa_decrypt.bin\".\n\n");
}

/**
 * @brief Decrypts RSA ciphertext and prints the plaintext.
 *
 * @param[in] ciphertext      Pointer to the ciphertext bytes
 * @param[in] ciphertext_len  Length of the ciphertext in bytes
 * @param[in] rsa_keypair     EVP_PKEY containing the RSA private key
 */
void enc_asym_decrypt_RSA(const unsigned char* ciphertext, const size_t ciphertext_len,
                          EVP_PKEY *rsa_keypair) {
    if (!ciphertext || !rsa_keypair) {
        fprintf(stderr, "[ERROR] Null pointer passed to enc_asym_decrypt_RSA.\n");
        return;
    }

    printf("[INFO] Starting RSA decryption...\n");

    EVP_PKEY_CTX* dec_ctx = EVP_PKEY_CTX_new(rsa_keypair, NULL);
    if (!dec_ctx) handle_openssl_errors();
    printf("[STEP 1] Decryption context created.\n");

    if (EVP_PKEY_decrypt_init(dec_ctx) <= 0) handle_openssl_errors();
    printf("[STEP 2] Decryption context initialized.\n");

    if (EVP_PKEY_CTX_set_rsa_padding(dec_ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        handle_openssl_errors();
    printf("[STEP 3] RSA OAEP padding set.\n");

    size_t decrypted_msg_len;
    if (EVP_PKEY_decrypt(dec_ctx, NULL, &decrypted_msg_len, ciphertext, ciphertext_len) <= 0)
        handle_openssl_errors();
    printf("[STEP 4] Decrypted message length determined: %zu bytes.\n", decrypted_msg_len);

    unsigned char decrypted_msg[decrypted_msg_len + 1];
    if (EVP_PKEY_decrypt(dec_ctx, decrypted_msg, &decrypted_msg_len, ciphertext, ciphertext_len) <= 0)
        handle_openssl_errors();
    decrypted_msg[decrypted_msg_len] = '\0';
    printf("[STEP 5] Decryption complete.\n");

    printf("[INFO] Decrypted plaintext:\n");
    printf("======================================================\n");
    printf("%s\n", (char*) decrypted_msg);
    printf("======================================================\n\n");
}