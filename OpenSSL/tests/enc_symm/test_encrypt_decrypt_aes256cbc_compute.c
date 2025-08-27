#include <openssl/evp.h>
#include <openssl/rand.h>
#include "utils.h"
#include "enc_symm/enc_symm_utils.h"

/**
 * @brief Test AES-256-CBC encryption on a small buffer.
 *
 * Performs:
 *  - Random key and IV generation
 *  - Encrypts a fixed plaintext buffer
 *
 * @return 0 on success, 1 on failure
 */
int test_encrypt_aes256_compute(void) {
    int rc;
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    const int key_len = EVP_CIPHER_get_key_length(cipher);
    const int aes_block_size = EVP_CIPHER_get_block_size(cipher);

    unsigned char *key = OPENSSL_malloc(key_len);
    rc = RAND_bytes(key, key_len);
    if (rc != 1) {
        handle_openssl_errors();
        OPENSSL_free(key);
        return EXIT_FAILURE;
    }

    unsigned char *iv = OPENSSL_malloc(aes_block_size);
    rc = RAND_bytes(iv, aes_block_size);
    if (rc != 1) {
        handle_openssl_errors();
        OPENSSL_free(key);
        OPENSSL_free(iv);
        return EXIT_FAILURE;
    }

    const unsigned char plaintext[34] = "Hi guys! this has to be encrypted";
    const int plaintext_len = sizeof(plaintext) - 1; // exclude null terminator
    unsigned char ciphertext[sizeof(plaintext) + EVP_MAX_BLOCK_LENGTH];
    int ciphertext_len = 0;

    if (!enc_symm_encrypt_compute(plaintext, ciphertext, iv, key, plaintext_len, &ciphertext_len, cipher)) {
        printf("ERROR: Encryption failed\n");
        OPENSSL_free(key);
        OPENSSL_free(iv);
        return EXIT_FAILURE;
    }

    OPENSSL_free(key);
    OPENSSL_free(iv);

    return EXIT_SUCCESS;
}