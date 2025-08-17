#include <openssl/evp.h>
#include <openssl/rand.h>
#include "utils.h"
#include "enc_symm/encryption_symmetric_utils.h"


int test_encrypt_aes256_compute(void) {
    int rc;
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    const int key_len = EVP_CIPHER_get_key_length(cipher);
    const int aes_block_size = EVP_CIPHER_get_block_size(cipher);
    unsigned char *key = OPENSSL_malloc(key_len);
    rc = RAND_bytes(key, key_len);
    if (rc != 1)
        handle_openssl_errors();
    unsigned char *iv = OPENSSL_malloc(aes_block_size);
    rc = RAND_bytes(iv, aes_block_size);
    if (rc != 1)
        handle_openssl_errors();

    const unsigned char plaintext[34] = "Hi guys! this has to be encrypted";
    const int plaintext_len = sizeof(plaintext) - 1; // exclude the terminator
    unsigned char ciphertext[sizeof(plaintext) + EVP_MAX_BLOCK_LENGTH]; // should be an array of 48 bytes (3 blocks)
    int ciphertext_len = 0;

    if (!enc_symm_encrypt_compute(plaintext, ciphertext, iv, key, plaintext_len, &ciphertext_len, cipher)) {
        printf("ERROR: Encryption failed");
    }




    OPENSSL_free(key);
    OPENSSL_free(iv);
    return 1;
}
