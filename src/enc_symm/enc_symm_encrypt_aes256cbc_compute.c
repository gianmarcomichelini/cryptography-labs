
#include "utils.h"

enum MODE {
    ENCRYPT = 1,
    DECRYPT = 0
};

int enc_symm_encrypt_aes256_compute(const unsigned char *plaintext, unsigned char *ciphertext,
                                    const unsigned char *iv, const unsigned char* key,
                                    const int plaintext_len, int *ciphertext_len,
                                    const EVP_CIPHER* cipher) {

    int rc;
    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) {
        handle_openssl_errors();
    }
    rc = EVP_CipherInit(cipher_ctx, cipher, key, iv, ENCRYPT);
    if (rc != 1) {
        handle_openssl_errors();
    }

    int update_len = 0, final_len = 0;
    int ct_len = 0;

    rc = EVP_CipherUpdate(cipher_ctx, ciphertext, &update_len, plaintext, plaintext_len);
    if (rc != 1) {
        handle_openssl_errors();
    }
    ct_len += update_len;
    printf("CipherUpdate, current ciphertext length: %2d\n", ct_len);

    // finalize context (padding)
    rc = EVP_CipherFinal_ex(cipher_ctx, ciphertext + ct_len, &final_len);
    if (rc != 1) {
        handle_openssl_errors();
    }
    ct_len += final_len;
    printf("Padding Length: %d\n", final_len);

    *ciphertext_len = ct_len;

    printf("The ciphertext of \"%s\" is:\n", (const char *) plaintext);
    print_hex_buffer(ciphertext, *ciphertext_len);
    printf("Ciphertext Length: %d\n", *ciphertext_len);

    EVP_CIPHER_CTX_free(cipher_ctx);


    return 1;
}
