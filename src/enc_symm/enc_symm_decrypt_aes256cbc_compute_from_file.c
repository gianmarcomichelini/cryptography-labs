#include "utils.h"

enum MODE {
    ENCRYPT = 1,
    DECRYPT = 0
};

int enc_symm_decrypt_aes256cbc_compute_from_file(const unsigned char *key,
                                                 const unsigned char *iv,
                                                 const EVP_CIPHER *cipher,
                                                 FILE *f_in, FILE *f_out) {
    int update_len = 0, final_len = 0;
    size_t n_read = 0;
    unsigned char buf_in[BUFSIZ];
    unsigned char buf_out[BUFSIZ + EVP_CIPHER_block_size(cipher)];

    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) {
        handle_openssl_errors();
    }

    if (!EVP_CipherInit(cipher_ctx, cipher, key, iv, DECRYPT))
        handle_openssl_errors();

    // Read-decrypt-write loop
    while ((n_read = fread(buf_in, 1, BUFSIZ, f_in)) > 0) {
        if (!EVP_CipherUpdate(cipher_ctx, buf_out, &update_len, buf_in, (int) n_read)) {
            handle_openssl_errors();
        }
        if (fwrite(buf_out, 1, update_len, f_out) != (size_t) update_len) {
            perror("fwrite failed");
            EVP_CIPHER_CTX_free(cipher_ctx);
            return 0;
        }
    }

    // Finalize decryption
    if (!EVP_CipherFinal_ex(cipher_ctx, buf_out, &final_len)) {
        handle_openssl_errors();
    }
    if (fwrite(buf_out, 1, final_len, f_out) != (size_t) final_len) {
        perror("fwrite failed");
        EVP_CIPHER_CTX_free(cipher_ctx);
        return 0;
    }

    EVP_CIPHER_CTX_free(cipher_ctx);
    return 1;
}
