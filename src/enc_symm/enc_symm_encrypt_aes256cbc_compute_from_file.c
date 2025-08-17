#include "utils.h"

enum MODE {
    ENCRYPT = 1,
    DECRYPT = 0
};


int enc_symm_encrypt_aes256cbc_compute_from_file(unsigned char *ciphertext,
                                                 const unsigned char *iv, const unsigned char *key,
                                                 int *ciphertext_len,
                                                 const EVP_CIPHER *cipher,
                                                 FILE *f_in, FILE *f_out) {
    int rc;
    int update_len = 0, final_len = 0;
    size_t n_read = 0, total_written = 0;
    unsigned char buf[BUFSIZ];

    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) {
        handle_openssl_errors();
    }

    rc = EVP_CipherInit(cipher_ctx, cipher, key, iv, ENCRYPT);
    if (rc != 1) {
        handle_openssl_errors();
    }

    while ((n_read = fread(buf, 1, BUFSIZ, f_in)) > 0) {
        if (!EVP_CipherUpdate(cipher_ctx, ciphertext + *ciphertext_len, &update_len, buf, (int) n_read)) {
            handle_openssl_errors();
        }
        *ciphertext_len += update_len;
    }

    if (!EVP_CipherFinal_ex(cipher_ctx, ciphertext + *ciphertext_len, &final_len)) {
        handle_openssl_errors();
    }
    *ciphertext_len += final_len;


    size_t n_written;
    while (total_written < *ciphertext_len) {
        n_written = fwrite(ciphertext + total_written, 1, *ciphertext_len - total_written, f_out);
        if (n_written == 0) {
            if (ferror(f_out)) {
                perror("fwrite failed");
                break;
            }
        }
        total_written += n_written;
    }


    EVP_CIPHER_CTX_free(cipher_ctx);
    return 1;
}
