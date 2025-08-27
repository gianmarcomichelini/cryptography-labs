#include "utils.h"

enum MODE {
    ENCRYPT = 1,
    DECRYPT = 0
};

/**
 * @brief Encrypts a plaintext buffer using a symmetric cipher.
 *
 * @param[in]  plaintext       Pointer to input data
 * @param[in]  iv              Initialization vector
 * @param[in]  key             Symmetric key
 * @param[in]  plaintext_len   Length of the plaintext in bytes
 * @param[in]  cipher          EVP_CIPHER describing the cipher (e.g., EVP_aes_256_cbc())
 * @param[out] ciphertext      Pointer to buffer where encrypted data will be written
 * @param[out] ciphertext_len  Pointer to store resulting ciphertext length
 *
 * @return 1 on success, 0 on failure
 */
int enc_symm_encrypt_compute(const unsigned char *plaintext, unsigned char *ciphertext,
                             const unsigned char *iv, const unsigned char* key,
                             const int plaintext_len, int *ciphertext_len,
                             const EVP_CIPHER* cipher) {
    if (!plaintext || !ciphertext || !iv || !key || !ciphertext_len || !cipher) {
        fprintf(stderr, "[ERROR] Null pointer passed to enc_symm_encrypt_compute.\n");
        return 0;
    }

    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) handle_openssl_errors();

    if (EVP_CipherInit(cipher_ctx, cipher, key, iv, ENCRYPT) != 1)
        handle_openssl_errors();

    int update_len = 0, final_len = 0;
    int ct_len = 0;

    if (EVP_CipherUpdate(cipher_ctx, ciphertext, &update_len, plaintext, plaintext_len) != 1)
        handle_openssl_errors();
    ct_len += update_len;

    if (EVP_CipherFinal_ex(cipher_ctx, ciphertext + ct_len, &final_len) != 1)
        handle_openssl_errors();
    ct_len += final_len;

    *ciphertext_len = ct_len;

    EVP_CIPHER_CTX_free(cipher_ctx);
    return 1;
}

/**
 * @brief Encrypts an input file using a symmetric cipher and writes ciphertext to output file.
 *
 * @param[out] ciphertext      Buffer to store ciphertext
 * @param[in]  iv              Initialization vector
 * @param[in]  key             Symmetric key
 * @param[out] ciphertext_len  Pointer to store total ciphertext length
 * @param[in]  cipher          EVP_CIPHER describing the cipher
 * @param[in]  f_in            Input FILE pointer
 * @param[in]  f_out           Output FILE pointer
 *
 * @return 1 on success, 0 on failure
 */
int enc_symm_encrypt_compute_from_file(unsigned char *ciphertext,
                                       const unsigned char *iv, const unsigned char *key,
                                       int *ciphertext_len,
                                       const EVP_CIPHER *cipher,
                                       FILE *f_in, FILE *f_out) {
    if (!ciphertext || !iv || !key || !ciphertext_len || !cipher || !f_in || !f_out) {
        fprintf(stderr, "[ERROR] Null pointer passed to enc_symm_encrypt_compute_from_file.\n");
        return 0;
    }

    int rc;
    int update_len = 0, final_len = 0;
    size_t n_read = 0, total_written = 0;
    unsigned char buf[BUFSIZ];

    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) handle_openssl_errors();

    if ((rc = EVP_CipherInit(cipher_ctx, cipher, key, iv, ENCRYPT)) != 1)
        handle_openssl_errors();

    *ciphertext_len = 0;
    while ((n_read = fread(buf, 1, BUFSIZ, f_in)) > 0) {
        if (!EVP_CipherUpdate(cipher_ctx, ciphertext + *ciphertext_len, &update_len, buf, (int)n_read))
            handle_openssl_errors();
        *ciphertext_len += update_len;
    }

    if (!EVP_CipherFinal_ex(cipher_ctx, ciphertext + *ciphertext_len, &final_len))
        handle_openssl_errors();
    *ciphertext_len += final_len;

    size_t n_written;
    while (total_written < (size_t)*ciphertext_len) {
        n_written = fwrite(ciphertext + total_written, 1, *ciphertext_len - total_written, f_out);
        if (n_written == 0) {
            if (ferror(f_out)) {
                perror("[ERROR] fwrite failed");
                EVP_CIPHER_CTX_free(cipher_ctx);
                return 0;
            }
        }
        total_written += n_written;
    }

    EVP_CIPHER_CTX_free(cipher_ctx);
    return 1;
}