#include "utils.h"

enum MODE {
    ENCRYPT = 1,
    DECRYPT = 0
};

/**
 * @brief Decrypts data from an input file using a symmetric cipher and writes the result to an output file.
 *
 * @param[in]  key     Pointer to the symmetric key
 * @param[in]  iv      Pointer to the initialization vector
 * @param[in]  cipher  EVP_CIPHER describing the cipher (e.g., EVP_aes_256_cbc())
 * @param[in]  f_in    Input FILE pointer to read encrypted data
 * @param[in]  f_out   Output FILE pointer to write decrypted data
 *
 * @return 1 on success, 0 on failure
 */
int enc_symm_decrypt_compute_from_file(const unsigned char *key,
                                       const unsigned char *iv,
                                       const EVP_CIPHER *cipher,
                                       FILE *f_in, FILE *f_out) {
    if (!key || !iv || !cipher || !f_in || !f_out) {
        fprintf(stderr, "[ERROR] Null pointer provided to enc_symm_decrypt_compute_from_file.\n");
        return 0;
    }

    printf("[INFO] Starting symmetric decryption from file...\n");

    int update_len = 0, final_len = 0;
    size_t n_read = 0;
    unsigned char buf_in[BUFSIZ];
    unsigned char buf_out[BUFSIZ + EVP_CIPHER_block_size(cipher)];

    // Step 1: Create cipher context
    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) handle_openssl_errors();
    printf("[STEP 1] Cipher context created.\n");

    // Step 2: Initialize decryption
    if (!EVP_CipherInit(cipher_ctx, cipher, key, iv, DECRYPT))
        handle_openssl_errors();
    printf("[STEP 2] Cipher context initialized for decryption.\n");

    // Step 3: Read, decrypt, and write in chunks
    printf("[STEP 3] Decrypting input file in chunks...\n");
    while ((n_read = fread(buf_in, 1, BUFSIZ, f_in)) > 0) {
        if (!EVP_CipherUpdate(cipher_ctx, buf_out, &update_len, buf_in, (int)n_read))
            handle_openssl_errors();

        if (fwrite(buf_out, 1, update_len, f_out) != (size_t)update_len) {
            perror("[ERROR] fwrite failed during decryption");
            EVP_CIPHER_CTX_free(cipher_ctx);
            return 0;
        }
    }
    printf("[STEP 3] Decryption of chunks completed.\n");

    // Step 4: Finalize decryption (handle padding)
    if (!EVP_CipherFinal_ex(cipher_ctx, buf_out, &final_len))
        handle_openssl_errors();

    if (fwrite(buf_out, 1, final_len, f_out) != (size_t)final_len) {
        perror("[ERROR] fwrite failed during final decryption step");
        EVP_CIPHER_CTX_free(cipher_ctx);
        return 0;
    }
    printf("[STEP 4] Final decryption step completed. Output written.\n");

    // Step 5: Clean up
    EVP_CIPHER_CTX_free(cipher_ctx);
    printf("[INFO] Symmetric decryption completed successfully.\n\n");

    return 1;
}