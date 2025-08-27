#include <string.h>
#include "utils.h"
#include "enc_symm/enc_symm_utils.h"
#include "random/random_utils.h"
#define MAX_ENC_LEN 1000000

/**
 * @brief Test AES-256-CBC symmetric encryption/decryption on a file.
 *
 * Performs:
 *  - Random key and IV generation
 *  - File encryption to "../data/symm_decrypt.txt"
 *  - File decryption to "../data/symm_decrypt_result.txt"
 *
 * @return 0 on success, 1 on failure
 */
extern int test_encrypt_aes256cbc_compute_from_file(void) {
    unsigned char *ciphertext = OPENSSL_malloc(MAX_ENC_LEN);
    int ciphertext_len = 0;

    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    const int key_len = EVP_CIPHER_get_key_length(cipher);
    unsigned char *key = OPENSSL_malloc(key_len);
    const int iv_len = EVP_CIPHER_get_block_size(cipher);
    unsigned char *iv = OPENSSL_malloc(iv_len);

    if (generate_random_bytes(key, key_len) != 0 ||
        generate_random_bytes(iv, iv_len) != 0) {
        handle_openssl_errors();
        return EXIT_FAILURE;
    }

    FILE *f_in = fopen("../data/symm_encrypt.txt", "rb");
    if (!f_in) {
        perror("fopen failed for input file");
        return EXIT_FAILURE;
    }

    FILE *f_out = fopen("../data/symm_decrypt.txt", "wb");
    if (!f_out) {
        perror("fopen failed for output file");
        fclose(f_in);
        return EXIT_FAILURE;
    }

    if (!enc_symm_encrypt_compute_from_file(ciphertext, iv, key, &ciphertext_len,
                                            cipher, f_in, f_out)) {
        printf("ERROR: not able to encrypt the file\n");
        fclose(f_in);
        fclose(f_out);
        return EXIT_FAILURE;
    }

    fclose(f_in);
    fclose(f_out);

    printf("The ciphertext can be found at: ../data/symm_decrypt.txt\n");

    // Reopen ciphertext for decryption
    f_out = fopen("../data/symm_decrypt.txt", "rb");
    FILE *f_result = fopen("../data/symm_decrypt_result.txt", "wb");
    if (!f_out || !f_result) {
        perror("fopen failed for decryption files");
        if (f_out) fclose(f_out);
        if (f_result) fclose(f_result);
        return EXIT_FAILURE;
    }

    if (!enc_symm_decrypt_compute_from_file(key, iv, cipher, f_out, f_result)) {
        printf("ERROR: not able to decrypt the file\n");
        fclose(f_out);
        fclose(f_result);
        return EXIT_FAILURE;
    }

    printf("The plaintext (decrypted) can be found at: ../data/symm_decrypt_result.txt\n");

    OPENSSL_free(key);
    OPENSSL_free(iv);
    OPENSSL_free(ciphertext);
    fclose(f_out);
    fclose(f_result);

    return EXIT_SUCCESS;
}