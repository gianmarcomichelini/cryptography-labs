#include <string.h>
#include "utils.h"
#include "enc_symm/encryption_symmetric_utils.h"
#include "random/random_utils.h"
#define MAX_ENC_LEN 1000000

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
    }

    FILE *f_in = fopen("../data/symm_encrypt.txt", "rb");
    if (!f_in) {
        perror("fopen failed for input file");
        return 1;
    }

    FILE *f_out = fopen("../data/symm_decrypt.txt", "wb");
    if (!f_out) {
        perror("fopen failed for output file");
        return 1;
    }

    if (!enc_symm_encrypt_aes256cbc_compute_from_file(ciphertext, iv, key, &ciphertext_len,
                                                      cipher, f_in, f_out)) {
        printf("ERROR: not able to encrypt the file\n");
        return 1;
    }

    fclose(f_in);
    fclose(f_out);

    printf("The ciphertext can be found at: ../data/symm_decrypt.txt\n");

    // Reopen ciphertext for decryption
    f_out = fopen("../data/symm_decrypt.txt", "rb");
    FILE *f_result = fopen("../data/symm_decrypt_result.txt", "wb");
    if (!f_out || !f_result) {
        perror("fopen failed for decryption files");
        return 1;
    }

    if (!enc_symm_decrypt_compute_from_file(key, iv, cipher, f_out, f_result)) {
        printf("ERROR: not able to decrypt the file\n");
        return 1;
    }

    printf("The plaintext (decrypted) can be found at: ../data/symm_decrypt_result.txt\n");

    OPENSSL_free(key);
    OPENSSL_free(iv);
    OPENSSL_free(ciphertext);
    fclose(f_out);
    fclose(f_result);

    return 0;
}
