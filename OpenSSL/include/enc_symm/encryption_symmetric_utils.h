//
// Created by gim on 16/08/25.
//

#ifndef ENCRYPTION_SYMMETRIC_H
#define ENCRYPTION_SYMMETRIC_H
#include <openssl/evp.h>

extern int enc_symm_encrypt_compute(const unsigned char *plaintext, unsigned char *ciphertext,
                                           const unsigned char *iv, const unsigned char *key,
                                           int plaintext_len, int *ciphertext_len,
                                           const EVP_CIPHER *cipher);

extern int enc_symm_encrypt_compute(const unsigned char *plaintext, unsigned char *ciphertext,
                                           const unsigned char *iv, const unsigned char *key,
                                           int plaintext_len, int *ciphertext_len,
                                           const EVP_CIPHER *cipher);

extern int enc_symm_encrypt_aes256cbc_compute_from_file(unsigned char *ciphertext,
                                                        const unsigned char *iv, const unsigned char *key,
                                                        int *ciphertext_len,
                                                        const EVP_CIPHER *cipher,
                                                        const FILE *f_in, const FILE *f_out);

extern int enc_symm_decrypt_compute_from_file(const unsigned char *key,
                                                 const unsigned char *iv,
                                                 const EVP_CIPHER *cipher,
                                                 FILE *f_in, FILE *f_out);


#endif //ENCRYPTION_SYMMETRIC_H
