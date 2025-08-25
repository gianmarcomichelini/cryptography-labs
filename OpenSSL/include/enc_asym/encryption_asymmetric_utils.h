#ifndef ENCRYPTION_ASYMMETRIC_UTILS_H
#define ENCRYPTION_ASYMMETRIC_UTILS_H

#include <openssl/rsa.h>
#include <openssl/pem.h>

extern void enc_asym_key_generation(EVP_PKEY **rsa_keypair, unsigned int n_bits);

extern void enc_asym_write_pkey_file(const EVP_PKEY *key_keypair, FILE *key_public_file);

extern void enc_asym_write_private_key_file(const EVP_PKEY *key_keypair, FILE *key_private_file);

extern void enc_asym_encrypt_RSA(const char plaintext[], EVP_PKEY *rsa_keypair);

extern void enc_asym_decrypt_RSA(const unsigned char* ciphertext,size_t ciphertext_len, EVP_PKEY *rsa_keypair);


#endif //ENCRYPTION_ASYMMETRIC_UTILS_H
