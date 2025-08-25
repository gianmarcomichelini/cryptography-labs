#include "utils.h"
#include "enc_asym/encryption_asymmetric_utils.h"

/**
 * Writes the public key of an RSA keypair to a PEM file.
 *
 * @param key_keypair      Pointer to an EVP_PKEY structure containing the RSA keypair.
 * @param key_public_file  Open FILE pointer to write the public key.
 *
 * This function serializes the public key in PEM format and writes it to the
 * provided file. If writing fails, it calls handle_openssl_errors() and terminates.
 * The file is closed after writing.
 */
void enc_asym_write_pkey_file(const EVP_PKEY* key_keypair, FILE *key_public_file) {
    if (!PEM_write_PUBKEY(key_public_file, key_keypair))
        handle_openssl_errors();  // handle OpenSSL write errors
    fclose(key_public_file);      // close the file after writing
}

/**
 * Writes the private key of an RSA keypair to a PEM file (unencrypted).
 *
 * @param key_keypair       Pointer to an EVP_PKEY structure containing the RSA keypair.
 * @param key_private_file  Open FILE pointer to write the private key.
 *
 * This function serializes the private key in PEM format and writes it to the
 * provided file without encryption. If writing fails, it calls handle_openssl_errors()
 * and terminates. The file is closed after writing.
 */
void enc_asym_write_private_key_file(const EVP_PKEY* key_keypair, FILE *key_private_file) {
    if (!PEM_write_PrivateKey(key_private_file, key_keypair, NULL, NULL, 0, NULL, NULL))
        handle_openssl_errors();  // handle OpenSSL write errors
    fclose(key_private_file);      // close the file after writing
}