#include "utils.h"
#include "enc_asym/enc_asym_utils.h"

/**
 * @brief Writes the public key of an RSA keypair to a PEM file.
 *
 * @param[in] key_keypair      Pointer to an EVP_PKEY structure containing the RSA keypair.
 * @param[in] key_public_file  Open FILE pointer to write the public key.
 *
 * @note The public key is serialized in PEM format and written to the provided file.
 *       The file is closed after writing.
 */
void enc_asym_write_pkey_file(const EVP_PKEY* key_keypair, FILE *key_public_file) {
    if (!key_keypair || !key_public_file) {
        fprintf(stderr, "[ERROR] Null pointer passed to enc_asym_write_pkey_file.\n");
        return;
    }

    printf("[INFO] Writing RSA public key to PEM file...\n");

    if (!PEM_write_PUBKEY(key_public_file, key_keypair)) {
        fprintf(stderr, "[ERROR] Failed to write public key to file.\n");
        handle_openssl_errors();
    } else {
        printf("[SUCCESS] Public key written successfully.\n");
    }

    fclose(key_public_file);
    printf("[INFO] Public key file closed.\n\n");
}

/**
 * @brief Writes the private key of an RSA keypair to a PEM file (unencrypted).
 *
 * @param[in] key_keypair       Pointer to an EVP_PKEY structure containing the RSA keypair.
 * @param[in] key_private_file  Open FILE pointer to write the private key.
 *
 * @note The private key is serialized in PEM format without encryption and written to
 *       the provided file. The file is closed after writing.
 */
void enc_asym_write_private_key_file(const EVP_PKEY* key_keypair, FILE *key_private_file) {
    if (!key_keypair || !key_private_file) {
        fprintf(stderr, "[ERROR] Null pointer passed to enc_asym_write_private_key_file.\n");
        return;
    }

    printf("[INFO] Writing RSA private key to PEM file (unencrypted)...\n");

    if (!PEM_write_PrivateKey(key_private_file, key_keypair, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "[ERROR] Failed to write private key to file.\n");
        handle_openssl_errors();
    } else {
        printf("[SUCCESS] Private key written successfully.\n");
    }

    fclose(key_private_file);
    printf("[INFO] Private key file closed.\n\n");
}