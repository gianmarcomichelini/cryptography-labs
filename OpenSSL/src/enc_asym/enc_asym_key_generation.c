#include "utils.h"
#include "enc_asym/enc_asym_utils.h"

/**
 * @brief Generates an RSA keypair of the specified size in bits.
 *
 * @param[out] rsa_keypair  Pointer to an EVP_PKEY pointer to store the generated keypair.
 * @param[in]  n_bits       Size of the RSA key in bits (e.g., 2048, 4096).
 *
 * @note The generated keypair is stored in *rsa_keypair. If generation fails,
 *       handle_openssl_errors() is called to report the error.
 */
void enc_asym_key_generation(EVP_PKEY **rsa_keypair, const unsigned int n_bits) {
    if (!rsa_keypair) {
        fprintf(stderr, "[ERROR] NULL pointer passed to enc_asym_key_generation.\n");
        return;
    }

    printf("[INFO] Generating RSA keypair with %u bits...\n", n_bits);

    *rsa_keypair = EVP_RSA_gen(n_bits);
    if (!*rsa_keypair) {
        fprintf(stderr, "[ERROR] RSA keypair generation failed.\n");
        handle_openssl_errors();
    } else {
        printf("[SUCCESS] RSA keypair generated successfully.\n\n");
    }
}