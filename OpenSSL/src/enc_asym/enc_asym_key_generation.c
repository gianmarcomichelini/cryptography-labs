#include "utils.h"
#include "enc_asym/encryption_asymmetric_utils.h"


void enc_asym_key_generation(EVP_PKEY **rsa_keypair, const unsigned int n_bits) {
    if ((*rsa_keypair = EVP_RSA_gen(n_bits)) == NULL) {
        handle_openssl_errors();
    }
}
