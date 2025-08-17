#ifndef HASHING_H
#define HASHING_H

extern int hashing_md5_compute(const unsigned char *message, size_t message_len, unsigned char **out_digest,
                               unsigned int *out_digest_len);

extern int hashing_hmac_sha256_compute(const unsigned char *key, size_t key_len,
                                       const unsigned char *message, size_t message_len,
                                       unsigned char **out_hmac, size_t *out_hmac_len);

extern int hashing_hmac_sha256_verify(const unsigned char *key, size_t key_len,
                                      const unsigned char *message, size_t message_len,
                                      const unsigned char *expected_digest, size_t expected_digest_len);

extern void hashing_print_context_info(EVP_MD_CTX *ctx);

extern void hashing_handle_md_errors(const char *err, EVP_MD_CTX *ctx);

extern int hashing_hmac_sha256_compute_from_file(FILE *fp,
                                          const unsigned char *key, const size_t key_len,
                                          unsigned char *hmac_out, unsigned int* hmac_out_len);


#endif //HASHING_H
