//
// Created by gim on 10/08/25.
//

#ifndef TESTS_H
#define TESTS_H

extern int test_digest_md5_compute(void);

extern int test_hmac_sha256_compute(void);

extern int test_hmac_sha256_verify(void);

extern int test_bytewise_operations(void);

extern int test_xor_randoms_and_obtain_key(void);

extern int test_hmac_sha256_compute_from_file(void);

extern int test_encrypt_aes256_compute (void);

extern int test_encrypt_aes256cbc_compute_from_file (void);

extern int test_encrypt_aes256cbc_compute_from_file(void);

extern int test_bignum_basics(void);

extern int test_bignum_basic_operations(void);




#endif //TESTS_H
