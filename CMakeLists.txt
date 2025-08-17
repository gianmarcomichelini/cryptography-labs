cmake_minimum_required(VERSION 3.31)
project(ctf_crypto_labs C)

set(CMAKE_C_STANDARD 11)

set(OPENSSL_ROOT_DIR /opt/homebrew/opt/openssl@3)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

include_directories(include)

add_executable(ctf_lab_runner
        src/main.c
        src/utils.c
        tests/misc/test_bytewise_operations.c
        tests/random/test_generate_and_xor_random_numbers.c
        include/random/random_utils.h
        include/utils.h
        include/hashing/hashing_utils.h
        src/hashing/hashing_md5_compute.c
        src/hashing/hashing_hmac_compute.c
        src/hashing/hashing_hmac_verify.c
        tests/hashing/test_md5.c
        include/tests/tests.h
        tests/hashing/test_hmac_sha256_compute.c
        tests/hashing/test_hmac_sha256_verify.c
        src/random/random_seed_prng.c
        src/random/random_generate_bytes.c
        tests/hashing/test_hmac_compute_from_file.c
        src/hashing/hashing_hmac_compute_from_file.c
        src/hashing/hashing_utils.c
        include/enc_symm/encryption_symmetric_utils.h
        tests/enc_symm/test_encrypt_decrypt_aes256cbc_compute.c
        src/enc_symm/enc_symm_encrypt_compute.c
        src/enc_symm/enc_symm_encrypt_compute_from_file.c
        tests/enc_symm/test_encrypt_aes256cbc_compute_from_file.c
        src/enc_symm/enc_symm_decrypt_compute_from_file.c
)

target_link_libraries(ctf_lab_runner OpenSSL::SSL OpenSSL::Crypto)