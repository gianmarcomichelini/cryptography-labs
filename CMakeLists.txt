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
        src/rand/randoms_bytewise_operations.c
        src/rand/randoms_create_randoms.c
        include/rand/rand.h
        include/utils.h
        include/hashing/hashing.h
        src/hashing/hashing_md5_basics.c
)

target_link_libraries(ctf_lab_runner OpenSSL::SSL OpenSSL::Crypto)