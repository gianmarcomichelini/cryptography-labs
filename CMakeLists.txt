cmake_minimum_required(VERSION 3.31)
project(ctf_crypto_labs C)

set(CMAKE_C_STANDARD 11)

# Specify OpenSSL root directory if not found
set(OPENSSL_ROOT_DIR /opt/homebrew/opt/openssl@3)
# Find OpenSSL
find_package(OpenSSL REQUIRED)
# Include OpenSSL headers
include_directories(${OPENSSL_INCLUDE_DIR})

include_directories(include)

add_executable(ctf_lab_runner
        src/main.c            # dispatcher main
)