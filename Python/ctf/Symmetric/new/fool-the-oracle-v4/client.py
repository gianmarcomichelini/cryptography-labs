# server encrypts data with AES-192 in ECB mode (ECB performs deterministic encryption?)
# ECB byte-by-byte decryption attack

import os

os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *
from Crypto.Cipher import AES

HOST = "130.192.5.212"
PORT = 6544

# padding1 is between 1 and 6 B long
# padding2 is 10-padding1 B long


# the flag: 46 bytes, with unkown part of 36 bytes - pad2 (variable) is considered at the beginning
# pad2 is for sure < 9 => 4 blocks are enough to contain the flag+ pad
# ????CRYPTO25{SSSSSSS SSSSSSSSSSSSSSSS SSSSSSSSSSSSS}PP


# example: pad1=5 => pad2=5: FIRST ITERATION
# 1                2                3                4                5                6                7                8                9                1                2                3                4
# the server encrypts:
# MMMMMAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAG AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAM MMMMRYPTO25{SSSS SSSSSSSSSSSSSSSS SSSSSSSSSSSSSSSS }PPPPPPPPPPPPPPP
#
# the initial aligner is
#      AAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAA?
# padding after the guessed byte (to contain pad2+flag) is
#                                                                     AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAA AAAAAAAAAAAAAAA?
#                                                    ----------------                                                    ----------------
#                                                    CHECKING                                                            CHECKING (starting from the second padding)
# first padding                                      ----------------                                                    ----------------

# the aligner is decreased after a byte is found

secret = b''
server = remote(HOST, PORT)

m = b'A' * ((AES.block_size) * 3 - 9)   # 38 B of As
# get pad len simply by looking when a new block is created
server_first_pad = 0
for j in range(1, 9):
    menu = server.recvuntil(b">")
    server.sendline(b"enc")
    server.recvuntil(b">")
    server.sendline(m.hex().encode())
    ciphertext_hex = server.recvline().strip().decode()
    ciphertext = bytes.fromhex(ciphertext_hex)

    if ciphertext[16:31] == ciphertext[32:47]:  # equal adjacent blocks of As
        server_first_pad = 10 - j
        break
    m = m + b'A'

print(f"First pad applied by the server: {server_first_pad}")
print(f"Second pad applied by the server: {10-server_first_pad}")

# aligner is used to align the unknown byte to a know position in the block
# I need 4 blocks because the flag contains also the second padding
aligner = b"A" * (4 * AES.block_size - 1 - server_first_pad)

# given by server
server_second_pad = 10 - server_first_pad

# counting also the second pad in the flag
len_flag = server_second_pad + len("CRYPTO25{}") + 36

# len_flag is flexible because contains also the flexible second padding inserted by the server
for i in range(len_flag - 1):   # last char is }
    # specify which block in the ciphertext must be checked for each guessed byte
    a = 4
    b = 8
    pad = (4 * AES.block_size - i - 1) * b'A'

    if i < server_second_pad:
        guessable = range(256)  # try all values of 1 byte
    else:
        guessable = string.printable

    for guess in guessable:

        if i < server_second_pad:
            guess = bytes([guess])  # extract a (single) byte from an int (so use [])
        else:
            guess = guess.encode()  # byte encoding

        # server does: payload = padding1 + data + padding2 + flag
        # the aligner already counts the pad1
        message = aligner + secret + guess + pad
        #print(message)

        menu = server.recvuntil(b">")
        # print(menu.decode())
        server.sendline(b"enc")
        server.recvuntil(b">")
        server.sendline(message.hex().encode())
        ciphertext_hex = server.recvline().strip().decode()
        ciphertext = bytes.fromhex(ciphertext_hex)
        # print(message)

        # print(guess)

        # checking that 4th block and 7th block are equal (byte-by-byte, like a classic ECB decryption attack)
        if ciphertext[(a - 1) * AES.block_size:a * AES.block_size] == ciphertext[
                                                                      (b - 1) * AES.block_size:b * AES.block_size]:
            print(message)
            secret += guess
            # secret contains also the second padding added by the server
            print(f"Operation [{i+1}/{len_flag}], guessed byte is:", secret)
            if len(aligner) == 0:
                secret = secret[1:]

            # adding a char for the next guess, so removing a byte from aligner
            aligner = aligner[1:]

            # found a char, so go next, the alogorithm stops by itself while reaching len_flag-1
            break

print(secret)