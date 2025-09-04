from pwn import *
from Crypto.Cipher import AES
import string

HOST = "130.192.5.212"
PORT = 6541

BLOCK_SIZE = AES.block_size  # = 16
PREFIX = "CRYPTO25{"
SUFFIX = "}"

KNOWN_LEN = len(PREFIX + SUFFIX)
known_flag = "CRYPTO25{"
secret = ""

TOTAL_FLAG_LEN = len(PREFIX) + len(SUFFIX) + 36
UNKNOWN_LEN = TOTAL_FLAG_LEN - len(PREFIX) - len(SUFFIX)

s = remote(HOST, PORT)

# 1                2                3                4                5                6                7                8                9
# the flag: 46 bytes, with unkown part of 36 bytes
# CRYPTO25{SSSSSSS SSSSSSSSSSSSSSSS SSSSSSSSSSSSS}PP

# input data (under my control): 6 blocks (because of 3 blocks of secret) - 1 for the plaintext
# AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAC RYPTO25{SSSSSSSS SSSSSSSSSSSSSSSS  SSSSSSSSSSSS}PP

# AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAA? AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAC RYPTO25{SSSSSSSS SSSSSSSSSSSSSSSS  SSSSSSSSSSSS}PP

# when found the first block:
# AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA CRYPTO25{SSSSSSS AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA CRYPTO25{SSSSSSS SSSSSSSSSSSSSSSS SSSSSSSSSSSSS}PP


# iterating for the unknown plaintext len (avoiding "CRYPTO25{" +"}")
# going to guess one unknown byte of the flag per iteration
for i in range(TOTAL_FLAG_LEN):

    pad_len = (3 * BLOCK_SIZE - len(secret)) - 1
    pad = b"A" * pad_len

    # trying each possible byte
    for guessed_byte in string.printable:
        msg = pad + secret.encode() + guessed_byte.encode() + pad # beware of padding at the sides

        s.sendlineafter(b"> ", b"enc")
        #print(msg)
        s.sendlineafter(b"> ", msg.hex().encode())
        ct = bytes.fromhex(s.recvline().decode().strip())

        if ct[:48] == ct[48:96]:
            secret += guessed_byte
            print(f"[{i + 1}/{TOTAL_FLAG_LEN}] Found: {guessed_byte}")
            break

s.close()

# add final brace
print("\nFinal flag:")
print(secret)
