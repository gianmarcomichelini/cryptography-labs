from pwn import *
from Crypto.Cipher import AES
import string

HOST = "130.192.5.212"
PORT = 6542

BLOCK_SIZE = AES.block_size  # = 16
PREFIX = "CRYPTO25{"
SUFFIX = "}"

KNOWN_LEN = len(PREFIX + SUFFIX)
known_flag = "CRYPTO25{"
secret = known_flag

TOTAL_FLAG_LEN = 46
UNKNOWN_LEN = TOTAL_FLAG_LEN - len(known_flag) - 1  # -1 for the closing brace, inserted at the last print

s = remote(HOST, PORT)

# SERVER DOES: padding (5 bytes) + data + flag
# then i add a dummy initial block for managing the padding

# 1                2                3                4                5                6                7                8                9
# the flag: 46 bytes, with unkown part of 36 bytes
# CRYPTO25{SSSSSSS SSSSSSSSSSSSSSSS SSSSSSSSSSSSS}PP

# input data (under my control): 6 blocks (because of 3 blocks of secret) - 1 for the plaintext
# MMMMMAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAC RYPTO25{SSSSSSSS SSSSSSSSSSSSSSSS SSSSSSSSSSSS}PP

# MMMMMAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAA? AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAC RYPTO25{SSSSSSSS SSSSSSSSSSSSSSSS SSSSSSSSSSSS}PP

# at the beginning:
# MMMMMAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAACRYPTO25{ AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAACRYPTO25{ SSSSSSSSSSSSSSSS SSSSSSSSSSSSSSSSS SSS}PPPPPPPPPP


# iterating for the unknown plaintext len (avoiding "CRYPTO25{" +"}")
# going to guess one unknown byte of the flag per iteration
for i in range(UNKNOWN_LEN):

    pad_len = (3 * BLOCK_SIZE - len(secret)) - 1  # now secret is already filled with "CRYPTO25{"
    pad = b"A" * pad_len

    # trying each possible byte
    for guessed_byte in string.printable:
        msg = b"A" * (BLOCK_SIZE-len("AAAAA")) + pad + secret.encode() + guessed_byte.encode() + pad  # beware of padding at the sides

        s.sendlineafter(b"> ", b"enc")
        # print(msg)
        s.sendlineafter(b"> ", msg.hex().encode())
        ct = bytes.fromhex(s.recvline().decode().strip())

        if ct[16:64] == ct[64:112]:
            secret += guessed_byte
            print(f"[{i + 1}/{UNKNOWN_LEN}] Found: {guessed_byte}")
            break

s.close()

# add final brace
print("\nFinal flag:")
print(secret+SUFFIX)
