

# SERVER DOES: padding (not fixed, between 1 and 15) + data + flag
# then i add a dummy initial block for managing the padding
# need to work on the ct
# bw: padding=size(ct)-len(msg)-len(flag)

# 1                2                3                4                5                6                7                8                9
# the flag: 46 bytes, with unknown part of 36 bytes, then 3 blocks are enough to contain the secret
# CRYPTO25{SSSSSSS SSSSSSSSSSSSSSSS SSSSSSSSSSSSS}PP

# AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAC RYPTO25{SSSSSSSS SSSSSSSSSSSSSSSS SSSSSSSSSSSS}PP

# iterating for the unknown plaintext len (avoiding "CRYPTO25{" +"}")
# going to guess one unknown byte of the flag per iteration

import os

os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *
from Crypto.Cipher import AES

HOST = "130.192.5.212"
PORT = 6543
len_flag = len("CRYPTO25{}") + 36
# 43         cut 1 of g
# PPPPPAAAAAAAAAAA  PPPPPaaaaaaggg  PPPPPaaaaagggg                      PPPPPggggggggggg    PPPPPggggggggggg
# AAAAAAAAAAAAAAAA  gggggggggggggg  gggggggggggggg                      gggggggggggggggg    gggggggggggggggg
# AAAAAAAAAAAAAAAg  gggggggggggggg  gggggggggggggg          3 - 6       gggggggggggggggx    gggggggggggggggx
# AAAAAAAAAAAAAAAA  aaaaaaaaaaafff  aaaaaaaaaaffff                      aaaaafffffffffff    aaaaffffffffffff
# AAAAAAAAAAAAAAAA  ffffffffffffff  ffffffffffffff                      ffffffffffffffff    ffffffffffffffff
# AAAAAAAAAAAAAAAf  ffffffffffffff  ffffffffffffff                      ffffffffffffffff    ffffffffffffffff
# ffffffffffffffff  fppppppppppppp                                      fffppppppppppppp    ffpppppppppppppp
# ffffffffffffffff
# fffppppppppppppp


# AAAAAAAAAAAAAAAA
# ffffffffffffffff          1
# ffffffffffffffff
# ffffffffffffff

# AAAAAAAAAAAAAAAf
# ffffffffffffffff          2
# ffffffffffffffff
# fffffffffffff

# AAAAAAAAAAAAAAff
# ffffffffffffffff          3
# ffffffffffffffff
# ffffffffffff

# AAffffffffffffff
# ffffffffffffffff          15
# ffffffffffffffff
#

# PPPPPPPPPPAAAAAA
# AAAAAAAAAAAAAAAA
# AAAAAAAAAAAAAAAg
# AAAAAAAAAAAAAAAA
# AAAAAAAAAAAAAAAA
# AAAAAAAAAAAAAAAf
# ffffffffffffffff
# ffffffffffffffff
# fffffffffffff---

# PPPPPPPPPPPPPPPA
# AAAAAAAAAAAAAAAA
# AAAAAAAAAAAAAAC0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA


# All printable characters
printable = "-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{|}"

print("Looking in this set: " + printable)

secret = b''
server = remote(HOST, PORT)

m = b'A' * (AES.block_size)
for j in range(1, 15):  # or while and impose padding 1
    menu = server.recvuntil(b">")
    server.sendline(b"enc")
    server.recvuntil(b">")
    server.sendline(m.hex().encode())
    ciphertext_hex = server.recvline().strip().decode()
    ciphertext = bytes.fromhex(ciphertext_hex)

    if len(ciphertext) == 4 * AES.block_size:
        server_pad = j
        break
    m = m[1:]

print(f"Server pad: {server_pad}")
postfix = b"A" * (47 - server_pad - 9) + b"CRYPTO25{"

for i in range(len_flag - 9 - 1):
    a = 3
    b = 6
    pad = (3 * AES.block_size - i - 1 - 9) * b'A'

    for guess in printable:

        message = postfix + secret + guess.encode() + pad
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
        # print(f"{(a-1)*AES.block_size} : {a*AES.block_size}")

        if ciphertext[(a - 1) * AES.block_size:a * AES.block_size] == ciphertext[
                                                                      (b - 1) * AES.block_size:b * AES.block_size]:
            print("Found=" + guess)
            secret += guess.encode()
            #print(secret)
            if len(postfix) == 0:
                secret = secret[1:]
            postfix = postfix[1:]

            break

print("CRYPTO25{"+secret.decode(errors="replace") + "}")