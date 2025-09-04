# ACPA ECB

# CRYPTO25{df0b0f03-0bd4-4dc8-9043-bcdac301684c}

import os

os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *
from Crypto.Cipher import AES

HOST = "130.192.5.212"
PORT = 6544

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


# PPPPPPPPPAAAAAAA
# AAAAAAAAAAAAAAAA      #9
# AAAAAAAAAAAAAAAA
# P

# PPPPPPPPAAAAAAAA
# AAAAAAAAAAAAAAAA      #8
# AAAAAAAAAAAAAAAA
# PP

# PAAAAAAAAAAAAAAA
# AAAAAAAAAAAAAAAA      #1
# AAAAAAAAAAAAAAAA
# PPPPPPPPP

# All printable characters
printable = "-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{|}"

print("Looking in this set: " + printable)

secret = b''
server = remote(HOST, PORT)

m = b'A' * ((AES.block_size) * 3 - 9)
for j in range(1, 9):
    menu = server.recvuntil(b">")
    server.sendline(b"enc")
    server.recvuntil(b">")
    server.sendline(m.hex().encode())
    ciphertext_hex = server.recvline().strip().decode()
    ciphertext = bytes.fromhex(ciphertext_hex)

    if ciphertext[16:31] == ciphertext[32:47]:
        server_pad = 10 - j
        break
    m = m + b'A'

print(f"Server initial pad: {server_pad}")
postfix = b"A" * (4 * AES.block_size - 1 - server_pad)

final_pad = 10 - server_pad

len_flag = final_pad + len("CRYPTO25{}") + 36

for i in range(len_flag - 1):
    a = 4
    b = 8
    pad = (4 * AES.block_size - i - 1) * b'A'

    if (i < final_pad):
        guessable = range(256)
    else:
        guessable = printable

    for guess in guessable:

        if (i < final_pad):
            guess = bytes([guess])
        else:
            guess = guess.encode()

        message = postfix + secret + guess + pad
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
            print("Found=" + str(guess))
            secret += guess
            #print(secret)
            if len(postfix) == 0:
                secret = secret[1:]
            postfix = postfix[1:]

            break

print(secret.decode(errors="replace") + "}")