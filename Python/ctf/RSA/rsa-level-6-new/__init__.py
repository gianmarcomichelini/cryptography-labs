from Crypto.Util.number import long_to_bytes, bytes_to_long
from math import gcd

import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *


HOST = "130.192.5.212"
PORT = 6646

server = remote(HOST, PORT)

e = 65537

#server sends number as str(num).encode()
c = int(server.recvline().strip())
#print(c)

# BLINDING ATTACK
# exploiting RSA multiplicative properties (homomorphism)
# hide ("blinding") the plaintext m behind a random multiplier s
#   the server will encrypt arbitrary values and decrypt-chosen ciphertexts (oracle behavior).

s2 = 2
server.sendline(b'e' + str(s2).encode())
s2_enc = int(server.recvline().strip()) # 2^e mod n
print(f"3^e (mod n): {s2_enc}")

s3 = 3
server.sendline(b'e' + str(s3).encode())
s3_enc = int(server.recvline().strip()) # 3^e mod n
print(f"2^e (mod n): {s3_enc}")

# extracting a multiple of the modulo from both integers
x = s3**e - s3_enc   # 3^e - (3^e  mod n) = k1 n
y = s2**e - s2_enc  #  2^e - (2^e  mod n) = k2 n

# x and y are much smaller, so compute the gcd

# the modulus n is obtained by the non coprimes x and y, because k1 n != k2 n
n = gcd(x, y)       #  gcd(k1*n, k2*n) = n
print(n)


# (3^e m^e) mod n = (3 m)^e mod n

c2 = (s3_enc * c) % n
server.sendline(b'd' + str(c2).encode())

# let decrypt the message by the oracle
#   s3 m = (3 m)^e ^d mod n = (3 m) mod n
s3m = int(server.recvline().strip())

# ensure that the modular inverse exists, iff gcd = 1
gcd = gcd(s3, n)
print(gcd) # = 1, modular inverse exists

# compute modular inverse of s3
inv_s = pow(s3, -1, n)

# unblind the plaintext (removing the blinding factor)
# ((3 m) mod n) (3^-1 mod n) = m mod n
unblinded_m = (s3m * inv_s) % n
unblinded_m = long_to_bytes(unblinded_m)
print(unblinded_m.decode())