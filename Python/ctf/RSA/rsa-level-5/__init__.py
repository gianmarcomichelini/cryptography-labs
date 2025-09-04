from Crypto.Util.number import long_to_bytes
from math import gcd

import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *


HOST = "130.192.5.212"
PORT = 6645

server = remote(HOST, PORT)

e = 65537

# multiplicative chosen-ciphertext attack
#   exploits the fact in RSA that encryption is multiplicatively homomorphic and here not padding is applied

# c = m^e (mod n)

# pick a random r, smaller than n but greater than 1
# sending (r^e c) (mod n) = (m r)^e mod n

# due to RSA multiplicative properties i don't need to know d, because the oracle operates for me
# receiving (r^e c)^d mod n = (r^1 c^d) mod n = (r m) mod n

# get m with a simple multiplication
#   m = (r m) * r^-1 (mod n)


#server sends number as str(num).encode()
n = int(server.recvline().strip())
#print(n)
c = int(server.recvline().strip())
#print(c)

while True:
    r = randint(2, n-1)
    if gcd(r, n) == 1:
        break
#modular inverse exists iff gcd(r, n) = 1.

c2 = (pow(r, e, n) * c) % n
server.sendline(b'd' + str(c2).encode())
rm = int(server.recvline().strip())
inv_r = pow(r, -1, n) 
m = (rm * inv_r) % n
m = long_to_bytes(m)
print(m) 