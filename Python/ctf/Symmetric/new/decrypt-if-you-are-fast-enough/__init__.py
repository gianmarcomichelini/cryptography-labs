import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *

HOST = "130.192.5.212" 
PORT = 6562


server = remote(HOST, PORT)
#server.interactive()
server.recvuntil(b"f)")
server.sendline(b"y")
server.recvuntil(b">")

# chosen-plaintext
# 46 bytes because the flag is supposed to be 46 B long
msg = b"A"*46
server.sendline(msg)
msg_enc_hex = server.recvline().decode()

server.recvuntil(b"f)")
server.sendline(b"f")

flag_enc_hex = server.recvline().decode()
flag_enc_b = bytes.fromhex(flag_enc_hex)
msg_enc_b = bytes.fromhex(msg_enc_hex)

print(f"Encrypted msg (hex): {msg_enc_hex}")
print(f"Encrypted msg (bytes): {msg_enc_b}")

print(f"Encrypted msg (hex): {flag_enc_hex}")
print(f"Encrypted msg (bytes): {flag_enc_b}")


# obtain the keystream from a simple operation on stream cipher
# ct = pt ^ ks
keystream = bytearray(msg)
for i in range(46):
    keystream[i] = msg_enc_b[i] ^ msg[i]



print(f"Keystream: {keystream.hex()}")

flag = bytearray(msg)

for i in range(46):
    flag[i] = flag_enc_b[i] ^ keystream[i]

print(flag.decode())

server.close()