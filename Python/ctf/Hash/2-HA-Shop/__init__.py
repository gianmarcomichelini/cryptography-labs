# length extension attack
#   use the known implementation of md4 to extend the hash for a given string

#Original (signed): username=mat&value=10
#New one:           username=mat&value=10<PADDING>&value=1000
import hashlib
import os
from binascii import hexlify, unhexlify

os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *
from length_extender import run_length_extender


HOST = "130.192.5.212"
PORT = 6630

server = remote(HOST, PORT)
#server.interactive()

server.sendlineafter(b"Choose an option (1-3): ", b'1')
server.sendlineafter(b"Enter your name: ", b'mat')
server.recvuntil(b"Coupon: ")
msg_hex_bytes = server.recvline().strip()
server.recvuntil(b"MAC: ")
mac_bytes = server.recvline().strip()

print(msg_hex_bytes)
print(mac_bytes)

msg_bytes = bytes.fromhex(msg_hex_bytes.decode())
extra_data_bytes = b"&value=1000"

key_len = 16

print(msg_bytes)  # must be b'username=mat&value=10'

msg2_bytes, mac2_hex = run_length_extender(msg_bytes, extra_data_bytes, key_len, mac_bytes,Hfunction="SHA256")

print(">>> msg2_hex: ", msg2_bytes.hex(),"\n"
      ">>> mac2_hex: ", mac2_hex)



server.sendlineafter(b"Choose an option (1-3): ", b'2',timeout=1)

server.sendlineafter(b"Enter your coupon: ", msg2_bytes.hex().encode() ,timeout=1)

server.sendlineafter(b"Enter your MAC: ", mac2_hex.encode(), timeout=1)

print("====================================")
server.recvuntil(b"Result: ")
result = server.recvline().decode().strip()
print(result)
print("====================================")
