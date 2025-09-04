import os

os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *
from Crypto.Cipher import AES

HOST = "130.192.5.212"
PORT = 6531

BLOCK_SIZE = AES.block_size
BLOCK_SIZE_HEX = 2 * BLOCK_SIZE

server = remote(HOST, PORT)


for i in range(128):
    try:
        server.recvuntil(b"Challenge")

        server.recvuntil(b"The otp I'm using: ")
        otp_hex = server.recv(64).strip().decode("utf-8")
        server.recv()

        server.sendline(otp_hex.encode())   # send the received OTP in order to let the server xor them and obtain 0

            # after encryption i will obtain the specific mode

        server.recvuntil(b"Output: ")

        output = server.recv(64)
        output_hex = output.strip().decode("utf-8")

        server.recvuntil(b"What mode did I use? (ECB, CBC)")
        if output_hex[:BLOCK_SIZE_HEX] == output_hex[BLOCK_SIZE_HEX: 2 * BLOCK_SIZE_HEX]:
            server.sendline(b"ECB")
        else:
            server.sendline(b"CBC")
        print(f"{i}: Sending...")

        response = server.recvline().strip().decode("utf-8")
        print(f"Response: {response}")
    except Exception as e:
        print(f"Error during cycle {i}: {e}")
        break
    ok = server.recvline().strip().decode("utf-8")
    print(f"OK?: {ok}")

flag= server.recvline().strip().decode("utf-8")
print(f"Flag: {flag}")

server.close()




