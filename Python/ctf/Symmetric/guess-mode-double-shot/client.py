import os

os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *
from Crypto.Cipher import AES

HOST = "130.192.5.212"
PORT = 6532

BLOCK_SIZE = AES.block_size
BLOCK_SIZE_HEX = 2 * BLOCK_SIZE

s = remote(HOST, PORT)

#s.interactive()

for i in range(128):
    try:


        # otp is 32 random bytes

        # data are 32 chosen bytes

        # server xor data with otp and print the output x2 times

        data_to_encrypt = b'0'*64
        s.sendlineafter(delim="Input: ", data=data_to_encrypt, timeout=1)

        s.recvuntil(b"Output: ")

        first_output = s.recv(64)
        first_output_hex = first_output.strip().decode("utf-8")

        s.sendlineafter(delim="Input: ", data=data_to_encrypt, timeout=1)

        s.recvuntil(b"Output: ")
        second_output = s.recv(64)
        second_output_hex = second_output.strip().decode("utf-8")

        print("First Output:  " + first_output_hex)
        print("Second Output: " + second_output_hex)


        # server asks for which mode it used
        s.recvuntil(b"What mode did I use? (ECB, CBC)")
        if first_output_hex == second_output_hex:
            s.sendline(b"ECB")
        else:
            s.sendline(b"CBC")
        print(f"{i}: Sending...")

        response = s.recvline().strip().decode("utf-8")
        print(f"Response: {response}")
    except Exception as e:
        print(f"Error during cycle {i}")
        break
    ok = s.recvline().strip().decode("utf-8")
    print(f"OK?: {ok}")

flag= s.recvline().strip().decode("utf-8")
print(f"Flag: {flag}")

s.close()




