# using the encrypted text with the well known plaintext to obtain the keystream and then forge the required cookie

import json
import os
from asyncio import timeout

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import long_to_bytes, bytes_to_long

os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *

HOST = "130.192.5.212"
PORT = 6552
BLOCK_SIZE = AES.block_size


def main():

    try:
        s = remote(HOST, PORT)
    except ConnectionRefusedError:
        print("ERROR Connecting")
        exit(1)
    #s.interactive()

    username_bytes = b"A"*7 + pad(b"true", BLOCK_SIZE) + b"A"*9

    s.sendlineafter(delim=b"Username: ", data=username_bytes, timeout=3)


    # server-side: cookie = f"username={username}&admin=false" - AES encryption
    # server sends "long" data
    # receive a long -> transform in int (not a string) -> transform in bytes
    token_enc = long_to_bytes(int(s.recvline(keepends=False, timeout=1)))

    s.sendlineafter(delim=b"> ", data=b"flag", timeout=1)

    # 16 bytes block for AES - using ECB so i change the encrypted version of true in the second block
    # username=AAAAAAA || trueAAAAAAAAAAAA || AAAAAAAAA&admin= || falseAAAA


    forged_token = bytes_to_long(token_enc[:16] + token_enc[32:48] + token_enc[16:32])

    s.sendlineafter(delim=b"Cookie: ", data=str(forged_token).encode(), timeout=1)


    try:
        print(s.recvuntil(timeout=1, delims=b"}").decode())
    except EOFError:
        print("\nFAIL")

    s.close()
















if __name__ == '__main__':
    main()
