# using the encrypted text with the well known plaintext to obtain the keystream and then forge the required cookie

import json
import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *

HOST = "130.192.5.212"
PORT = 6521

username_bytes = b"aldo"

def xor_bytes(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

def main():
    s = remote(HOST, PORT)
    #s.interactive()

    s.sendlineafter(delim=b"> ", data=username_bytes, timeout=3)

    s.recvline(keepends=True,timeout=1)
    s.recvuntil(delims=b"This is your token: ",timeout=1)

    curr_line_b64 = s.recvline(keepends=False,timeout=1).decode()
    # print(curr_line_b64)

    nonce_b64_enc, token_b64_enc = curr_line_b64.split(".")  # not stripped because keepends' option is false
    ct = base64.b64decode(token_b64_enc)
    # print("Base64 ciphertext: ", base64.b64encode(ct))

    s.sendlineafter(delim=b"> ", data=b"flag", timeout=1)

    original_plaintext_bytes = json.dumps({"username": "aldo"}).encode()
    keystream = xor_bytes(original_plaintext_bytes, ct) # obtain the keystream

    target_plaintext = json.dumps({"admin": True}).encode()
    target_plaintext_padded = target_plaintext.ljust(len(original_plaintext_bytes), b' ')   # adding spaces to match the length

    forged_ciphertext = xor_bytes(keystream, target_plaintext_padded)

    token_to_send = f"{nonce_b64_enc}.{base64.b64encode(forged_ciphertext).decode()}"
    s.sendlineafter(delim=b"> ",data=token_to_send.encode(), timeout=1)

    print(s.recvuntil(timeout=1, delims=b"}").decode()) # response











if __name__ == '__main__':
    main()
