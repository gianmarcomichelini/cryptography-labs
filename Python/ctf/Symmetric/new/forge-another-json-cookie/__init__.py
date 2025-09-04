from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os

# Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *
import json
import base64

# ECB cut-and-paste attack
HOST = "130.192.5.212"
PORT = 6551

server = remote(HOST, PORT)

# Crafted name to align blocks for the ECB attack
name = (
        b"a" * 2 +  # 1st block: {"username": "aa
        b" " * 15 + b'"' +  # " escaped to \" -> " goes in the next line
        b"PPPPP" + b" " * 10 +  # the previews " + 15 bytes
        b" " * 15 + b'":' +  # again, " is escaped to \", and ": goes in the next line
        b" " * 14 + # the previews ": + 14 spaces for filling the line
        b" " * 15 + b"," +  # 15 spaces and ',' for filling another line
        b" " * 12 + b"true" +   # get a line with true (to copy and paste in the attack)
        b"PPPP" # pad to obatin the "false" of admin in another line
)
print(f"The crafted name is: |{name.decode()}|")


def debug():
    # create a token like the server would do
    token = json.dumps({
        "username": name.decode(),
        # "username": "mark",
        "admin": False  # initially mandatory!
    })

    print(token.encode())
    print(token)
    # token using name.encode():
    # b'{"username": "aa               \\"PPPPP                         \\":                             ,            truePPPP", "admin": false}'

    # Print plaintext blocks (16 bytes of blocks)
    print("------------")
    print("INITIAL TOKEN")
    print()
    for i in range(0, len(token), AES.block_size):
        block = token[i:i + AES.block_size]
        print(f"Block {(i // AES.block_size) + 1} [{i}:{i+AES.block_size-1}]: |{block}|")
    print("Initial token length: ", len(token))

    # Reconstructing plaintext to align admin=true
    token2 = (
            token[:16] +        # {"username": "aa
            token[112:128] +    # PPPP", "admin":
            token[96:112] +     #             true
            token[80:96] +      #                ,
            token[32:48] +      # "PPPPP
            token[64:80] +      # ":
            token[128:134]      # false}
    )
    print("------------")
    print("CRAFTED TOKEN")
    print()
    for i in range(0, len(token2), AES.block_size):
        block = token2[i:i + AES.block_size]
        print(f"Block {(i // AES.block_size) + 1} [{i}:{i+AES.block_size-1}]: |{block}|")
    print("Crafted token length: ", len(token2))

    # Encrypt original token
    key = get_random_bytes(32)  # # Local test key
    cipher = AES.new(key=key, mode=AES.MODE_ECB)

    print()

    enc_token2 = cipher.encrypt(pad(token.encode(), AES.block_size))
    print("Initial encrypted token length: ", len(enc_token2))

    # Rebuild token with reordered ciphertext blocks
    new_enc_token = (
            enc_token2[:16] +  # block 1
            enc_token2[112:128] +
            enc_token2[96:112] +
            enc_token2[80:96] +
            enc_token2[32:48] +
            enc_token2[64:80] +
            enc_token2[128:144]  # block 7: contains "true"
    )
    print("Crafted encrypted token length: ", len(new_enc_token))

    # Decrypt and check reconstructed plaintext
    cipher = AES.new(key=key, mode=AES.MODE_ECB)

    print()

    dec_token = unpad(cipher.decrypt(new_enc_token), AES.block_size)
    print("The token (JSON format  ) is: ", dec_token.decode())

    # converting the token to a python object
    user = json.loads(dec_token)
    print("The token (python object) is: ", user)


def ECB_cut_and_paste_with_json_cookie():
    # Send crafted name
    server.sendlineafter(b"> ", name)

    # Receive and decode original cookie
    server.recvuntil(b"This is your token: ")
    cookie1_b64 = server.recvline().strip()
    cookie1_b = base64.b64decode(cookie1_b64)
    print(f"Cookie1: {cookie1_b}, {len(cookie1_b)} bytes long")

    message = server.recvuntil(b"> ")
    #print(message.decode())

    server.sendline(b"flag")
    question = server.recvuntil(b'> ')
    #print(question.decode())

    adminCookie = (
            cookie1_b[:16] +
            cookie1_b[112:128] +
            cookie1_b[96:112] +
            cookie1_b[80:96] +
            cookie1_b[32:48] +
            cookie1_b[64:80] +
            cookie1_b[128:144]
    )
    print(f"My cookie is: {adminCookie}, Len: {len(adminCookie)}")

    adminCookie_b64 = base64.b64encode(adminCookie)
    print(adminCookie_b64)

    # Send forged token
    server.sendline(adminCookie_b64)

    # Receive result
    result = server.recv(4096)
    print(result.decode())


if __name__ == '__main__':
    debug()
    #ECB_cut_and_paste_with_json_cookie()

server.close()
