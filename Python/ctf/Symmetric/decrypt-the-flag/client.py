from os import wait3
from string import ascii_letters, printable

import numpy as np
from pwnlib.tubes.remote import remote
from Crypto.Util.strxor import strxor

# vulnerability, keystream reuse with chacha20

HOST = "130.192.5.212"
PORT = 6561

def main():
    s = remote(HOST, PORT)
    #s.interactive()

    ciphertexts = []

    # offering the seed
    s.sendlineafter(delim=b"> ", data=b"0", timeout=1)

    # obtaining server's data
    received = s.recvlines(keepends=False, timeout=1, numlines=2)

    # extracting the secret
    ciphertexts.append(bytes.fromhex(received[1].decode()))

    s.sendlineafter(delim=b"(y/n)", data=b"y", timeout=1)
    s.sendlineafter(delim=b"message? ", data=b"0"*46, timeout=1)


    received = s.recvline(keepends=False, timeout=1)
    ciphertexts.append(bytes.fromhex(received.decode()))

    print(ciphertexts)

    s.close()

    keystream = strxor(b"0"*46, ciphertexts[1])



    print("Keystream is: ", keystream.hex(), "Length: ", len(keystream))


    plaintext = strxor(ciphertexts[0], keystream)
    print("----\n",plaintext.decode(),"\n----")


if __name__ == '__main__':
    main()