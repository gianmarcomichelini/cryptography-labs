from pwnlib.tubes.remote import remote

HOST = "130.192.5.212"
PORT = 6523

leak= b"mynamesuperadmin"
# server uses AES in cbc mode with key of 16 bytes (128 bits)

def main():
    s = remote(HOST, PORT)
    #s.interactive()

    s.sendlineafter(delim=b"> ", data=b"enc", timeout=1)

    pt = b"F" * 16
    s.sendlineafter(delim=b"> ", data=pt.hex().encode(), timeout=1)

    iv_line, ct_line = s.recvlines(numlines=2,keepends=False, timeout=1)
    # stored: IV: <40d382f246af49b7083df3aff1516fdb> + Encrypted: <ccb8391b8b31dce17397954e8e1594cf>
    print(iv_line.decode(), ct_line.decode())
    iv = bytes.fromhex(iv_line.decode().split()[1])
    ct = bytes.fromhex(ct_line.decode().split()[1])

    s.sendlineafter(delim=b"> ", data=b"dec", timeout=1)

    # text to decrypt
    s.sendlineafter(delim=b"> ", data=ct.hex().encode(), timeout=1)

    iv_pt_xored = bytes(a ^ b ^ c for a, b, c in zip(pt, leak, iv))
    # iv
    s.sendlineafter(delim=b"> ", data=iv_pt_xored.hex().encode(), timeout=1)


    response = s.recvlinesS(numlines=2, keepends=False,timeout=0.5)

    print("\nRESULTS --- ")
    print(response[0])
    if response[1] is not None:
        print("leak is: ", leak.hex())
        print("Dec:     ",response[1].split()[1])









if __name__ == '__main__':
    main()
