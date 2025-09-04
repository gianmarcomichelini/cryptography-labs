#nc 130.192.5.212 6631
from pwnlib.tubes.remote import remote

from md4_ex1 import start_test

HOST= "130.192.5.212"
PORT = 6631

# find a collision in md4

def md4_collision():
    s = remote(HOST, PORT)

    string1, string2 = start_test()
    #string1 = b'\x17\xd02\x15\xdf\x8co\xa9+@u\xbc\xca\x00\xe3\xc723\xb2\x17T\xad\x028\xfe\x8d\xd6_\x02\x14T\xd0\xa8\xd7 }\xc6\xea;\x93\x8cPw\x00q/\xbd\x04^\xe7:~\xd1\x1c\x00\xba\x88W\\\x19\x99o\xd1\x99'
    #string2 = b'\x17\xd02\x15\xdf\x8co)+@u,\xca\x00\xe3\xc723\xb2\x17T\xad\x028\xfe\x8d\xd6_\x02\x14T\xd0\xa8\xd7 }\xc6\xea;\x93\x8cPw\x00q/\xbd\x04^\xe79~\xd1\x1c\x00\xba\x88W\\\x19\x99o\xd1\x99'

    print(f"String1: {string1.hex()}")
    print(f"String2: {string2.hex()}")

    #s.interactive()


    s.sendlineafter(b"Enter the first string: ", data=string1.hex().encode(), timeout=1)
    s.sendlineafter(b"Enter your second string: ", data=string2.hex().encode(), timeout=1)

    recv = s.recvlinesS(numlines=1, keepends=False, timeout=1)
    print(recv[0])

    s.close()



if __name__ == '__main__':
    md4_collision()

