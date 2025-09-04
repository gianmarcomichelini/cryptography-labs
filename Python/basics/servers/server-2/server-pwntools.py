import base64
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from pwnlib.tubes.sock import *

from Exercises.Lectures.servers.myconfig import *


def aes_256_cbc(msg, iv, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)

    msg_bytes = msg.encode()
    msg_padded = pad(msg_bytes, AES.block_size)
    ct_bytes = cipher.encrypt(msg_padded)
    ct = base64.b64encode(ct_bytes).decode()

    return ct


if __name__ == '__main__':

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Socket created')

    try:
        s.bind((HOST, PORT))
    except socket.error as msg:
        print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()
    print('Socket bind complete')

    s.listen(10)
    print('Socket now listening')

    while True:
        conn, addr = s.accept()
        print('A new encryption requested by ' + addr[0] + ':' + str(addr[1]))

        key = b'\x00' * 32
        iv = b'\x00' * 16

        input0 = conn.recv(1024).decode()
        message = "This is what I received: " + input0 + " -- END OF MESSAGE"
        print("Plaintext: " + message)


        plaintext = "BEFORE-->" + message + "<--AFTER"
        ciphertext = aes_256_cbc(plaintext, iv, key).encode()

        conn.send(ciphertext)
        conn.close()

    s.close()
