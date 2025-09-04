import base64
from sys import argv
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def aes_cbc(msg, iv, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)

    msg_bytes = msg.encode()
    msg_padded = pad(msg_bytes, AES.block_size)
    ct_bytes = cipher.encrypt(msg_padded)
    ct = base64.b64encode(ct_bytes).decode()

    print("This is the encrypted string:")
    print(ct)



if __name__ == '__main__':
    input_data = argv[1]
    # print(f"The input data is {input_data}")



    key = b'\x00' * 16
    iv = b'\x00' * 16

    aes_cbc(input_data, iv, key)

