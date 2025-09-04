from base64 import b64encode
import json

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def aes_ofb(msg, k, iv):
    cipher = AES.new(k, AES.MODE_OFB, iv)
    ct_bytes = cipher.encrypt(msg)

    ct = b64encode(ct_bytes).decode()
    iv_decoded = b64encode(iv).decode()

    result = json.dumps({"algo": "aes-128-ofb", "iv": iv_decoded, "ciphertext": ct})
    print(result)


def aes_ctr(msg, k):
    cipher = AES.new(k, AES.MODE_CTR)
    ct_bytes = cipher.encrypt(msg)  # no need for padding
    nonce = b64encode(cipher.nonce).decode('utf-8') # created implicitly by the aes module
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({"algo": "aes-128-ctr","nonce": nonce,"iv": b64encode(iv).decode(), "ciphertext": ct})

    print(result)



def aes_cfb(msg, k, iv):
    block_size = AES.block_size

    msg_padded = pad(msg, block_size)

    cipher = AES.new(k, AES.MODE_ECB)  # aes in electronic code book mode

    chunks = [msg_padded[i:i+block_size] for i in range(0, len(msg_padded), block_size)]

    pre_cipher = cipher.encrypt(iv)
    ciphertext = bytes([a^b for a,b in zip(pre_cipher, chunks[0])]) # dividing the plaintext in chunks

    for chunk in chunks[1:]:
        pre_cipher = cipher.encrypt(ciphertext)
        ciphertext = bytes([a^b for a,b in zip(pre_cipher, chunk)])

    result = json.dumps({"algo": "aes-128-cfb", "iv": b64encode(iv).decode(), "ciphertext": b64encode(ciphertext).decode()})
    print(result)

if __name__ == '__main__':
    plaintext = b'ThisIsTheStringToEncrypt'
    key = b'\x00' * 16
    iv = b'\x00' * 16

    aes_cfb(plaintext, key, iv)

    aes_ctr(plaintext, key)

    aes_ofb(plaintext, key, iv)





