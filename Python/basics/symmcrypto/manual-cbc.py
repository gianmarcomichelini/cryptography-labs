import json
from base64 import b64encode

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes


def aes_cbc(msg, iv, key):
    block_size = 16  # 128-bit block size in bytes

    # some modes (namely ECB and CBC) require that the final block be padded before encryption - wikipedia
    msg_padded = pad(msg, block_size)

    cipher = AES.new(key, AES.MODE_ECB)

    # Split message into 128-bit (16-byte) chunks
    chunks = [msg_padded[i:i + block_size] for i in range(0, len(msg_padded), block_size)]

    # First block: XOR with IV before encryption
    pre_cipher = bytes([a ^ b for a, b in zip(chunks[0], iv)])
    ciphertext = cipher.encrypt(pre_cipher)

    encrypted_data = ciphertext  # Store final ciphertext output

    # Encrypt remaining blocks
    for chunk in chunks[1:]:
        pre_cipher = bytes([a ^ b for a, b in zip(chunk, ciphertext)])
        ciphertext = cipher.encrypt(pre_cipher)

    result = json.dumps({"iv": b64encode(iv).decode('utf-8'), "ciphertext": b64encode(ciphertext).decode('utf-8')})

    print(result)


if __name__ == '__main__':

    key = b'\x00' * 16  # AES 128-bit key   # otherwise, also get_random_bytes(16)
    iv = b'\x00' * 16  # IV must be 16 bytes
    msg = b"Hello, AES CBC !"  # Example plaintext message

    aes_cbc(msg, iv, key)
