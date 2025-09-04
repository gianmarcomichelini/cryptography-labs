import requests
from Crypto.Util.number import long_to_bytes, bytes_to_long
import time

HOST = "http://130.192.5.212:6522"


def sanitize_field(field: str) -> str:
    return field \
        .replace(" ", "_") \
        .replace("/", "_") \
        .replace("&", "") \
        .replace(":", "") \
        .replace(";", "") \
        .replace("<", "") \
        .replace(">", "") \
        .replace('"', "") \
        .replace("'", "") \
        .replace("(", "") \
        .replace(")", "") \
        .replace("[", "") \
        .replace("]", "") \
        .replace("{", "") \
        .replace("}", "") \
        .replace("=", "")


def derive_keystream(ciphertext: bytes, known_plaintext: bytes) -> bytes:
    return bytes([c ^ p for c, p in zip(ciphertext, known_plaintext)])


def xor_data(data: bytes, keystream: bytes) -> bytes:
    return bytes([a ^ b for a, b in zip(data, keystream)])


if __name__ == "__main__":
    s = requests.Session()

    # Login using known username
    username = "AAAAAA"
    print("[*] Logging in...")
    r = s.get(f"{HOST}/login", params={"username": username, "admin": 1})
    login_data = r.json()

    nonce = login_data['nonce']
    enc_cookie = login_data['cookie']
    enc_cookie_bytes = long_to_bytes(enc_cookie)

    # Reconstruct plaintext used in the encryption
    now = int(time.time())
    expire = now + 30 * 24 * 60 * 60  # Same as server
    known_plaintext = f"username={sanitize_field(username)}&expires={expire}&admin=1".encode()
    print(f"[+] Reconstructed plaintext: {known_plaintext.decode()}")

    # Derive keystream
    keystream = derive_keystream(enc_cookie_bytes, known_plaintext)

    # Calculate target expire date based on session['admin_expire_date']
    # We know the server sets: session['admin_expire_date'] = now - random(10..266) * 24*60*60
    # So we can guess a range based on now - avg(10..266) ≈ 138 days ago
    target_offset_days = 295  # Target middle of the valid range
    for i in range(10, 266):
        target_expire = now - (i * 24 * 60 * 60) + (target_offset_days * 24 * 60 * 60)
        target_plaintext = f"username={sanitize_field(username)}&expires={int(target_expire)}&admin=1".encode()
        print(f"[+] Forging plaintext: {target_plaintext.decode()}")

        # Encrypt forged plaintext using derived keystream
        forged_cookie_bytes = xor_data(target_plaintext, keystream)
        forged_cookie_int = bytes_to_long(forged_cookie_bytes)

        # Send to /flag with forged cookie
        print("[*] Sending forged request to /flag...")
        r = s.get(f"{HOST}/flag", params={
            "nonce": nonce,
            "cookie": forged_cookie_int
        })

        print("[+] Server response:")
        print(r.text)
