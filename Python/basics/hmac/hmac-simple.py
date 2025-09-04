from Crypto.Hash import HMAC, SHA256

# openssl dgst -sha256 -hmac "$(cat key.bin)" data.bin

if __name__ == '__main__':
    # Data to verify
    data_to_verify = 'Hello World!'.encode()
    with open('utils/data.bin', 'wb') as f:
        f.write(data_to_verify)

    # Replace with a secret key (ensure it's a byte string)
    secret_key = 'mysecretkey123'.encode()

    with open('utils/key.bin', 'wb') as f:
        f.write(secret_key)


    # Create HMAC object using the secret key and SHA256
    h = HMAC.new(secret_key, digestmod=SHA256)

    # Feed data into the HMAC object
    h.update(data_to_verify)

    # Print the computed HMAC as a hexadecimal string
    print(f"Computed HMAC: {h.hexdigest()}")