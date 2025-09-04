import sys
from Crypto.Hash import HMAC, SHA224, SHA256, SHA384, SHA512

#  openssl dgst -sha256 -hmac "$(cat random1024-key.bin)" data.bin

# Function to read the key from a binary file
def read_key_from_file(filename):
    try:
        with open(filename, 'rb') as file:
            return file.read()
    except FileNotFoundError:
        print(f"ERROR: File {filename} not found.")
        sys.exit(1)

# Function to get the correct hash function based on input
def get_hash_function(hash_algo_string):
    if hash_algo_string == "SHA-224":
        return SHA224
    elif hash_algo_string == "SHA-256":
        return SHA256
    elif hash_algo_string == "SHA-384":
        return SHA384
    elif hash_algo_string == "SHA-512":
        return SHA512
    else:
        print(f"ERROR: Unsupported hash algorithm: {hash_algo_string}")
        sys.exit(1)

# Function to verify the file integrity using HMAC
def verify_hmac(key, hash_function, file_to_verify, received_hmac):
    # Compute HMAC for the file content
    h = HMAC.new(key=key, digestmod=hash_function)
    with open(file_to_verify, 'rb') as f:
        text_to_verify = f.read()
        h.update(text_to_verify)

    # Compare the calculated HMAC with the received one
    try:
        h.hexverify(received_hmac)
        print("✅ HMAC Verification Passed!")
    except ValueError:
        print("❌ HMAC Verification Failed!")
        print(f"Calculated HMAC: {h.hexdigest()}")
        print(f"Expected HMAC:   {received_hmac}")
        sys.exit(1)

# Main function to orchestrate the process
if __name__ == '__main__':

    # Retrieve file names from command line arguments
    key_file = "utils/random1024-key.bin"
    hash_algo_file = "utils/hashName.txt"
    received_hmac_file = "utils/received-hmac.txt"
    file_to_verify = "utils/data.bin"

    # Read the key from the binary file
    key = read_key_from_file(key_file)

    # Read the hash algorithm from the text file
    try:
        with open(hash_algo_file, 'r') as file:
            hash_algo_string = file.read().strip()
    except FileNotFoundError:
        print(f"ERROR: File {hash_algo_file} not found.")
        sys.exit(1)

    # Get the hash function based on the hash algorithm
    hash_function = get_hash_function(hash_algo_string)

    # Read the received HMAC from the binary file
    try:
        with open(received_hmac_file, 'rb') as file:
            received_hmac = file.read().strip()
            if not received_hmac:
                print("ERROR: received_hmac was empty")
                sys.exit(1)
    except FileNotFoundError:
        print(f"ERROR: File {received_hmac_file} not found.")
        sys.exit(1)

    # Verify the HMAC
    verify_hmac(key, hash_function, file_to_verify, received_hmac)