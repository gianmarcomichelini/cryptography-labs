import hashlib
import hmac
import json

from mykey import key

# echo -n "Hi there!" | openssl dgst -sha256 -hmac "mysecretkey123" -> ee7e7260bdefdbf8a0f5ca7be4b5a251b8f8fc453dbdc281c5f4fb1fd98b0242


if __name__ == '__main__':

    hash_function = hashlib.sha256

    jsonfile = "/utils/data.json"

    # check if the file exists and read data
    try:
        with open(jsonfile, "r") as json_data:
            data = json.load(json_data)
            received_hmac = data["hmac"]
            data_to_verify = data["Message"].encode()  # Ensure the message is in bytes

    except FileNotFoundError:
        # If file doesn't exist, create it with default values
        with open(jsonfile, "w+") as jfile:
            default_data = {"Message": "Hi there!",
                            "hmac": "ee7e7260bdefdbf8a0f5ca7be4b5a251b8f8fc453dbdc281c5f4fb1fd98b0242"}
            json.dump(default_data, jfile)

        # Read the newly created file
        with open(jsonfile, "r") as json_data:
            data = json.load(json_data)
            received_hmac = data["hmac"]
            data_to_verify = data["Message"].encode()  # Ensure the message is in bytes

    # Compute HMAC with the provided key and data
    computed_hmac = hmac.new(key, data_to_verify, digestmod=hash_function)


    # Compare computed HMAC with the received HMAC
    if computed_hmac.hexdigest() == received_hmac:
        print("✅ HMAC Verification Passed!")
    else:
        print("😩 HMAC Verification Failed!")
        print(computed_hmac.hexdigest())
        print(received_hmac)