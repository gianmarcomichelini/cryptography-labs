import hashlib

if __name__ == '__main__':
    filename = "utils/data.bin" # -> 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069

    with open(filename, "r") as f:
        data = f.read().encode()

    m = hashlib.sha256()
    m.update(data)
    print(f"The digest - sha256 - (in hex) is: {m.hexdigest()}")
    print(f"The digest - sha256 -(in byte) is: {m.digest()}")