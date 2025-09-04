import Crypto.Random

argv1 = 5
argv2 = "./utils/out.txt"

if __name__ == '__main__':
    num_bytes = int(argv1)
    filename = argv2

    rand = Crypto.Random.get_random_bytes(num_bytes)

    with open(filename, 'wb') as file:
        file.write(rand)

    for i in range(num_bytes):
        print(f"random byte number {i+1}: {rand[i]:02x}")