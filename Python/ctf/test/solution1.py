from pwn import remote


def calculate(a, operator, b):
    if operator == '+':
        return a + b
    elif operator == '-':
        return a - b
    elif operator == '*':
        return a * b
    else:
        raise ValueError("Unsupported operator")


# Connect to the remote server
r = remote('130.192.5.212', 6500)
r.recvuntil(b"Username:")
r.sendline(b"player")

# Read the remaining newline and throw it away
r.recvline()

for _ in range(128):
    line = r.recvline().decode()
    print("Received:", line.strip())

    # Some manual parsing: after extracting the expression, split the line into words (by using spaces)
    # then, extract the first number, operator, and second number
    parts = line.split(":")[1].split()
    a = int(parts[0])  # First number
    operator = parts[1]  # Operator (+, -, or *)
    b = int(parts[2])  # Second number
    result = calculate(a, operator, b)

    r.sendline(str(result).encode())

print(r.recvall().decode())
