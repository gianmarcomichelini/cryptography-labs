# nc 130.192.5.212 6647
import decimal
import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwnlib.tubes.remote import remote


# LSB oracle attack
#   the oracle reveals only the least significant bit of the plaintext corresponding to a ciphertext
#   the algorithm runs for 1024 times, performing 1024 interval computations => n/2^1024 ~ 1
#   at the end, the interval converges to the exact plaintext m

PORT = 6647
HOST = "130.192.5.212"
e = 65537

def to_bytes(m,l):
    return int.to_bytes(m, l, byteorder='big')


def LSB_oracle_attack():
    s = remote(HOST, PORT)

    # s.interactive()
    n_enc, c_enc = s.recvlines(numlines=2, keepends=False, timeout=1)
    n = int(n_enc.decode())
    c = int(c_enc.decode())

    print(f"Modulus (n): {n}")
    print(f"Ciphertext (c): {c}\n")

    decimal.getcontext().prec = n.bit_length()
    lower_bound = decimal.Decimal(0)
    upper_bound = decimal.Decimal(n)

    # is used a multiplier to perform a right-shift on the bits of plaintext
    #     exploiting the multiplicatively homomorphic property of RSA
    multiplier = pow(2, e, n)
    current_c = c

    for i in range(n.bit_length()):
        # Calculate C_i+1 = (2^e * C_i) mod n = (2 * m)^e mod n
        current_c = (multiplier * current_c) % n

        # Send the modified ciphertext to the oracle
        s.sendline(str(current_c).encode())

        # Receive the LSB from the oracle
        bit_response = s.recvline().strip().decode()

        bit = int(bit_response)  # Convert to integer for easier comparison

        # the extracted bit indicates if m_i is in the upper/lower half of the current interval
        if bit == 1:
            # If LSB is 1, it means 2*m_i mod n was odd, implying 2*m_i >= n.
            # So, m_i must be in the upper half of the current interval.
            lower_bound = (upper_bound + lower_bound) // 2
            print(f"  Iteration {i + 1}/{n.bit_length()}: LSB is 1. New interval: [{lower_bound}, {upper_bound})")
        else:
            # If LSB is 0, it means 2*m_i mod n was even, implying 2*m_i < n.
            # So, m_i must be in the lower half of the current interval.
            upper_bound = (upper_bound + lower_bound) // 2
            print(f"  Iteration {i + 1}/{n.bit_length()}: LSB is 0. New interval: [{lower_bound}, {upper_bound})")


    flag = to_bytes(int(upper_bound),n.bit_length()).decode()
    flag = ''.join(c for c in flag if c.isprintable())
    flag = flag[:-1] + "}"

    print(flag)

    s.close()


if __name__ == '__main__':
    LSB_oracle_attack()
