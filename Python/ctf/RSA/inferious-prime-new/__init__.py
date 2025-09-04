from Crypto.Util.number import inverse, long_to_bytes
from factordb.factordb import FactorDB

n = 770071954467068028952709005868206184906970777429465364126693
e = 3
ct = 388435672474892257936058543724812684332943095105091384265939


def inferious_prime():
    f = FactorDB(n)
    f.connect()

    factors = f.get_factor_list()
    # phi = (p-1) * (q-1)
    phi = (factors[0] - 1) * (factors[1] - 1)
    d = inverse(e, phi)
    msg = pow(ct, d, n)
    print(long_to_bytes(msg).decode())


if __name__ == "__main__":
    inferious_prime()
    

