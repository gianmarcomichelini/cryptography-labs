from Crypto.Util.number import long_to_bytes, inverse
from factordb.factordb import FactorDB

# data obtained from observation
# n is 128 bits, so insecure in practice, trying to factorize n using FactorDB

n = 176278749487742942508568320862050211633 # public modulus (to be factorized)
c = 46228309104141229075992607107041922411  # ciphertext
e = 65537   # public exponent

f = FactorDB(n)
f.connect()
p, q = f.get_factor_list()
# found the two prime factors p and q

# compute the Euler's totient function for given p and q
phi = (p - 1) * (q - 1)

# compute the modular inverse (multiplicative inverse) of the public exponent e (because e multiplied by d is equal to 1 mod phi)
d = inverse(e, phi)

# decrypt the ciphertext
m = pow(c, d, n)
print(long_to_bytes(m))