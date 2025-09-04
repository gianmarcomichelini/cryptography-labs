'''
Created on Dec 14, 2011

@author: pablocelayes
'''

import ContinuedFractions, Arithmetic
from Crypto.Util.number import long_to_bytes

n = 770071954467068028952709005868206184906970777429465364126693
e = 3
ct = 388435672474892257936058543724812684332943095105091384265939

def hack_RSA(e, n):
    '''
    Finds d knowing (e,n)
    applying the Wiener continued fraction attack
    '''
    _, convergents = ContinuedFractions.rational_to_contfrac(e, n)

    for (k, d) in convergents:

        if k != 0 and (e * d - 1) % k == 0:
            phi = (e * d - 1) // k
            s = n - phi + 1
            discr = s * s - 4 * n
            if discr >= 0:
                t = Arithmetic.is_perfect_square(discr)
                if t != -1 and (s + t) % 2 == 0:
                    print("Hacked!")
                    return d
    return None

if __name__ == '__main__':
    print("Starting...")
    d = hack_RSA(e, n)
    if d:
        print("d =", d)
        m = pow(ct, d, n)
        try:
            print("Decrypted message:", long_to_bytes(m).decode())
        except:
            print("Decrypted bytes (not UTF-8):", long_to_bytes(m))
    else:
        print("Wiener's attack failed.")