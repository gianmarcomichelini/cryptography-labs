from Crypto.Util.number import getPrime, getRandomInteger, long_to_bytes, inverse, isPrime
from gmpy2 import isqrt

def next_prime(p):
    while True:
        p = p+1
        if isPrime(p):
            return p



def fermat(n):
    print("init")

    a = isqrt(n)
    b = a
    b2 = pow(a,2) - n

    print("a= "+str(a))
    print("b= " + str(b))
    print("b2=" + str(b2))

    print("delta-->" + str(pow(b, 2) - b2 % n)+"\n-----------")
    print("iterate")
    i = 0

    while True:
        if b2 == pow(b,2):
            print("found at iteration "+str(i))
            break;
        else:
            a +=1
            b2 = pow(a, 2) - n
            b = isqrt(b2)
        i+=1
        print("iteration="+str(i))
        print("a= " + str(a))
        print("b= " + str(b))
    print("b2 =" + str(b2))
    print("delta-->" + str(pow(b, 2) - b2 % n) + "\n-----------")

    p = a+b
    q = a-b

    return p,q



if __name__ == '__main__':
        n = 60509355275518728792864353034381323203712352065221533863094540755630035742080855136016830887120470658395455751858380183285852786807229077435165810022519265154399424311072791755790585544921699474779996198610853766677088209156457859301755313246598035577293799853256065979074343370064111263698164125580000165237
        c = 44695558076372490838321125335259117268430036823123326565653896322404966549742986308988778274388721345811255801305658387179978736924822440382730114598169989281210266972874387657989210875921956705640740514819089546339431934001119998309992280196600672180116219966257003764871670107271245284636072817194316693323
        e = 65537

        num_bits = 512
        p1 = getPrime(num_bits)
        delta = getRandomInteger(num_bits // 2 + 8)
        # delta = getRandomInteger(100)
        p2 = next_prime(p1 + delta)

        p, q = fermat(n)

        phi = (p - 1) * (q - 1)

        try:
            d = inverse(e, phi)
            m = pow(c, d, n)
            plaintext = long_to_bytes(m).decode()
            print(plaintext)
        except ValueError as ve:
            print("Error with these primes, trying again...")
        except Exception as ex:
            print("Decoding error, trying again...")
