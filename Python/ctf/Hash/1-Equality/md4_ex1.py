# encoding: utf-8
from Crypto.Hash import MD4 as CryptoMD4
import random
import struct
import time
import re



def Endian(b):
    return [struct.unpack('<I', b[i:i + 4])[0] for i in range(0, len(b), 4)]


def LeftRot(n, b):
    return ((n << b) | ((n & 0xffffffff) >> (32 - b))) & 0xffffffff


def RightRot(n, b):
    return ((n >> b) | ((n & 0xffffffff) << (32 - b))) & 0xffffffff


def F(x, y, z): return x & y | ~x & z


def G(x, y, z): return x & y | x & z | y & z


def H(x, y, z): return x ^ y ^ z


def FF(a, b, c, d, k, s, X): return LeftRot(a + F(b, c, d) + X[k], s)


def GG(a, b, c, d, k, s, X): return LeftRot(a + G(b, c, d) + X[k] + 0x5a827999, s)


def HH(a, b, c, d, k, s, X): return LeftRot(a + H(b, c, d) + X[k] + 0x6ed9eba1, s)


def MD4(m):
    md4 = CryptoMD4.new()
    if isinstance(m, str):
        m = m.encode('latin1')
    md4.update(m)
    return md4.hexdigest()


def FirstRound(abcd, j, i, s, x, constraints):
    v = LeftRot(abcd[j % 4] + F(abcd[(j + 1) % 4], abcd[(j + 2) % 4], abcd[(j + 3) % 4]) + x[i], s)
    for constraint in constraints:
        if constraint[0] == '=':
            v ^= (v ^ abcd[(j + 1) % 4]) & (1 << constraint[1])
        elif constraint[0] == '0':
            v &= ~(1 << constraint[1])
        elif constraint[0] == '1':
            v |= 1 << constraint[1]
    x[i] = (RightRot(v, s) - abcd[j % 4] - F(abcd[(j + 1) % 4], abcd[(j + 2) % 4], abcd[(j + 3) % 4])) % 2 ** 32
    abcd[j % 4] = v


def FindCollision(m):
    x = Endian(m)
    initial_abcd = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    abcd = initial_abcd[:]

    constraints = [
        [['=', 6]], [['0', 6], ['=', 7], ['=', 10]],
        [['1', 6], ['1', 7], ['0', 10], ['=', 25]],
        [['1', 6], ['0', 7], ['0', 10], ['0', 25]],
        [['1', 7], ['1', 10], ['0', 25], ['=', 13]],
        [['0', 13], ['=', 18], ['=', 19], ['=', 20], ['=', 21], ['1', 25]],
        [['=', 12], ['0', 13], ['=', 14], ['0', 18], ['0', 19], ['1', 20], ['0', 21]],
        [['1', 12], ['1', 13], ['0', 14], ['=', 16], ['0', 18], ['0', 19], ['0', 20], ['0', 21]],
        [['1', 12], ['1', 13], ['1', 14], ['0', 16], ['0', 18], ['0', 19], ['0', 20], ['=', 22], ['1', 21], ['=', 25]],
        [['1', 12], ['1', 13], ['1', 14], ['0', 16], ['0', 19], ['1', 20], ['1', 21], ['0', 22], ['1', 25], ['=', 29]],
        [['1', 16], ['0', 19], ['0', 20], ['0', 21], ['0', 22], ['0', 25], ['1', 29], ['=', 31]],
        [['0', 19], ['1', 20], ['1', 21], ['=', 22], ['1', 25], ['0', 29], ['0', 31]],
        [['0', 22], ['0', 25], ['=', 26], ['=', 28], ['1', 29], ['0', 31]],
        [['0', 22], ['0', 25], ['1', 26], ['1', 28], ['0', 29], ['1', 31]],
        [['=', 18], ['1', 22], ['1', 25], ['0', 26], ['0', 28], ['0', 29]],
        [['0', 18], ['=', 25], ['1', 26], ['1', 28], ['0', 29], ['=', 31]]
    ]

    shift = [3, 7, 11, 19] * 4
    change = [0, 3, 2, 1] * 4

    for i in range(16):
        FirstRound(abcd, change[i], i, shift[i], x, constraints[i])

    constraints2 = [
        [['=', 18, 2], ['1', 25], ['0', 26], ['1', 28], ['1', 31]],
        [['=', 18, 0], ['=', 25, 1], ['=', 26, 1], ['=', 28, 1], ['=', 31, 1]]
    ]

    a5 = GG(abcd[0], abcd[1], abcd[2], abcd[3], 0, 3, x)
    for constraint in constraints2[0]:
        if constraint[0] == '=':
            a5 ^= ((a5 ^ abcd[constraint[2]]) & (1 << constraint[1]))
        elif constraint[0] == '0':
            a5 &= ~(1 << constraint[1])
        elif constraint[0] == '1':
            a5 |= (1 << constraint[1])

    q = (RightRot(a5, 3) - abcd[0] - G(abcd[1], abcd[2], abcd[3]) - 0x5a827999) % 2 ** 32

    a0, b0, c0, d0 = initial_abcd
    a_ = FF(a0, b0, c0, d0, 0, 3, [q])
    a1 = FF(a0, b0, c0, d0, 0, 3, x)
    d1 = FF(d0, a1, b0, c0, 1, 7, x)
    x[0] = q
    x[1] = (RightRot(d1, 7) - d0 - F(a_, b0, c0)) % 2 ** 32
    c1 = FF(c0, d1, a1, b0, 2, 11, x)
    x[2] = (RightRot(c1, 11) - c0 - F(d1, a_, b0)) % 2 ** 32
    b1 = FF(b0, c1, d1, a1, 3, 19, x)
    x[3] = (RightRot(b1, 19) - b0 - F(c1, d1, a_)) % 2 ** 32
    a2 = FF(a1, b1, c1, d1, 4, 3, x)
    x[4] = (RightRot(a2, 3) - a_ - F(b1, c1, d1)) % 2 ** 32

    abcd[0] = a5
    d5 = GG(abcd[3], abcd[0], abcd[1], abcd[2], 4, 5, x)

    for constraint in constraints2[1]:
        if constraint[0] == '=':
            d5 ^= ((d5 ^ abcd[constraint[2]]) & (1 << constraint[1]))
        elif constraint[0] == '0':
            d5 &= ~(1 << constraint[1])
        elif constraint[0] == '1':
            d5 |= (1 << constraint[1])

    q = (RightRot(d5, 5) - abcd[3] - G(abcd[0], abcd[1], abcd[2]) - 0x5a827999) % 2 ** 32

    a, b, c, d = initial_abcd
    a = FF(a, b, c, d, 0, 3, x)
    d = FF(d, a, b, c, 1, 7, x)
    c = FF(c, d, a, b, 2, 11, x)
    b = FF(b, c, d, a, 3, 19, x)
    a2_ = FF(a, b, c, d, 4, 3, [q] * 5)
    a2 = FF(a, b, c, d, 4, 3, x)
    d2 = FF(d, a2, b, c, 5, 7, x)
    x[4] = q
    x[5] = (RightRot(d2, 7) - d - F(a2_, b, c)) % 2 ** 32
    c2 = FF(c, d2, a2, b, 6, 11, x)
    x[6] = (RightRot(c2, 11) - c - F(d2, a2_, b)) % 2 ** 32
    b2 = FF(b, c2, d2, a2, 7, 19, x)
    x[7] = (RightRot(b2, 19) - b - F(c2, d2, a2_)) % 2 ** 32
    a3 = FF(a2, b2, c2, d2, 8, 3, x)
    x[8] = (RightRot(a3, 3) - a2_ - F(b2, c2, d2)) % 2 ** 32

    m = b''.join([struct.pack('<I', i) for i in x])
    m_ = CreateCollision(m)

    if MD4(m) == MD4(m_):
        return m, m_
    return None, None


def CreateCollision(m):
    x = list(Endian(m))
    x[1] = (x[1] + (1 << 31)) % 2 ** 32
    x[2] = (x[2] + ((1 << 31) - (1 << 28))) % 2 ** 32
    x[12] = (x[12] - (1 << 16)) % 2 ** 32
    return b''.join([struct.pack('<I', i) for i in x])


def Collision():
    attempts = 0
    while True:
        m = bytes([random.randint(0, 255) for _ in range(64)])
        ma, mb = FindCollision(m)
        if ma:
            break
        attempts += 1
    return ma.hex(), mb.hex(), MD4(ma), MD4(mb)


def start_test():
    start = time.perf_counter()
    print("[+] Finding Collision...")
    try:
        m1, m2, h1, h2 = Collision()
    except TypeError:
        print("[-] Collision generation failed.")
        return "", ""
    M1 = re.findall(r'.{8}', m1)
    M2 = re.findall(r'.{8}', m2)
    mm1 = ''
    mm2 = ''
    for i in range(len(M1)):
        if M1[i] != M2[i]:
            mm1 += '[' + M1[i] + ']'
            mm2 += '[' + M2[i] + ']'
        else:
            mm1 += M1[i]
            mm2 += M2[i]

    print("  [-] The M1 is:", m1)
    print("  [-] The M2 is:", m2)
    print("  [-] M1 and M2 diff:\n    [*] " + mm1 + "\n    [*] " + mm2)
    print("  [-] The MD4(M1) is:", h1)
    print("  [-] The MD4(M2) is:", h2)
    print("[!] M1 == M2 ?", m1 == m2)
    print("[!] MD4(M1) == MD4(M2) ?", h1 == h2)
    print("[!] All done!")
    print("[!] Timer:", round(time.perf_counter() - start, 2), "s")
    return bytes.fromhex(m1), bytes.fromhex(m2)


