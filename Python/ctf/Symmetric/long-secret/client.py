import numpy
from string import *


CHARACTER_FREQ = {
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610,
    'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513,
    'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
    'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182
}  # ','

with open("/Exercises/ctf/Symmetric/long-secret/hacker-manifesto.enc") as f:
    enc_lines = [bytes.fromhex(line) for line in f.readlines()]


ciphertexts = enc_lines

print("stats")
print(len(ciphertexts))

longest_c = max(ciphertexts, key=len)
max_len = len(longest_c)
print(len(longest_c))

shortest_c = min(ciphertexts, key=len)
min_len = len(shortest_c)
print(len(shortest_c))

#################################################

candidates_list = []

for byte_to_guess in range(max_len):
    freqs = numpy.zeros(256, dtype=float)

    for guessed_byte in range(256):
        for c in ciphertexts:
            if byte_to_guess >= len(c):
                continue
            if chr(c[byte_to_guess] ^ guessed_byte) in printable:
                freqs[guessed_byte] += CHARACTER_FREQ.get(chr(c[byte_to_guess] ^ guessed_byte).lower(), 0)

    max_matches = max(freqs)
    # print(max_matches)

    match_list = [(freqs[i], i) for i in range(256)]
    # print(match_list)
    ordered_match_list = sorted(match_list, reverse=True)
    # print(candidates)
    candidates_list.append(ordered_match_list)


keystream = bytearray()
for candidate in candidates_list:
    keystream += candidate[0][1].to_bytes(1, byteorder='big')

from Crypto.Util.strxor import strxor

# keystream[0] = 148



keystream[0] = ciphertexts[0][0] ^ ord('T')
keystream[1] = ciphertexts[0][1] ^ ord('h')
keystream[2] = ciphertexts[0][2] ^ ord('i')
keystream[3] = ciphertexts[0][3] ^ ord('s')
keystream[4] = ciphertexts[0][4] ^ ord(' ')
keystream[5] = ciphertexts[0][5] ^ ord('i')
keystream[34] = ciphertexts[0][34] ^ ord('f')
keystream[49] = ciphertexts[0][49] ^ ord('a')
keystream[53] = ciphertexts[0][53] ^ ord('t')

keystream[28] = ciphertexts[1][28] ^ ord('u')
keystream[8] = ciphertexts[2][8] ^ ord('o')
keystream[16] = ciphertexts[4][16] ^ ord('x')
keystream[20] = ciphertexts[4][20] ^ ord('w')

keystream[16] = ciphertexts[6][16] ^ ord('o')
keystream[17] = ciphertexts[6][17] ^ ord('u')

keystream[37] = ciphertexts[6][37] ^ ord(' ')
keystream[38] = ciphertexts[6][38] ^ ord('y')
keystream[39] = ciphertexts[6][39] ^ ord('o')
keystream[40] = ciphertexts[6][40] ^ ord('u')
keystream[43] = ciphertexts[6][43] ^ ord('i')
keystream[69] = ciphertexts[6][69] ^ ord('s')

keystream[45] = ciphertexts[1][45] ^ ord('a')
keystream[46] = ciphertexts[1][46] ^ ord('l')
keystream[57] = ciphertexts[1][57] ^ ord('t')
keystream[58] = ciphertexts[1][58] ^ ord('i')
keystream[59] = ciphertexts[1][59] ^ ord('n')
keystream[65] = ciphertexts[1][65] ^ ord('h')
keystream[67] = ciphertexts[1][67] ^ ord('u')

keystream[38] = ciphertexts[5][38] ^ ord('i')
keystream[39] = ciphertexts[5][39] ^ ord('n')
keystream[40] = ciphertexts[5][40] ^ ord('a')
keystream[42] = ciphertexts[5][42] ^ ord('s')

for c in ciphertexts:
    l = min(len(keystream), len(c))
    print(strxor(c[:l], keystream[:l]))

