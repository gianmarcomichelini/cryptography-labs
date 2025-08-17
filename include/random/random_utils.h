//
// Created by gim on 08/08/25.
//

#ifndef RAND_H
#define RAND_H
#include <openssl/rand.h>

extern int seed_prng(size_t seed_bytes);

extern int generate_random_bytes(unsigned char *buffer, size_t len);

#endif //RAND_H
