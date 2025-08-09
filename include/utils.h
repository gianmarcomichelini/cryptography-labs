//
// Created by gim on 03/08/25.
//

#ifndef UTILS_H
#define UTILS_H

#include <stdlib.h>

extern char *remove_dashes(const char *string, const size_t len);
extern unsigned char hex_to_byte(const char high, const char low);
extern void print_openssl_errors(const unsigned long error, char *buf);
extern void print_hex_buffer(unsigned char *buf, const size_t len);

#endif //UTILS_H
