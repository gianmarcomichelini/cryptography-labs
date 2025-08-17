//
// Created by gim on 03/08/25.
//

#ifndef UTILS_H
#define UTILS_H

#include <openssl/evp.h>

extern char *remove_dashes(const char *string, size_t len);

extern unsigned char hex_to_byte(char high, char low);

extern void print_openssl_errors(unsigned long error, char *buf);

extern void print_hex_buffer(unsigned char *buf, size_t len);

extern void xor_buffers(const unsigned char *buf1, const unsigned char *buf2, unsigned char *out, size_t len);

extern void handle_openssl_errors(void);


#endif //UTILS_H
