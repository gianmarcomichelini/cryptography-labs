#include "utils.h"

#include <ctype.h>
#include <openssl/err.h>

char *remove_dashes(const char *string, const size_t len) {
    char *cleaned = malloc(len + 1);
    if (!cleaned) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (string[i] != '-') {
            cleaned[j++] = string[i];
        }
    }
    cleaned[j] = '\0';
    return cleaned;
}

unsigned char hex_to_byte(const char high, const char low) {
    const unsigned char h = isdigit(high) ? high - '0' : tolower(high) - 'a' + 10;
    const unsigned char l = isdigit(low) ? low - '0' : tolower(low) - 'a' + 10;
    return (h << 4) | l;
}

void print_openssl_errors(const unsigned long error, char *buf) {
    ERR_error_string(error, buf);
    fprintf(stderr, "OpenSSL error: %s\n", buf);
}

void print_hex_buffer(unsigned char *buf, const size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
        if (i < len - 1) printf("-");
    }
    printf("\n");
}