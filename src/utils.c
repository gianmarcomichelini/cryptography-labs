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


void print_context_info(EVP_MD_CTX *ctx) {
    printf("Some context information:\n");

    if (!ctx) {
        printf("\tContext is NULL\n");
        return;
    }

    printf("\tDigest context pointer address: %p\n", (void *) ctx);

    const EVP_MD *md = EVP_MD_CTX_get0_md(ctx);
    if (md) {
        printf("\tDigest algorithm: %s\n", EVP_MD_name(md));
        printf("\tDigest size: %d bytes\n\n", EVP_MD_size(md));
    } else {
        printf("\tNo digest algorithm set in context.\n\n");
    }
}

__attribute__((noreturn))
void handle_md_errors(const char *err, EVP_MD_CTX *ctx) {
    fprintf(stderr, "\n%s\n", err);
    if (ctx)
        EVP_MD_CTX_free(ctx);
    abort();
}
