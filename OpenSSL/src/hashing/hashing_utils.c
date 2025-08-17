//
// Created by gim on 11/08/25.
//


#include <ctype.h>
#include <openssl/evp.h>


__attribute__((noreturn))
void hashing_handle_md_errors(const char *err, EVP_MD_CTX *ctx) {
    fprintf(stderr, "\n%s\n", err);
    if (ctx)
        EVP_MD_CTX_free(ctx);
    abort();
}




void hashing_print_context_info(EVP_MD_CTX *ctx) {
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
