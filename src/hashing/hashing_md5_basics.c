#include <openssl/evp.h>

__attribute__((noreturn))
void handle_errors(const char *err, EVP_MD_CTX *ctx) {
    fprintf(stderr, "\n%s\n", err);
    if (ctx)
        EVP_MD_CTX_free(ctx);
    abort();
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

int hashing_basics(void) {
    int rc; // check return codes

    printf(
        "\n"
        "================================"
        "\n"
        "Execute basic hashing operations"
        "\n"
        "================================"
        "\n\n");

    printf("Create the context...\n\n");
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
        handle_errors("ERROR: creation of digest context", NULL);
    print_context_info(md_ctx);

    printf("Initialize the context...\n\n");
    const EVP_MD *hash_function = EVP_md5();
    rc = EVP_DigestInit_ex(md_ctx, hash_function, NULL);
    if (rc != 1)
        handle_errors("ERROR: initializing the digest context", md_ctx);
    print_context_info(md_ctx);

    const char message[15] = "Simple message";
    printf("Updating the context with \"%s\"\n\n", message);
    rc = EVP_DigestUpdate(md_ctx, message, sizeof(message));
    if (rc != 1)
        handle_errors("ERROR: updating the digest context", md_ctx);

    printf("Allocating heap memory for the digest\n\n");
    const unsigned int digest_len = EVP_MD_size(hash_function);
    unsigned char *digest = (unsigned char *) OPENSSL_malloc(digest_len);
    if (!digest)
        handle_errors("ERROR: Allocating memory for the digest", md_ctx);

    printf("Store the context output in the digest...\n");
    rc = EVP_DigestFinal_ex(md_ctx, digest, &digest_len);
    if (rc != 1)
        handle_errors("ERROR: Storing the context output in the digest", md_ctx);

    printf("Digest: ");
    for (size_t i = 0; i < digest_len; i++)
        printf("%02X", digest[i]);
    printf("\n\n");

    printf("Cleanup...\n\n");
    EVP_MD_CTX_free(md_ctx);
    OPENSSL_free(digest);

    return 0;
}
