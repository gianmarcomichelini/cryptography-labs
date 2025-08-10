#include <openssl/evp.h>

#include "utils.h"




int hashing_md5_compute(void) {
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
        handle_md_errors("ERROR: creation of digest context", NULL);
    print_context_info(md_ctx);

    printf("Initialize the context...\n\n");
    const EVP_MD *hash_function = EVP_md5();
    rc = EVP_DigestInit_ex(md_ctx, hash_function, NULL);
    if (rc != 1)
        handle_md_errors("ERROR: initializing the digest context", md_ctx);
    print_context_info(md_ctx);

    const char message[15] = "Simple message";
    printf("Updating the context with \"%s\"\n\n", message);
    rc = EVP_DigestUpdate(md_ctx, message, sizeof(message));
    if (rc != 1)
        handle_md_errors("ERROR: updating the digest context", md_ctx);

    printf("Allocating heap memory for the digest\n\n");
    unsigned int digest_len = EVP_MD_size(hash_function);
    unsigned char *digest = (unsigned char *) OPENSSL_malloc(digest_len);
    if (!digest)
        handle_md_errors("ERROR: Allocating memory for the digest", md_ctx);

    printf("Store the context output in the digest...\n");
    rc = EVP_DigestFinal_ex(md_ctx, digest, &digest_len);
    if (rc != 1)
        handle_md_errors("ERROR: Storing the context output in the digest", md_ctx);

    printf("Digest: ");
    print_hex_buffer(digest, sizeof(digest));
    printf("\n\n");

    printf("Cleanup...\n\n");
    EVP_MD_CTX_free(md_ctx);
    OPENSSL_free(digest);

    return EXIT_SUCCESS;
}
