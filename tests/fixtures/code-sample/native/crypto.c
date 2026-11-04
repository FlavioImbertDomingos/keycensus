#include <openssl/evp.h>
#include <openssl/rsa.h>

int main(void) {
    const EVP_MD *md = EVP_sha1();
    const EVP_CIPHER *tdes = EVP_des_ede3_cbc();
    const EVP_CIPHER *ecb = EVP_aes_128_ecb();
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 4096);
    return md && tdes && ecb && ctx ? 0 : 1;
}
