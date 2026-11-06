using System.Security.Cryptography;

static class Padding
{
    static byte[] Encrypt(RSA rsa, byte[] data) => rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
    static byte[] Sign(RSA rsa, byte[] digest) => rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
}
