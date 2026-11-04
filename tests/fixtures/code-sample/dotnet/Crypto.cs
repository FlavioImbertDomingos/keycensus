using System.Security.Cryptography;

static class Crypto
{
    static byte[] Hash(byte[] d) { using var md5 = MD5.Create(); return md5.ComputeHash(d); }

    static Aes Legacy()
    {
        var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        return aes;
    }

    static RSA Rsa() => RSA.Create(2048);

    static ECDsa Ec() => ECDsa.Create(ECCurve.NamedCurves.nistP256);
}
