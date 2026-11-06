import java.security.Signature;
import javax.crypto.Cipher;

public class Padding {
    static Cipher oaep() throws Exception {
        return Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    }

    static Signature pkcs1() throws Exception {
        return Signature.getInstance("SHA256withRSA");
    }

    static Signature pss() throws Exception {
        return Signature.getInstance("RSASSA-PSS");
    }

    static Signature ecdsa() throws Exception {
        return Signature.getInstance("SHA384withECDSA");
    }
}
