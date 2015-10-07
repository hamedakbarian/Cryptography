import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.*;
import java.util.Enumeration;
import javax.crypto.*;
import sun.misc.BASE64Encoder;
import sun.misc.BASE64Decoder;
import sun.security.validator.KeyStores;

public class MyPKCS12 {
    public static void main(String args[]) throws Exception {
        FileInputStream fis = new FileInputStream("D://KeyStore2/key/sabtAsnad.p12");

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(fis, "12345678".toCharArray());

        for (Enumeration<String> e = ks.aliases() ; e.hasMoreElements() ;) {
            String s = e.nextElement();
            System.out.println("Alias: " + s);

            Key k = ks.getKey(s, "12345678".toCharArray());
            System.out.println("Private Key = " + k);
            System.out.println("k.getAlgorithm() = " + k.getAlgorithm());
            System.out.println("k.getFormat() = " + k.getFormat());

            k = ks.getCertificate(s).getPublicKey();
            System.out.println("Public Key = " + k);
            System.out.println("k.getAlgorithm() = " + k.getAlgorithm());
            System.out.println("k.getFormat() = " + k.getFormat());

            String temp = "12345";
            System.out.println("byte Array:" + temp.getBytes());
        }
    }
}