import java.io.DataInputStream;
import java.io.File;
import java.security.*;
import java.io.FileInputStream;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class SignatureTest {
    private static byte[] sign(String datafile, PrivateKey prvKey,
                               String sigAlg) throws Exception {
        Signature sig = Signature.getInstance(sigAlg);
        sig.initSign(prvKey);
        FileInputStream fis = new FileInputStream(datafile);
        byte[] dataBytes = new byte[1024];
        int nread = fis.read(dataBytes);
        System.out.println("String is:" + new String(dataBytes));
        System.out.println(" bytes:" + dataBytes);

        while (nread > 0) {
            sig.update(dataBytes, 0, nread);
            nread = fis.read(dataBytes);
        };
        return sig.sign();
    }

    private static byte[] signString(String data, PrivateKey prvKey,
                               String sigAlg) throws Exception {
        Signature sig = Signature.getInstance(sigAlg);
        sig.initSign(prvKey);
        sig.update(data.getBytes(), 0, data.length());
        return sig.sign();
    }

    private static boolean verify(String datafile, PublicKey pubKey,
                                   String sigAlg, byte[] sigbytes) throws Exception {
        Signature sig = Signature.getInstance(sigAlg);
        sig.initVerify(pubKey);
        FileInputStream fis = new FileInputStream(datafile);
        byte[] dataBytes = new byte[1024];
        int nread = fis.read(dataBytes);
        while (nread > 0) {
            sig.update(dataBytes, 0, nread);
            nread = fis.read(dataBytes);
        };
        return sig.verify(sigbytes);
    }

    private static boolean verifyString(String data, PublicKey pubKey,
                                  String sigAlg, byte[] sigbytes) throws Exception {
        Signature sig = Signature.getInstance(sigAlg);
        sig.initVerify(pubKey);
        sig.update(data.getBytes(), 0, data.length());
        return sig.verify(sigbytes);
    }

    public static void main(String[] unused) throws Exception {
        final String p12_ADRESS = "D://KeyStore2/key/sabtAsnad.p12";
        final String datafile = "D://KeyStore2/key/matn.txt";
        final String alias_name = "امضای الکترونیک تست";//"farafan";
        final String sigAlg = "SHA1withRSA";
        final char[] keypassword = "12345678".toCharArray();

        FileInputStream fis = new FileInputStream(p12_ADRESS);
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(fis, keypassword);

        Key myKey =  ks.getKey(alias_name, keypassword);
        PrivateKey prvk = (PrivateKey)myKey;
        PublicKey pubk = ks.getCertificate(alias_name).getPublicKey();

//        // Generate a key-pair
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
//        kpg.initialize(1024); // 512 is the keysize.
//        KeyPair kp = kpg.generateKeyPair();
//        PublicKey pubk = kp.getPublic();
//        PrivateKey prvk = kp.getPrivate();


        byte[] sigbytes = signString(datafile, prvk, sigAlg);
        StringBuffer temp = new StringBuffer();
        for (byte b : sigbytes) {
            temp.append(String.format("%02X ", b));
            temp.append(" "); // delimiter
        }
        System.out.println("bytes:" + sigbytes);
        System.out.println("Signature(in hex):: " +
                temp.toString());

        boolean result = verifyString(datafile, pubk, sigAlg, sigbytes);
        System.out.println("Signature Verification Result = " + result);
        String s = new String(sigbytes);
        System.out.println("Text Decryted : " + s);
    }
}