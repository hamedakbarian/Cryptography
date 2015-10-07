import sun.misc.BASE64Encoder;

import javax.crypto.SecretKey;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/**
 * Created by weblogic12 on 9/12/2015.
 */
public class ExtractAlias {
    public static void main(String[] args) {

        SymmetricEncrypt encryptUtil = new SymmetricEncrypt();
        String strDataToEncrypt = "Hello World";
        byte[] byteDataToTransmit = strDataToEncrypt.getBytes();

        // Generating a SecretKey for Symmetric Encryption
        SecretKey senderSecretKey = SymmetricEncrypt.getSecret();

        //1. Encrypt the data using a Symmetric Key
        byte[] byteCipherText = encryptUtil.encryptData(byteDataToTransmit, senderSecretKey, "AES");
        String strCipherText = new BASE64Encoder().encode(byteCipherText);


        //2. Encrypt the Symmetric key using the Receivers public key
        try {
            // 2.1 Specify the Keystore where the Receivers certificate has been imported
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            char[] password = "12345678".toCharArray();
            java.io.FileInputStream fis = new java.io.FileInputStream("D://KeyStore2/key/asnad.jks");
            ks.load(fis, password);
            fis.close();

            // 2.2 Creating an X509 Certificate of the Receiver
            X509Certificate recvcert;
            MessageDigest md = MessageDigest.getInstance("MD5");
            recvcert = (X509Certificate) ks.getCertificate("امضای الکترونیک تست");
            Enumeration<String> temp = ks.aliases();
            while(temp.hasMoreElements()){
                System.out.println(temp.nextElement());
            }
        }
        catch (Exception e){

        }
    }
}
