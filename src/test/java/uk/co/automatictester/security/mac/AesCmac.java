package uk.co.automatictester.security.mac;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.testng.annotations.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@Slf4j
public class AesCmac {

    private static final SecretKey KEY;

    static {
        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
            KEY = keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void testAesCmac() throws NoSuchAlgorithmException, InvalidKeyException {
        String message = "Lorem ipsum dolor sit amet";

        Mac mac = Mac.getInstance("AESCMAC", new BouncyCastleProvider());
        mac.init(KEY);
        mac.update(message.getBytes());
        byte[] rawMac = mac.doFinal();

        String hexMac = Hex.toHexString(rawMac);
        log.info(hexMac);
    }
}
