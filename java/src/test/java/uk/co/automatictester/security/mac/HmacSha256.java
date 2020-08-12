package uk.co.automatictester.security.mac;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import org.testng.annotations.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@Slf4j
public class HmacSha256 {

    private static final String ALGORITHM = "HmacSHA256";
    private static final SecretKey KEY;

    static {
        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            KEY = keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void testHmacSha256() throws NoSuchAlgorithmException, InvalidKeyException {
        String message = "Lorem ipsum dolor sit amet";

        Mac mac = Mac.getInstance(ALGORITHM);
        mac.init(KEY);
        mac.update(message.getBytes());
        byte[] rawMac = mac.doFinal();

        String hexMac = Hex.toHexString(rawMac);
        log.info(hexMac);
    }
}
