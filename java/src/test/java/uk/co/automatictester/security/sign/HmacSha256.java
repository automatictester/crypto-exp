package uk.co.automatictester.security.sign;

import lombok.extern.slf4j.Slf4j;
import org.testng.annotations.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

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
        byte[] message = "Lorem ipsum dolor sit amet".getBytes();

        Mac mac = Mac.getInstance(ALGORITHM);
        mac.init(KEY);
        byte[] hmacSha256 = mac.doFinal(message);

        String base64encodedHmacSha265 = Base64.getEncoder().encodeToString(hmacSha256);
        log.info(base64encodedHmacSha265);
    }
}
