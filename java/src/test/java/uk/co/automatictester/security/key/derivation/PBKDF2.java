package uk.co.automatictester.security.key.derivation;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.Test;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

@Slf4j
public class PBKDF2 {

    @Test
    public void testPbkdf2() throws NoSuchAlgorithmException, InvalidKeySpecException {
        char[] password = "P@ssw0rd".toCharArray();
        byte[] salt = getSalt();
        int iterationCount = 1048;
        int keyLength = 256;

        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WITHHMACSHA256", new BouncyCastleProvider());
        PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterationCount, keyLength);

        byte[] key1 = keyFactory.generateSecret(keySpec).getEncoded();
        log.info("Key 1: {}", Base64.getEncoder().encodeToString(key1));

        byte[] key2 = keyFactory.generateSecret(keySpec).getEncoded();
        log.info("Key 2: {}", Base64.getEncoder().encodeToString(key2));

        assertThat(key1, is(equalTo(key2)));
    }

    private byte[] getSalt() {
        byte[] salt = new byte[256];
        new SecureRandom().nextBytes(salt);
        return salt;
    }
}
