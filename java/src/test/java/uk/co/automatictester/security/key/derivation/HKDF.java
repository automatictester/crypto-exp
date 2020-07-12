package uk.co.automatictester.security.key.derivation;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base32;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.testng.annotations.Test;

import javax.crypto.KeyGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

@Slf4j
public class HKDF {

    @Test
    public void testKeyDerivation() {
        byte[] ikm = getKey();
        byte[] salt = getIv();
        byte[] info = "derived-key-a".getBytes();
        int lenght = 16;
        byte[] okm1 = deriveKey(ikm, salt, info, lenght);
        byte[] okm2 = deriveKey(ikm, salt, info, lenght);

        String base32okm1 = new Base32().encodeAsString(okm1);
        String base32okm2 = new Base32().encodeAsString(okm2);
        log.info("{}", base32okm1);
        assertThat(base32okm1, equalTo(base32okm2));
    }

    private byte[] deriveKey(byte[] ikm, byte[] salt, byte[] info, int length) {
        Digest hashFunction = new SHA256Digest();
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(hashFunction);
        DerivationParameters params = new HKDFParameters(ikm, salt, info);
        hkdf.init(params);
        byte[] okm = new byte[length];
        hkdf.generateBytes(okm, 0, length);
        return okm;
    }

    private byte[] getKey() {
        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            return keyGenerator.generateKey().getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] getIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}
