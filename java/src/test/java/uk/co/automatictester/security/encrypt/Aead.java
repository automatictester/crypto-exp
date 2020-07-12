package uk.co.automatictester.security.encrypt;

import lombok.extern.slf4j.Slf4j;
import org.testng.annotations.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

@Slf4j
public class Aead {

    private static final int IV_LENGTH = 12;
    private static final int AUTHENTICATION_TAG_BIT_LENGTH = 128;
    private static final int IV_START_OFFSET = 0;
    private static final SecretKey KEY;

    static {
        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            KEY = keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void testAesGcm() throws Exception {
        String input = "Lorem ipsum dolor sit amet";
        String metadata = "metadata";
        byte[] encrypted = encrypt(input.getBytes(), metadata.getBytes());
        String decrypted = new String(decrypt(encrypted, metadata.getBytes()));
        assertThat(decrypted, equalTo(input));
    }

    public byte[] encrypt(byte[] input, byte[] metadata) throws Exception {
        byte[] iv = getIv();
        Cipher cipher = getCipher();
        GCMParameterSpec gcmParams = new GCMParameterSpec(AUTHENTICATION_TAG_BIT_LENGTH, iv);

        cipher.init(Cipher.ENCRYPT_MODE, KEY, gcmParams);
        cipher.updateAAD(metadata);
        byte[] encrypted = cipher.doFinal(input);

        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encrypted.length);
        byteBuffer.put(iv);
        byteBuffer.put(encrypted);
        return byteBuffer.array();
    }

    public byte[] decrypt(byte[] encrypted, byte[] metadata) throws Exception {
        Cipher cipher = getCipher();
        GCMParameterSpec gcmParams =
                new GCMParameterSpec(AUTHENTICATION_TAG_BIT_LENGTH, encrypted, IV_START_OFFSET, IV_LENGTH);

        cipher.init(Cipher.DECRYPT_MODE, KEY, gcmParams);
        cipher.updateAAD(metadata);
        return cipher.doFinal(encrypted, IV_LENGTH, encrypted.length - IV_LENGTH);
    }

    private Cipher getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    private byte[] getIv() {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}
