package uk.co.automatictester.security.encryption;

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
public class AesGcmAead {

    private final int ivLength = 12;
    private final int authenticationTagBitLength = 128;
    private SecretKey key;

    @Test
    public void testAesGcm() throws Exception {
        key = generateKey();
        String plaintext = "Lorem ipsum dolor sit amet";
        String associatedData = "metadata";
        byte[] ciphertext = encrypt(plaintext.getBytes(), associatedData.getBytes());
        String decrypted = new String(decrypt(ciphertext, associatedData.getBytes()));
        assertThat(decrypted, equalTo(plaintext));
    }

    public byte[] encrypt(byte[] input, byte[] metadata) throws Exception {
        byte[] iv = getIv();
        Cipher cipher = getCipher();
        GCMParameterSpec gcmParams = new GCMParameterSpec(authenticationTagBitLength, iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParams);
        cipher.updateAAD(metadata);
        byte[] encrypted = cipher.doFinal(input);

        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encrypted.length);
        byteBuffer.put(iv);
        byteBuffer.put(encrypted);
        return byteBuffer.array();
    }

    public byte[] decrypt(byte[] encrypted, byte[] metadata) throws Exception {
        Cipher cipher = getCipher();
        int ivStartOffset = 0;
        GCMParameterSpec gcmParams =
                new GCMParameterSpec(authenticationTagBitLength, encrypted, ivStartOffset, ivLength);

        cipher.init(Cipher.DECRYPT_MODE, key, gcmParams);
        cipher.updateAAD(metadata);
        return cipher.doFinal(encrypted, ivLength, encrypted.length - ivLength);
    }

    private Cipher getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    private byte[] getIv() {
        byte[] iv = new byte[ivLength];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }
}
