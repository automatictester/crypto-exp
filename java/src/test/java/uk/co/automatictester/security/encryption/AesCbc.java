package uk.co.automatictester.security.encryption;

import lombok.extern.slf4j.Slf4j;
import org.testng.annotations.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

@Slf4j
public class AesCbc {

    private SecretKey key;
    private byte[] iv;

    @Test
    public void testAesCbc() throws Exception {
        String plaintext = "Lorem ipsum dolor sit amet";
        byte[] ciphertext = encrypt(plaintext.getBytes());
        String decrypted = new String(decrypt(ciphertext));
        assertThat(decrypted, equalTo(plaintext));
    }

    public byte[] encrypt(byte[] input) throws Exception {
        key = generateKey();
        Cipher cipher = getCipher();
        cipher.init(Cipher.ENCRYPT_MODE, key);
        iv = cipher.getIV();
        return cipher.doFinal(input);
    }

    public byte[] decrypt(byte[] encrypted) throws Exception {
        Cipher cipher = getCipher();
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        return cipher.doFinal(encrypted);
    }

    private Cipher getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
        return Cipher.getInstance("AES/CBC/PKCS5Padding");
    }

    private SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }
}
