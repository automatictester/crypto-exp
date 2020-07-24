package uk.co.automatictester.security.encryption;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

@Slf4j
public class ChaCha20 {

    private SecretKey key;
    private byte[] iv;

    @Test
    public void testChaCha20() throws Exception {
        key = generateKey();
        String plaintext = "Lorem ipsum dolor sit amet";
        byte[] ciphertext = encrypt(plaintext.getBytes());
        String decrypted = new String(decrypt(ciphertext));
        assertThat(decrypted, equalTo(plaintext));
        log.info("len(P): {}, len(C): {}", plaintext.length(), ciphertext.length);
    }

    public byte[] encrypt(byte[] input) throws Exception {
        Cipher cipher = Cipher.getInstance("ChaCha20", new BouncyCastleProvider());
        cipher.init(Cipher.ENCRYPT_MODE, key);
        iv = cipher.getIV();
        return cipher.doFinal(input);
    }

    public byte[] decrypt(byte[] encrypted) throws Exception {
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("ChaCha20", new BouncyCastleProvider());
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        return cipher.doFinal(encrypted);
    }

    private SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("ChaCha20", new BouncyCastleProvider());
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }
}
