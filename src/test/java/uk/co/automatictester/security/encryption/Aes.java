package uk.co.automatictester.security.encryption;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

@Slf4j
public class Aes {

    private SecretKey key;
    private byte[] iv;

    @DataProvider(name = "cipher")
    public Object[][] getCipher() {
        return new Object[][]{
                {"AES/CBC/PKCS5Padding"},
                {"AES/CBC/CTSPadding"},
                {"AES/CFB/NoPadding"},
                {"AES/OFB/NoPadding"},
                {"AES/CTR/NoPadding"},
        };
    }

    @Test(dataProvider = "cipher")
    public void testAes(String cipherString) throws Exception {
        key = generateKey();
        String plaintext = "Lorem ipsum dolor sit amet";
        byte[] ciphertext = encrypt(cipherString, plaintext.getBytes());
        String decrypted = new String(decrypt(cipherString, ciphertext));
        assertThat(decrypted, equalTo(plaintext));
        log.info("cipher: {}, len(P): {}, len(C): {}", cipherString, plaintext.length(), ciphertext.length);
    }

    public byte[] encrypt(String cipherString, byte[] input) throws Exception {
        Cipher cipher = Cipher.getInstance(cipherString, new BouncyCastleProvider());
        cipher.init(Cipher.ENCRYPT_MODE, key);
        iv = cipher.getIV();
        return cipher.doFinal(input);
    }

    public byte[] decrypt(String cipherString, byte[] encrypted) throws Exception {
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(cipherString, new BouncyCastleProvider());
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        return cipher.doFinal(encrypted);
    }

    private SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }
}
