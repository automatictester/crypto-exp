package uk.co.automatictester.security.encryption;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

@Slf4j
public class AesAead {

    @DataProvider(name = "cipher")
    public Object[][] cipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
        return new Object[][]{
                {Cipher.getInstance("AES/GCM/NoPadding", new BouncyCastleProvider())},
                {Cipher.getInstance("AES/CCM/NoPadding", new BouncyCastleProvider())},
                {Cipher.getInstance("AES/EAX/NoPadding", new BouncyCastleProvider())},
                {Cipher.getInstance("AES/OCB/NoPadding", new BouncyCastleProvider())},
        };
    }

    @Test(dataProvider = "cipher")
    public void testAesAead(Cipher cipher) throws Exception {
        SecretKey key = generateKey();
        byte[] iv = getIv();
        int tagLength = 128;
        byte[] plaintext = "Lorem ipsum dolor sit amet".getBytes();
        byte[] associatedData = "metadata".getBytes();
        byte[] ciphertext = encrypt(cipher, key, iv, tagLength, plaintext, associatedData);
        byte[] decrypted = decrypt(cipher, key, iv, tagLength, ciphertext, associatedData);
        assertThat(decrypted, equalTo(plaintext));
    }

    public byte[] encrypt(Cipher cipher, SecretKey key, byte[] iv, int tagLength, byte[] plaintext, byte[] associatedData) throws Exception {
        GCMParameterSpec gcmParams = new GCMParameterSpec(tagLength, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParams);
        cipher.updateAAD(associatedData);
        return cipher.doFinal(plaintext);
    }

    public byte[] decrypt(Cipher cipher, SecretKey key, byte[] iv, int tagLength, byte[] ciphertext, byte[] associatedData) throws Exception {
        AEADParameterSpec gcmParams = new AEADParameterSpec(iv, tagLength, associatedData);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParams);
        return cipher.doFinal(ciphertext);
    }

    private byte[] getIv() {
        int ivLength = 12;
        byte[] iv = new byte[ivLength];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        int keyLength = 256;
        keyGenerator.init(keyLength);
        return keyGenerator.generateKey();
    }
}
