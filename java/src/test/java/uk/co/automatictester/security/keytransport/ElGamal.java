package uk.co.automatictester.security.keytransport;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import javax.crypto.*;
import java.security.*;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

@Slf4j
public class ElGamal {

    @DataProvider(name = "variant")
    public Object[][] variant() {
        return new Object[][]{
                {"ElGamal/NONE/OAEPwithSHA256andMGF1Padding"},
        };
    }

    @Test(dataProvider = "variant")
    public void testRsa(String variant) throws Exception {
        KeyPair keyPair = generateKeyPair();
        SecretKey symmetricKey = generateKey();
        for (int i = 0; i < 2; i++) {
            doStuff(variant, keyPair, symmetricKey);
        }
    }

    private void doStuff(String variant, KeyPair keyPair, SecretKey symmetricKey)
            throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        byte[] wrappedKey = wrapKey(variant, symmetricKey, publicKey);
        String wrappedKeyAlgorithm = symmetricKey.getAlgorithm();
        SecretKey unwrappedKey = unwrapKey(variant, wrappedKey, wrappedKeyAlgorithm, privateKey);
        assertThat(symmetricKey, is(equalTo(unwrappedKey)));
        log.info("Length: {}, Hex: {}", wrappedKey.length, Hex.toHexString(wrappedKey));
    }

    private SecretKey unwrapKey(String variant, byte[] wrappedKey, String wrappedKeyAlgorithm, PrivateKey privateKey)
            throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance(variant, new BouncyCastleProvider());
        cipher.init(Cipher.UNWRAP_MODE, privateKey);
        return (SecretKey) cipher.unwrap(wrappedKey, wrappedKeyAlgorithm, Cipher.SECRET_KEY);
    }

    private byte[] wrapKey(String variant, SecretKey symmetricKey, PublicKey publicKey)
            throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(variant, new BouncyCastleProvider());
        cipher.init(Cipher.WRAP_MODE, publicKey);
        return cipher.wrap(symmetricKey);
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }
}
