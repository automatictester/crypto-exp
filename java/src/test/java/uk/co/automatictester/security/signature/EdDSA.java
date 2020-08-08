package uk.co.automatictester.security.signature;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.security.*;
import java.util.Base64;

import static org.testng.Assert.assertTrue;

@Slf4j
public class EdDSA {

    @DataProvider(name = "variant")
    public Object[][] variant() {
        return new Object[][]{
                {"Ed25519"},
                {"Ed448"},
        };
    }

    @Test(dataProvider = "variant")
    public void testEdDsa(String variant) throws Exception {
        KeyPair keyPair = generateKeyPair(variant);
        byte[] plaintext = "Lorem ipsum dolor sit amet".getBytes();
        for (int i = 0; i < 2; i++) {
            doStuff(variant, keyPair, plaintext);
        }
    }

    private void doStuff(String variant, KeyPair keyPair, byte[] plaintext) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        byte[] signature = generateSignature(variant, plaintext, privateKey);
        boolean signatureVerificationResult = verifySignature(variant, plaintext, signature, publicKey);
        assertTrue(signatureVerificationResult);
        log.info("Length: {}, Base64: {}", signature.length, Base64.getEncoder().encodeToString(signature));
    }

    private boolean verifySignature(String variant, byte[] plaintext, byte[] signatureToVerify, PublicKey publicKey)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(variant, new BouncyCastleProvider());
        signature.initVerify(publicKey);
        signature.update(plaintext);
        return signature.verify(signatureToVerify);
    }

    private byte[] generateSignature(String variant, byte[] plaintext, PrivateKey privateKey)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(variant, new BouncyCastleProvider());
        signature.initSign(privateKey);
        signature.update(plaintext);
        return signature.sign();
    }

    private KeyPair generateKeyPair(String variant) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(variant, new BouncyCastleProvider());
        return keyPairGenerator.generateKeyPair();
    }
}
