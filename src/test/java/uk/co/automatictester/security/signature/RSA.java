package uk.co.automatictester.security.signature;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.security.*;
import java.security.spec.RSAKeyGenParameterSpec;

import static org.testng.Assert.assertTrue;

@Slf4j
public class RSA {

    @DataProvider(name = "variant")
    public Object[][] variant() {
        return new Object[][]{
                {"SHA256withRSA"}, // RSA, PKCS#1 v1.5
                {"SHA256withRSAandMGF1"}, // RSA-PSS, PKCS#1 v2.1
        };
    }

    @Test(dataProvider = "variant")
    public void testRsa(String variant) throws Exception {
        KeyPair keyPair = generateKeyPair();
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
        log.info("Length: {}, Hex: {}", signature.length, Hex.toHexString(signature));
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

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        RSAKeyGenParameterSpec parameterSpec = new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4);
        keyPairGenerator.initialize(parameterSpec);
        return keyPairGenerator.generateKeyPair();
    }
}
