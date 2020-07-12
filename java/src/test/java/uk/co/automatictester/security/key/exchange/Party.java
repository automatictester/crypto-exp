package uk.co.automatictester.security.key.exchange;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Slf4j
public class Party {

    private final String name;
    private KeyPair keyPair;
    private KeyAgreement keyAgreement;
    private SecretKeySpec secretKey;

    // initial setup

    public Party(String name) throws Exception {
        this.name = name;
        prepareForKeyExchange();
    }

    public Party(String name, String otherPartyBase64EncodedPublicKey) throws Exception {
        this.name = name;
        exchangeKey(otherPartyBase64EncodedPublicKey);
    }

    public void finalizeKeyExchange(String otherPartyBase64EncodedPublicKey) throws Exception {
        PublicKey otherPartyPublicKey = base64ToPublicKey(otherPartyBase64EncodedPublicKey);
        finalizeKeyExchange(otherPartyPublicKey);
    }

    private void finalizeKeyExchange(PublicKey otherPartyPublicKey) throws Exception {
        keyAgreement.doPhase(otherPartyPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        secretKey = getSecretKey(sharedSecret);
        log.info("{} secret key: {}", name, secretKey.getEncoded());
    }

    // key exchange and rotation

    public void prepareForKeyExchange() throws Exception {
        keyPair = getKeyPair();
        keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(keyPair.getPrivate());
    }

    public void exchangeKey(String otherPartyBase64EncodedPublicKey) throws Exception {
        PublicKey otherPartyPublicKey = base64ToPublicKey(otherPartyBase64EncodedPublicKey);
        DHParameterSpec dhParamFromOtherPartyPublicKey = ((DHPublicKey) otherPartyPublicKey).getParams();
        keyPair = getKeyPair(dhParamFromOtherPartyPublicKey);
        keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(keyPair.getPrivate());
        finalizeKeyExchange(otherPartyPublicKey);
    }

    // internal methods

    private KeyPair getKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = getKeyPairGenerator();
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private KeyPair getKeyPair(DHParameterSpec dhParameterSpec) throws Exception {
        KeyPairGenerator keyPairGenerator = getKeyPairGenerator();
        keyPairGenerator.initialize(dhParameterSpec);
        return keyPairGenerator.generateKeyPair();
    }

    private String publicKeyToBase64() {
        return toBase64(keyPair.getPublic().getEncoded());
    }

    private String toBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private PublicKey base64ToPublicKey(String base64EncodedKey) throws Exception {
        byte[] publicKey = Base64.getDecoder().decode(base64EncodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKey);
        return keyFactory.generatePublic(x509KeySpec);
    }

    private SecretKeySpec getSecretKey(byte[] sharedSecret) {
        return new SecretKeySpec(sharedSecret, 0, 16, "AES");
    }

    private KeyPairGenerator getKeyPairGenerator() throws Exception {
        return KeyPairGenerator.getInstance("DH");
    }

    private Cipher getCipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    private GCMParameterSpec getGcmParams(byte[] iv) {
        int authenticationTagBitLength = 128;
        return new GCMParameterSpec(authenticationTagBitLength, iv);
    }

    // public API

    public byte[] encrypt(String input, byte[] iv) throws Exception {
        log.info("{} sent: '{}'", name, input);
        Cipher cipher = getCipher();
        GCMParameterSpec gcmParams = getGcmParams(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParams);
        return cipher.doFinal(input.getBytes());
    }

    public String decrypt(byte[] encrypted, byte[] iv) throws Exception {
        log.info("{} received: '{}'", name, encrypted);
        Cipher cipher = getCipher();
        GCMParameterSpec gcmParams = getGcmParams(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParams);
        String decprypted = new String(cipher.doFinal(encrypted));
        log.info("{} decrypted: '{}'", name, decprypted);
        return decprypted;
    }

    public String getPublicKey() {
        return publicKeyToBase64();
    }
}
