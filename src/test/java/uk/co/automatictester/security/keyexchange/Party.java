package uk.co.automatictester.security.keyexchange;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
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
    private SecretKey secretKey;

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
        secretKey = keyAgreement.generateSecret("AES");
        String hexKey = Hex.toHexString(secretKey.getEncoded());
        int keyLength = secretKey.getEncoded().length * 8;
        log.info("{} secret key: {}, length: {} bit", name, hexKey, keyLength);
    }

    public void prepareForKeyExchange() throws Exception {
        keyPair = generateKeyPair();
        keyAgreement = KeyAgreement.getInstance("DH", new BouncyCastleProvider());
        keyAgreement.init(keyPair.getPrivate());
    }

    public void exchangeKey(String otherPartyBase64EncodedPublicKey) throws Exception {
        PublicKey otherPartyPublicKey = base64ToPublicKey(otherPartyBase64EncodedPublicKey);
        DHParameterSpec dhParamFromOtherPartyPublicKey = ((DHPublicKey) otherPartyPublicKey).getParams();
        keyPair = generateKeyPair(dhParamFromOtherPartyPublicKey);
        keyAgreement = KeyAgreement.getInstance("DH", new BouncyCastleProvider());
        keyAgreement.init(keyPair.getPrivate());
        finalizeKeyExchange(otherPartyPublicKey);
    }

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = getKeyPairGenerator();
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private KeyPair generateKeyPair(DHParameterSpec dhParameterSpec) throws Exception {
        KeyPairGenerator keyPairGenerator = getKeyPairGenerator();
        keyPairGenerator.initialize(dhParameterSpec);
        return keyPairGenerator.generateKeyPair();
    }

    private KeyPairGenerator getKeyPairGenerator() throws Exception {
        return KeyPairGenerator.getInstance("DH");
    }

    private PublicKey base64ToPublicKey(String base64EncodedKey) throws Exception {
        byte[] publicKey = Base64.getDecoder().decode(base64EncodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKey);
        return keyFactory.generatePublic(x509KeySpec);
    }

    private Cipher getCipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    private GCMParameterSpec getGcmParams(byte[] iv) {
        int tagLength = 128;
        return new GCMParameterSpec(tagLength, iv);
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
        log.info("{} received encrypted: '{}'", name, Hex.toHexString(encrypted));
        Cipher cipher = getCipher();
        GCMParameterSpec gcmParams = getGcmParams(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParams);
        String decprypted = new String(cipher.doFinal(encrypted));
        log.info("{} decrypted: '{}'\n", name, decprypted);
        return decprypted;
    }

    public String getPublicKey() {
        byte[] publicKey = keyPair.getPublic().getEncoded();
        return Base64.getEncoder().encodeToString(publicKey);
    }
}
