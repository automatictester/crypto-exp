package uk.co.automatictester.security.keyexchange;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Slf4j
public class DHKeyExchangeParty {

    private final String keyAlgorithm = "DH";
    private final KeyPair keyPair;
    private DHPublicKey otherPartyPublicKey;

    public DHKeyExchangeParty(int keySize) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm);
        keyPairGenerator.initialize(keySize);
        keyPair = keyPairGenerator.generateKeyPair();
    }

    public DHKeyExchangeParty(String otherPartyBase64EncodedPublicKey) throws Exception {
        otherPartyPublicKey = base64ToPublicKey(otherPartyBase64EncodedPublicKey);
        DHParameterSpec dhParameterSpec = otherPartyPublicKey.getParams();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm);
        keyPairGenerator.initialize(dhParameterSpec);
        keyPair = keyPairGenerator.generateKeyPair();
    }

    public byte[] generateSharedSecret(String otherPartyBase64EncodedPublicKey) throws Exception {
        otherPartyPublicKey = base64ToPublicKey(otherPartyBase64EncodedPublicKey);
        return generateSharedSecret();
    }

    public byte[] generateSharedSecret() throws Exception {
        if (otherPartyPublicKey == null) {
            throw new IllegalStateException();
        }
        String keyExchangeAlgorithm = "DH";
        PrivateKey privateKey = keyPair.getPrivate();
        KeyAgreement keyAgreement = KeyAgreement.getInstance(keyExchangeAlgorithm);
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(otherPartyPublicKey, true);

        byte[] sharedSecret = keyAgreement.generateSecret();
        String sharedSecretAsHex = Hex.toHexString(sharedSecret);
        int keyLength = sharedSecret.length * 8;
        log.info("shared secret: {}, length: {} bit", sharedSecretAsHex, keyLength);
        return sharedSecret;
    }

    public String getBase64EncodedPublicKey() {
        byte[] publicKey = keyPair.getPublic().getEncoded();
        return Base64.getEncoder().encodeToString(publicKey);
    }

    public DHPublicKey getPublicKey() {
        return (DHPublicKey) keyPair.getPublic();
    }

    private DHPublicKey base64ToPublicKey(String base64EncodedKey) throws Exception {
        byte[] publicKey = Base64.getDecoder().decode(base64EncodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKey);
        return (DHPublicKey) keyFactory.generatePublic(x509KeySpec);
    }
}
