package uk.co.automatictester.security.keyexchange;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.KeyAgreement;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Slf4j
public class ECDHKeyExchangeParty {

    private final String keyAlgorithm = "EC";
    private final KeyPair keyPair;
    private ECPublicKey otherPartyPublicKey;

    public ECDHKeyExchangeParty() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm);
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(ecGenParameterSpec);
        keyPair = keyPairGenerator.generateKeyPair();
    }

    public ECDHKeyExchangeParty(String otherPartyBase64EncodedPublicKey) throws Exception {
        otherPartyPublicKey = base64ToPublicKey(otherPartyBase64EncodedPublicKey);
        ECParameterSpec ecParameterSpec = otherPartyPublicKey.getParams();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm);
        keyPairGenerator.initialize(ecParameterSpec);
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
        String keyExchangeAlgorithm = "ECDH";
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

    public ECPublicKey getPublicKey() {
        return (ECPublicKey) keyPair.getPublic();
    }

    private ECPublicKey base64ToPublicKey(String base64EncodedKey) throws Exception {
        byte[] publicKey = Base64.getDecoder().decode(base64EncodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKey);
        return (ECPublicKey) keyFactory.generatePublic(x509KeySpec);
    }
}
