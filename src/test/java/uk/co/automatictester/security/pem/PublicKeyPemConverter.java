package uk.co.automatictester.security.pem;

import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class PublicKeyPemConverter {

    public static PublicKey fromPem(String publicKeyPem, String algorithm)
            throws IOException, InvalidKeySpecException {
        validateInput(publicKeyPem, algorithm);

        StringReader stringReader = new StringReader(publicKeyPem);
        PEMParser pemParser = new PEMParser(stringReader);
        PemObject publicKeyObject = pemParser.readPemObject();

        validatePublicKeyObject(publicKeyObject, publicKeyPem);

        byte[] publicKeyBytes = publicKeyObject.getContent();
        KeyFactory keyFactory = getKeyFactory(algorithm);
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        return keyFactory.generatePublic(x509EncodedKeySpec);
    }

    private static void validateInput(String publicKeyPem, String algorithm) {
        if (publicKeyPem == null) {
            throw new IllegalArgumentException("Public key PEM is null");
        } else if (algorithm == null) {
            throw new IllegalArgumentException("Algorithm is null");
        }
    }

    private static void validatePublicKeyObject(PemObject pemObject, String publicKeyPem) {
        if (pemObject == null) {
            String errorMessage = String.format("Invalid public key PEM: '%s'", publicKeyPem);
            throw new IllegalArgumentException(errorMessage);
        }
    }

    private static KeyFactory getKeyFactory(String algorithm) {
        try {
            return KeyFactory.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            String errorMessage = String.format("Invalid algorithm: '%s'", algorithm);
            throw new IllegalArgumentException(errorMessage, e);
        }
    }

    public static String toPem(PublicKey publicKey) throws IOException {
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        byte[] publicKeyBytes = publicKey.getEncoded();
        String pemObjectType = "PUBLIC KEY";
        PemObjectGenerator pemObjectGenerator = new PemObject(pemObjectType, publicKeyBytes);
        pemWriter.writeObject(pemObjectGenerator);
        pemWriter.flush();
        pemWriter.close();
        return stringWriter.toString();
    }
}
