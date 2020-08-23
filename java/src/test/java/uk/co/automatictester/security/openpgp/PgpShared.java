package uk.co.automatictester.security.openpgp;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Date;

public class PgpShared {

    public static PGPSignature generateSignature(PGPSignatureGenerator pgpSignatureGenerator, byte[] message) throws Exception {
        pgpSignatureGenerator.update(message);
        return pgpSignatureGenerator.generate();
    }

    public static PGPSignatureGenerator getPGPSignatureGenerator(PGPKeyPair pgpKeyPair, int pgpSignatureType) throws Exception {
        PGPPrivateKey pgpPrivateKey = pgpKeyPair.getPrivateKey();
        int signingAlgorithm = pgpKeyPair.getPublicKey().getAlgorithm();

        JcaPGPContentSignerBuilder pgpContentSignerBuilder =
                new JcaPGPContentSignerBuilder(signingAlgorithm, PGPUtil.SHA256)
                        .setProvider(new BouncyCastleProvider());

        PGPSignatureGenerator pgpSignatureGenerator = new PGPSignatureGenerator(pgpContentSignerBuilder);
        pgpSignatureGenerator.init(pgpSignatureType, pgpPrivateKey);

        return pgpSignatureGenerator;
    }

    public static PGPKeyPair generatePgpDsaKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA", new BouncyCastleProvider());
        keyPairGenerator.initialize(2048);
        KeyPair dsaKeyPair = keyPairGenerator.generateKeyPair();
        Date keyPairCreationDate = new Date();
        return new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKeyPair, keyPairCreationDate);
    }

    public static PGPKeyPair generatePgpRsaEncryptionKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        RSAKeyGenParameterSpec parameterSpec = new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4);
        keyPairGenerator.initialize(parameterSpec);
        Date keyPairCreationDate = new Date();
        KeyPair rsaKeyPair = keyPairGenerator.generateKeyPair();
        return new JcaPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, rsaKeyPair, keyPairCreationDate);
    }
}
