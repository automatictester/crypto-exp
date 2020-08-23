package uk.co.automatictester.security.openpgp;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertTrue;

public class DetachedSignature {

    @Test
    public void testPgpDetachedSignature() throws Exception {
        byte[] message = "Lorem ipsum dolor sit amet".getBytes();
        PGPKeyPair pgpKeyPair = PgpShared.generatePgpDsaKeyPair();
        PGPPublicKey pgpPublicKey = pgpKeyPair.getPublicKey();

        PGPSignature pgpSignature = generateSignature(message, pgpKeyPair);
        assertTrue(verifySignature(pgpPublicKey, pgpSignature, message));
    }

    private PGPSignature generateSignature(byte[] message, PGPKeyPair pgpKeyPair) throws Exception {
        int pgpSignatureType = PGPSignature.BINARY_DOCUMENT;
        PGPSignatureGenerator pgpSignatureGenerator = PgpShared.getPGPSignatureGenerator(pgpKeyPair, pgpSignatureType);
        return PgpShared.generateSignature(pgpSignatureGenerator, message);
    }

    private boolean verifySignature(PGPPublicKey pgpPublicKey, PGPSignature pgpSignature, byte[] data) throws Exception {
        PGPContentVerifierBuilderProvider pgpContentVerifierBuilderProvider =
                new JcaPGPContentVerifierBuilderProvider()
                        .setProvider(new BouncyCastleProvider());

        if (pgpSignature.getKeyID() != pgpPublicKey.getKeyID()) {
            throw new RuntimeException("Signature not generated using this key");
        }

        pgpSignature.init(pgpContentVerifierBuilderProvider, pgpPublicKey);
        pgpSignature.update(data);
        return pgpSignature.verify();
    }
}
