package uk.co.automatictester.security.openpgp;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

public class PgpSignedMessageValidator {
    // it is not clear if it is possible to read One-Pass Signature using JcaPGPObjectFactory and not get truncated data
    // for that reason this class was extracted from PgpSignedMessage for the sole purpose of importing byte array for verification
    // however, we don't allow subsequent re-export of entire Signed Message to a byte array

    private final JcaPGPObjectFactory pgpObjectFactory;

    private PGPOnePassSignature onePassSignature;
    private byte[] literalData;
    private PGPSignature pgpSignature;

    public PgpSignedMessageValidator(byte[] signedMessage) throws Exception {
        pgpObjectFactory = new JcaPGPObjectFactory(signedMessage);
        parseOnePassSignature();
        parseMessage();
        parseSignature();
    }

    private void parseOnePassSignature() throws Exception {
        // here we store truncated One-Pass Signature only for the purpose of signature verification, as truncation doesn't affect it
        PGPOnePassSignatureList onePassSignatureList = (PGPOnePassSignatureList) pgpObjectFactory.nextObject();
        this.onePassSignature = onePassSignatureList.get(0);
    }

    private void parseMessage() throws Exception {
        PGPLiteralData pgpLiteralData = (PGPLiteralData) pgpObjectFactory.nextObject();

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        InputStream pgpLiteralDataInputStream = pgpLiteralData.getInputStream();
        int b;
        while ((b = pgpLiteralDataInputStream.read()) >= 0) {
            byteArrayOutputStream.write(b);
        }
        pgpLiteralDataInputStream.close();
        byteArrayOutputStream.close();

        literalData = byteArrayOutputStream.toByteArray();
    }

    private void parseSignature() throws Exception {
        PGPSignatureList pgpSignatures = (PGPSignatureList) pgpObjectFactory.nextObject();
        pgpSignature = pgpSignatures.get(0);
    }

    public boolean validate(PGPPublicKey pgpPublicKey) throws Exception {
        PGPContentVerifierBuilderProvider pgpContentVerifierBuilderProvider =
                new JcaPGPContentVerifierBuilderProvider().setProvider(new BouncyCastleProvider());

        if (pgpSignature.getKeyID() != pgpPublicKey.getKeyID()) {
            throw new RuntimeException("Signature not generated using this key");
        }

        onePassSignature.init(pgpContentVerifierBuilderProvider, pgpPublicKey);
        onePassSignature.update(literalData);

        return onePassSignature.verify(pgpSignature);
    }
}
