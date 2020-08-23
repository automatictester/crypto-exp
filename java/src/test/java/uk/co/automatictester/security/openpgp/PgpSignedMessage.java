package uk.co.automatictester.security.openpgp;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.Date;

@Slf4j
public class PgpSignedMessage {

    private byte[] onePassSignatureList;

    @Getter
    private byte[] literalData;

    private PGPSignature pgpSignature;

    public PgpSignedMessage(byte[] message, PGPKeyPair pgpKeyPair, int pgpSignatureType, char pgpLiteralDataType)
            throws Exception {
        int messageLength = message.length;
        storeOnePassSignature(pgpKeyPair, pgpSignatureType, messageLength, pgpLiteralDataType);
        storeLiteralData(message);
        storeSignature(pgpKeyPair, pgpSignatureType);
    }

    private void storeOnePassSignature(PGPKeyPair pgpKeyPair, int pgpSignatureType, int messageLength, char pgpLiteralDataType)
            throws Exception {
        // this method is a bit convoluted, due to how OpenPGP-related classes in BC are implemented
        // namely, One-Pass Signature aka signature header is generated in two separate steps (see below)

        PGPSignatureGenerator pgpSignatureGenerator = PgpShared.getPGPSignatureGenerator(pgpKeyPair, pgpSignatureType);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        BCPGOutputStream onePassSignatureOutputStream = new BCPGOutputStream(byteArrayOutputStream);

        // One-Pass Signature generation - step 1/2
        pgpSignatureGenerator.generateOnePassVersion(false).encode(onePassSignatureOutputStream);

        PGPLiteralDataGenerator pgpLiteralDataGenerator = new PGPLiteralDataGenerator();

        // One-Pass Signature generation - step 2/2
        OutputStream literalDataOutputStream = pgpLiteralDataGenerator.open(
                onePassSignatureOutputStream,
                pgpLiteralDataType,
                PGPLiteralData.CONSOLE,
                messageLength,
                new Date()
        );

        pgpLiteralDataGenerator.close();
        literalDataOutputStream.close();
        onePassSignatureOutputStream.close();
        byteArrayOutputStream.close();

        onePassSignatureList = byteArrayOutputStream.toByteArray();
    }

    private void storeLiteralData(byte[] message) {
        literalData = message;
    }

    private void storeSignature(PGPKeyPair pgpKeyPair, int pgpSignatureType) throws Exception {
        PGPSignatureGenerator pgpSignatureGenerator = PgpShared.getPGPSignatureGenerator(pgpKeyPair, pgpSignatureType);
        pgpSignature = PgpShared.generateSignature(pgpSignatureGenerator, literalData);
    }

    public boolean validate(PGPPublicKey pgpPublicKey) throws Exception {
        PGPContentVerifierBuilderProvider pgpContentVerifierBuilderProvider =
                new JcaPGPContentVerifierBuilderProvider().setProvider(new BouncyCastleProvider());

        if (pgpSignature.getKeyID() != pgpPublicKey.getKeyID()) {
            throw new RuntimeException("Signature not generated using this key");
        }

        PGPOnePassSignature onePassSignature = getOnePassSignature();
        onePassSignature.init(pgpContentVerifierBuilderProvider, pgpPublicKey);
        onePassSignature.update(literalData);

        return onePassSignature.verify(pgpSignature);
    }

    private PGPOnePassSignature getOnePassSignature() throws Exception {
        JcaPGPObjectFactory pgpObjectFactory = new JcaPGPObjectFactory(onePassSignatureList);
        PGPOnePassSignatureList pgpOnePassSignatureList = (PGPOnePassSignatureList) pgpObjectFactory.nextObject();
        return pgpOnePassSignatureList.get(0);
    }

    public byte[] asBytes() throws Exception {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(onePassSignatureList);
        byteArrayOutputStream.write(literalData);
        byteArrayOutputStream.write(pgpSignature.getEncoded());
        byteArrayOutputStream.close();
        return byteArrayOutputStream.toByteArray();
    }
}
