package uk.co.automatictester.security.openpgp;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Date;

@Slf4j
public class PgpSignedMessage {

    @Getter
    private PGPOnePassSignature pgpOnePassSignature;

    private byte[] literalData;

    @Getter
    private PGPSignature pgpSignature;

    public PgpSignedMessage(byte[] message, PGPKeyPair pgpKeyPair, int pgpSignatureType, char pgpLiteralDataType) throws Exception {
        storeOnePassSignature(pgpKeyPair, pgpSignatureType);
        storeLiteralData(message, pgpLiteralDataType);
        storeSignature(pgpKeyPair, pgpSignatureType);
    }

    public PgpSignedMessage(byte[] encodedSignedMessage) throws Exception {
        JcaPGPObjectFactory pgpObjectFactory = new JcaPGPObjectFactory(encodedSignedMessage);
        parseOnePassSignature(pgpObjectFactory);
        parseMessage(pgpObjectFactory);
        parseSignature(pgpObjectFactory);
    }

    private void storeOnePassSignature(PGPKeyPair pgpKeyPair, int pgpSignatureType) throws Exception {
        PGPSignatureGenerator pgpSignatureGenerator = PgpShared.getPGPSignatureGenerator(pgpKeyPair, pgpSignatureType);
        pgpOnePassSignature = pgpSignatureGenerator.generateOnePassVersion(false);
    }

    private void storeLiteralData(byte[] message, char pgpLiteralDataType) throws Exception {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        BCPGOutputStream onePassSignatureOutputStream = new BCPGOutputStream(byteArrayOutputStream);
        Date modificationTime = new Date();

        PGPLiteralDataGenerator pgpLiteralDataGenerator = new PGPLiteralDataGenerator();
        OutputStream outputStream = pgpLiteralDataGenerator.open(
                onePassSignatureOutputStream,
                pgpLiteralDataType,
                PGPLiteralData.CONSOLE,
                message.length,
                modificationTime
        );
        outputStream.write(message);

        pgpLiteralDataGenerator.close();
        outputStream.close();
        onePassSignatureOutputStream.close();
        byteArrayOutputStream.close();

        literalData = byteArrayOutputStream.toByteArray();
    }

    private void storeSignature(PGPKeyPair pgpKeyPair, int pgpSignatureType) throws Exception {
        PGPSignatureGenerator pgpSignatureGenerator = PgpShared.getPGPSignatureGenerator(pgpKeyPair, pgpSignatureType);
        pgpSignature = PgpShared.generateSignature(pgpSignatureGenerator, getMessage());
    }

    private void parseOnePassSignature(JcaPGPObjectFactory pgpObjectFactory) throws Exception {
        PGPOnePassSignatureList onePassSignatureList = (PGPOnePassSignatureList) pgpObjectFactory.nextObject();
        pgpOnePassSignature = onePassSignatureList.get(0);
    }

    private void parseMessage(JcaPGPObjectFactory pgpObjectFactory) throws Exception {
        PGPLiteralData pgpLiteralData = (PGPLiteralData) pgpObjectFactory.nextObject();
        String filename = pgpLiteralData.getFileName();
        Date modificationTime = pgpLiteralData.getModificationTime();
        char pgpLiteralDataType = (char) pgpLiteralData.getFormat();

        InputStream pgpLiteralDataInputStream = pgpLiteralData.getInputStream();
        byte[] message = Streams.readAll(pgpLiteralDataInputStream);
        pgpLiteralDataInputStream.close();

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        BCPGOutputStream onePassSignatureOutputStream = new BCPGOutputStream(byteArrayOutputStream);

        PGPLiteralDataGenerator pgpLiteralDataGenerator = new PGPLiteralDataGenerator();
        OutputStream outputStream = pgpLiteralDataGenerator.open(
                onePassSignatureOutputStream,
                pgpLiteralDataType,
                filename,
                message.length,
                modificationTime
        );
        outputStream.write(message);

        pgpLiteralDataGenerator.close();
        outputStream.close();
        onePassSignatureOutputStream.close();
        byteArrayOutputStream.close();

        literalData = byteArrayOutputStream.toByteArray();
    }

    private void parseSignature(JcaPGPObjectFactory pgpObjectFactory) throws Exception {
        PGPSignatureList pgpSignatures = (PGPSignatureList) pgpObjectFactory.nextObject();
        pgpSignature = pgpSignatures.get(0);
    }

    public boolean validate(PGPPublicKey pgpPublicKey) throws Exception {
        PGPContentVerifierBuilderProvider pgpContentVerifierBuilderProvider =
                new JcaPGPContentVerifierBuilderProvider().setProvider(new BouncyCastleProvider());

        if (pgpSignature.getKeyID() != pgpPublicKey.getKeyID()) {
            throw new RuntimeException("Signature not generated using this key");
        }

        pgpOnePassSignature.init(pgpContentVerifierBuilderProvider, pgpPublicKey);
        pgpOnePassSignature.update(getMessage());

        return pgpOnePassSignature.verify(pgpSignature);
    }

    public byte[] getMessage() throws Exception {
        JcaPGPObjectFactory pgpObjectFactory = new JcaPGPObjectFactory(literalData);
        PGPLiteralData pgpLiteralData = (PGPLiteralData) pgpObjectFactory.nextObject();

        InputStream pgpLiteralDataInputStream = pgpLiteralData.getInputStream();
        byte[] message = Streams.readAll(pgpLiteralDataInputStream);
        pgpLiteralDataInputStream.close();

        return message;
    }

    public byte[] asBytes() throws Exception {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(pgpOnePassSignature.getEncoded());
        byteArrayOutputStream.write(literalData);
        byteArrayOutputStream.write(pgpSignature.getEncoded());
        byteArrayOutputStream.close();
        return byteArrayOutputStream.toByteArray();
    }
}
