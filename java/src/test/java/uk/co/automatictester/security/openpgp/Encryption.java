package uk.co.automatictester.security.openpgp;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

@Slf4j
public class Encryption {

    @DataProvider
    private Object[][] data() throws Exception {
        return new Object[][]{
                {PgpShared.generatePgpRsaEncryptionKeyPair()},
                {PgpShared.generatePgpElGamalEncryptionKeyPair()},
                {PgpShared.generatePgpEcDhEncryptionKeyPair()},
        };
    }

    @Test(dataProvider = "data")
    public void testEncryption(PGPKeyPair pgpKeyPair) throws Exception {
        byte[] plaintext = "Lorem ipsum dolor sit amet".getBytes();
        PGPPublicKey pgpPublicKey = pgpKeyPair.getPublicKey();
        PGPPrivateKey pgpPrivateKey = pgpKeyPair.getPrivateKey();

        PGPEncryptedDataGenerator pgpEncryptedDataGenerator = createPgpEncryptedDataGenerator(pgpPublicKey);
        byte[] ciphertext = encrypt(pgpEncryptedDataGenerator, plaintext);
        byte[] decrypted = decrypt(pgpPrivateKey, ciphertext);

        assertThat(decrypted, equalTo(plaintext));
    }

    private PGPEncryptedDataGenerator createPgpEncryptedDataGenerator(PGPPublicKey encryptionPublicKey) {
        PGPEncryptedDataGenerator pgpEncryptedDataGenerator = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                        .setWithIntegrityPacket(true)
                        .setSecureRandom(new SecureRandom())
                        .setProvider(new BouncyCastleProvider()));
        pgpEncryptedDataGenerator.addMethod(
                new JcePublicKeyKeyEncryptionMethodGenerator(encryptionPublicKey)
                        .setProvider(new BouncyCastleProvider()));
        return pgpEncryptedDataGenerator;
    }

    private byte[] encrypt(PGPEncryptedDataGenerator pgpEncryptedDataGenerator, byte[] plaintext) throws Exception {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        byte[] buffer = new byte[4096];
        OutputStream encryptedOutputStream = pgpEncryptedDataGenerator.open(byteArrayOutputStream, buffer);

        PGPLiteralDataGenerator pgpLiteralDataGenerator = new PGPLiteralDataGenerator();
        OutputStream outputStream = pgpLiteralDataGenerator.open(
                encryptedOutputStream,
                PGPLiteralData.BINARY,
                PGPLiteralData.CONSOLE,
                plaintext.length,
                new Date());

        outputStream.write(plaintext);

        outputStream.close();
        encryptedOutputStream.close();

        return byteArrayOutputStream.toByteArray();
    }

    private byte[] decrypt(PGPPrivateKey encryptionPrivateKey, byte[] ciphertext) throws Exception {
        PGPObjectFactory ciphertextFactory = new JcaPGPObjectFactory(ciphertext);
        PGPEncryptedDataList pgpEncryptedDataList = (PGPEncryptedDataList) ciphertextFactory.nextObject();
        PGPPublicKeyEncryptedData pgpPublicKeyEncryptedData = (PGPPublicKeyEncryptedData) pgpEncryptedDataList.get(0);

        int keyAlgorithmId = encryptionPrivateKey.getPublicKeyPacket().getAlgorithm();
        String keyAlgorithm = PgpShared.getKeyAlgorithm(keyAlgorithmId);
        log.info("Key algorithm: {}", keyAlgorithm);

        if (pgpPublicKeyEncryptedData.getKeyID() != encryptionPrivateKey.getKeyID()) {
            throw new RuntimeException("Signature not generated using this key");
        }

        PublicKeyDataDecryptorFactory publicKeyDataDecryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder()
                .setProvider(new BouncyCastleProvider())
                .build(encryptionPrivateKey);

        InputStream encryptedDataInputStream = pgpPublicKeyEncryptedData.getDataStream(publicKeyDataDecryptorFactory);
        byte[] literalData = Streams.readAll(encryptedDataInputStream);
        encryptedDataInputStream.close();

        if (!pgpPublicKeyEncryptedData.verify()) {
            throw new IllegalStateException("Integrity check failed");
        }

        PGPObjectFactory literalDatFactory = new JcaPGPObjectFactory(literalData);
        PGPLiteralData pgpLiteralData = (PGPLiteralData) literalDatFactory.nextObject();
        return Streams.readAll(pgpLiteralData.getInputStream());
    }
}
