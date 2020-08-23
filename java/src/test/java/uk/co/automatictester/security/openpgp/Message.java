package uk.co.automatictester.security.openpgp;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.testng.annotations.Test;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.Date;

@Slf4j
public class Message {

    @Test
    public void testMessageGeneration() throws Exception {
        byte[] message = "Lorem ipsum dolor sit amet".getBytes();

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(byteArrayOutputStream);
        PGPLiteralDataGenerator pgpLiteralDataGenerator = new PGPLiteralDataGenerator();

        OutputStream outputStream = pgpLiteralDataGenerator.open(
                armoredOutputStream,
                PGPLiteralData.TEXT,
                PGPLiteralData.CONSOLE,
                message.length,
                new Date()
        );

        outputStream.write(message);
        outputStream.close();
        armoredOutputStream.close();

        byte[] pgpMessage = byteArrayOutputStream.toByteArray();
        log.info(new String(pgpMessage));
    }
}
