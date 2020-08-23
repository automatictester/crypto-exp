package uk.co.automatictester.security.openpgp;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

@Slf4j
public class SignedMessage {

    @DataProvider
    private Object[][] data() {
        return new Object[][]{
                {PGPSignature.BINARY_DOCUMENT, PGPLiteralData.BINARY},
                {PGPSignature.CANONICAL_TEXT_DOCUMENT, PGPLiteralData.TEXT},
        };
    }

    @Test(dataProvider = "data")
    public void testPgpSignedMessageCreation(int pgpSignature, char pgpLiteralData) throws Exception {
        byte[] originalMessage = "Lorem ipsum dolor sit amet".getBytes();
        log.info("Original message: {}", new String(originalMessage));

        PGPKeyPair pgpKeyPair = PgpShared.generatePgpDsaKeyPair();
        PGPPublicKey pgpPublicKey = pgpKeyPair.getPublicKey();

        // create signed message from input
        PgpSignedMessage signedMessage = new PgpSignedMessage(originalMessage, pgpKeyPair, pgpSignature, pgpLiteralData);
        log.info("Signed message: \n{}", new String(signedMessage.asBytes()));
        log.info("Recovered message: {}", new String(signedMessage.getLiteralData()));
        assertTrue(signedMessage.validate(pgpPublicKey));
        assertEquals(originalMessage, signedMessage.getLiteralData());

        // create signed message from bytes
        byte[] signedMessageAsBytes = signedMessage.asBytes();
        PgpSignedMessageValidator pgpSignedMessageValidator = new PgpSignedMessageValidator(signedMessageAsBytes);
        assertTrue(pgpSignedMessageValidator.validate(pgpPublicKey));
    }
}
