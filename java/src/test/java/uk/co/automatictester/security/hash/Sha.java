package uk.co.automatictester.security.hash;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@Slf4j
public class Sha {

    @DataProvider(name = "hash")
    public Object[][] getHash() {
        return new Object[][]{
                {"SHA-224"},
                {"SHA3-224"},
                {"SHA-256"},
                {"SHA3-256"},
                {"SHA-384"},
                {"SHA3-384"},
                {"SHA-512"},
                {"SHA3-512"},
        };
    }

    @Test(dataProvider = "hash")
    public void testSha(String hash) throws NoSuchAlgorithmException {
        String plaintext = "Lorem ipsum dolor sit amet";

        MessageDigest digest = MessageDigest.getInstance(hash, new BouncyCastleProvider());
        digest.update(plaintext.getBytes());
        byte[] rawDigest = digest.digest();
        String base64encodedDigest = Base64.getEncoder().encodeToString(rawDigest);

        log.info("Hash: {}, length: {}, Base64-encoded digest: {}", hash, rawDigest.length, base64encodedDigest);
    }
}
