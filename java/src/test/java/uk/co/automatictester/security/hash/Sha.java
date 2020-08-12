package uk.co.automatictester.security.hash;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

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
        String hexDigest = Hex.toHexString(rawDigest);

        log.info("Hash: {}, length: {}, Hex digest: {}", hash, rawDigest.length, hexDigest);
    }
}
