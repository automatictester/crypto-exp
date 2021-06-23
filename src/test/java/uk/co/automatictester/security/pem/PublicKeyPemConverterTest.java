package uk.co.automatictester.security.pem;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

public class PublicKeyPemConverterTest {

    @Test
    public void testConversion()
            throws IOException, InvalidKeySpecException {
        String publicKeyPem = readPublicKeyFromFile();
        String algorithm = "EC";

        PublicKey publicKeyObject = PublicKeyPemConverter.fromPem(publicKeyPem, algorithm);
        String publicKeyPemAgain = PublicKeyPemConverter.toPem(publicKeyObject);

        assertThat(publicKeyPem, equalTo(publicKeyPemAgain));
    }

    @DataProvider(name = "data")
    public Object[][] data() {
        return new Object[][]{
                {readPublicKeyFromFile(), ""},
                {readPublicKeyFromFile(), null},
                {"", "EC"},
                {null, "EC"}
        };
    }

    @Test(dataProvider = "data", expectedExceptions = IllegalArgumentException.class)
    public void testConversionExceptions(String publicKeyPem, String algorithm)
            throws IOException, InvalidKeySpecException {

        PublicKey publicKeyObject = PublicKeyPemConverter.fromPem(publicKeyPem, algorithm);
        String publicKeyPemAgain = PublicKeyPemConverter.toPem(publicKeyObject);

        assertThat(publicKeyPem, equalTo(publicKeyPemAgain));
    }

    private String readPublicKeyFromFile() {
        InputStream inputStream = ClassLoader.getSystemResourceAsStream("github-com.pem");
        return new Scanner(inputStream).useDelimiter("\\A").next();
    }
}
