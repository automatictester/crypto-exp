package uk.co.automatictester.security.encode;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base32;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

@Slf4j
public class Base32Class {

    @DataProvider
    private Object[][] data() {
        return new Object[][]{
                {"https"},
                {"https://"},
                {"https://stackoverflow.com"},
                {"https://stackoverflow.com/search?q=base32"},
        };
    }

    @Test(dataProvider = "data")
    public void testBase32Encoding(String data) {
        String encoded = new Base32().encodeAsString(data.getBytes());
        log.info(encoded);
    }
}
