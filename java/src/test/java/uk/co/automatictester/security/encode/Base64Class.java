package uk.co.automatictester.security.encode;

import lombok.extern.slf4j.Slf4j;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.Base64;

@Slf4j
public class Base64Class {

    @DataProvider
    private Object[][] data() {
        return new Object[][]{
                {"Lorem"},
                {"Lorem ipsum"},
                {"Lorem ipsum dolor"},
                {"Lorem ipsum dolor sit"},
                {"Lorem ipsum dolor sit amet"},
        };
    }

    @Test(dataProvider = "data")
    public void testBase64Encoding(String data) {
        // common options include:
        // - Base64.getEncoder().withoutPadding()
        // - Base64.getUrlEncoder()
        // - Base64.getMimeEncoder()
        String encoded = Base64.getEncoder().encodeToString(data.getBytes());
        log.info(encoded);
    }
}
