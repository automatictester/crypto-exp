package uk.co.automatictester.security.revocation;

import org.testng.annotations.Test;

import javax.net.ssl.SSLHandshakeException;
import java.io.IOException;
import java.net.URL;
import java.security.Security;

public class RevocationChecker {

    @Test(expectedExceptions = SSLHandshakeException.class, expectedExceptionsMessageRegExp = ".*Certificate has been revoked.*")
    public void checkCRL() throws IOException {
        System.setProperty("com.sun.net.ssl.checkRevocation", "true");
        System.setProperty("com.sun.security.enableCRLDP", "true");
        call();
    }

    @Test(expectedExceptions = SSLHandshakeException.class, expectedExceptionsMessageRegExp = ".*Certificate has been revoked.*")
    public void checkOCSP() throws IOException {
        System.setProperty("com.sun.net.ssl.checkRevocation", "true");
        Security.setProperty("ocsp.enable", "true");
        call();
    }

    // this method will fail if executed as part of the entire class. this is because setting properties at runtime is
    // not always reliable. some classes will read property values only once and will miss any updates.
    @Test
    public void noChecks() throws IOException {
        call();
    }

    private void call() throws IOException {
        new URL("https://revoked.badssl.com").openConnection().connect();
    }
}
