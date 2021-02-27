package uk.co.automatictester.security.ec;

import org.testng.annotations.Test;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;

public class ECKeys {

    @Test
    public void compareKeyParams() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        ECPublicKey ecPublicKeyA = generateECPublicKey();
        ECPublicKey ecPublicKeyB = generateECPublicKey();

        assertThat(ecPublicKeyA.getParams(), equalTo(ecPublicKeyB.getParams()));
        assertThat(ecPublicKeyA.getW(), not(equalTo(ecPublicKeyB.getW())));
    }

    private ECPublicKey generateECPublicKey()
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec params = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(params);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return (ECPublicKey) keyPair.getPublic();
    }
}
