package uk.co.automatictester.security.keyexchange;

import lombok.extern.slf4j.Slf4j;
import org.testng.annotations.Test;

import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

@Slf4j
public class DHKeyExchange {

    @Test
    public void testKeyExchange() throws Exception {
        int keySize = 2048;

        DHKeyExchangeParty bob = new DHKeyExchangeParty(keySize);
        String bobBase64EncodedPublicKey = bob.getBase64EncodedPublicKey();

        DHKeyExchangeParty alice = new DHKeyExchangeParty(bobBase64EncodedPublicKey);
        String aliceBase64EncodedPublicKey = alice.getBase64EncodedPublicKey();

        byte[] aliceSharedSecret = alice.generateSharedSecret();
        byte[] bobSharedSecret = bob.generateSharedSecret(aliceBase64EncodedPublicKey);
        assertThat(aliceSharedSecret, equalTo(bobSharedSecret));

        assertThat(alice.getPublicKey(), not(equalTo(bob.getPublicKey())));
    }
}
