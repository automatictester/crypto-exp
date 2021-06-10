package uk.co.automatictester.security.keyexchange;

import lombok.extern.slf4j.Slf4j;
import org.testng.annotations.Test;

import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

@Slf4j
public class ECDHKeyExchange {

    @Test
    public void testKeyExchange() throws Exception {
        ECDHKeyExchangeParty bob = new ECDHKeyExchangeParty();
        String bobBase64EncodedPublicKey = bob.getBase64EncodedPublicKey();

        ECDHKeyExchangeParty alice = new ECDHKeyExchangeParty(bobBase64EncodedPublicKey);
        String aliceBase64EncodedPublicKey = alice.getBase64EncodedPublicKey();

        byte[] aliceSharedSecret = alice.generateSharedSecret();
        byte[] bobSharedSecret = bob.generateSharedSecret(aliceBase64EncodedPublicKey);
        assertThat(aliceSharedSecret, equalTo(bobSharedSecret));

        assertThat(alice.getPublicKey().getParams(), equalTo(bob.getPublicKey().getParams()));
        assertThat(alice.getPublicKey().getW(), not(equalTo(bob.getPublicKey().getW())));
    }
}
