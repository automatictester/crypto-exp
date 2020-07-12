package uk.co.automatictester.security.key.exchange;

import lombok.extern.slf4j.Slf4j;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.security.SecureRandom;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

@Slf4j
public class DiffieHellman {

    private Party alice;
    private Party bob;

    @BeforeClass
    public void setup() throws Exception {
        alice = new Party("Alice");
        String alicePublicKey = alice.getPublicKey();

        bob = new Party("Bob", alicePublicKey);
        String bobPublicKey = bob.getPublicKey();

        alice.finalizeKeyExchange(bobPublicKey);
    }

    @Test
    public void testKeyExchange() throws Exception {
        send(alice, bob, "message #1", getIv());
        send(bob, alice, "message #2", getIv());
        send(alice, bob, "message #3", getIv());
        send(bob, alice, "message #4", getIv());
    }

    @Test
    public void testKeyRotation() throws Exception {
        alice.prepareForKeyExchange();
        String alicePublicKey = alice.getPublicKey();

        bob.exchangeKey(alicePublicKey);
        String bobPublicKey = bob.getPublicKey();

        alice.finalizeKeyExchange(bobPublicKey);

        send(alice, bob, "message #1", getIv());
        send(bob, alice, "message #2", getIv());
        send(alice, bob, "message #3", getIv());
        send(bob, alice, "message #4", getIv());
    }

    private void send(Party sender, Party recipient, String message, byte[] iv) throws Exception {
        byte[] encrypted = sender.encrypt(message, iv);
        String decrypted = recipient.decrypt(encrypted, iv);
        assertThat(message, equalTo(decrypted));
    }

    private byte[] getIv() {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        log.debug("Initialization vector: {}", iv);
        return iv;
    }
}
