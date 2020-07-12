package uk.co.automatictester.security.history;

import org.testng.annotations.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

public class Caesar {

    private static final int SHIFT = 3;
    private static final int LOWER_BOUND = 65;
    private static final int UPPER_BOUND = 90;

    @Test
    public void testEncrypt() {
        String plaintext = "ABCDEFXYZ";
        String ciphertext = encrypt(plaintext);
        String expected = "DEFGHIABC";
        assertThat(ciphertext, equalTo(expected));
    }

    @Test
    public void testDecrypt() {
        String ciphertext = "ABCDEFXYZ";
        String plaintext = decrypt(ciphertext);
        String expected = "XYZABCUVW";
        assertThat(plaintext, equalTo(expected));
    }

    private String encrypt(String s) {
        StringBuilder ciphertext = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            validate(c);
            char next = encryptChar(c);
            ciphertext.append(next);
        }
        return ciphertext.toString();
    }

    private String decrypt(String s) {
        StringBuilder plaintext = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            validate(c);
            char next = decryptChar(c);
            plaintext.append(next);
        }
        return plaintext.toString();
    }

    private char encryptChar(char c) {
        int zeroBasedValue = c - LOWER_BOUND;
        int newZeroBasedValue = (zeroBasedValue + SHIFT) % 26;
        return (char) (newZeroBasedValue + LOWER_BOUND);
    }

    private char decryptChar(char c) {
        int zeroBasedValue = c - LOWER_BOUND;
        int forwardShift = -SHIFT + 26;
        int newZeroBasedValue = (zeroBasedValue + forwardShift) % 26;
        return (char) (newZeroBasedValue + LOWER_BOUND);
    }

    private void validate(char c) {
        if (c < LOWER_BOUND || c > UPPER_BOUND) throw new IllegalArgumentException();
    }
}
