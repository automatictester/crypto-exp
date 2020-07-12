package uk.co.automatictester.security.history;

import org.testng.annotations.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

public class ROT13 {

    private static final int SHIFT = 13;
    private static final int LOWER_BOUND = 65;
    private static final int UPPER_BOUND = 90;

    @Test
    public void testEncrypt() {
        String plaintext = "ABCDEFXYZ";
        String ciphertext = encrypt(plaintext);
        String expected = "NOPQRSKLM";
        assertThat(expected, equalTo(ciphertext));

        String plaintextAgain = encrypt(ciphertext);
        assertThat(plaintextAgain, equalTo(plaintext));
    }

    private String encrypt(String s) {
        StringBuilder cippertext = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            validate(c);
            char next = encryptChar(c);
            cippertext.append(next);
        }
        return cippertext.toString();
    }

    private char encryptChar(char c) {
        int zeroBasedValue = c - LOWER_BOUND;
        int newZeroBasedValie = (zeroBasedValue + SHIFT) % 26;
        return (char) (newZeroBasedValie + LOWER_BOUND);
    }

    private void validate(char c) {
        if (c < LOWER_BOUND || c > UPPER_BOUND) throw new IllegalArgumentException();
    }
}
