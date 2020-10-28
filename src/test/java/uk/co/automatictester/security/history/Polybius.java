package uk.co.automatictester.security.history;

import org.testng.annotations.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

public class Polybius {

    private final String[][] encryptionTable = new String[][]{
            {"A", "B", "C", "D", "E"},
            {"F", "G", "H", "I", "K"},
            {"L", "M", "N", "O", "P"},
            {"Q", "R", "S", "T", "U"},
            {"V", "W", "X", "Y", "Z"},
    };

    @Test
    public void testEncryption() {
        String plaintext = "BATJ";
        String ciphertext = encrypt(plaintext);
        assertThat(ciphertext, equalTo("12114424"));
    }

    @Test
    public void testDecryption() {
        String ciphertext = "12114424";
        String plaintext = decrypt(ciphertext);
        assertThat(plaintext, equalTo("BATI"));
    }

    private String encrypt(String plaintext) {
        String processedPlaintext = plaintext.replace("J", "I");
        StringBuilder ciphertext = new StringBuilder();
        for (int i = 0; i < processedPlaintext.length(); i++) {
            String nextCharacter = processedPlaintext.substring(i, i + 1);
            String nextNumber = characterToNumber(nextCharacter);
            ciphertext.append(nextNumber);
        }
        return ciphertext.toString();
    }

    private String characterToNumber(String character) {
        for (int row = 0; row < 5; row++) {
            for (int col = 0; col < 5; col++) {
                if (encryptionTable[row][col].equals(character)) {
                    return "" + (row + 1) + (col + 1);
                }
            }
        }
        throw new IllegalArgumentException();
    }

    private String decrypt(String ciphertext) {
        StringBuilder plaintext = new StringBuilder();
        for (int i = 0; i < ciphertext.length(); i += 2) {
            String number = ciphertext.substring(i, i + 2);
            String character = numberToCharacter(number);
            plaintext.append(character);
        }
        return plaintext.toString();
    }

    private String numberToCharacter(String number) {
        int row = Integer.parseInt(number.substring(0, 1)) - 1;
        int col = Integer.parseInt(number.substring(1, 2)) - 1;
        return encryptionTable[row][col];
    }
}
