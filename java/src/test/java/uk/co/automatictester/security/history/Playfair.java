package uk.co.automatictester.security.history;

import lombok.extern.slf4j.Slf4j;
import org.testng.annotations.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

@Slf4j
public class Playfair {

    private final String[][] encryptionTable = new String[][]{
            {"P", "L", "A", "Y", "F"},
            {"I", "R", "B", "C", "D"},
            {"E", "G", "H", "K", "M"},
            {"N", "O", "Q", "S", "T"},
            {"U", "V", "W", "X", "Z"},
    };

    @Test
    public void testEncryption() {
        String plaintext = "TEKSTJAWNY";
        String ciphertext = encrypt(plaintext);
        assertThat(ciphertext, equalTo("NMSXNDBASP"));
    }

    @Test
    public void testDecryption() {
        String ciphertext = "NMSXNDBASP";
        String plaintext = decrypt(ciphertext);
        assertThat(plaintext, equalTo("TEKSTIAWNY"));
    }

    private String encrypt(String plaintext) {
        String sanitizedPlaintext = sanitize(plaintext);
        log.debug("Sanitized plaintext: {}", sanitizedPlaintext);
        StringBuilder ciphertext = new StringBuilder();
        for (int i = 0; i < sanitizedPlaintext.length(); i += 2) {
            String first = sanitizedPlaintext.substring(i, i + 1);
            String second = sanitizedPlaintext.substring(i + 1, i + 2);
            if (sameRow(first, second)) {
                ciphertext.append(encryptSameRow(first));
                ciphertext.append(encryptSameRow(second));
            } else if (sameCol(first, second)) {
                ciphertext.append(encryptSameCol(first));
                ciphertext.append(encryptSameCol(second));
            } else {
                ciphertext.append(handleDifferentRowAndCol(first, second));
            }
        }
        return ciphertext.toString();
    }

    private String decrypt(String ciphertext) {
        StringBuilder plaintext = new StringBuilder();
        for (int i = 0; i < ciphertext.length(); i += 2) {
            String first = ciphertext.substring(i, i + 1);
            String second = ciphertext.substring(i + 1, i + 2);
            if (sameRow(first, second)) {
                plaintext.append(decryptSameRow(first));
                plaintext.append(decryptSameRow(second));
            } else if (sameCol(first, second)) {
                plaintext.append(decryptSameCol(first));
                plaintext.append(decryptSameCol(second));
            } else {
                plaintext.append(handleDifferentRowAndCol(first, second));
            }
        }
        return plaintext.toString();

    }

    private String sanitize(String plaintext) {
        plaintext = plaintext.replace("J", "I");
        plaintext = separateSameCharactersWithX(plaintext);
        plaintext = padIfOddLengthWithX(plaintext);
        return plaintext;
    }

    private String separateSameCharactersWithX(String plaintext) {
        int plaintextLength = plaintext.length();
        for (int i = 0; i < plaintextLength - 1; i++) {
            if (plaintext.substring(i, i + 1).equals(plaintext.substring(i + 1, i + 2))) {
                plaintext = plaintext.substring(0, i + 1) + "X" + plaintext.substring(i + 1);
                plaintextLength++;
                i++;
            }
        }
        return plaintext;
    }

    private String padIfOddLengthWithX(String plaintext) {
        if (plaintext.length() % 2 != 0) {
            plaintext += "X";
        }
        return plaintext;
    }

    private boolean sameRow(String first, String second) {
        int matches = 0;
        for (int row = 0; row < 5; row++) {
            for (int col = 0; col < 5; col++) {
                String current = encryptionTable[row][col];
                if (current.equals(first) || current.equals(second)) {
                    matches++;
                }
            }
            if (matches == 2) {
                return true;
            } else {
                matches = 0;
            }
        }
        return false;
    }

    private boolean sameCol(String first, String second) {
        int matches = 0;
        for (int col = 0; col < 5; col++) {
            for (int row = 0; row < 5; row++) {
                String current = encryptionTable[row][col];
                if (current.equals(first) || current.equals(second)) {
                    matches++;
                }
            }
            if (matches == 2) {
                return true;
            } else {
                matches = 0;
            }
        }
        return false;
    }

    private String encryptSameRow(String character) {
        int[] firstPosition = getPosition(character);
        int row = firstPosition[0];
        int col = firstPosition[1];
        int newCol = ++col % 5;
        return encryptionTable[row][newCol];
    }

    private String encryptSameCol(String character) {
        int[] firstPosition = getPosition(character);
        int row = firstPosition[0];
        int col = firstPosition[1];
        int newRow = ++row % 5;
        return encryptionTable[newRow][col];
    }

    private String handleDifferentRowAndCol(String first, String second) {
        int[] firstPosition = getPosition(first);
        int[] secondPosition = getPosition(second);
        String firstCipher = encryptionTable[firstPosition[0]][secondPosition[1]];
        String secondCipher = encryptionTable[secondPosition[0]][firstPosition[1]];
        return firstCipher + secondCipher;
    }

    private String decryptSameRow(String character) {
        int[] firstPosition = getPosition(character);
        int row = firstPosition[0];
        int col = firstPosition[1];
        int newCol = (col + 4) % 5;
        return encryptionTable[row][newCol];
    }

    private String decryptSameCol(String character) {
        int[] firstPosition = getPosition(character);
        int row = firstPosition[0];
        int col = firstPosition[1];
        int newRow = (row + 4) % 5;
        return encryptionTable[newRow][col];
    }

    private int[] getPosition(String character) {
        for (int col = 0; col < 5; col++) {
            for (int row = 0; row < 5; row++) {
                String current = encryptionTable[row][col];
                if (current.equals(character)) {
                    int[] position = new int[2];
                    position[0] = row;
                    position[1] = col;
                    return position;
                }
            }
        }
        throw new IllegalArgumentException();
    }
}
