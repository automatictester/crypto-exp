package uk.co.automatictester.security.history;

import lombok.extern.slf4j.Slf4j;
import org.testng.annotations.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

@Slf4j
public class Vigenere {

    private final String[][] encryptionTable;
    private final int asciiCodeForLetterA = 65;

    public Vigenere() {
        String[][] encryptionTable = new String[26][26];
        for (int row = 0; row < 26; row++) {
            for (int col = 0; col < 26; col++) {
                if (row == 0) {
                    encryptionTable[row][col] = String.valueOf((char) (asciiCodeForLetterA + col));
                } else {
                    int newCol = (col + 1) % 26;
                    encryptionTable[row][col] = encryptionTable[row - 1][newCol];
                }
            }
        }
        this.encryptionTable = encryptionTable;
    }

    @Test
    public void testEncryption() {
        log.debug("Generated encryption table: \n{}", tableToPrettyString(encryptionTable));
        String plaintext = "ATTACKATDAWN";
        String rawKey = "LEMON";
        String key = getKey(plaintext, rawKey);
        log.debug("Key: {}", key);
        String ciphertext = encrypt(plaintext, key);
        assertThat(ciphertext, equalTo("LXFOPVEFRNHR"));
    }

    @Test
    public void testDecryption() {
        log.debug("Generated encryption table: \n{}", tableToPrettyString(encryptionTable));
        String ciphertext = "LXFOPVEFRNHR";
        String rawKey = "LEMON";
        String key = getKey(ciphertext, rawKey);
        log.debug("Key: {}", key);
        String plaintext = decrypt(ciphertext, key);
        assertThat(plaintext, equalTo("ATTACKATDAWN"));
    }

    private String decrypt(String ciphertext, String key) {
        StringBuilder plaintext = new StringBuilder();
        for (int i = 0; i < ciphertext.length(); i++) {
            String ciphertextCharacter = ciphertext.substring(i, i + 1);
            String keyCharacter = key.substring(i, i + 1);
            int row = getTableIndex(keyCharacter);
            int characterPosition = getCharacterPosition(ciphertextCharacter, row);
            String nextCharacter = String.valueOf((char) (characterPosition + asciiCodeForLetterA));
            plaintext.append(nextCharacter);
        }
        return plaintext.toString();
    }

    private int getCharacterPosition(String character, int row) {
        for (int i = 0; i < 26; i++) {
            if (encryptionTable[row][i].equals(character)) {
                return i;
            }
        }
        throw new IllegalArgumentException();
    }

    private String encrypt(String plaintext, String key) {
        StringBuilder ciphertext = new StringBuilder();
        for (int i = 0; i < plaintext.length(); i++) {
            String plaintextCharacter = plaintext.substring(i, i + 1);
            String keyCharacter = key.substring(i, i + 1);
            int row = getTableIndex(plaintextCharacter);
            int col = getTableIndex(keyCharacter);
            String nextCharacter = encryptionTable[row][col];
            ciphertext.append(nextCharacter);
        }
        return ciphertext.toString();
    }

    private int getTableIndex(String character) {
        return character.charAt(0) - asciiCodeForLetterA;
    }

    private String getKey(String plaintext, String rawKey) {
        String tempKey = rawKey;
        do {
            if (plaintext.length() == tempKey.length()) {
                return tempKey;
            } else if (plaintext.length() > tempKey.length()) {
                tempKey += tempKey;
            } else {
                return tempKey.substring(0, plaintext.length());
            }
        } while (true);
    }

    private String tableToPrettyString(String[][] table) {
        StringBuilder prettyTable = new StringBuilder();
        for (int row = 0; row < table.length; row++) {
            for (int col = 0; col < table[0].length; col++) {
                String cell = table[row][col];
                if (cell == null) {
                    prettyTable.append("_");
                } else {
                    prettyTable.append(cell);
                }
            }
            prettyTable.append("\n");
        }
        int lastCharacterIndex = prettyTable.length() - 1;
        prettyTable.deleteCharAt(lastCharacterIndex);
        return prettyTable.toString();
    }
}
