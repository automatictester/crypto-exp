package uk.co.automatictester.security.history;

import lombok.extern.slf4j.Slf4j;
import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.lang.Math.ceil;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

@Slf4j
public class ADFGVX {

    private final String[][] encryptionTable = new String[][]{
            {"N", "A", "1", "C", "3", "H"},
            {"8", "T", "B", "2", "O", "M"},
            {"E", "5", "W", "R", "P", "D"},
            {"4", "F", "6", "G", "7", "I"},
            {"9", "J", "0", "K", "L", "Q"},
            {"S", "U", "V", "X", "Y", "Z"},
    };
    private final String[] resultingCharacters = new String[]{"A", "D", "F", "G", "V", "X"};
    private final String transpositionKey = "PRIVACY";

    @Test
    public void testEncryption() {
        String plaintext = "ATTACKAT1200AM";
        String fractionatedMessage = getFractionatedMessage(plaintext);
        String[][] table = fractionatedMessageToTable(fractionatedMessage);
        Map<Integer, Integer> transpositionMap = getTranspositionMap();
        String[][] transposedTable = transposeTable(table, transpositionMap);
        String cipherText = tableToCiphertext(transposedTable);
        log.info("Ciphertext: {}", cipherText);
        assertThat(cipherText, equalTo("DGDD DAGD DGAF ADDF DADV DVFA ADVX"));
    }

    @Test
    public void testDecryption() {
        String ciphertext = "DGDD DAGD DGAF ADDF DADV DVFA ADVX".replace(" ", "");
        String[][] table = ciphertextToTable(ciphertext);
        Map<Integer, Integer> transpositionMap = getTranspositionMap();
        String[][] reverseTransposedTable = reverseTransposeTable(table, transpositionMap);
        String fractionatedMessage = tableToFractionatedMessage(reverseTransposedTable);
        String plaintext = getPlaintext(fractionatedMessage);
        log.info("Plaintext: {}", plaintext);
        assertThat(plaintext, equalTo("ATTACKAT1200AM"));
    }

    // ################################ encryption ################################

    /**
     * Converts:
     * ATTACKATONE => DGXGXGDGAADDDGXGADFAXA
     */
    private String getFractionatedMessage(String plaintext) {
        StringBuilder ciphertext = new StringBuilder();
        for (int i = 0; i < plaintext.length(); i++) {
            String nextFractionatedCharacter = plaintext.substring(i, i + 1);
            String cipherNext = getFractionatedCharacter(nextFractionatedCharacter);
            ciphertext.append(cipherNext);
        }
        String ciphertextAsString = ciphertext.toString();
        log.debug("Fractionated message: {}", ciphertextAsString);
        return ciphertextAsString;
    }

    /**
     * Converts:
     * A => DG
     */
    private String getFractionatedCharacter(String character) {
        int tableRow = getTableRowFor(character);
        int tableCol = getTableColFor(character);
        String firstCharacter = resultingCharacters[tableRow];
        String secondCharacter = resultingCharacters[tableCol];
        return firstCharacter + secondCharacter;
    }

    private int getTableRowFor(String character) {
        for (int row = 0; row <= 5; row++) {
            for (int col = 0; col <= 5; col++) {
                if (encryptionTable[row][col].equals(character)) return row;
            }
        }
        throw new IllegalArgumentException("Character not found: " + character);
    }

    private int getTableColFor(String character) {
        for (int row = 0; row <= 5; row++) {
            for (int col = 0; col <= 5; col++) {
                if (encryptionTable[row][col].equals(character)) return col;
            }
        }
        throw new IllegalArgumentException("Character not found: " + character);
    }

    private String[][] fractionatedMessageToTable(String fractionatedMessage) {
        int rowCount = (int) ceil((float) fractionatedMessage.length() / (float) transpositionKey.length());
        log.debug("Calculated row count: {}", rowCount);
        int colCount = transpositionKey.length();

        String[][] table = new String[rowCount][colCount];
        int i = 0;
        for (int row = 0; row < rowCount; row++) {
            for (int col = 0; col < colCount; col++) {
                if (i < fractionatedMessage.length()) {
                    table[row][col] = fractionatedMessage.substring(i, i + 1);
                    i++;
                }
            }
        }
        String prettyTable = tableToPrettyString(table);
        log.debug("Table before transposition: \n{}", prettyTable);
        return table;
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

    private Map<Integer, Integer> getTranspositionMap() {
        char[] keyCharacters = transpositionKey.toCharArray();
        Arrays.sort(keyCharacters);
        String sortedKey = new String(keyCharacters);
        log.debug("Sorted key: {}", sortedKey);

        Map<Integer, Integer> transpositionMap = new HashMap<>();
        int keyLength = keyCharacters.length;
        for (int positionBeforeSorting = 0; positionBeforeSorting < keyLength; positionBeforeSorting++) {
            String character = transpositionKey.substring(positionBeforeSorting, positionBeforeSorting + 1);
            int positionAfterSorting = sortedKey.indexOf(character);
            transpositionMap.put(positionBeforeSorting, positionAfterSorting);
        }
        return transpositionMap;
    }

    private String[][] transposeTable(String[][] table, Map<Integer, Integer> transpositionMap) {
        int rowCount = table.length;
        int colCount = table[0].length;
        String[][] transposedTable = new String[rowCount][colCount];

        for (int oldCol : transpositionMap.keySet()) {
            int newCol = transpositionMap.get(oldCol);
            for (int row = 0; row < rowCount; row++) {
                transposedTable[row][newCol] = table[row][oldCol];
            }
        }

        String prettyTransposedTable = tableToPrettyString(transposedTable);
        log.debug("Table after transposition: \n{}", prettyTransposedTable);
        return transposedTable;
    }

    private String tableToCiphertext(String[][] table) {
        StringBuilder ciphertext = new StringBuilder();
        int rowCount = table.length;
        int colCount = table[0].length;
        for (int col = 0; col < colCount; col++) {
            for (int row = 0; row < rowCount; row++) {
                String nextCharacter = table[row][col];
                if (nextCharacter != null) {
                    ciphertext.append(nextCharacter);
                }
            }
            ciphertext.append(" ");
        }
        int lastCharacterIndex = ciphertext.length() - 1;
        ciphertext.deleteCharAt(lastCharacterIndex);
        return ciphertext.toString();
    }

    // ################################ decryption ################################

    private String[][] ciphertextToTable(String ciphertext) {
        int colCount = transpositionKey.length();
        int rowCount = (int) ceil((float) ciphertext.length() / (float) colCount);
        log.debug("Calculated row count: {}", rowCount);
        String[][] table = new String[rowCount][colCount];
        int i = 0;
        for (int col = 0; col < colCount; col++) {
            for (int row = 0; row < rowCount; row++) {
                String character = ciphertext.substring(i, i + 1);
                table[row][col] = character;
                i++;
            }
        }
        String prettyTable = tableToPrettyString(table);
        log.debug("Table before reverse transposition: \n{}", prettyTable);
        return table;
    }

    private String[][] reverseTransposeTable(String[][] table, Map<Integer, Integer> transpositionMap) {
        int rowCount = table.length;
        int colCount = table[0].length;
        String[][] reverseTransposedTable = new String[rowCount][colCount];

        for (int oldCol : transpositionMap.keySet()) {
            int newCol = transpositionMap.get(oldCol);
            for (int row = 0; row < rowCount; row++) {
                reverseTransposedTable[row][oldCol] = table[row][newCol];
            }
        }

        String prettyTransposedTable = tableToPrettyString(reverseTransposedTable);
        log.debug("Table after reverse transposition: \n{}", prettyTransposedTable);
        return reverseTransposedTable;
    }

    private String tableToFractionatedMessage(String[][] table) {
        int rowCount = table.length;
        int colCount = table[0].length;
        StringBuilder fractionatedMessage = new StringBuilder();
        for (int row = 0; row < rowCount; row++) {
            for (int col = 0; col < colCount; col++) {
                String nextCharacter = table[row][col];
                fractionatedMessage.append(nextCharacter);
            }
        }
        String fractionatedMessageAsString = fractionatedMessage.toString();
        log.debug("Fractionated message: {}", fractionatedMessageAsString);
        return fractionatedMessageAsString;
    }

    private String getPlaintext(String fractionatedMessage) {
        StringBuilder plaintext = new StringBuilder();
        for (int i = 0; i < fractionatedMessage.length(); i += 2) {
            String nextCharacters = fractionatedMessage.substring(i, i + 2);
            String plainNext = getPlaintextCharacter(nextCharacters);
            plaintext.append(plainNext);
        }
        return plaintext.toString();
    }

    private String getPlaintextCharacter(String fractionatedCharacters) {
        List<String> resultingCharactersAsList = Arrays.asList(resultingCharacters);
        String firstCharacter = fractionatedCharacters.substring(0, 1);
        String secondCharacter = fractionatedCharacters.substring(1, 2);
        int firstCharacterIndex = resultingCharactersAsList.indexOf(firstCharacter);
        int secondCharacterIndex = resultingCharactersAsList.indexOf(secondCharacter);
        return encryptionTable[firstCharacterIndex][secondCharacterIndex];
    }
}
