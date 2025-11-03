import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Scanner;
//LIBS FOR ERROR HANDLING
import java.security.spec.InvalidKeySpecException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;


public class DES {

    // Cryptographic algorithm constants
    private static final String ALGORITHM = "DES"; // JCA name for DES algorithm
    private static final String TRANSFORMATION = "DES/ECB/PKCS5Padding"; // DES with ECB mode and PKCS5 padding

    // Key specification constants
    private static final int DES_KEY_LENGTH_BYTES = 8; // DES requires exactly 8-byte keys
    private static final int HEX_KEY_LENGTH_CHARS = 16; // 8 bytes = 16 hex chars (2 chars per byte)

    // Input limits to prevent resource exhaustion
    private static final int MAX_PLAINTEXT_LENGTH = 1000; // Maximum allowed plaintext length in characters

    // Entry point of the program
    public static void main(String[] args) {
        // Using try-with-resources to ensure Scanner is properly closed
        try (Scanner scanner = new Scanner(System.in)) {

            // Step 1: Get encryption key from user
            byte[] keyBytes = getKeyBytes(scanner);
            if (keyBytes == null) {
                return; // Exit if key input failed
            }

            // Step 2: Get plaintext to encrypt
            String plaintext = getPlaintext(scanner);
            if (plaintext == null) {
                return; // Exit if plaintext input failed
            }

            // Display summary of inputs before processing
            displayInputSummary(plaintext, keyBytes);

            try {
                // Step 3: Perform encryption
                byte[] encrypted = encrypt(plaintext.getBytes(StandardCharsets.UTF_8), keyBytes);

//                CONVERTS THE ENCRYPTED MESSAGE TO BASE 64 -> USEFUL FOR JSON AND HTTP
                String encryptedBase64 = Base64.getEncoder().encodeToString(encrypted);

//                CONVERTS THE ENCRYPTED MESSAGE TO HEX -> HAVING NOTHING TO DO EXCEPT EASY DEBUG
                String encryptedHex = byteArrayToHexString(encrypted);

                // Step 4: Perform decryption (to verify the process)
                byte[] decrypted = decrypt(encrypted, keyBytes);
                String decryptedText = new String(decrypted, StandardCharsets.UTF_8);

                // Step 5: Display results
                displayResults(encryptedBase64, encryptedHex, decryptedText);

                // Step 6: Verify encryption/decryption worked correctly
                verifyResults(plaintext, decryptedText);

            } catch (Exception e) {
                handleCryptoError(e);
            }
        }
    }


    /**
     * Gets the encryption key from user input with validation
     *
     * @param scanner The Scanner instance for user input
     * @return byte array containing the valid DES key, or null if input failed
     */
    private static byte[] getKeyBytes(Scanner scanner) {
        System.out.println("\n[Key Input]");
        System.out.println("Choose key input format:");
        System.out.println("1. 8-byte text string (e.g., 'mypass12')");
        System.out.println("2. 16-character hex string (e.g., '1a3f5c7e9b2d4f6a')");
        System.out.print("Enter choice (1 or 2): ");

        try {
            int choice = scanner.nextInt();
            scanner.nextLine(); // Consume the leftover newline

            System.out.print(choice == 1 ?
                    "Enter 8-byte secret key: " :
                    "Enter 16-character hex key: ");

            String keyInput = scanner.nextLine().trim();

            if (choice == 1) {
                // Text key processing
                byte[] keyBytes = keyInput.getBytes(StandardCharsets.UTF_8);

                // DES requires exactly 8-byte keys
                if (keyBytes.length != DES_KEY_LENGTH_BYTES) {
                    System.err.println("Error: DES requires exactly 8-byte keys. Got " + keyBytes.length + " bytes.");
                    return null;
                }
                return keyBytes;

            } else if (choice == 2) {
                // Hex key processing
                if (keyInput.length() != HEX_KEY_LENGTH_CHARS) {
                    System.err.println("Error: Hex key must be exactly 16 characters (8 bytes).");
                    return null;
                }

                byte[] keyBytes = hexStringToByteArray(keyInput);
                if (keyBytes == null) {
                    System.err.println("Error: Key contains invalid hexadecimal characters.");
                    return null;
                }
                return keyBytes;

            } else {
                System.err.println("Error: Invalid choice. Must be 1 or 2.");
                return null;
            }
        } catch (Exception e) {
            System.err.println("Error reading key input: " + e.getMessage());
            return null;
        }
    }

    /**
     * Gets the plaintext to encrypt with validation
     *
     * @param scanner The Scanner instance for user input
     * @return Valid plaintext string, or null if input failed
     */
    private static String getPlaintext(Scanner scanner) {
        System.out.println("\n[Plaintext Input]");
        System.out.print("Enter plaintext (max " + MAX_PLAINTEXT_LENGTH + " chars): ");
        String plaintext = scanner.nextLine();

        // Validate plaintext length
        if (plaintext.length() > MAX_PLAINTEXT_LENGTH) {
            System.err.println("Error: Plaintext exceeds maximum length of " + MAX_PLAINTEXT_LENGTH + " characters.");
            return null;
        }

        // Validate plaintext is not empty
        if (plaintext.isEmpty()) {
            System.err.println("Error: Plaintext cannot be empty.");
            return null;
        }

        return plaintext;
    }

    /**
     * Displays summary of the input parameters
     *
     * @param plaintext The plaintext to be encrypted
     * @param keyBytes The encryption key in byte array form
     */
    private static void displayInputSummary(String plaintext, byte[] keyBytes) {
        System.out.println("\n[Input Summary]");
        System.out.println("Plaintext length: " + plaintext.length() + " characters");
        System.out.println("Plaintext (first 16 chars): " +
                (plaintext.length() > 16 ? plaintext.substring(0, 16) + "..." : plaintext));
        System.out.println("Key (hex): " + byteArrayToHexString(keyBytes));
        System.out.println("Key length: " + keyBytes.length + " bytes");
    }

    /**
     * Performs DES encryption
     *
     * @param plaintext The plaintext bytes to encrypt
     * @param keyBytes The encryption key bytes
     * @return Encrypted ciphertext bytes
     * @throws NoSuchAlgorithmException If DES algorithm is not available
     * @throws NoSuchPaddingException If PKCS5 padding is not available
     * @throws InvalidKeyException If the key is invalid
     * @throws InvalidKeySpecException If the key specification is invalid
     * @throws IllegalBlockSizeException If the block size is invalid
     * @throws BadPaddingException If the padding is corrupt
     */
    public static byte[] encrypt(byte[] plaintext, byte[] keyBytes)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidKeySpecException,
            IllegalBlockSizeException, BadPaddingException {
        // Validate key meets DES requirements
        validateKey(keyBytes);

        // Create DES key specification
        DESKeySpec keySpec = new DESKeySpec(keyBytes);

        // Get a SecretKeyFactory instance for DES
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);

        // Generate the secret key
        SecretKey secretKey = keyFactory.generateSecret(keySpec);

        // Get cipher instance with DES/ECB/PKCS5Padding
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);

        // Initialize cipher in encryption mode
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        // Perform encryption
        return cipher.doFinal(plaintext);
    }

    /**
     * Performs DES decryption
     *
     * @param ciphertext The ciphertext bytes to decrypt
     * @param keyBytes The decryption key bytes (must be same as encryption key)
     * @return Decrypted plaintext bytes
     * @throws NoSuchAlgorithmException If DES algorithm is not available
     * @throws NoSuchPaddingException If PKCS5 padding is not available
     * @throws InvalidKeyException If the key is invalid
     * @throws InvalidKeySpecException If the key specification is invalid
     * @throws IllegalBlockSizeException If the block size is invalid
     * @throws BadPaddingException If the padding is corrupt
     */
    public static byte[] decrypt(byte[] ciphertext, byte[] keyBytes)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidKeySpecException,
            IllegalBlockSizeException, BadPaddingException {
        // Validate key meets DES requirements
        validateKey(keyBytes);

        // Create DES key specification
        DESKeySpec keySpec = new DESKeySpec(keyBytes);

        // Get a SecretKeyFactory instance for DES
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);

        // Generate the secret key
        SecretKey secretKey = keyFactory.generateSecret(keySpec);

        // Get cipher instance with DES/ECB/PKCS5Padding
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);

        // Initialize cipher in decryption mode
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        // Perform decryption
        return cipher.doFinal(ciphertext);
    }

    /**
     * Validates that a key meets DES requirements
     *
     * @param keyBytes The key to validate
     * @throws InvalidKeyException If the key is invalid
     */
    private static void validateKey(byte[] keyBytes) throws InvalidKeyException {
        if (keyBytes == null) {
            throw new InvalidKeyException("Key cannot be null");
        }
        if (keyBytes.length != DES_KEY_LENGTH_BYTES) {
            throw new InvalidKeyException(
                    "Invalid DES key length. Expected " + DES_KEY_LENGTH_BYTES +
                            " bytes but got " + keyBytes.length);
        }
    }

    /**
     * Converts a hexadecimal string to a byte array
     *
     * @param s The hex string to convert (e.g., "1a2b3c4d")
     * @return The byte array, or null if input is invalid
     */
    private static byte[] hexStringToByteArray(String s) {
        // Check for null or odd-length strings
        if (s == null || s.length() % 2 != 0) {
            return null;
        }

        byte[] data = new byte[s.length() / 2];

        // Process each hex byte pair
        for (int i = 0; i < s.length(); i += 2) {
            try {
                // Convert two hex chars to one byte
                int firstDigit = Character.digit(s.charAt(i), 16);
                int secondDigit = Character.digit(s.charAt(i + 1), 16);

                // Check for invalid hex digits
                if (firstDigit == -1 || secondDigit == -1) {
                    return null;
                }

                data[i / 2] = (byte) ((firstDigit << 4) + secondDigit);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return data;
    }

    /**
     * Converts a byte array to a hexadecimal string
     *
     * @param bytes The byte array to convert
     * @return Hexadecimal representation of the bytes
     */
    private static String byteArrayToHexString(byte[] bytes) {
        if (bytes == null) {
            return "null";
        }

        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            // Format each byte as two lowercase hex digits
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }




































    /**
     * Displays the encryption/decryption results
     *
     * @param encryptedBase64 Base64-encoded ciphertext
     * @param encryptedHex Hex-encoded ciphertext
     * @param decryptedText The decrypted plaintext
     */
    private static void displayResults(String encryptedBase64, String encryptedHex, String decryptedText) {
        System.out.println("\n[Results]");
        System.out.println("Encrypted (Base64): " + encryptedBase64);
        System.out.println("Encrypted (Hex): " + encryptedHex);
        System.out.println("Decrypted Text: " + decryptedText);
    }

    /**
     * Verifies that decryption produced the original plaintext
     *
     * @param original The original plaintext
     * @param decrypted The decrypted plaintext
     */
    private static void verifyResults(String original, String decrypted) {
        System.out.println("\n[Verification]");

        if (original.equals(decrypted)) {
            System.out.println("SUCCESS: Original and decrypted text match exactly.");
        } else {
            System.out.println("FAILURE: Original and decrypted text differ!");
            System.out.println("Original length: " + original.length() + " chars");
            System.out.println("Decrypted length: " + decrypted.length() + " chars");

            // Show first difference found
            int minLength = Math.min(original.length(), decrypted.length());
            for (int i = 0; i < minLength; i++) {
                if (original.charAt(i) != decrypted.charAt(i)) {
                    System.out.println("First difference at position " + i +
                            ": original='" + original.charAt(i) +
                            "' vs decrypted='" + decrypted.charAt(i) + "'");
                    break;
                }
            }
        }
    }






























    /**
     * Handles cryptographic operation errors
     *
     * @param e The exception that occurred
     */
    private static void handleCryptoError(Exception e) {
        System.err.println("\n[Error Details]");
        System.err.println("Operation failed: " + e.getClass().getSimpleName());

        // Provide specific guidance for common crypto exceptions
        if (e instanceof InvalidKeyException) {
            System.err.println("Key problem: The provided key is invalid for DES");
            System.err.println("- Ensure key is exactly 8 bytes (56+8 parity bits)");
        }
        else if (e instanceof IllegalBlockSizeException) {
            System.err.println("Block size problem: Data length doesn't match cipher block size");
            System.err.println("- This can happen with improper padding");
        }
        else if (e instanceof BadPaddingException) {
            System.err.println("Padding problem: Decrypted data has corrupt padding");
            System.err.println("- Possible causes: Wrong key, corrupted data, or incorrect padding scheme");
        }

        System.err.println("\nTechnical details for debugging:");
        e.printStackTrace();
    }
}