import java.util.Scanner;

public class RSA {
    // Fixed prime numbers for demonstration (small for simplicity)
    private static final int p = 61;
    private static final int q = 53;
    private static final int n = p * q;
    private static final int phi = (p - 1) * (q - 1);
    private static final int e = 17; // Public exponent
    private static final int d = 2753; // Private exponent (modular inverse of e mod phi)

    // Encrypt a single character
    private static int encryptChar(int c) {
        return modPow(c, e, n);
    }

    // Decrypt a single character
    private static int decryptChar(int c) {
        return modPow(c, d, n);
    }

    // Modular exponentiation (a^b mod m)
    private static int modPow(int a, int b, int m) {
        int result = 1;
        a = a % m;

        while (b > 0) {
            if ((b & 1) == 1) {
                result = (result * a) % m;
            }
            a = (a * a) % m;
            b = b >> 1;
        }
        return result;
    }

    // Encrypt a string
    public static String encrypt(String message) {
        StringBuilder encrypted = new StringBuilder();
        for (int i = 0; i < message.length(); i++) {
            int c = message.charAt(i);
            encrypted.append(encryptChar(c)).append(" ");
        }
        return encrypted.toString().trim();
    }

    // Decrypt a string
    public static String decrypt(String encrypted) {
        StringBuilder decrypted = new StringBuilder();
        String[] parts = encrypted.split(" ");
        for (String part : parts) {
            int c = Integer.parseInt(part);
            decrypted.append((char)decryptChar(c));
        }
        return decrypted.toString();
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("RSA with fixed primes p=" + p + ", q=" + q);
        System.out.println("Public key (e,n): (" + e + ", " + n + ")");
        System.out.println("Private key (d,n): (" + d + ", " + n + ")");

        System.out.println("\nEnter message to encrypt:");
        String message = scanner.nextLine();

        System.out.println("\nOriginal message: " + message);

        // Encrypt
        String encrypted = encrypt(message);
        System.out.println("Encrypted message: " + encrypted);

        // Decrypt
        String decrypted = decrypt(encrypted);
        System.out.println("Decrypted message: " + decrypted);

        scanner.close();
    }
}