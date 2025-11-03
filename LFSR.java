import java.util.Scanner;

// <--- LFSR CLASS STARTS --->

public class LFSR {

// SETTING PRIVATE MEMBERS OF THE CLASS
    private String seed;
    private int[] taps;

// SETTING PUBLIC MEMBERS OF THE CLASS

//    A CONSTRUCTOR TO INITIALIZE THE POSITIONS OF THE MEMBERS GIVEN
    public LFSR(String seed, int[] taps) {
        this.seed = seed;
        this.taps = taps;
    }


    /*

    APPLYING FIRST FUNCTION:
        1. GENERATE THE LENGTH OF THE CODED TEXT
        2. APPENDING THE LAST BIT "FIRST RULE OF LFSR"
        3. CALCULATING THE FEEDBACK BYXOR

    */

    public String generate(int length) {
        StringBuilder sequence = new StringBuilder(); /*need to recognise this line*/

//  SETTING THE START POINT TO THE INITIAL POINT OF SEED
        String currentSeed = seed;

//  GENERATING THE LENGTH NUMBER OF BITS
        for (int i = 0; i < length; i++) {

            /*FIRST RULE OF LFSR: APPENDING THE LAST BIT NUMBER*/
//  APPENDING THE LAST BIT OF THE SEED
            sequence.append(currentSeed.charAt(currentSeed.length() - 1));

            int feedback = 0;
            for (int tap : taps) { /*need to recognise this line*/
                // XORing the feedback with
                feedback ^= Character.getNumericValue(currentSeed.charAt(currentSeed.length() - 1 - tap));
            }
             currentSeed = feedback + currentSeed.substring(0, currentSeed.length() - 1);
        }

        return sequence.toString();
    }




    public String encryptDecrypt(String plaintext, String keyStream) {
        StringBuilder result = new StringBuilder();

        for (int i = 0; i < plaintext.length(); i++) {
            char plaintextChar = plaintext.charAt(i);
            char keyChar = keyStream.charAt(i % keyStream.length()); // Wrap around key stream if needed

            result.append((char) (plaintextChar ^ keyChar));
        }
        return result.toString();
    }



// <--- LFSR CLASS ENDS --->

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter the initial seed (binary string): ");
        String seed = scanner.nextLine();

        System.out.print("Enter the tap positions (comma-separated integers, e.g., 2,5): ");
        String tapsInput = scanner.nextLine();
        String[] tapsStr = tapsInput.split(",");
        int[] taps = new int[tapsStr.length];
        for (int i = 0; i < tapsStr.length; i++) {
            taps[i] = Integer.parseInt(tapsStr[i].trim());
        }

        System.out.print("Enter the length of the sequence to generate: ");
        int sequenceLength = scanner.nextInt();
        scanner.nextLine(); // Consume newline left-over from nextInt()

        LFSR lfsr = new LFSR(seed, taps);
        String keyStream = lfsr.generate(sequenceLength);

        System.out.println("Generated Key Stream (" + sequenceLength + " bits): " + keyStream);

        System.out.print("Enter the plaintext message: ");
        String plaintext = scanner.nextLine();

        String encrypted = lfsr.encryptDecrypt(plaintext, keyStream);
        String decrypted = lfsr.encryptDecrypt(encrypted, keyStream);

        System.out.println("Plaintext: " + plaintext);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);

        scanner.close();
    }
}