import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Scanner;
import java.security.SecureRandom;

public class CCMPProtocol {

    //Метод за генерирање на случаен AES клуч
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }

    // AES енкрипција во CTR mode
    public static byte[] encrypt(SecretKey key, byte[] plaintext, byte[] nonce) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        IvParameterSpec ivSpec = new IvParameterSpec(nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        return cipher.doFinal(plaintext);
    }

    // AES декрипција во CTR mode
    public static byte[] decrypt(SecretKey key, byte[] ciphertext, byte[] nonce) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        IvParameterSpec ivSpec = new IvParameterSpec(nonce);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        return cipher.doFinal(ciphertext);
    }

    // Метод за калулирање на MIC користејќи HMAC и SHA-256
    public static byte[] calculateMIC(byte[] key, byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(key);
        digest.update(data);
        return Arrays.copyOf(digest.digest(), 8); // MIC: 64 bits
    }

    // Метод за креирање 128-bit блокови со падинг
    public static byte[][] createBlocks(byte[] packet) {
        int blockSize = 16; // 128 bits = 16 bytes
        int numberOfBlocks = (packet.length + blockSize - 1) / blockSize;
        byte[][] blocks = new byte[numberOfBlocks][blockSize];

        for (int i = 0; i < numberOfBlocks; i++) {
            int offset = i * blockSize;
            int length = Math.min(packet.length - offset, blockSize);
            System.arraycopy(packet, offset, blocks[i], 0, length);
            // Ако последниот блок е помал од 128-бита, се пополнува со 0.
            if (length < blockSize) {
                Arrays.fill(blocks[i], length, blockSize, (byte) 0);
            }
        }
        return blocks;
    }

    // Генерирање nonce (12 bytes) за AES-CTR mode и пополнување до 16 bytes
    public static byte[] generateNonce() {
        byte[] nonce = new byte[12]; // 12 bytes (96 bits) за nonce
        new SecureRandom().nextBytes(nonce); // Полнење со случајни бајти

        // Пополнување на nonce до 16 bytes за AES-CTR mode (додавање 4 нулти bytes)
        byte[] nonce16Bytes = new byte[16];
        System.arraycopy(nonce, 0, nonce16Bytes, 0, 12);  // Copy 12 bytes of the original nonce
        // Последните бајти во овој случај ќе останат 0 (може да се заменат со друго доколку е потребно)
        return nonce16Bytes;
    }

    public static void main(String[] args) {

        try (Scanner scanner = new Scanner(System.in)) {
            // Генерирање AES key
            SecretKey key = generateKey();

            // Внеси IP Packet
            System.out.print("Enter the IP packet: ");
            String input = scanner.nextLine();

            // Конвертирај input string во bytes (packet)
            byte[] packet = input.getBytes(StandardCharsets.UTF_8);

            // Генерирај nonce (PN + MAC address + QoS) и дополни го до 16 bytes
            byte[] nonce = generateNonce();
            System.out.println("Generated Nonce: " + bytesToHex(nonce));

            // Крирај 128-bit blocks од packet
            byte[][] blocks = createBlocks(packet);

            // Енкриптирај го секој блок и зачувај го како ciphertext
            byte[] ciphertext = new byte[blocks.length * 16];
            for (int i = 0; i < blocks.length; i++) {
                byte[] encryptedBlock = encrypt(key, blocks[i], nonce);
                System.arraycopy(encryptedBlock, 0, ciphertext, i * 16, 16);
            }
            System.out.println("Ciphertext: " + bytesToHex(ciphertext));

            // Калкулирај MIC за ciphertext
            byte[] mic = calculateMIC(key.getEncoded(), ciphertext);
            System.out.println("MIC: " + bytesToHex(mic));

            // Симулирај примање на рамката(ciphertext + MIC)
            byte[] receivedCiphertext = ciphertext; // примен ciphertext
            byte[] receivedMic = mic; // примен MIC

            // Декриптирај го секој блок и реконструирај го оригиналниот пакет
            byte[] decryptedPacket = new byte[packet.length];
            int decryptedLength = 0; // Прати ја должината на декриптитаните податоци
            for (int i = 0; i < blocks.length; i++) {
                byte[] decryptedBlock = decrypt(key, Arrays.copyOfRange(receivedCiphertext, i * 16, (i + 1) * 16), nonce);
                // Израчунај ја вистинската должина за copy operation
                int lengthToCopy = (i == blocks.length - 1) ? packet.length % 16 : 16;
                System.arraycopy(decryptedBlock, 0, decryptedPacket, decryptedLength, lengthToCopy);
                decryptedLength += lengthToCopy;
            }
            System.out.println("Decrypted packet: " + new String(decryptedPacket, 0, decryptedLength, StandardCharsets.UTF_8));

            // Верифицирај MIC
            boolean isMicValid = Arrays.equals(calculateMIC(key.getEncoded(), receivedCiphertext), receivedMic);
            System.out.println("MIC valid: " + isMicValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Метод за конвертирање byte array во hex string
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
