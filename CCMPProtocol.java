import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Scanner;


public class CCMPProtocol {


        //metod za generiranje slucaen AES kluc
        public static SecretKey generateKey() throws Exception
        {
            KeyGenerator kluc=KeyGenerator.getInstance("AES");
            kluc.init(128);
            return kluc.generateKey();
        }

        //AES Enkripcija vo ECB mode

    public static byte[] encrypt(SecretKey key,byte[] plaintext) throws Exception
    {
        Cipher cipher=Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE,key);
        return  cipher.doFinal(plaintext);
    }

    public static byte[] decrypt(SecretKey key,byte[] ciphertext) throws Exception
    {
        Cipher cipher=Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE,key);
        return cipher.doFinal(ciphertext);
    }

    //Metod za kalkulacija na HMAC (MIC)

    public static byte[] calculateMIC(byte[] key,byte[] data) throws Exception
    {
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        digest.update(key);
        digest.update(data);
        return Arrays.copyOf(digest.digest(),8); //MIC:64 bits
    }

    //Metod za kreiranje 128-bit blocks so padding
    public static byte[][] createBlocks(byte[] packet)
    {
        int blockSize=16; //128 bits=16 bytes
        int numberOfBlocks=(packet.length+blockSize-1)/blockSize;
        byte[][]blocks=new byte[numberOfBlocks][blockSize];

        for(int i=0;i<numberOfBlocks;i++)
        {
            int offset=i*blockSize;
            int length=Math.min(packet.length - offset,blockSize);
            System.arraycopy(packet,offset,blocks[i],0,length);
            //Ako posledniot blok e pomal od 128 bita popolni go ostatokot so 0
            if(length<blockSize)
            {
                Arrays.fill(blocks[i],length,blockSize,(byte)0);

            }

        }
        return blocks;
    }

    public static void main(String[] args) {

            try (Scanner scanner=new Scanner(System.in)){
                //Generiraj AES kluc
                SecretKey key=generateKey();

                //Vnesi poraka(IP Packet)
                System.out.print("Enter the IP packet: ");
                String input=scanner.nextLine();

                //Input stringot se convertira vo bytes
                byte[] packet=input.getBytes(StandardCharsets.UTF_8);

                //Kreiranje na 128-bit blokovi od paketot
                byte[][]blocks=createBlocks(packet);

                //Enkriptiranje na sekoj blok i zacuvuvanje na ciphertext
                byte[] ciphertext=new byte[blocks.length*16];
                for (int i=0;i<blocks.length;i++)
                {
                    byte[] encryptedBlock=encrypt(key,blocks[i]);
                    System.arraycopy(encryptedBlock,0,ciphertext,i*16,16);
                }
                System.out.println("Ciphertext: "+ bytesToHex(ciphertext));

                //Kalkuliranje na MIC za celiot ciphertext
                byte[]mic=calculateMIC(key.getEncoded(),ciphertext);
                System.out.println("MIC: "+bytesToHex(mic));

                //Simuliranje primanje na ramka (ciphertext+MIC)
                byte[] receivedCipherText=ciphertext; //primen ciphertext
                byte[] receivedMic=mic; //primen MIC

                //Dekriptiranje na sekoj blok i rekonstruiranje na originalniot paket
                byte[] decryptedPacket=new byte[packet.length];
                int decryptedLength=0; //pratenje na golemina na dekriptirani podatoci
                for (int i=0;i< blocks.length;i++)
                {
                    byte[] decryptedBlock=decrypt(key,Arrays.copyOfRange(receivedCipherText,i*16,(i+1)*16));

                   //Kalklacija na vistinska golemina za kopiranje
                    int lengthToCopy=(i== blocks.length-1) ? packet.length%16:16;
                    System.arraycopy(decryptedBlock,0,decryptedPacket,decryptedLength,lengthToCopy);
                    decryptedLength+=lengthToCopy;
                }
                System.out.println("Decrypted packet: "+ new String(decryptedPacket,0,decryptedLength,StandardCharsets.UTF_8));

                //Verifikacija na MIC

                boolean isMicValid=Arrays.equals(calculateMIC(key.getEncoded(),receivedCipherText),receivedMic);
                System.out.println("MIC valid: "+isMicValid);
            }

            catch (Exception e) {
               e.printStackTrace();
            }
    }

    //Metod za pretvoranje bajti vo hex
    public static String bytesToHex(byte[] bytes)
    {
        StringBuilder sb=new StringBuilder();
        for (byte b:bytes)
        {
            sb.append(String.format("%02x",b));

        }
        return sb.toString();
    }
}