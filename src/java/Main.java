package src.java;

import src.java.utils.Utils;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class Main {

    /**
     * Programa principal.
     * args para encriptar un archivo: -ef <key> <input file> <output file>
     * args para desencriptar un archivo: -df <key> <output file> <input file>
     */
    public static void main(String[] args) throws IOException {
        if(args.length!=4){
            errorMessage();
        }
        if(args[0].equals("-ef")){
            System.out.println("encrypting file....");
            encryptFile(args[1], args[2], args[3]);
            System.out.println("Done!");
        }
        if(args[0].equals("-df")){
            System.out.println("decrypting file....");
            decryptFile(args[1], args[2], args[3]);
            System.out.println("Done!");
        }
    }

    private static void encryptFile(String inputKey, String inputFile, String outputFile)
    throws IOException{
        File plaintext= new File (inputFile); // plaintext file

        File ciphertext= new File(outputFile); // ciphertext file in which ciphertext will be stored
        byte [] key = Utils.toByteArray(inputKey); // key for encryption

        InputStream plain_t = new BufferedInputStream
                (new FileInputStream(plaintext));
        OutputStream cipher_t = new BufferedOutputStream
                (new FileOutputStream (ciphertext));

        Path path = Paths.get(plaintext.getAbsolutePath());
        byte[] p = Files.readAllBytes(path); // reads all bytes from file

        List<Byte> d = new ArrayList<>();
        for (byte b:p) {
            d.add(b);
        }
        d.add((byte) 0x80); // adding padding

        if(d.size() % 4 !=0){ // padding
            while(d.size()%4 !=0 ){
                d.add((byte)0x00);
            }
        }
        byte [] padded = (byte[]) padArray(d);  // padded array of bytes
        Encrypt encrypt = new Encrypt(key, padded);
        encrypt.setKey(key); // sets the key
        encrypt.keySchedule(); // generates 22 subkyes
        int iter=0;
        while( iter != padded.length){ // encrytion of 4 bytes ata time
            int prev= iter;
            byte [] temp = {(byte) (padded[iter]) ,(byte)(padded[++iter]), (byte)(padded[++iter]), (byte)(padded[++iter])};
            int temp2= Utils.packIntBigEndian(temp, 0);
            Utils.unpackIntBigEndian(temp2, temp, 0);
            encrypt.encrypt(temp);
            padded[prev]= temp[0];
            padded[++prev]= temp[1];
            padded[++prev]= temp[2];
            padded[++prev]= temp[3];
            iter++;
        }


        int f=0;

        while(f!= padded.length){
            cipher_t.write(padded[f]);
            f++;
        }

        plain_t.close();
        cipher_t.close();
    }

    private static void decryptFile(String inputKey, String inputFile, String outputFile)
    throws IOException{
        File chiphertext= new File (inputFile);  // input file
        File plaintext= new File(outputFile); // output file
        byte [] key = Utils.toByteArray(inputKey); // key
        InputStream  cipher_t= new BufferedInputStream
                (new FileInputStream (chiphertext));
        OutputStream plain_t = new BufferedOutputStream
                (new FileOutputStream (plaintext));

        Path path = Paths.get(chiphertext.getAbsolutePath());
        byte [] p = Files.readAllBytes(path); // reads all the bytes of file

        Decrypt decrypt = new Decrypt(key, p);
        decrypt.setKey(key); // sets the key
        decrypt.keySchedule(); // generates subkeys

        int iter=0;
        while( iter != p.length){  // decrypts the 4 bytes at a time
            int prev= iter;
            byte [] temp = {(byte) (p[iter]) ,(byte)(p[++iter]), (byte)(p[++iter]), (byte)(p[++iter])};
            int temp2= Utils.packIntBigEndian(temp, 0);
            Utils.unpackIntBigEndian(temp2, temp, 0);
            decrypt.decrypt(temp);
            p[prev]= temp[0];
            p[++prev]= temp[1];
            p[++prev]= temp[2];
            p[++prev]= temp[3];
            iter++;
        }

        byte [] t = removePadding(p); // orginaml plaintext without padding
        // writies plaintext without padding to the file
        int c=0;
        while(c!= t.length){
            plain_t.write(t[c]);
            c++;
        }
        plain_t.close();
        cipher_t.close();

    }

    private static byte[] padArray(List<Byte> d) {
        byte [] temp = new byte[d.size()];
        for( int i=0; i< temp.length; i++){
            temp[i]= (byte)d.get(i);
        }
        return temp;
    }

    private static byte[] removePadding(byte [] ciphertext_ ){
        int i=ciphertext_.length-1;
        int counter=0;
        List<Byte> u = new ArrayList<Byte>();
        byte[] temp;

        while(ciphertext_[i]== 0x0000){
            counter++;
            i--;
        }


        for( int j=0; j<(ciphertext_.length-(counter+1)); j++){
            u.add(ciphertext_[j]);
        }

        temp= new byte[ciphertext_.length-(counter+1)];

        for(int k=0; k< temp.length; k++){
            temp[k]= u.get(k);
        }
        return temp;

    }

    private static void errorMessage() {
        System.err.println ("Usage: java src.java.EncryptFile <key> <plaintext> <ciphertext>");
        System.err.println ("<ptfile> = Plaintext file name");
        System.err.println ("<ctfile> = Ciphertext file name");
        System.err.println ("<key> = Key (64 hex digits)");
        System.exit (1);
    }
}
