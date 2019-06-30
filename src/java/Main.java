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
     * uso:
     *  para encriptar un archivo: -ef <key> <input file> <output file>
     *  para desencriptar un archivo: -df <key> <output file> <input file>
     *  para encriptar un texto plano: -e <key> <plaintext>
     *  para desencriptar un texto cifrado: -d <key> <ciphertext>
     */
    public static void main(String[] args) throws IOException {
        if(args.length < 3 || args.length > 4){
            errorMessage();
        }
        if(args[0].equals("-ef")){
            System.out.println("Encriptando archivo....");
            encryptFile(args[1], args[2], args[3]);
            System.out.println("Listo!");
        }
        else if(args[0].equals("-df")){
            System.out.println("Desencriptando archivo....");
            decryptFile(args[1], args[2], args[3]);
            System.out.println("Listo!");
        }
        else if(args[0].equals("-e")){
            System.out.println("Encriptando entrada....");
            encryptPlainText(args[1], args[2]);
            System.out.println("Listo!");
        }
        else if(args[0].equals("-d")){
            System.out.println("Desencriptando entrada....");
            decryptCipherText(args[1], args[2]);
            System.out.println("Listo!");
        }
        else{
            System.err.println("No has ingresado una entrada correcta.");
            errorMessage();
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
        byte [] padded = padArray(d);  // padded array of bytes
        Encrypt encrypt = new Encrypt(key, padded);
        encrypt.setKey(key); // sets the key
        encrypt.keySchedule(); // generates 22 subkyes
        int iter=0;
        while( iter != padded.length){ // encrytion of 4 bytes at a time
            int prev= iter;
            byte [] temp = {(padded[iter]), (padded[++iter]), (padded[++iter]), (padded[++iter])};
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
            byte [] temp = {(p[iter]), (p[++iter]), (p[++iter]), (p[++iter])};
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

    private static void encryptPlainText(String inputKey, String inputPlaintext){
        byte[] key = Utils.toByteArray(inputKey);
        byte[] plaintext = Utils.toByteArray(inputPlaintext);
        Encrypt encrypt= new Encrypt(key, plaintext);
        encrypt.setKey(key);
        encrypt.keySchedule();
        encrypt.encrypt(plaintext);
        System.out.println(Utils.toString(plaintext)); // printing the ciphertext  output
    }

    private static void decryptCipherText(String inputKey, String inputCiphertext){
        byte[] key =Utils.toByteArray(inputKey);
        byte[] ciphertext = Utils.toByteArray(inputCiphertext);
        Decrypt decrypt= new Decrypt(key, ciphertext);
        decrypt.setKey(key);
        decrypt.keySchedule();
        decrypt.decrypt(ciphertext);
        System.out.println(Utils.toString(ciphertext)); // this prints the plaintext output
    }

    private static byte[] padArray(List<Byte> d) {
        byte [] temp = new byte[d.size()];
        for( int i=0; i< temp.length; i++){
            temp[i]= d.get(i);
        }
        return temp;
    }

    private static byte[] removePadding(byte [] ciphertext_ ){
        int i=ciphertext_.length-1;
        int counter=0;
        List<Byte> u = new ArrayList<>();
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
        System.err.println("Implementación de Speck en su variante 32/64");
        System.err.println("Uso:");
        System.err.println ("Encriptar archivo: -ef <key> <ptfile> <ctfile>");
        System.err.println ("Desencriptar archivo: -df <key> <ctfile> <ptfile>");
        System.err.println ("Encriptar texto plano: -e <key> <pt>");
        System.err.println ("Desencriptar texto cifrado: -d <key> <ct>");
        System.err.println ("<ptfile> = Archivo de texto plano");
        System.err.println ("<ctfile> = Archivo de texto cifrado");
        System.err.println ("<key> = Key (16 dígitos Hexadecimales)");
        System.err.println ("<pt> = Texto plano (8 dígitos Hexadecimales)");
        System.err.println ("<ct> = Texto cifrado (8 dígitos Hexadecimales)");
        System.exit (1);
    }
}
