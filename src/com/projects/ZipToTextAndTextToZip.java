package personal.projects;
//http://www.java2s.com/Code/Jar/o/Downloadorgapachecommonscodecjar.htm
/*********
converts zip file to encrypted text file and vice-versa

**********/

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.Key;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Scanner;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;


public class ZipToTextAndTextToZip
{
    static String encryptionKey = "0123456789abcdef";


    private static int bufferSize = 16 * 1024;
    private static int decryptBufferSize = 21848;
    static String IV = "AAAAAAAAAAAAAAAA";
  /*  private static final String ALGO = "AES";*/



 /*   private static final byte[] keyValue =
            new byte[] { 'T', 'h', 'e', 'B', 'e', 's', 't',
                    'S', 'e', 'c', 'r','e', 't', 'K', 'e', 'y' };*/
  /*  public static byte[] encrypt(byte[] Data) throws Exception {
        Key key = generateKey();
        Cipher c = Cipher.getInstance(ALGO);
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encVal = c.doFinal(Data);
        //String encryptedValue = new BASE64Encoder().encode(encVal);
        return encVal;
    }

    public static byte[] decrypt(byte[] encryptedData) throws Exception {
        Key key = generateKey();
        Cipher c = Cipher.getInstance(ALGO);
        c.init(Cipher.DECRYPT_MODE, key);

        byte[] decValue = c.doFinal(encryptedData);
        return decValue;
    }*/

    public static byte[] encrypt(byte[] bytes) throws Exception
    {
        String plainText = bytes.toString();
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
        SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
        return cipher.doFinal(/*plainText.getBytes("UTF-8")*/bytes);
    }

    public static byte[] decrypt(byte[] cipherText) throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
        SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
        // return (new String(cipher.doFinal(cipherText),"UTF-8")).getBytes();
        return cipher.doFinal(cipherText);
    }

    /*   private static Key generateKey() throws Exception {
           Key key = new SecretKeySpec(keyValue, ALGO);
           return key;
       }*/
    public static boolean isAlphanumeric(String str)
    {
        for (int i = 0; i < str.length(); i++)
        {
            char c = str.charAt(i);
            if (!Character.isDigit(c) && !Character.isLetter(c))
                return false;
        }

        return true;
    }
    // Create a single shared Scanner for keyboard input
    private static Scanner scanner = new Scanner( System.in );

    public static void main(String[] args) throws Exception
    {

        System.out.print( "Give input file name with complete path ending with .zip or .txt" );
        String inputFileName = scanner.nextLine();
        System.out.println( "input = " + inputFileName );

        System.out.print( "Give the KEY(16 character alphanumeric)" );
        String key = scanner.nextLine();
        System.out.println( "input = " + inputFileName );

        if (key.length() == 16 && isAlphanumeric(key)) Del.encryptionKey = args[1];
        else System.out.println("using default encryption/decryption key");

        if (inputFileName.endsWith(".zip"))
        {
            System.out.println("encoding...");   //String inputZipFileForEncrypt="C:/Users/rbhushan/Desktop/system.zip";//output will be outdir+ <zipFileName> +encoded.txt
            convertZipwholetoText(inputFileName);
        } else if (inputFileName.endsWith(".txt"))
        {
            System.out.println("decoding...");            //String inputTextFileToZip="C:/Users/rbhushan/Desktop/systemencoded.txt";//output will be outdir + zip file
            Del.encryptionKey = "0123456789abcdef";
            convertTextToZip(inputFileName);
        } else
        {
            System.out.println("Not a valid fileName.");
            return;
        }


        // convertZiptoHex();
        //encrypt();decrypt();
        //convertHextoFiles();

    }

    private static void convertTextToZip(String inputTextFileToZip) throws Exception
    {
        //String inputTextFileToZip=outdir+"/encoded.txt";


        File file = new File(inputTextFileToZip);
        if (file.exists())
        {
        } else
        {
            System.out.println("input text file dont exists.");
            return;
        }

        InputStream stream = new FileInputStream(inputTextFileToZip);
        FileOutputStream output = new FileOutputStream(file.getParent() + File.separator + file.getName() + "_decoded.zip");
        byte[] inBuffer = new byte[decryptBufferSize/*bufferSize*/];
        int len;
        while ((len = stream.read(inBuffer)) > 0)
        {
            byte[] tmp = Base64.decodeBase64(inBuffer);
            tmp = decrypt(tmp);
            output.write((tmp), 0, tmp.length);
        }
        output.close();
        stream.close();
    }

    private static void convertZipwholetoText(String inputZipFileForEncrypt) throws Exception
    {


        File file = new File(inputZipFileForEncrypt);
        if (file.exists())
        {
        } else
        {
            System.out.println("input zip file dont exists.");
            return;
        }
        InputStream stream = new FileInputStream(inputZipFileForEncrypt);
        FileOutputStream output = new FileOutputStream(file.getParent() + File.separator + file.getName() + "_encoded.txt");
        byte[] inBuffer = new byte[bufferSize];
        int len;
        while ((len = stream.read(inBuffer)) > 0)
        {
            // System.out.println(len);
            //System.out.println(inBuffer.length);
            if (len % 16 != 0)
            {
                for (int i = len; i < bufferSize; i++)
                {
                    inBuffer[i] = 0;
                }
            }
            //System.out.println(inBuffer.length);
            byte[] tmp = encrypt(inBuffer);

            //System.out.println(tmp.length);
            tmp = Base64.encodeBase64(tmp);
            //System.out.println(tmp.length);
            output.write((tmp), 0, tmp.length);
        }
        output.close();
        stream.close();
    }

   /* private static void convertHextoFiles() throws Exception
    {

        //byte[] buffer = new byte[2048];
        byte[] inBuffer = new byte[1];//dont change array size
        byte[] buffer = new byte[2];//dont change array size

        String inputFile="C:/Users/rbhushan/Desktop/hi5.txt";
        String outdir="C:/Users/rbhushan/Desktop";
        InputStream  stream = (new FileInputStream(inputFile));

        try
        {

            http://forums.whirlpool.net.au/archive/2099632
            http://stackoverflow.com/questions/2899974/need-to-convert-a-zip-file-to-a-random-text-file

            ZipEntry entry;
            while((entry = stream.getNextEntry())!=null)
            {
                String s = String.format("Entry: %s len %d added %TD",
                        entry.getName(), entry.getSize(),
                        new Date(entry.getTime()));
                System.out.println(s);



                String outpath = outdir + "/" + ;
                FileOutputStream output = null;
                output = new FileOutputStream(outpath);

                try
                {
                    String fileName = entry.getName()+"\n";
                    int len1= fileName.length();
                    List<String> hexStringArrayForFileName = new ArrayList<>(len1);//hexStringArray
                    for(int i =0; i<len1;i++){

                        hexStringArrayForFileName.add(String.format("%02x", (int) fileName.charAt(i)));
                    }

                    for(int i =0;i<len1;i++){//writing filename
                        buffer[0]=(byte)(hexStringArrayForFileName.get(i).charAt(0)& 0x00FF);
                        buffer[1]=(byte)(hexStringArrayForFileName.get(i).charAt(1)& 0x00FF);
                        output.write(buffer, 0, buffer.length);
                    }



                    int len = 0;
                    while ((len = stream.read(inBuffer)) > 0)
                    {
                        if(len>0)
                        {
                            int decimalValue= inBuffer[0] &  0xff;
                            String second = Integer.toHexString(decimalValue/16);
                            String first= Integer.toHexString(decimalValue- ((int)decimalValue/16)*16);

                            buffer[1] = (byte) (first.charAt(0) & 0x00FF);
                            buffer[0] = (byte) (second.charAt(0) & 0x00FF);
                        }

                        output.write(buffer, 0, len*2);
                    }

                    for(int i =0;i<len1;i++){//writing filename
                        buffer[0]=(byte)(hexStringArrayForFileName.get(i).charAt(0)& 0x00FF);
                        buffer[1]=(byte)(hexStringArrayForFileName.get(i).charAt(1)& 0x00FF);
                        output.write(buffer, 0, buffer.length);
                    }

                }
                finally
                {
                    // we must always close the output file
                    if(output!=null) output.close();
                }
            }
        }
        finally
        {
            // we must always close the zip file.
            stream.close();
        }
    }*/


    private static void convertZiptoHex() throws Exception
    {

        //byte[] buffer = new byte[2048];
        byte[] inBuffer = new byte[1];//dont change array size
        byte[] buffer = new byte[2];//dont change array size

        String inputFile = "C:/Users/rbhushan/Desktop/hi.zip";
        String outdir = "C:/Users/rbhushan/Desktop";
        ZipInputStream stream = new ZipInputStream(new FileInputStream(inputFile));

        try
        {

            String outpath = outdir + "/" + /*entry.getName()*/"hi5.txt";
            FileOutputStream output = null;
            output = new FileOutputStream(outpath);

            ZipEntry entry;
            while ((entry = stream.getNextEntry()) != null)
            {
                String s = String.format("Entry: %s len %d added %TD",
                        entry.getName(), entry.getSize(),
                        new Date(entry.getTime()));
                System.out.println(s);



                /*String outpath = outdir + "/" + *//*entry.getName()*//*"hi5.txt";
                FileOutputStream output = null;
                output = new FileOutputStream(outpath);*/

                try
                {
                    String fileName = entry.getName() + "\n";
                    int len1 = fileName.length();
                    List<String> hexStringArrayForFileName = new ArrayList<>(len1);//hexStringArray
                    for (int i = 0; i < len1; i++)
                    {

                        hexStringArrayForFileName.add(String.format("%02x", (int) fileName.charAt(i)));
                    }

                    for (int i = 0; i < len1; i++)
                    {//writing filename
                        buffer[0] = (byte) (hexStringArrayForFileName.get(i).charAt(0) & 0x00FF);
                        buffer[1] = (byte) (hexStringArrayForFileName.get(i).charAt(1) & 0x00FF);
                        output.write(buffer, 0, buffer.length);
                    }


                    int len = 0;
                    while ((len = stream.read(inBuffer)) > 0)
                    {
                        if (len > 0)
                        {
                            int decimalValue = inBuffer[0] & 0xff;
                            String second = Integer.toHexString(decimalValue / 16);
                            String first = Integer.toHexString(decimalValue - ((int) decimalValue / 16) * 16);

                            buffer[1] = (byte) (first.charAt(0) & 0x00FF);
                            buffer[0] = (byte) (second.charAt(0) & 0x00FF);
                        }

                        output.write(buffer, 0, len * 2);
                    }

                    for (int i = 0; i < len1; i++)
                    {//writing filename
                        buffer[0] = (byte) (hexStringArrayForFileName.get(i).charAt(0) & 0x00FF);
                        buffer[1] = (byte) (hexStringArrayForFileName.get(i).charAt(1) & 0x00FF);
                        output.write(buffer, 0, buffer.length);
                    }

                } finally
                {
                    // we must always close the output file
                    if (output != null) output.close();
                }
            }
        } finally
        {
            // we must always close the zip file.
            stream.close();
        }
    }
}
