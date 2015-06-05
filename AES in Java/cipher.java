import java.util.Scanner;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import Utils.ByteUtils;

public class cipher
{
	public static Key generateKey(String algorithm) throws NoSuchAlgorithmException
	{
			KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
			SecretKey key = keyGenerator.generateKey();
			return key;
	}

	public static Key generateKey(String algorithm, byte[] keyData) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException
	{
		SecretKeySpec keySpec = new SecretKeySpec(keyData, algorithm);
		return keySpec;
	}


	public static void main(String[] args) throws Exception 
	{
		Scanner sc = new Scanner(System.in);
		
		// key input
		System.out.print("Enter key value : ");
		String keyString = sc.nextLine();
		int len = keyString.length();
		if(len < 16) {
			keyString = ByteUtils.stringToHex(keyString);
			for(int i=0; i<16-len; i++)
				keyString += "10"; 
		}
		else {
			keyString = ByteUtils.stringToHex(keyString);
		}
		Key key = generateKey("AES", ByteUtils.toBytes(keyString, 16));
		
		// Encryption mode and padding mode setting step
		String transformation = "AES/CBC/PKCS5Padding";
		
		// Put IV data. Currently it'll not get data from user. It can be changed.
		// You need to use same IV value when you decrypt file.(same as key)
		byte bt[] = new byte[16];
		bt = ByteUtils.toBytes("696d697373796f7568616e6765656e61", 16);
		IvParameterSpec iv = new IvParameterSpec(bt);
		
		Cipher cipher = Cipher.getInstance(transformation);
		
		System.out.print("Enter directory : ");
		
		String directory = sc.nextLine();
		String dir = directory.replaceAll("\\\\", "/");
		
		System.out.print("Enter file name : ");
		String fileName = sc.nextLine();
		System.out.println("1.Encryption 2.Decryption");
		int a = sc.nextInt();
		
		BufferedInputStream input = null;
		BufferedOutputStream output = null;
		
		if(a == 1)
		{
			File plainFile = new File(dir + '/' + fileName);
			File encryptFile = new File(dir + '/' + fileName + ".enc");
			
			//time
			long startTime = System.nanoTime();
			cipher.init(Cipher.ENCRYPT_MODE, key, iv);	
			
			try
			{
				input = new BufferedInputStream(new FileInputStream(plainFile));
				output = new BufferedOutputStream(new FileOutputStream(encryptFile));
				int read = 0;
				byte[] inBuf = new byte[1024];
				byte[] outBuf = null;
				while ((read = input.read(inBuf)) != -1) {
					outBuf = cipher.update(inBuf, 0, read);
					if (outBuf != null) {
						output.write(outBuf);
					}
				}
				outBuf = cipher.doFinal();
				if (outBuf != null) {
					output.write(outBuf);
				}
			}
			finally {
					if (output != null) try {output.close();} catch(IOException ie) {}
					if (input != null) try {input.close();} catch(IOException ie) {}
			}

			//time
			long endTime = System.nanoTime();
			long lTime = endTime - startTime;
			System.out.println("Encryption TIME : " + (lTime/1000000.0)/1000 + "(s)");
		}
		else {
			File encryptFile = new File(dir + '/' + fileName);
			String dFile = fileName.substring(0, fileName.lastIndexOf("."));
			File decryptFile = new File(dir + '/' + dFile);
			
			//time
			long startTime = System.nanoTime();
			cipher.init(Cipher.DECRYPT_MODE, key, iv);
			try {
				input = new BufferedInputStream(new FileInputStream(encryptFile));
				output = new BufferedOutputStream(new FileOutputStream(decryptFile));
	
				int read = 0;
				byte[] inBuf = new byte[1024];
				byte[] outBuf = null;
				while ((read = input.read(inBuf)) != -1) {
					outBuf = cipher.update(inBuf, 0, read);
					if (outBuf != null) {
						output.write(outBuf);
					}
				}
				outBuf = cipher.doFinal();
				if (outBuf != null) {
					output.write(outBuf);
					}
			} 
			finally {
					if (output != null) try {output.close();} catch(IOException ie) {}
					if (input != null) try {input.close();} catch(IOException ie) {}
			}
			//time
			long endTime = System.nanoTime();
			long lTime = endTime - startTime;
			System.out.println("Decryption TIME : " + (lTime/1000000.0)/1000 + "(s)");
			encryptFile.delete();
		}
		sc.close();
	}	
}
