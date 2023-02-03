package ism.ase.ro.sap.exam.Mocanita.Mara;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.stream.Collectors;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.plaf.synth.SynthSeparatorUI;

public class MocanitaMaraExam {

	// provided method for getting the public key from a X509 certificate file
	public static PublicKey getCertificateKey(String file) throws IOException, CertificateException {
		File certFile = new File(file);

		if(!certFile.exists()) {
			throw new FileNotFoundException();
		}

		FileInputStream fis = new FileInputStream(file);

		CertificateFactory cerFactory = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate) cerFactory.generateCertificate(fis);
		fis.close();

		return certificate.getPublicKey();
	}
	
	//provided method to print a byte array to console
	public static String getHex(byte[] values) {
		StringBuilder sb = new StringBuilder();
		for (byte value : values) {
			sb.append(String.format("%02x", value));
		}

		return sb.toString();
	}
	

	// method for getting the private key from a keystore
	public static PrivateKey getPrivateKey(
			String keyStoreFileName, 
			String keyStorePass, 
			String keyAlias,
			String keyPass) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
					UnrecoverableKeyException {

		File file = new File(keyStoreFileName);
		if(!file.exists()) {
			System.out.println("NO SUCH FILE!!!");
			throw new FileNotFoundException();
		}

		FileInputStream fis = new FileInputStream(file);

		KeyStore keyStore = KeyStore.getInstance("pkcs12");
		keyStore.load(fis, keyStorePass.toCharArray());

		fis.close();

		if(keyStore == null) {
			System.out.println("no such keystore");
			throw new UnsupportedOperationException();
		}
		if(keyStore.containsAlias(keyAlias)) {
			return (PrivateKey) keyStore.getKey(keyAlias, keyPass.toCharArray());
		}else {
			System.out.println("no such alias");
			throw new UnsupportedOperationException();
		}
	}

	
	// method for computing the RSA digital signature
	public static void getDigitalSignature(
			String inputFileName, 
			String signatureFileName, 
			PrivateKey key)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {

		File file = new File(inputFileName);
		if (!file.exists())
			throw new FileNotFoundException();

		FileInputStream fis = new FileInputStream(file);

		byte[] fileContent = fis.readAllBytes();

		fis.close();

		Signature digitalSignature = Signature.getInstance("SHA1withRSA");
		digitalSignature.initSign(key);
		digitalSignature.update(fileContent); //pas obligatoriu
		var digSign = digitalSignature.sign();

		File outputFile = new File(signatureFileName);
		if (!outputFile.exists()) {
			outputFile.createNewFile();
		}
		FileOutputStream fos = new FileOutputStream(outputFile);
		fos.write(digSign);
		fos.close();

	}


	//proposed function for generating the hash value
	public static byte[] getSHA1Hash(File file)
			throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		
		//generate the SHA-1 value of the received file
		if (!file.exists()) {
			throw new FileNotFoundException();
		}
		FileInputStream fis = new FileInputStream(file);
		var values = fis.readAllBytes();
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		return md.digest(values);
	}

	//proposed function for decryption
	public static void decryptAESCBC(
			File inputFile, 
			File outputFile, 
			byte[] key)
					throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, ShortBufferException, BadPaddingException,
			IOException {

		//decrypt the input file using AES in CBC
		//the file was encrypted without using padding - didn't need it
		//the IV is at the beginning of the input file


		if (!inputFile.exists()) {
			throw new FileNotFoundException();
		}

		FileInputStream fis = new FileInputStream(inputFile);
		BufferedInputStream bis = new BufferedInputStream(fis); //pregatit pt citire


		if (!outputFile.exists()) {
			outputFile.createNewFile();
		}

		FileOutputStream fos = new FileOutputStream(outputFile);
		BufferedOutputStream bos = new BufferedOutputStream(fos); //pregatit pt scriere


		Cipher cipher = Cipher.getInstance("AES" + "/CBC/NoPadding");
		SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

		//generate iv
		byte[] iv = new byte[cipher.getBlockSize()];
		bis.read(iv);
		IvParameterSpec ivParamSpec = new IvParameterSpec(iv);

		cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParamSpec);


		byte[] buffer = new byte[cipher.getBlockSize()];
		int noBytes = 0;
		byte[] cipherBuffer;

		while(noBytes != -1) {
			noBytes = bis.read(buffer); //la ultimul bloc trbeuie sa apelezi "doFinal"
			// ca sa aplice bitii de padding daca sunt necesari.
			// altfel n-o sa citeasca nimic
			if (noBytes != -1) {
				cipherBuffer = cipher.update(buffer, 0, noBytes);
				bos.write(cipherBuffer);
			}

		}
		cipherBuffer = cipher.doFinal();
		bos.write(cipherBuffer);

		bis.close();
		bos.close();

	}

    //proposed function for print the text file content
	public static void printTextFileContent(
			String textFileName) throws	IOException {

		//print the text file content on the console
		//you need to do this to get values for the next request

		File input = new File(textFileName);
		if (!input.exists()) {
			throw new FileNotFoundException();
		}

		FileReader fr = new FileReader(input);
		BufferedReader br = new BufferedReader(fr);
		var fileContent = br.lines().collect(Collectors.toList());

		System.out.println(fileContent);

	}


	

	public static void main(String[] args) {
		try {

			
			/*
			 * 
			 * @Mocanita Mara - Please write your name here and also rename the class
			 * 
			 * 
			 * 
			 */
			/*
			 * Request 1
			 */
			File passFile = new File("Passphrase.txt");
			byte[] hashValue = getSHA1Hash(passFile);
			System.out.println("SHA1: " + getHex(hashValue));

			
			
			//check point - you should get 268F10........ 
			
			
			/*
			 * Request 2
			 */

			//generate the key form previous hash
			byte[] key = new byte[16];
			for (int i = 0; i < 16; i++) {
				key[i] = hashValue[i];
			}
			
			//decrypt the input file 
			//there is no need for padding and the IV is written at the beginning of the file
			decryptAESCBC(new File("EncryptedData.data"), new File("OriginalData.txt"), key);
			

			printTextFileContent("OriginalData.txt");
			
			//get the keyStorePassword from OriginalMessage.txt. Copy paste the values from the console
			String ksPassword = "you_already_made_it";
			String keyName = "sapexamkey";
			String keyPassword = "grant_access";
			
			/*
			* Request 3
			*/


			//compute the RSA digital signature for the EncryptedMessage.cipher file and store it in the
			//	signature.ds file
			
			PrivateKey privKey = getPrivateKey("sap_exam_keystore.ks",ksPassword,keyName,keyPassword);
			getDigitalSignature("OriginalData.txt", "DataSignature.ds", privKey);
			
			
			//optionally - you can check if the signature is ok using the given SAPExamCertificate.cer
			//not mandatory
			//write code that checks the previous signature

			System.out.println("Done");

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
