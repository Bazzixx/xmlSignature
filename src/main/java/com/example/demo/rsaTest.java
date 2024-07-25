package com.example.demo;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;

import javax.crypto.Cipher;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;

public class rsaTest {
	public static final SecureRandom random = new SecureRandom();

	public static String getSalt() {
		byte[] salt = new byte[16];
		random.nextBytes(salt);

		return Base64.getEncoder().encodeToString(salt);
	}

	public static String sha256WithSaltEncode(String data, String salt) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			digest.update(salt.getBytes(StandardCharsets.UTF_8));
			byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));

			return Base64.getEncoder().encodeToString(hash);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	public static String sha256Encode(String data) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));

			return Base64.getEncoder().encodeToString(hash);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	public static void main(String[] args) {
		String password = "password";

		String hashData = sha256Encode(password);
		System.out.println("hashData = " + hashData);
		if(hashData.equals("XohImNooBHFR0OVvjcYpJ3NgPQ1qq73WKhHvch0VQtg=")) {
			System.out.println("Password Matched");
		}
		String hashDataWithSalt = sha256WithSaltEncode(password, getSalt());
		System.out.println("hashDataWithSalt = " + hashDataWithSalt);
		String hashDataWithSalt2 = sha256WithSaltEncode(password, getSalt());
		System.out.println("hashDataWithSalt = " + hashDataWithSalt2);
		String hashDataWithSalt3 = sha256WithSaltEncode(password, getSalt());
		System.out.println("hashDataWithSalt = " + hashDataWithSalt3);



		if(hashDataWithSalt.equals(hashDataWithSalt2)) {
			System.out.println("Password Matched");
		} else {
			System.out.println("Password Not Matched");
		}

		if(hashDataWithSalt.equals(hashDataWithSalt3)) {
			System.out.println("Password Matched");
		} else {
			System.out.println("Password Not Matched");
		}
	}




}