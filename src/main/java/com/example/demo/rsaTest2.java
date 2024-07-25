package com.example.demo;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class rsaTest2 {
	public static void main(String[] args) throws Exception {
		// 1. RSA 키 생성
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		KeyPair keyPair = keyGen.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();

		// XML 데이터 샘플
		String xmlData = "<note>" +
			"<to>Tove</to>" +
			"<from>Jani</from>" +
			"<heading>Reminder</heading>" +
			"<body>Don't forget me this weekend!</body>" +
			"</note>";

		// XML 파싱
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		DocumentBuilder builder = factory.newDocumentBuilder();
		Document document = builder.parse(new java.io.ByteArrayInputStream(xmlData.getBytes()));

		// 2. XML 데이터의 해시 생성
		Node root = document.getDocumentElement();
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		Transformer transformer = transformerFactory.newTransformer();
		java.io.StringWriter writer = new java.io.StringWriter();
		transformer.transform(new DOMSource(root), new StreamResult(writer));
		String xmlString = writer.getBuffer().toString();

		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] hash = digest.digest(xmlString.getBytes());

		// 3. 해시를 서명
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(privateKey);
		signature.update(hash);
		byte[] signedHash = signature.sign();

		// 4. 서명 데이터를 XML에 추가
		String signatureBase64 = Base64.getEncoder().encodeToString(signedHash);
		Element signatureElement = document.createElement("Signature");
		Element signatureValueElement = document.createElement("SignatureValue");
		signatureValueElement.appendChild(document.createTextNode(signatureBase64));
		signatureElement.appendChild(signatureValueElement);
		root.appendChild(signatureElement);

		// 결과 XML 출력
		transformer.transform(new DOMSource(document), new StreamResult(System.out));

		// 서명 검증
		boolean isSignatureValid = verifySignature(document, publicKey);
		System.out.println("\nSignature valid: " + isSignatureValid);
	}

	public static boolean verifySignature(Document document, PublicKey publicKey) throws Exception {
		// 1. Signature 요소를 찾기
		NodeList signatureNodeList = document.getElementsByTagName("Signature");
		if (signatureNodeList.getLength() == 0) {
			throw new Exception("No Signature element found in the XML document.");
		}
		Element signatureElement = (Element) signatureNodeList.item(0);

		// 2. SignatureValue 추출
		String signatureBase64 = signatureElement.getElementsByTagName("SignatureValue").item(0).getTextContent();
		byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);

		// 3. XML 데이터의 해시 생성
		Node root = document.getDocumentElement();
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		Transformer transformer = transformerFactory.newTransformer();
		java.io.StringWriter writer = new java.io.StringWriter();
		transformer.transform(new DOMSource(root), new StreamResult(writer));
		String xmlString = writer.getBuffer().toString();
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] hash = digest.digest(xmlString.getBytes());

		// 4. 서명 검증
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initVerify(publicKey);
		signature.update(hash);
		return signature.verify(signatureBytes);
	}
}