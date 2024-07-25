package com.example.demo;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class rsaTest3 {
	public static void main(String[] args) {
		try {
			// 키 쌍 생성
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			KeyPair keyPair = kpg.generateKeyPair();

			// XML 파일 로드 및 서명 생성
			Document doc = signXMLDocument(keyPair);

			// 서명된 XML 문서 저장
			saveXMLDocument(doc, "signedExample2.xml");

			// 서명 검증
			boolean isValid = verifySignature(doc, keyPair.getPublic());
			System.out.println("서명 검증 결과: " + (isValid ? "유효함" : "무효함"));

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static Document signXMLDocument(KeyPair keyPair) throws Exception {
		PrivateKey privateKey = keyPair.getPrivate();

		// XML 파일 로드
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		disableExternalEntities(dbf);

		DocumentBuilder db = dbf.newDocumentBuilder();
		Document doc = db.parse(new File("example2.xml"));

		Element elementToSign = doc.getDocumentElement();
		//String canonicalizedXML = canonicalize(doc.getDocumentElement());

		// Canonicalize XML
		String canonicalizedXML = canonicalize(elementToSign);

		// Calculate Digest
		String calculatedDigest = calculateDigest(canonicalizedXML);

		System.out.println("Canonicalized XML: " + canonicalizedXML);
		System.out.println("Calculated Digest: " + calculatedDigest);

		// Digest 생성
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(canonicalizedXML.getBytes(StandardCharsets.UTF_8));
		String digestValue = Base64.getEncoder().encodeToString(digest);
		System.out.println("digest = " + digest);

		// 서명 생성
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(privateKey);
		signature.update(digest); // Update with the digest
		byte[] signedDigest = signature.sign();
		String signatureValue = Base64.getEncoder().encodeToString(signedDigest);

		// XML 문서에 서명 추가
		Element signatureElement = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "Signature");

		Element signedInfoElement = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "SignedInfo");
		Element canonicalizationMethod = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "CanonicalizationMethod");
		canonicalizationMethod.setAttribute("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#");
		signedInfoElement.appendChild(canonicalizationMethod);

		Element signatureMethod = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "SignatureMethod");
		signatureMethod.setAttribute("Algorithm", "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
		signedInfoElement.appendChild(signatureMethod);

		Element referenceElement = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "Reference");
		referenceElement.setAttribute("URI", "");

		Element transformsElement = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "Transforms");
		Element transformElement = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "Transform");
		transformElement.setAttribute("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature");
		transformsElement.appendChild(transformElement);
		referenceElement.appendChild(transformsElement);

		Element digestMethodElement = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "DigestMethod");
		digestMethodElement.setAttribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256");
		referenceElement.appendChild(digestMethodElement);

		Element digestValueElement = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "DigestValue");
		digestValueElement.setTextContent(digestValue);
		referenceElement.appendChild(digestValueElement);

		signedInfoElement.appendChild(referenceElement);
		signatureElement.appendChild(signedInfoElement);

		Element signatureValueElement = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "SignatureValue");
		signatureValueElement.setTextContent(signatureValue);
		signatureElement.appendChild(signatureValueElement);

		doc.getDocumentElement().appendChild(signatureElement);

		return doc;
	}

	private static boolean verifySignature(Document doc, PublicKey publicKey) throws Exception {
		NodeList signatureNodeList = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
		if (signatureNodeList.getLength() == 0) {
			throw new Exception("서명 요소를 찾을 수 없음");
		}
		Element signatureElement = (Element) signatureNodeList.item(0);

		NodeList signatureValueNodeList = signatureElement.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "SignatureValue");
		if (signatureValueNodeList.getLength() == 0) {
			throw new Exception("SignatureValue 요소를 찾을 수 없음");
		}
		String signatureValue = signatureValueNodeList.item(0).getTextContent();

		// Canonicalize XML (서명 요소 제거 후)
		signatureElement.getParentNode().removeChild(signatureElement);
		String canonicalizedXML = canonicalize(doc.getDocumentElement());

		// Digest 생성
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(canonicalizedXML.getBytes(StandardCharsets.UTF_8));

		// 서명 검증
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initVerify(publicKey);
		signature.update(digest);
		byte[] signedDigest = Base64.getDecoder().decode(signatureValue);

		String calculatedDigest2 = calculateDigest(canonicalizedXML);

		System.out.println("calculatedDigest2 = " + calculatedDigest2);
		System.out.println("digest = " + digest);
		System.out.println("signedDigest = " + signedDigest);

		return signature.verify(signedDigest);
	}

	private static void disableExternalEntities(DocumentBuilderFactory dbf) {
		try {
			dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
			dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
			dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		}
	}

	/*private static String canonicalize(Element element) throws Exception {
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer transformer = tf.newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		transformer.transform(new DOMSource(element), new StreamResult(baos));
		return new String(baos.toByteArray(), StandardCharsets.UTF_8);
	}*/

	public static String canonicalize(Element element) throws Exception {
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer transformer = tf.newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		transformer.setOutputProperty(OutputKeys.INDENT, "no");
		transformer.setOutputProperty(OutputKeys.CDATA_SECTION_ELEMENTS, "yes");

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		transformer.transform(new DOMSource(element), new StreamResult(baos));
		return new String(baos.toByteArray(), StandardCharsets.UTF_8);
	}

	public static String calculateDigest(String canonicalizedXML) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(canonicalizedXML.getBytes(StandardCharsets.UTF_8));
		return Base64.getEncoder().encodeToString(digest);
	}

	private static void saveXMLDocument(Document doc, String filename) throws Exception {
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer transformer = tf.newTransformer();
		transformer.setOutputProperty(OutputKeys.INDENT, "yes");
		DOMSource source = new DOMSource(doc);
		StreamResult result = new StreamResult(new FileOutputStream(filename));
		transformer.transform(source, result);
	}

	private static String extractDataToSign(Document doc) {
		try {
			// DOM을 문자열로 변환
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer transformer = tf.newTransformer();
			DOMSource source = new DOMSource(doc);
			StreamResult result = new StreamResult(new File("temp.xml"));
			transformer.transform(source, result);

			// 임시 파일에서 데이터 추출
			byte[] encoded = Files.readAllBytes(Paths.get("temp.xml"));
			return new String(encoded, StandardCharsets.UTF_8);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
}