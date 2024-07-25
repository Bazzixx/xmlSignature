package com.example.demo;

import java.io.File;
import java.io.FileOutputStream;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;

import java.security.PublicKey;
import java.util.Collections;

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
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class signatureXml {
	public static void main(String[] args) {
		try {
			KeyPair keyPair = generateKeyPair();
			PrivateKey privateKey = keyPair.getPrivate();
			PublicKey publicKey = keyPair.getPublic();

			Document doc = loadXMLDocument("example2.xml");

			signXMLDocument(doc, privateKey, publicKey);

			saveXMLDocument(doc, "signedExample2.xml");

			System.out.println("XML 서명 완료: signedExample2.xml");

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	// 1. 키 쌍 생성
	private static KeyPair generateKeyPair() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		return kpg.generateKeyPair();
	}

	// 2. XML 파일 로드
	private static Document loadXMLDocument(String filename) throws Exception {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		DocumentBuilder db = dbf.newDocumentBuilder();
		return db.parse(new File(filename));
	}

	// 3. XML 서명 생성
	private static void signXMLDocument(Document doc, PrivateKey privateKey, PublicKey publicKey) throws Exception {
		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

		// ID 속성을 가진 요소를 서명 대상으로 지정
		Element targetElement = (Element) doc.getElementsByTagName("module").item(0);
		if (targetElement == null) {
			throw new Exception("서명 대상 요소를 찾을 수 없음");
		}
		targetElement.setIdAttribute("Id", true);

		Reference ref = fac.newReference(
			"#module-to-sign",
			fac.newDigestMethod(DigestMethod.SHA256, null),
			Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
			null,
			null
		);

		SignedInfo si = fac.newSignedInfo(
			fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
			fac.newSignatureMethod(SignatureMethod.RSA_SHA256, null),
			Collections.singletonList(ref)
		);

		KeyInfoFactory kif = fac.getKeyInfoFactory();
		KeyValue kv = kif.newKeyValue(publicKey);
		KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));

		DOMSignContext dsc = new DOMSignContext(privateKey, doc.getDocumentElement());

		XMLSignature signature = fac.newXMLSignature(si, ki);

		signature.sign(dsc);
	}

	// 4. 서명된 XML 문서 저장
	private static void saveXMLDocument(Document doc, String filename) throws Exception {
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer trans = tf.newTransformer();
		DOMSource src = new DOMSource(doc);
		StreamResult result = new StreamResult(new FileOutputStream(filename));
		trans.transform(src, result);
	}
}