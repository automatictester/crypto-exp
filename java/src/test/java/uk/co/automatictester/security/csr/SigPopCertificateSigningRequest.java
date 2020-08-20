package uk.co.automatictester.security.csr;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessage;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessageBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.testng.annotations.Test;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.RSAKeyGenParameterSpec;

import static org.testng.Assert.assertTrue;

public class SigPopCertificateSigningRequest {

    @Test
    public void testSignatureBasedPopCertSigningRequest() throws Exception {
        byte[] certificationRequest = generateCertificateSigningRequest();
        boolean result = validateCertificateSigningRequest(certificationRequest);
        assertTrue(result);
    }

    private boolean validateCertificateSigningRequest(byte[] certificationRequest) throws Exception {
        JcaCertificateRequestMessage jcaRequest =
                new JcaCertificateRequestMessage(certificationRequest).setProvider(new BouncyCastleProvider());

        PublicKey publicKey = jcaRequest.getPublicKey();

        ContentVerifierProvider verifierProvider =
                new JcaContentVerifierProviderBuilder().setProvider(new BouncyCastleProvider()).build(publicKey);

        return jcaRequest.isValidSigningKeyPOP(verifierProvider);
    }

    private byte[] generateCertificateSigningRequest() throws Exception {
        X500Name name = getX500Name();
        KeyPair keyPair = generateRsaKeyPair();
        String signatureAlgorithm = "SHA256withRSAandMGF1";
        BigInteger requestId = BigInteger.valueOf(1235);

        byte[] encodedPublicKey = keyPair.getPublic().getEncoded();
        SubjectPublicKeyInfo subjectPublicKeyInfo =
                SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(encodedPublicKey));

        JcaCertificateRequestMessageBuilder requestBuilder = new JcaCertificateRequestMessageBuilder(requestId);
        requestBuilder.setSubject(name)
                .setPublicKey(subjectPublicKeyInfo)
                .setProofOfPossessionSigningKeySigner(
                        new JcaContentSignerBuilder(signatureAlgorithm)
                                .setProvider(new BouncyCastleProvider())
                                .build(keyPair.getPrivate())
                );

        return requestBuilder.build().getEncoded();
    }

    private X500Name getX500Name() {
        return new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "UK")
                .addRDN(BCStyle.L, "London")
                .addRDN(BCStyle.O, "Sample Org")
                .addRDN(BCStyle.CN, "Sample Self-Signed Certificate")
                .build();
    }

    private KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        RSAKeyGenParameterSpec parameterSpec = new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4);
        keyPairGenerator.initialize(parameterSpec);
        return keyPairGenerator.generateKeyPair();
    }
}
