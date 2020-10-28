package uk.co.automatictester.security.csr;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.testng.annotations.Test;

import java.security.*;
import java.security.spec.RSAKeyGenParameterSpec;

import static org.testng.Assert.assertTrue;

public class Pkcs10CertificateSigningRequest {

    @Test
    public void testPkcs10CertSigningRequest() throws Exception {
        byte[] certificationRequest = generateCertificateSigningRequest();
        boolean result = validateCertificateSigningRequest(certificationRequest);
        assertTrue(result);
    }

    private boolean validateCertificateSigningRequest(byte[] certificationRequest) throws Exception {
        JcaPKCS10CertificationRequest jcaRequest =
                new JcaPKCS10CertificationRequest(certificationRequest).setProvider(new BouncyCastleProvider());

        PublicKey publicKey = jcaRequest.getPublicKey();

        ContentVerifierProvider verifierProvider =
                new JcaContentVerifierProviderBuilder().setProvider(new BouncyCastleProvider()).build(publicKey);

        return jcaRequest.isSignatureValid(verifierProvider);
    }

    private byte[] generateCertificateSigningRequest() throws Exception {
        X500Name name = getX500Name();
        KeyPair keyPair = generateRsaKeyPair();
        String signatureAlgorithm = "SHA256withRSAandMGF1";

        PKCS10CertificationRequestBuilder requestBuilder =
                new JcaPKCS10CertificationRequestBuilder(name, keyPair.getPublic());

        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider(new BouncyCastleProvider())
                .build(keyPair.getPrivate());

        return requestBuilder.build(contentSigner).getEncoded();
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
