package uk.co.automatictester.security.x509;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.testng.annotations.Test;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

public class SelfSignedCert {

    @Test
    public void generateSelfSignedCertAndStoreToJks() throws Exception {
        BigInteger serialNumber = BigInteger.valueOf(1234);
        Date validityDate = getValidityDate(12);
        KeyPair keyPair = generateRsaKeyPair();
        String signatureAlgorithm = "SHA256withRSAandMGF1";
        X500Name name = getX500Name();

        X509CertificateHolder certificateHolder = getCertificateHolder(
                name,
                keyPair,
                validityDate,
                serialNumber,
                signatureAlgorithm
        );

        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider())
                .getCertificate(certificateHolder);

        storeToJks(keyPair.getPrivate(), certificate);
        storeToP12(keyPair.getPrivate(), certificate);
    }

    private Date getValidityDate(int months) {
        LocalDateTime localDateTime = LocalDateTime.now().plusMonths(months);
        long futureDateInMillis = localDateTime.atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
        return new Date(futureDateInMillis);
    }

    private KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        RSAKeyGenParameterSpec parameterSpec = new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4);
        keyPairGenerator.initialize(parameterSpec);
        return keyPairGenerator.generateKeyPair();
    }

    private X500Name getX500Name() {
        return new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "UK")
                .addRDN(BCStyle.L, "London")
                .addRDN(BCStyle.O, "Sample Org")
                .addRDN(BCStyle.CN, "Sample Self-Signed Certificate")
                .build();
    }

    private X509CertificateHolder getCertificateHolder(X500Name name, KeyPair keyPair, Date validityDate,
                                                       BigInteger serialNumber, String signatureAlgorithm)
            throws OperatorCreationException {
        Date now = new Date();

        X509v1CertificateBuilder certificateBuilder = new JcaX509v1CertificateBuilder(
                name, serialNumber, now, validityDate, name, keyPair.getPublic()
        );

        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider(new BouncyCastleProvider())
                .build(keyPair.getPrivate());

        return certificateBuilder.build(contentSigner);
    }

    private void storeToJks(PrivateKey privateKey, Certificate certificate) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);
        keyStore.setKeyEntry(
                "self_signed_certificate",
                privateKey,
                "key_password".toCharArray(),
                new Certificate[]{certificate}
        );
        FileOutputStream fos = new FileOutputStream("example.jks");
        keyStore.store(fos, "store_password".toCharArray());

        /*
         * keytool -list -keystore example.jks -storepass store_password
         * Keystore type: jks
         * Keystore provider: SUN

         * Your keystore contains 1 entry

         * self_signed_certificate, Aug 17, 2020, PrivateKeyEntry,
         * Certificate fingerprint (SHA1): BE:FA:43:86:37:DF:0A:E9:A0:39:9C:9F:61:C0:94:BF:D5:70:51:5B
         */
    }

    private void storeToP12(PrivateKey privateKey, Certificate certificate) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry(
                "self_signed_certificate",
                privateKey,
                null,
                new Certificate[]{certificate}
        );
        FileOutputStream fos = new FileOutputStream("example.p12");
        keyStore.store(fos, "store_password".toCharArray());

        /*
         * keytool -list -keystore example.p12 -storepass store_password
         * Keystore type: PKCS12
         * Keystore provider: SUN

         * Your keystore contains 1 entry

         * self_signed_certificate, Aug 17, 2020, PrivateKeyEntry,
         * Certificate fingerprint (SHA1): BE:FA:43:86:37:DF:0A:E9:A0:39:9C:9F:61:C0:94:BF:D5:70:51:5B
         */
    }
}
