package uk.co.automatictester.security.openpgp;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;

@Slf4j
public class KeyRing {

    @Test
    public void testKeyRingGeneration() throws Exception {
        PGPKeyPair pgpDsaKeyPair = PgpShared.generatePgpDsaKeyPair();
        PGPKeyPair pgpRsaKeyPair = PgpShared.generatePgpRsaEncryptionKeyPair();

        String identity = "identity";
        char[] passphrase = "password".toCharArray();

        List<PGPKeyRing> pgpKeyRingList = getPgpKeyRings(pgpDsaKeyPair, pgpRsaKeyPair, identity, passphrase);
        PGPSecretKeyRing pgpSecretKeyRing = null;
        PGPPublicKeyRing pgpPublicKeyRing = null;

        for (PGPKeyRing pgpKeyRing : pgpKeyRingList) {
            if (pgpKeyRing instanceof PGPSecretKeyRing) {
                pgpSecretKeyRing = (PGPSecretKeyRing) pgpKeyRing;
            } else {
                pgpPublicKeyRing = (PGPPublicKeyRing) pgpKeyRing;
            }
        }

        List<PGPPublicKey> pgpPublicKeyList = new ArrayList<>();
        for (Iterator<PGPPublicKey> it = pgpPublicKeyRing.getPublicKeys(); it.hasNext(); ) {
            pgpPublicKeyList.add(it.next());
        }
        assertThat(pgpPublicKeyList.size(), equalTo(2));

        for (PGPPublicKey pgpPublicKey : pgpPublicKeyList) {
            long keyId = pgpPublicKey.getKeyID();
            String keyAlgorithm = PgpShared.getKeyAlgorithm(pgpPublicKey.getAlgorithm());
            int bitStrength = pgpPublicKey.getBitStrength();
            log.info("Key ID: {}, algorithm: {}, bit strength: {}", keyId, keyAlgorithm, bitStrength);

            // for each key in public key ring, check there is a public and secret key with the same key id in secret key ring
            assertThat(pgpSecretKeyRing.getPublicKey(keyId), is(notNullValue()));
            assertThat(pgpSecretKeyRing.getSecretKey(keyId), is(notNullValue()));
        }
    }

    private List<PGPKeyRing> getPgpKeyRings(PGPKeyPair signingKeyPair, PGPKeyPair encryptionKeyPair, String identity,
                                            char[] passphrase) throws PGPException {
        PGPDigestCalculator pgpDigestCalculator = new JcaPGPDigestCalculatorProviderBuilder()
                .build().get(HashAlgorithmTags.SHA1);

        JcaPGPContentSignerBuilder pgpContentSignerBuilder = new JcaPGPContentSignerBuilder(
                signingKeyPair.getPublicKey().getAlgorithm(),
                PGPUtil.SHA256
        );

        PBESecretKeyEncryptor pbeSecretKeyEncryptor = new JcePBESecretKeyEncryptorBuilder(
                PGPEncryptedData.AES_256, pgpDigestCalculator
        ).setProvider(new BouncyCastleProvider()).build(passphrase);

        PGPKeyRingGenerator pgpKeyRingGenerator = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION, signingKeyPair, identity, pgpDigestCalculator,
                null, null, pgpContentSignerBuilder, pbeSecretKeyEncryptor
        );

        pgpKeyRingGenerator.addSubKey(encryptionKeyPair);

        PGPSecretKeyRing secretKeyRing = pgpKeyRingGenerator.generateSecretKeyRing();
        PGPPublicKeyRing publicKeyRing = pgpKeyRingGenerator.generatePublicKeyRing();

        List<PGPKeyRing> pgpKeyRingList = new ArrayList<>();
        pgpKeyRingList.add(secretKeyRing);
        pgpKeyRingList.add(publicKeyRing);

        return pgpKeyRingList;
    }
}
