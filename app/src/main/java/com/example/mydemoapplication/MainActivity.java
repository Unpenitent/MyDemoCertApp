package com.example.mydemoapplication;

import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import androidx.appcompat.app.AppCompatActivity;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.net.HttpURLConnection;
import java.net.URL;

import java.io.OutputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.IOException;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import java.util.Date;

public class MainActivity extends AppCompatActivity {

    private static final String KEY_ALIAS = "myKeyAlias";
    private static final String CN_PATTERN = "CN=%s, O=Android Authority";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        try {
            KeyPair keyPair = generateKeyPair(KEY_ALIAS);

            Certificate selfSignedCertificate = generateSelfSignedCertificate(keyPair);

            storeKeyPairAndCertificate(KEY_ALIAS, keyPair, selfSignedCertificate);

            PKCS10CertificationRequest csr = generateCSR(keyPair);

            sendCSRToca(csr);

        } catch (Exception e) {
            Log.e("MainActivity", "Erreur dans la generation de la bi-clé", e);
        }
    }

    private KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE);

            KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(
                    MainActivity.KEY_ALIAS,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .setKeySize(2048)
                    .build();

            keyPairGenerator.initialize(keyGenParameterSpec);

            return keyPairGenerator.generateKeyPair();

        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            // Afficher le Log ou informer l'utilisateur de l'erreur
            Log.e("MainActivity", "Erreur dans la generation de la bi-clé", e);
            return null;
        }
    }

    private Certificate generateSelfSignedCertificate(KeyPair keyPair) throws OperatorCreationException, CertificateException {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);

        X500Name dnName = new X500Name(String.format(CN_PATTERN, KEY_ALIAS));
        BigInteger certSerialNumber = new BigInteger(Long.toString(now));

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                dnName,
                certSerialNumber,
                startDate,
                new Date(now + 20L * 365 * 24 * 60 * 60 * 1000), // Période de validité du certificat
                dnName,
                keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keyPair.getPrivate());

        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    }


    private void storeKeyPairAndCertificate(String alias, KeyPair keyPair, Certificate certificate) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);

        keyStore.setKeyEntry(alias, keyPair.getPrivate(), null, new Certificate[]{certificate});
    }

    private PKCS10CertificationRequest generateCSR(KeyPair keyPair) throws OperatorCreationException {
        X500Name subject = new X500Name(String.format(CN_PATTERN, KEY_ALIAS));
        return new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate()));
    }

    private void sendCSRToca(PKCS10CertificationRequest csr) throws IOException {
        // Conversion de la CSR au format PEM
        byte[] csrBytes = csr.getEncoded();
        String csrPEM = android.util.Base64.encodeToString(csrBytes, android.util.Base64.DEFAULT);

        // L'URL de l'API de l'Autorité de cértification
        URL url = new URL("https://demo-ca.com/api");

        // Création de la connexion
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-pem-file");
        conn.setRequestProperty("Accept", "application/json");
        conn.setDoOutput(true);

        // Write the CSR to the request body
        OutputStream os = conn.getOutputStream();
        byte[] input = csrPEM.getBytes("utf-8");
        os.write(input, 0, input.length);

        // Récéption de la réponse du serveur
        BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), "utf-8"));
        StringBuilder response = new StringBuilder();
        String responseLine = null;
        while ((responseLine = br.readLine()) != null) {
            response.append(responseLine.trim());
        }

        // Affichage de la réponse du serveur
        Log.i("MainActivity", "Réponse de l'AC: " + response.toString());
    }


}
