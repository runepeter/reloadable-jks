package org.brylex.jks.test;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 29/08/2017.
 */
public class Certificates {

    public static final X509Certificate EQUIFAX_ROOT = loadCertificate("/certificates/equifax.root.ca.pem");
    public static final X509Certificate GLOBALSIGN_R2 = loadCertificate("/certificates/globalsign.r2.pem");
    public static final X509Certificate GOOGLE_G2 = loadCertificate("/certificates/google.g2.pem");
    public static final X509Certificate GMAIL = loadCertificate("/certificates/mail.google.com.pem");
    public static final X509Certificate JETTY = loadCertificate("/certificates/jetty.pem");

    private Certificates() {
    }

    private static X509Certificate loadCertificate(String path) {
        try (InputStream is = Certificates.class.getResourceAsStream(path)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(is);
        } catch (Exception e) {
            throw new RuntimeException("Unable to load certificate from classpath resources [" + path + "].", e);
        }
    }

}
