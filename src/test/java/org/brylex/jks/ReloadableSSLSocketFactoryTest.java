package org.brylex.jks;

import org.brylex.jks.test.Certificates;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.hamcrest.core.IsEqual;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.security.KeyStore;

import static org.hamcrest.core.StringEndsWith.endsWith;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 29/08/2017.
 */
public class ReloadableSSLSocketFactoryTest {

    private TestHttpsServer httpsServer;

    private static int connect() throws Exception {
        try {
            HttpsURLConnection connection = (HttpsURLConnection) new URL("https://localhost:8443/").openConnection();
            return connection.getResponseCode();
        } catch (IOException e) {
            e.printStackTrace();
            throw e;
        }
    }

    @Before
    public void setUp() throws Exception {
        this.httpsServer = TestHttpsServer.startJetty();
    }

    @After
    public void tearDown() throws Exception {
        this.httpsServer.stopJetty();
    }

    @Test
    public void connectUsingFullyJKS() throws Exception {

        KeyStore jks = KeyStore.getInstance("JKS");
        jks.load(null);

        ManualObservableKeyStore keyStore = new ManualObservableKeyStore(jks);

        SSLSocketFactory sslSocketFactory = ReloadableSSLSocketFactory.create(keyStore);

        HttpsURLConnection.setDefaultSSLSocketFactory(sslSocketFactory);

        try {
            connect();
            fail();
        } catch (Exception e) {
            assertThat(e.getMessage(), endsWith("the trustAnchors parameter must be non-empty"));
        }

        jks.setCertificateEntry("jetty", Certificates.JETTY);
        keyStore.reload();

        int statusCode = connect();
        assertThat(statusCode, IsEqual.equalTo(200));
    }

    public static class TestHttpsServer extends AbstractHandler {

        private final Server server;

        private TestHttpsServer(Server server) {
            this.server = server;
        }

        public static TestHttpsServer startJetty() throws Exception {

            Server server = new Server();

            SslContextFactory sslContextFactory = new SslContextFactory();
            sslContextFactory.setKeyStorePath("src/test/resources/jks/jetty.jks");
            sslContextFactory.setKeyStorePassword("changeit");
            sslContextFactory.setExcludeCipherSuites("^.*_(MD5|SHA|SHA1)$");

            HttpConfiguration http_config = new HttpConfiguration();
            http_config.setSecureScheme("https");
            http_config.setSecurePort(8443);
            HttpConfiguration https_config = new HttpConfiguration(http_config);
            https_config.addCustomizer(new SecureRequestCustomizer());

            ServerConnector sslConnector = new ServerConnector(server,
                    new SslConnectionFactory(sslContextFactory, HttpVersion.HTTP_1_1.asString()),
                    new HttpConnectionFactory(https_config));
            sslConnector.setPort(8443);

            server.addConnector(sslConnector);

            TestHttpsServer testServer = new TestHttpsServer(server);
            server.setHandler(testServer);

            server.start();
            server.dumpStdErr();

            return testServer;
        }

        public void stopJetty() throws Exception {
            this.server.stop();
        }

        @Override
        public void handle(String s, Request request, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException, ServletException {

            httpServletResponse.setStatus(200);
            PrintWriter writer = httpServletResponse.getWriter();
            writer.println("OK");

            request.setHandled(true);
        }
    }

    private static class ManualObservableKeyStore implements ObservableKeyStore {

        private final KeyStore keyStore;

        private KeyStoreObserver observer;

        private ManualObservableKeyStore(KeyStore keyStore) {
            this.keyStore = keyStore;
        }

        void reload() {
            this.observer.onChange(this.keyStore);
        }

        @Override
        public void observe(KeyStoreObserver observer) {
            this.observer = observer;
        }

        @Override
        public KeyStore keyStore() {
            return keyStore;
        }
    }
}
