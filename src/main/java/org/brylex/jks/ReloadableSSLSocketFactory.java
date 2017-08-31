package org.brylex.jks;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.KeyStoreException;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 29/08/2017.
 */
public class ReloadableSSLSocketFactory extends SSLSocketFactory implements KeyStoreObserver {

    private final SSLSocketFactory delegate;
    private final TrustManagerFactory trustManagerFactory;
    private final SSLContext sslContext;

    private ReloadableSSLSocketFactory(SSLSocketFactory delegate, TrustManagerFactory trustManagerFactory, SSLContext sslContext) {
        this.delegate = delegate;
        this.trustManagerFactory = trustManagerFactory;
        this.sslContext = sslContext;
    }

    public static SSLSocketFactory create(ObservableKeyStore keyStore) {

        try {
            final TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509");
            tmf.init(keyStore.keyStore());

            final SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);

            ReloadableSSLSocketFactory sslSocketFactory = new ReloadableSSLSocketFactory(sslContext.getSocketFactory(), tmf, sslContext);

            keyStore.observe(sslSocketFactory);

            return sslSocketFactory;

        } catch (Exception e) {
            throw new RuntimeException("Unable to initialize SSLSocketFactory from KeyStore.", e);
        }
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return delegate.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket(Socket socket, String s, int i, boolean b) throws IOException {
        return delegate.createSocket(socket, s, i, b);
    }

    @Override
    public Socket createSocket(Socket socket, InputStream inputStream, boolean b) throws IOException {
        return delegate.createSocket(socket, inputStream, b);
    }

    @Override
    public Socket createSocket() throws IOException {
        return delegate.createSocket();
    }

    @Override
    public Socket createSocket(String s, int i) throws IOException, UnknownHostException {
        return delegate.createSocket(s, i);
    }

    @Override
    public Socket createSocket(String s, int i, InetAddress inetAddress, int i1) throws IOException, UnknownHostException {
        return delegate.createSocket(s, i, inetAddress, i1);
    }

    @Override
    public Socket createSocket(InetAddress inetAddress, int i) throws IOException {
        return delegate.createSocket(inetAddress, i);
    }

    @Override
    public Socket createSocket(InetAddress inetAddress, int i, InetAddress inetAddress1, int i1) throws IOException {
        return delegate.createSocket(inetAddress, i, inetAddress1, i1);
    }

    @Override
    public void onChange(KeyStore keyStore) {

        try {
            trustManagerFactory.init(keyStore);
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);
        } catch (Exception e) {
            throw new RuntimeException("Unable to re-initialize on changed KeyStore.", e);
        }
    }
}
