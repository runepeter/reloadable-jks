package org.brylex.jks;

import java.security.KeyStore;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 29/08/2017.
 */
public interface ObservableKeyStore {

    void observe(KeyStoreObserver observer);

    KeyStore keyStore();

}
